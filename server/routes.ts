import type { Express } from "express";
import { createServer, type Server } from "http";
import session from "express-session";
import MemoryStore from "memorystore";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { authService } from "./auth";
import { secureUserStorage } from "./security/userStorage";
import { insertNumberSchema, loginSchema, changeCredentialsSchema } from "@shared/schema";
import { Request, Response } from "express";
import { z } from "zod";
import { githubBackup } from "./services/githubBackup";

declare module "express-session" {
  interface SessionData {
    isAuthenticated?: boolean;
    userId?: number;
    username?: string;
    role?: string;
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Initialize storage
  await storage.initializeData();

  // Session middleware - use PostgreSQL if available, otherwise memory store
  const sessionTtl = 30 * 60 * 1000; // 30 minutes
  let sessionStore;

  if (process.env.DATABASE_URL) {
    const pgStore = connectPg(session);
    sessionStore = new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true,
      ttl: sessionTtl,
      tableName: "sessions",
    });
  } else {
    const MemoryStoreSession = MemoryStore(session);
    sessionStore = new MemoryStoreSession({
      checkPeriod: sessionTtl,
    });
  }

  app.use(session({
    secret: process.env.SESSION_SECRET || "your-secret-key-change-in-production",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset session timeout on each request
    cookie: {
      secure: false, // Set to true in production with HTTPS
      httpOnly: true,
      maxAge: sessionTtl,
    },
  }));

  // Auth middleware
  const requireAuth = (req: any, res: any, next: any) => {
    if (!req.session.isAuthenticated) {
      return res.status(401).json({ message: "Authentication required" });
    }
    next();
  };

  const requireAdmin = (req: any, res: any, next: any) => {
    if (!req.session.isAuthenticated || req.session.role !== "admin") {
      return res.status(403).json({ message: "Admin access required" });
    }
    next();
  };

  // Login endpoint
  app.post("/api/auth/login", async (req, res) => {
    try {
      const loginData = loginSchema.parse(req.body);
      const user = await authService.validateLogin(loginData);

      if (user) {
        req.session.isAuthenticated = true;
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.json({ success: true, message: "Login successful" });
      } else {
        res.status(401).json({ message: "Invalid username or password" });
      }
    } catch (error) {
      console.error("Login error:", error);
      res.status(400).json({ message: "Invalid request data" });
    }
  });

  // Logout endpoint
  app.post("/api/auth/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "Could not log out" });
      }
      res.json({ message: "Logged out successfully" });
    });
  });

  // Check auth status
  app.get("/api/auth/me", async (req, res) => {
    if (req.session.isAuthenticated) {
      try {
        // Verify user still exists in secure storage
        const user = await authService.getUserById(req.session.userId!);
        if (user) {
          res.json({ 
            isAuthenticated: true,
            userId: user.id,
            username: user.username,
            role: user.role
          });
        } else {
          // User not found, clear session
          req.session.destroy(() => {
            res.json({ isAuthenticated: false });
          });
        }
      } catch (error) {
        console.error("Error verifying user:", error);
        res.status(500).json({ message: "Failed to verify user" });
      }
    } else {
      res.json({ isAuthenticated: false });
    }
  });

  // Change credentials (admin only)
  app.post("/api/auth/change-credentials", requireAdmin, async (req, res) => {
    try {
      const changeData = changeCredentialsSchema.parse(req.body);
      const success = await authService.changeCredentials(
        req.session.userId!,
        changeData.currentPassword,
        changeData
      );

      if (success) {
        // Update session with new username
        req.session.username = changeData.newUsername;
        res.json({ success: true, message: "Credentials updated successfully" });
      } else {
        res.status(400).json({ message: "Current password is incorrect" });
      }
    } catch (error: any) {
      if (error.name === "ZodError") {
        res.status(400).json({ message: "Invalid data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to update credentials" });
      }
    }
  });

  // Create new user (admin only)
  app.post("/api/auth/create-user", requireAdmin, async (req, res) => {
    try {
      const { username, password, role } = req.body;

      if (!username || !password || !role) {
        return res.status(400).json({ message: "Username, password, and role are required" });
      }

      if (!["admin", "user"].includes(role)) {
        return res.status(400).json({ message: "Role must be either 'admin' or 'user'" });
      }

      if (username.length < 3) {
        return res.status(400).json({ message: "Username must be at least 3 characters" });
      }

      if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters" });
      }

      const newUser = await secureUserStorage.createUser(username, password, role);

      res.status(201).json({ 
        success: true, 
        message: "User created successfully",
        user: {
          id: newUser.id,
          username: newUser.username,
          role: newUser.role
        }
      });
    } catch (error: any) {
      if (error.message === "Username already exists") {
        res.status(409).json({ message: "Username already exists" });
      } else {
        console.error("Error creating user:", error);
        res.status(500).json({ message: "Failed to create user" });
      }
    }
  });

  // Get all users (admin only)
  app.get("/api/auth/users", requireAdmin, async (req, res) => {
    try {
      const users = await secureUserStorage.getAllUsers();
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  // Get all numbers (protected)
  app.get("/api/numbers", requireAuth, async (req, res) => {
    try {
      const numbers = await storage.getNumbers();
      res.json(numbers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch numbers" });
    }
  });

  // Add new number (protected)
  app.post("/api/numbers", requireAuth, async (req, res) => {
    try {
      const numberData = insertNumberSchema.parse(req.body);
      const newNumber = await storage.addNumber(numberData);
      res.status(201).json(newNumber);
    } catch (error: any) {
      if (error.name === "ZodError") {
        res.status(400).json({ message: "Invalid number data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to add number" });
      }
    }
  });

  // Delete number (admin only)
  app.delete("/api/numbers/:id", requireAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (isNaN(id)) {
        return res.status(400).json({ message: "Invalid number ID" });
      }

      const deleted = await storage.deleteNumber(id);
      if (deleted) {
        res.json({ message: "Number deleted successfully" });
      } else {
        res.status(404).json({ message: "Number not found" });
      }
    } catch (error) {
      res.status(500).json({ message: "Failed to delete number" });
    }
  });

  // Export data endpoint
  app.get("/api/export", requireAuth, async (req: Request, res: Response) => {
    try {
      const numbers = await storage.getNumbers();
      const users = req.user?.role === "admin" ? await storage.getAllUsers() : [];

      const exportData = {
        numbers,
        users: users.map(user => ({
          id: user.id,
          username: user.username,
          role: user.role,
          createdAt: user.createdAt
        })), // Exclude password from export
        exportedAt: new Date().toISOString()
      };

      res.json(exportData);
    } catch (error) {
      console.error("Export error:", error);
      res.status(500).json({ error: "Failed to export data" });
    }
  });

  // GitHub backup configuration
  app.post("/api/github-backup/configure", requireAuth, async (req: any, res: Response) => {
    try {
      if (req.session.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const { repoUrl } = req.body;

      if (!repoUrl) {
        return res.status(400).json({ error: "Repository URL is required" });
      }

      await githubBackup.addRemote(repoUrl);
      res.json({ success: true, message: "GitHub backup configured successfully" });
    } catch (error) {
      console.error("GitHub backup configuration error:", error);
      res.status(500).json({ error: "Failed to configure GitHub backup" });
    }
  });

  // Manual backup trigger
  app.post("/api/github-backup/trigger", requireAuth, async (req: any, res: Response) => {
    try {
      if (req.session.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const numbers = await storage.getNumbers();
      const users = await storage.getAllUsers();

      const backupData = {
        numbers,
        users: users.map(user => ({
          id: user.id,
          username: user.username,
          role: user.role,
          createdAt: user.createdAt
        })),
        timestamp: new Date().toISOString()
      };

      await githubBackup.backupToGitHub(backupData, 'manual_backup.json');
      res.json({ success: true, message: "Manual backup completed successfully" });
    } catch (error) {
      console.error("Manual backup error:", error);
      res.status(500).json({ error: "Failed to trigger manual backup" });
    }
  });

  // Project backup trigger
  app.post("/api/github-backup/project", requireAuth, async (req: any, res: Response) => {
    try {
      if (req.session.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      await githubBackup.manualBackup();
      res.json({ success: true, message: "Project backup completed successfully" });
    } catch (error) {
      console.error("Project backup error:", error);
      res.status(500).json({ error: "Failed to trigger project backup" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}