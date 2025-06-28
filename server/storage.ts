import { numbers, users, type Number, type InsertNumber, type User, type InsertUser, type UpdateUser } from "@shared/schema";
import { eq } from "drizzle-orm";
import fs from "fs/promises";
import path from "path";

export interface IStorage {
  // Numbers management
  getNumbers(): Promise<Number[]>;
  addNumber(number: InsertNumber): Promise<Number>;
  deleteNumber(id: number): Promise<boolean>;

  // User management
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserById(id: number): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, updates: UpdateUser): Promise<User | undefined>;

  // Initialization
  initializeData(): Promise<void>;
}

interface FileData {
  numbers: Number[];
  nextNumberId: number;
}

import { githubBackup } from "./services/githubBackup";
export class FileStorage implements IStorage {
  private dataPath = path.join(process.cwd(), "data", "numbers.json");

  async initializeData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataPath), { recursive: true });

      // Check if data file exists, if not create it
      try {
        await fs.access(this.dataPath);
      } catch {
        const initialData: FileData = {
          numbers: [],
          nextNumberId: 1
        };
        await fs.writeFile(this.dataPath, JSON.stringify(initialData, null, 2));
      }
    } catch (error) {
      console.error("Failed to initialize data:", error);
    }
  }

  private async readData(): Promise<FileData> {
    try {
      const content = await fs.readFile(this.dataPath, "utf-8");
      return JSON.parse(content);
    } catch {
      return { numbers: [], nextNumberId: 1 };
    }
  }

  private async writeData(data: FileData): Promise<void> {
    await fs.writeFile(this.dataPath, JSON.stringify(data, null, 2));
  }

  // Numbers management
  async getNumbers(): Promise<Number[]> {
    const data = await this.readData();
    return data.numbers.reverse(); // Most recent first
  }

  async addNumber(insertNumber: InsertNumber): Promise<Number> {
    const data = await this.readData();
    const newNumber: Number = {
      id: data.nextNumberId,
      number: insertNumber.number,
      note: insertNumber.note || null,
      createdAt: new Date()
    };

    data.numbers.push(newNumber);
    data.nextNumberId++;
    await this.writeData(data);

    // Backup to GitHub
    await githubBackup.backupToGitHub(data, 'database_backup.json');

    return newNumber;
  }

  async deleteNumber(id: number): Promise<boolean> {
    const data = await this.readData();
    const initialLength = data.numbers.length;
    data.numbers = data.numbers.filter(n => n.id !== id);

    if (data.numbers.length < initialLength) {
      await this.writeData(data);
      // Backup to GitHub
      await githubBackup.backupToGitHub(data, 'database_backup.json');
      return true;
    }
    return false;
  }

  // User management - Using secure user storage
  async getUserByUsername(username: string): Promise<User | undefined> {
    const { secureUserStorage } = await import("./security/userStorage");
    const userData = await secureUserStorage.getUserByUsername(username);
    if (!userData) return undefined;

    return {
      id: userData.id,
      username: userData.username,
      role: userData.role,
      createdAt: new Date(userData.createdAt),
      updatedAt: new Date(userData.updatedAt)
    };
  }

  async getUserById(id: number): Promise<User | undefined> {
    const { secureUserStorage } = await import("./security/userStorage");
    const userData = await secureUserStorage.getUserById(id);
    if (!userData) return undefined;

    return {
      id: userData.id,
      username: userData.username,
      role: userData.role,
      createdAt: new Date(userData.createdAt),
      updatedAt: new Date(userData.updatedAt)
    };
  }

  async createUser(user: InsertUser): Promise<User> {
    const { secureUserStorage } = await import("./security/userStorage");
    const userData = await secureUserStorage.createUser(user.username, user.password, (user.role || "user") as "admin" | "user");
        // Backup to GitHub
        await githubBackup.backupToGitHub(userData, 'database_backup.json');
    return {
      id: userData.id,
      username: userData.username,
      role: userData.role,
      createdAt: new Date(userData.createdAt),
      updatedAt: new Date(userData.updatedAt)
    };
  }

  async updateUser(id: number, updates: UpdateUser): Promise<User | undefined> {
    const { secureUserStorage } = await import("./security/userStorage");
    const userData = await secureUserStorage.updateUser(id, {
      username: updates.username,
      role: updates.role as "admin" | "user" | undefined
    });
    if (!userData) return undefined;
            // Backup to GitHub
            await githubBackup.backupToGitHub(userData, 'database_backup.json');
    return {
      id: userData.id,
      username: userData.username,
      role: userData.role,
      createdAt: new Date(userData.createdAt),
      updatedAt: new Date(userData.updatedAt)
    };
  }
}

export class DatabaseStorage implements IStorage {
  private db: any;

  constructor() {
    // Lazy load db to avoid import issues
    this.db = null;
  }

  private async getDb() {
    if (!this.db) {
      const dbModule = await import("./db");
      this.db = dbModule.db;
      if (!this.db) {
        throw new Error("Database not available. Please set DATABASE_URL environment variable.");
      }
    }
    return this.db;
  }

  async initializeData(): Promise<void> {
    try {
      // Check if admin user exists, if not create one
      const adminUser = await this.getUserByUsername("admin");
      if (!adminUser) {
        await this.createUser({
          username: "admin",
          password: "admin123",
          role: "admin"
        });
      }

      // Check if regular user exists, if not create one
      const regularUser = await this.getUserByUsername("danixren");
      if (!regularUser) {
        await this.createUser({
          username: "danixren",
          password: "pendukungjava",
          role: "user"
        });
      }
    } catch (error) {
      console.error("Failed to initialize data:", error);
    }
  }

  // Numbers management
  async getNumbers(): Promise<Number[]> {
    const db = await this.getDb();
    const result = await db.select().from(numbers).orderBy(numbers.createdAt);
    return result.reverse(); // Most recent first
  }

  async addNumber(insertNumber: InsertNumber): Promise<Number> {
    const db = await this.getDb();
    const [number] = await db
      .insert(numbers)
      .values(insertNumber)
      .returning();

        // Backup to GitHub
        await githubBackup.backupToGitHub(number, 'database_backup.json');

    return number;
  }

  async deleteNumber(id: number): Promise<boolean> {
    const db = await this.getDb();
    const result = await db
      .delete(numbers)
      .where(eq(numbers.id, id))
      .returning();
    const deleted = result.length > 0;
            // Backup to GitHub
            await githubBackup.backupToGitHub(result, 'database_backup.json');
    return deleted;
  }

  // User management
  async getUserByUsername(username: string): Promise<User | undefined> {
    const db = await this.getDb();
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.username, username));
    return user ? {
      id: user.id,
      username: user.username,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    } : undefined;
  }

  async getUserById(id: number): Promise<User | undefined> {
    const db = await this.getDb();
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, id));
    return user ? {
      id: user.id,
      username: user.username,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    } : undefined;
  }

  async createUser(user: InsertUser): Promise<User> {
    const db = await this.getDb();
    const [newUser] = await db
      .insert(users)
      .values(user)
      .returning();
        // Backup to GitHub
        await githubBackup.backupToGitHub(newUser, 'database_backup.json');
    return {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      createdAt: newUser.createdAt,
      updatedAt: newUser.updatedAt
    };
  }

  async updateUser(id: number, updates: UpdateUser): Promise<User | undefined> {
    const db = await this.getDb();
    const [updatedUser] = await db
      .update(users)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
            // Backup to GitHub
            await githubBackup.backupToGitHub(updatedUser, 'database_backup.json');
    return updatedUser ? {
      id: updatedUser.id,
      username: updatedUser.username,
      role: updatedUser.role,
      createdAt: updatedUser.createdAt,
      updatedAt: updatedUser.updatedAt
    } : undefined;
  }
}

// Use DatabaseStorage if DATABASE_URL is available, otherwise fallback to FileStorage
export const storage = process.env.DATABASE_URL ? new DatabaseStorage() : new FileStorage();