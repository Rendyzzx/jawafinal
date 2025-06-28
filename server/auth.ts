import { loginSchema, changeCredentialsSchema, type LoginRequest, type ChangeCredentialsRequest } from "@shared/schema";
import { secureUserStorage } from "./security/userStorage";

interface AuthUser {
  id: number;
  username: string;
  role: "admin" | "user";
}

class AuthService {
  async validateLogin(loginData: LoginRequest): Promise<AuthUser | null> {
    const validation = loginSchema.safeParse(loginData);
    if (!validation.success) return null;

    const user = await secureUserStorage.validatePassword(loginData.username, loginData.password);
    if (!user) return null;

    // Return safe user data without password/salt
    return {
      id: user.id,
      username: user.username,
      role: user.role
    };
  }

  async changeCredentials(userId: number, currentPassword: string, changes: ChangeCredentialsRequest): Promise<boolean> {
    const validation = changeCredentialsSchema.safeParse(changes);
    if (!validation.success) return false;

    // Change password using secure storage
    const passwordChanged = await secureUserStorage.changePassword(userId, currentPassword, changes.newPassword);
    if (!passwordChanged) return false;

    // Update username if different
    if (changes.newUsername) {
      const user = await secureUserStorage.getUserById(userId);
      if (user && user.username !== changes.newUsername) {
        await secureUserStorage.updateUser(userId, { username: changes.newUsername });
      }
    }

    return true;
  }

  async getUserById(userId: number): Promise<AuthUser | null> {
    const user = await secureUserStorage.getUserById(userId);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      role: user.role
    };
  }

  isAdmin(user: AuthUser | null): boolean {
    return user?.role === "admin";
  }

  canDeleteNumbers(user: AuthUser | null): boolean {
    return this.isAdmin(user);
  }
}

export const authService = new AuthService();
