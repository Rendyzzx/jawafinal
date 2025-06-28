import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

interface UserData {
  id: number;
  username: string;
  passwordHash: string;
  role: "admin" | "user";
  salt: string;
  createdAt: string;
  updatedAt: string;
}

interface UserFile {
  users: UserData[];
  lastId: number;
  checksum: string;
}

class SecureUserStorage {
  private dataPath: string;
  private encryptionKey: string;

  constructor() {
    // Store outside public folders for security
    this.dataPath = path.join(process.cwd(), "server", "security", "users.enc");
    // Use environment variable or consistent default key
    this.encryptionKey = process.env.USER_ENCRYPTION_KEY || "danixren_secure_key_2025_replit_db";
  }

  private generateSecureKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private getKey(): Buffer {
    // Create consistent 32-byte key from our key string
    const hash = crypto.createHash('sha256');
    hash.update(this.encryptionKey);
    return hash.digest();
  }

  private encrypt(data: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.getKey(), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  }

  private decrypt(encryptedData: string): string {
    try {
      const parts = encryptedData.split(':');
      const iv = Buffer.from(parts[0], 'hex');
      const encrypted = parts[1];
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.getKey(), iv);
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt user data - possible tampering detected');
    }
  }

  private hashPassword(password: string, salt: string): string {
    return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  }

  private generateSalt(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private calculateChecksum(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private async loadUserData(): Promise<UserFile> {
    try {
      const encryptedData = await fs.readFile(this.dataPath, 'utf8');
      const decryptedData = this.decrypt(encryptedData);
      const userData: UserFile = JSON.parse(decryptedData);
      
      // Verify checksum to detect tampering
      const { checksum, ...dataToVerify } = userData;
      const calculatedChecksum = this.calculateChecksum(JSON.stringify(dataToVerify));
      
      if (checksum !== calculatedChecksum) {
        throw new Error('Data integrity check failed - file may have been tampered with');
      }
      
      return userData;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        // Initialize with default admin user
        return await this.initializeDefaultData();
      }
      throw error;
    }
  }

  private async saveUserData(userData: UserFile): Promise<void> {
    // Calculate checksum for integrity
    const { checksum, ...dataToChecksum } = userData;
    userData.checksum = this.calculateChecksum(JSON.stringify(dataToChecksum));
    
    const jsonData = JSON.stringify(userData, null, 2);
    const encryptedData = this.encrypt(jsonData);
    
    // Ensure directory exists
    const dir = path.dirname(this.dataPath);
    await fs.mkdir(dir, { recursive: true });
    
    // Write with strict permissions (owner read/write only)
    await fs.writeFile(this.dataPath, encryptedData, { mode: 0o600 });
  }

  private async initializeDefaultData(): Promise<UserFile> {
    const salt = this.generateSalt();
    const userData: UserFile = {
      users: [
        {
          id: 1,
          username: "danixren",
          passwordHash: this.hashPassword("pendukungjava", salt),
          role: "admin",
          salt: salt,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ],
      lastId: 1,
      checksum: ""
    };
    
    await this.saveUserData(userData);
    return userData;
  }

  async getUserByUsername(username: string): Promise<UserData | undefined> {
    const userData = await this.loadUserData();
    return userData.users.find(user => user.username === username);
  }

  async getUserById(id: number): Promise<UserData | undefined> {
    const userData = await this.loadUserData();
    return userData.users.find(user => user.id === id);
  }

  async validatePassword(username: string, password: string): Promise<UserData | null> {
    const user = await this.getUserByUsername(username);
    if (!user) return null;
    
    const passwordHash = this.hashPassword(password, user.salt);
    if (passwordHash === user.passwordHash) {
      return user;
    }
    
    return null;
  }

  async updateUser(id: number, updates: Partial<Pick<UserData, 'username' | 'role'>>): Promise<UserData | undefined> {
    const userData = await this.loadUserData();
    const userIndex = userData.users.findIndex(user => user.id === id);
    
    if (userIndex === -1) return undefined;
    
    userData.users[userIndex] = {
      ...userData.users[userIndex],
      ...updates,
      updatedAt: new Date().toISOString()
    };
    
    await this.saveUserData(userData);
    return userData.users[userIndex];
  }

  async changePassword(id: number, currentPassword: string, newPassword: string): Promise<boolean> {
    const user = await this.getUserById(id);
    if (!user) return false;
    
    // Verify current password
    const currentHash = this.hashPassword(currentPassword, user.salt);
    if (currentHash !== user.passwordHash) return false;
    
    // Generate new salt and hash for new password
    const newSalt = this.generateSalt();
    const newPasswordHash = this.hashPassword(newPassword, newSalt);
    
    const userData = await this.loadUserData();
    const userIndex = userData.users.findIndex(u => u.id === id);
    
    userData.users[userIndex].passwordHash = newPasswordHash;
    userData.users[userIndex].salt = newSalt;
    userData.users[userIndex].updatedAt = new Date().toISOString();
    
    await this.saveUserData(userData);
    return true;
  }

  async createUser(username: string, password: string, role: "admin" | "user"): Promise<UserData> {
    const userData = await this.loadUserData();
    
    // Check if username already exists
    if (userData.users.find(user => user.username === username)) {
      throw new Error('Username already exists');
    }
    
    const salt = this.generateSalt();
    const newUser: UserData = {
      id: ++userData.lastId,
      username,
      passwordHash: this.hashPassword(password, salt),
      role,
      salt,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    userData.users.push(newUser);
    await this.saveUserData(userData);
    
    return newUser;
  }

  async getAllUsers(): Promise<Omit<UserData, 'passwordHash' | 'salt'>[]> {
    const userData = await this.loadUserData();
    return userData.users.map(({ passwordHash, salt, ...user }) => user);
  }
}

export const secureUserStorage = new SecureUserStorage();