
import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs/promises';
import chokidar from 'chokidar';

const execAsync = promisify(exec);

export class GitHubBackupService {
  private backupDir: string;
  private isBackupInProgress: boolean = false;
  private watcher: chokidar.FSWatcher | null = null;
  private debounceTimer: NodeJS.Timeout | null = null;
  private githubUrl: string;

  constructor() {
    this.backupDir = process.cwd(); // Use project root directly
    this.githubUrl = process.env.GITHUB_BACKUP_URL || 'https://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@github.com/Rendyzzx/masmas.git';
  }

  async initializeBackup(): Promise<void> {
    try {
      // Check if already a git repository
      try {
        await execAsync('git status', { cwd: this.backupDir });
        console.log('Git repository already initialized');
      } catch {
        // Not a git repository, initialize it
        await execAsync('git init', { cwd: this.backupDir });
        
        // Set git config
        await execAsync('git config user.name "Database Backup Bot"', { cwd: this.backupDir });
        await execAsync('git config user.email "rendyraysa8@gmail,com"', { cwd: this.backupDir });
        
        // Add .gitignore for sensitive files
        await this.createGitignore();
        
        console.log('Git repository initialized for project backup');
      }

      // Configure remote
      await this.addRemote(this.githubUrl);
      
      // Start watching for file changes
      this.startWatching();
      
    } catch (error) {
      console.error('Failed to initialize backup:', error);
    }
  }

  private async createGitignore(): Promise<void> {
    const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Build outputs
dist/
build/

# Database
*.db
*.sqlite

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# nyc test coverage
.nyc_output

# Dependency directories
node_modules/

# Optional npm cache directory
.npm

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# next.js build output
.next

# nuxt.js build output
.nuxt

# vuepress build output
.vuepress/dist

# Serverless directories
.serverless

# FuseBox cache
.fusebox/

# DynamoDB Local files
.dynamodb/

# Backup directories
database-backup/
`;

    const gitignorePath = path.join(this.backupDir, '.gitignore');
    try {
      await fs.access(gitignorePath);
    } catch {
      await fs.writeFile(gitignorePath, gitignoreContent);
    }
  }

  private startWatching(): void {
    if (this.watcher) {
      this.watcher.close();
    }

    // Watch for file changes in the entire project
    this.watcher = chokidar.watch('.', {
      cwd: this.backupDir,
      ignored: [
        'node_modules/**',
        '.git/**',
        'dist/**',
        'build/**',
        '*.log',
        '.env*',
        'database-backup/**'
      ],
      persistent: true,
      ignoreInitial: true
    });

    this.watcher.on('all', (event, path) => {
      console.log(`File ${event}: ${path}`);
      this.debouncedBackup();
    });

    console.log('Started watching for file changes...');
  }

  private debouncedBackup(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    // Debounce backup for 5 seconds to avoid too frequent commits
    this.debounceTimer = setTimeout(() => {
      this.backupProject();
    }, 5000);
  }

  async backupProject(): Promise<void> {
    if (this.isBackupInProgress) {
      console.log('Backup already in progress, skipping...');
      return;
    }

    this.isBackupInProgress = true;

    try {
      console.log('Starting project backup...');

      // Check if there are any changes to commit
      const { stdout: status } = await execAsync('git status --porcelain', { cwd: this.backupDir });
      
      if (!status.trim()) {
        console.log('No changes to backup');
        return;
      }

      // Add all changes
      await execAsync('git add .', { cwd: this.backupDir });
      
      const commitMessage = `Auto backup - ${new Date().toISOString()}`;
      await execAsync(`git commit -m "${commitMessage}"`, { cwd: this.backupDir });

      // Push to GitHub
      try {
        await execAsync(`git push origin main`, { cwd: this.backupDir });
        console.log('Project backup pushed to GitHub successfully');
      } catch (pushError) {
        // If main branch doesn't exist, try creating it
        try {
          await execAsync(`git push -u origin main`, { cwd: this.backupDir });
          console.log('Project backup pushed to GitHub successfully (new branch created)');
        } catch (error) {
          console.error('Failed to push to GitHub:', error);
        }
      }

    } catch (error) {
      console.error('Failed to backup project:', error);
    } finally {
      this.isBackupInProgress = false;
    }
  }

  async backupToGitHub(data: any, filename: string = 'database.json'): Promise<void> {
    // Keep the old method for compatibility but also trigger project backup
    await this.backupProject();
  }

  async addRemote(repoUrl: string): Promise<void> {
    try {
      await execAsync(`git remote add origin ${repoUrl}`, { cwd: this.backupDir });
      console.log('GitHub remote added successfully');
    } catch (error) {
      // Remote might already exist, try to set URL
      try {
        await execAsync(`git remote set-url origin ${repoUrl}`, { cwd: this.backupDir });
        console.log('GitHub remote URL updated successfully');
      } catch (setError) {
        console.error('Failed to add/update remote:', setError);
      }
    }
  }

  async manualBackup(): Promise<void> {
    await this.backupProject();
  }

  stopWatching(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    console.log('Stopped watching for file changes');
  }
}

export const githubBackup = new GitHubBackupService();
