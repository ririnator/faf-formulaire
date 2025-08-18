/**
 * Production Backup and Restore System
 * Automated backup system for MongoDB, files, and configurations
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const tar = require('tar');

class BackupSystem {
  constructor() {
    this.config = {
      enabled: process.env.BACKUP_ENABLED === 'true',
      schedule: process.env.BACKUP_SCHEDULE || '0 2 * * *', // Daily at 2 AM
      retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS) || 30,
      storagePath: process.env.BACKUP_STORAGE_PATH || '/var/backups/faf',
      encryptionKey: process.env.BACKUP_ENCRYPTION_KEY,
      
      // MongoDB settings
      mongoUri: process.env.MONGODB_URI,
      
      // AWS S3 settings (optional)
      aws: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        bucket: process.env.AWS_S3_BUCKET,
        region: process.env.AWS_REGION || 'eu-west-1'
      },
      
      // What to backup
      targets: {
        database: true,
        applicationFiles: true,
        configurations: true,
        logs: true,
        uploads: true
      }
    };

    this.isRunning = false;
    this.currentBackup = null;
  }

  /**
   * Initialize backup system
   */
  async initialize() {
    console.log('💾 Initializing backup system...');
    
    if (!this.config.enabled) {
      console.log('⚠️ Backup system is disabled');
      return;
    }

    // Create backup directories
    await this.createBackupDirectories();
    
    // Validate configuration
    await this.validateConfiguration();
    
    // Schedule automatic backups
    this.scheduleBackups();
    
    console.log('✅ Backup system initialized');
  }

  /**
   * Create necessary backup directories
   */
  async createBackupDirectories() {
    const directories = [
      this.config.storagePath,
      path.join(this.config.storagePath, 'database'),
      path.join(this.config.storagePath, 'files'),
      path.join(this.config.storagePath, 'logs'),
      path.join(this.config.storagePath, 'temp')
    ];

    for (const dir of directories) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
        console.log(`📁 Created backup directory: ${dir}`);
      }
    }
  }

  /**
   * Validate backup configuration
   */
  async validateConfiguration() {
    const errors = [];

    // Check MongoDB connection
    if (this.config.targets.database && !this.config.mongoUri) {
      errors.push('MongoDB URI is required for database backups');
    }

    // Check encryption key
    if (this.config.encryptionKey && this.config.encryptionKey.length < 32) {
      errors.push('Encryption key must be at least 32 characters');
    }

    // Check storage path permissions
    try {
      fs.accessSync(this.config.storagePath, fs.constants.W_OK);
    } catch (error) {
      errors.push(`Backup storage path is not writable: ${this.config.storagePath}`);
    }

    // Test MongoDB connection
    if (this.config.targets.database && this.config.mongoUri) {
      try {
        const client = new MongoClient(this.config.mongoUri, {
          serverSelectionTimeoutMS: 5000
        });
        await client.connect();
        await client.close();
        console.log('✅ MongoDB connection test successful');
      } catch (error) {
        errors.push(`MongoDB connection failed: ${error.message}`);
      }
    }

    if (errors.length > 0) {
      throw new Error(`Backup configuration errors:\\n${errors.join('\\n')}`);
    }
  }

  /**
   * Schedule automatic backups
   */
  scheduleBackups() {
    const cron = require('node-cron');
    
    if (cron.validate(this.config.schedule)) {
      cron.schedule(this.config.schedule, async () => {
        try {
          await this.performFullBackup();
        } catch (error) {
          console.error('Scheduled backup failed:', error);
        }
      });
      
      console.log(`📅 Scheduled backups: ${this.config.schedule}`);
    } else {
      console.error('Invalid backup schedule format');
    }
  }

  /**
   * Perform full backup
   */
  async performFullBackup() {
    if (this.isRunning) {
      console.log('⚠️ Backup already in progress, skipping...');
      return;
    }

    console.log('🚀 Starting full backup...');
    
    const startTime = Date.now();
    const backupId = this.generateBackupId();
    
    this.isRunning = true;
    this.currentBackup = {
      id: backupId,
      startTime,
      status: 'running',
      progress: 0,
      targets: []
    };

    try {
      const backupDir = path.join(this.config.storagePath, backupId);
      fs.mkdirSync(backupDir, { recursive: true });

      // Backup database
      if (this.config.targets.database) {
        await this.backupDatabase(backupDir);
        this.currentBackup.progress += 25;
      }

      // Backup application files
      if (this.config.targets.applicationFiles) {
        await this.backupApplicationFiles(backupDir);
        this.currentBackup.progress += 25;
      }

      // Backup configurations
      if (this.config.targets.configurations) {
        await this.backupConfigurations(backupDir);
        this.currentBackup.progress += 25;
      }

      // Backup logs
      if (this.config.targets.logs) {
        await this.backupLogs(backupDir);
        this.currentBackup.progress += 25;
      }

      // Create backup archive
      const archivePath = await this.createBackupArchive(backupDir, backupId);
      
      // Encrypt if configured
      let finalPath = archivePath;
      if (this.config.encryptionKey) {
        finalPath = await this.encryptBackup(archivePath);
        fs.unlinkSync(archivePath); // Remove unencrypted archive
      }

      // Upload to cloud storage if configured
      if (this.config.aws.bucket) {
        await this.uploadToS3(finalPath, backupId);
      }

      // Clean up temporary files
      fs.rmSync(backupDir, { recursive: true, force: true });

      // Update backup record
      this.currentBackup.status = 'completed';
      this.currentBackup.endTime = Date.now();
      this.currentBackup.duration = this.currentBackup.endTime - startTime;
      this.currentBackup.size = fs.statSync(finalPath).size;
      this.currentBackup.path = finalPath;

      // Save backup metadata
      await this.saveBackupMetadata(this.currentBackup);

      // Clean up old backups
      await this.cleanupOldBackups();

      console.log(`✅ Backup completed successfully: ${backupId}`);
      console.log(`⏱️ Duration: ${Math.round(this.currentBackup.duration / 1000)}s`);
      console.log(`📦 Size: ${this.formatBytes(this.currentBackup.size)}`);

    } catch (error) {
      console.error('❌ Backup failed:', error);
      
      if (this.currentBackup) {
        this.currentBackup.status = 'failed';
        this.currentBackup.error = error.message;
        await this.saveBackupMetadata(this.currentBackup);
      }
      
      throw error;
    } finally {
      this.isRunning = false;
      this.currentBackup = null;
    }
  }

  /**
   * Backup MongoDB database
   */
  async backupDatabase(backupDir) {
    console.log('🗄️ Backing up database...');
    
    const dbBackupDir = path.join(backupDir, 'database');
    fs.mkdirSync(dbBackupDir, { recursive: true });

    return new Promise((resolve, reject) => {
      const args = [
        '--uri', this.config.mongoUri,
        '--out', dbBackupDir,
        '--gzip'
      ];

      const mongodump = spawn('mongodump', args, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let output = '';
      let errorOutput = '';

      mongodump.stdout.on('data', (data) => {
        output += data.toString();
      });

      mongodump.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      mongodump.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Database backup completed');
          resolve();
        } else {
          reject(new Error(`mongodump failed with code ${code}: ${errorOutput}`));
        }
      });
    });
  }

  /**
   * Backup application files
   */
  async backupApplicationFiles(backupDir) {
    console.log('📁 Backing up application files...');
    
    const appBackupDir = path.join(backupDir, 'application');
    fs.mkdirSync(appBackupDir, { recursive: true });

    // Files and directories to backup
    const targets = [
      'backend/',
      'frontend/',
      'package.json',
      'package-lock.json'
    ];

    const appRoot = process.cwd();
    
    for (const target of targets) {
      const sourcePath = path.join(appRoot, target);
      const targetPath = path.join(appBackupDir, target);
      
      if (fs.existsSync(sourcePath)) {
        await this.copyRecursive(sourcePath, targetPath, [
          'node_modules',
          '.git',
          'coverage',
          'logs',
          '.env*'
        ]);
      }
    }

    console.log('✅ Application files backup completed');
  }

  /**
   * Backup configurations
   */
  async backupConfigurations(backupDir) {
    console.log('⚙️ Backing up configurations...');
    
    const configBackupDir = path.join(backupDir, 'configs');
    fs.mkdirSync(configBackupDir, { recursive: true });

    // System configurations to backup
    const configs = [
      '/etc/nginx/sites-available/',
      '/etc/ssl/certs/',
      '/etc/systemd/system/faf*.service',
      '/etc/crontab'
    ];

    for (const configPath of configs) {
      try {
        if (fs.existsSync(configPath)) {
          const fileName = path.basename(configPath);
          const targetPath = path.join(configBackupDir, fileName);
          
          if (fs.statSync(configPath).isDirectory()) {
            await this.copyRecursive(configPath, targetPath);
          } else {
            fs.copyFileSync(configPath, targetPath);
          }
        }
      } catch (error) {
        console.warn(`Warning: Could not backup ${configPath}: ${error.message}`);
      }
    }

    // Environment configuration (without secrets)
    const envExample = this.createEnvironmentExample();
    fs.writeFileSync(path.join(configBackupDir, '.env.example'), envExample);

    console.log('✅ Configuration backup completed');
  }

  /**
   * Backup logs
   */
  async backupLogs(backupDir) {
    console.log('📝 Backing up logs...');
    
    const logsBackupDir = path.join(backupDir, 'logs');
    fs.mkdirSync(logsBackupDir, { recursive: true });

    const logDirectories = [
      '/var/log/faf/',
      '/var/log/nginx/',
      path.join(process.cwd(), 'logs/')
    ];

    for (const logDir of logDirectories) {
      if (fs.existsSync(logDir)) {
        const dirName = path.basename(logDir);
        const targetPath = path.join(logsBackupDir, dirName);
        await this.copyRecursive(logDir, targetPath);
      }
    }

    console.log('✅ Logs backup completed');
  }

  /**
   * Create backup archive
   */
  async createBackupArchive(backupDir, backupId) {
    console.log('📦 Creating backup archive...');
    
    const archivePath = path.join(this.config.storagePath, `${backupId}.tar.gz`);
    
    await tar.create(
      {
        gzip: true,
        file: archivePath,
        cwd: path.dirname(backupDir)
      },
      [path.basename(backupDir)]
    );

    console.log('✅ Archive created');
    return archivePath;
  }

  /**
   * Encrypt backup file
   */
  async encryptBackup(filePath) {
    console.log('🔐 Encrypting backup...');
    
    const encryptedPath = filePath + '.enc';
    const key = crypto.scryptSync(this.config.encryptionKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher('aes-256-cbc', key);
    const input = fs.createReadStream(filePath);
    const output = fs.createWriteStream(encryptedPath);
    
    // Write IV at the beginning of the file
    output.write(iv);
    
    return new Promise((resolve, reject) => {
      input
        .pipe(cipher)
        .pipe(output)
        .on('finish', () => {
          console.log('✅ Backup encrypted');
          resolve(encryptedPath);
        })
        .on('error', reject);
    });
  }

  /**
   * Upload backup to AWS S3
   */
  async uploadToS3(filePath, backupId) {
    if (!this.config.aws.bucket) {
      return;
    }

    console.log('☁️ Uploading to S3...');
    
    try {
      const AWS = require('aws-sdk');
      
      const s3 = new AWS.S3({
        accessKeyId: this.config.aws.accessKeyId,
        secretAccessKey: this.config.aws.secretAccessKey,
        region: this.config.aws.region
      });

      const fileStream = fs.createReadStream(filePath);
      const fileName = path.basename(filePath);
      
      const uploadParams = {
        Bucket: this.config.aws.bucket,
        Key: `faf-backups/${backupId}/${fileName}`,
        Body: fileStream,
        ServerSideEncryption: 'AES256',
        StorageClass: 'STANDARD_IA' // Infrequent Access for cost optimization
      };

      await s3.upload(uploadParams).promise();
      console.log('✅ Backup uploaded to S3');
      
    } catch (error) {
      console.error('S3 upload failed:', error);
      // Don't fail the entire backup for S3 issues
    }
  }

  /**
   * Restore from backup
   */
  async restoreFromBackup(backupId, options = {}) {
    console.log(`🔄 Starting restore from backup: ${backupId}`);
    
    const backupMetadata = await this.loadBackupMetadata(backupId);
    if (!backupMetadata) {
      throw new Error(`Backup not found: ${backupId}`);
    }

    const backupPath = backupMetadata.path;
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file not found: ${backupPath}`);
    }

    try {
      // Create temporary restore directory
      const restoreDir = path.join(this.config.storagePath, 'temp', `restore-${Date.now()}`);
      fs.mkdirSync(restoreDir, { recursive: true });

      // Decrypt backup if needed
      let archivePath = backupPath;
      if (backupPath.endsWith('.enc')) {
        archivePath = await this.decryptBackup(backupPath, restoreDir);
      }

      // Extract archive
      await tar.extract({
        file: archivePath,
        cwd: restoreDir
      });

      const extractedDir = fs.readdirSync(restoreDir)[0];
      const backupContentDir = path.join(restoreDir, extractedDir);

      // Restore components based on options
      if (options.database !== false) {
        await this.restoreDatabase(path.join(backupContentDir, 'database'));
      }

      if (options.configurations !== false) {
        await this.restoreConfigurations(path.join(backupContentDir, 'configs'));
      }

      if (options.applicationFiles !== false && options.confirmApplicationRestore) {
        await this.restoreApplicationFiles(path.join(backupContentDir, 'application'));
      }

      // Clean up
      fs.rmSync(restoreDir, { recursive: true, force: true });

      console.log('✅ Restore completed successfully');
      
    } catch (error) {
      console.error('❌ Restore failed:', error);
      throw error;
    }
  }

  /**
   * Decrypt backup file
   */
  async decryptBackup(encryptedPath, outputDir) {
    console.log('🔓 Decrypting backup...');
    
    const decryptedPath = path.join(outputDir, 'backup.tar.gz');
    const key = crypto.scryptSync(this.config.encryptionKey, 'salt', 32);
    
    const input = fs.createReadStream(encryptedPath);
    const output = fs.createWriteStream(decryptedPath);
    
    return new Promise((resolve, reject) => {
      // Read IV from the beginning of the file
      const ivBuffer = Buffer.alloc(16);
      let ivRead = false;
      
      input.on('readable', () => {
        if (!ivRead) {
          const iv = input.read(16);
          if (iv) {
            ivRead = true;
            const decipher = crypto.createDecipher('aes-256-cbc', key);
            
            input
              .pipe(decipher)
              .pipe(output)
              .on('finish', () => {
                console.log('✅ Backup decrypted');
                resolve(decryptedPath);
              })
              .on('error', reject);
          }
        }
      });
      
      input.on('error', reject);
    });
  }

  /**
   * Restore database
   */
  async restoreDatabase(databaseBackupDir) {
    if (!fs.existsSync(databaseBackupDir)) {
      console.log('⚠️ No database backup found, skipping...');
      return;
    }

    console.log('🗄️ Restoring database...');
    
    return new Promise((resolve, reject) => {
      const args = [
        '--uri', this.config.mongoUri,
        '--dir', databaseBackupDir,
        '--gzip',
        '--drop' // Drop existing collections before restore
      ];

      const mongorestore = spawn('mongorestore', args, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let errorOutput = '';

      mongorestore.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      mongorestore.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Database restore completed');
          resolve();
        } else {
          reject(new Error(`mongorestore failed with code ${code}: ${errorOutput}`));
        }
      });
    });
  }

  /**
   * Restore configurations
   */
  async restoreConfigurations(configBackupDir) {
    if (!fs.existsSync(configBackupDir)) {
      console.log('⚠️ No configuration backup found, skipping...');
      return;
    }

    console.log('⚙️ Restoring configurations...');
    
    // This is a simplified version - in production, you'd want more careful handling
    console.log('⚠️ Configuration restore requires manual review for security');
    console.log(`📁 Configuration backup available at: ${configBackupDir}`);
  }

  /**
   * Restore application files
   */
  async restoreApplicationFiles(appBackupDir) {
    if (!fs.existsSync(appBackupDir)) {
      console.log('⚠️ No application files backup found, skipping...');
      return;
    }

    console.log('📁 Restoring application files...');
    
    const appRoot = process.cwd();
    await this.copyRecursive(appBackupDir, appRoot);
    
    console.log('✅ Application files restored');
  }

  /**
   * List available backups
   */
  async listBackups() {
    const metadataDir = path.join(this.config.storagePath, 'metadata');
    
    if (!fs.existsSync(metadataDir)) {
      return [];
    }

    const metadataFiles = fs.readdirSync(metadataDir)
      .filter(file => file.endsWith('.json'))
      .sort()
      .reverse(); // Most recent first

    const backups = [];
    
    for (const file of metadataFiles) {
      try {
        const metadata = JSON.parse(
          fs.readFileSync(path.join(metadataDir, file), 'utf8')
        );
        backups.push(metadata);
      } catch (error) {
        console.warn(`Could not read backup metadata: ${file}`);
      }
    }

    return backups;
  }

  /**
   * Clean up old backups
   */
  async cleanupOldBackups() {
    console.log('🧹 Cleaning up old backups...');
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);
    
    const backups = await this.listBackups();
    
    for (const backup of backups) {
      const backupDate = new Date(backup.startTime);
      
      if (backupDate < cutoffDate) {
        try {
          // Remove backup file
          if (fs.existsSync(backup.path)) {
            fs.unlinkSync(backup.path);
          }
          
          // Remove metadata
          const metadataPath = path.join(
            this.config.storagePath, 
            'metadata', 
            `${backup.id}.json`
          );
          if (fs.existsSync(metadataPath)) {
            fs.unlinkSync(metadataPath);
          }
          
          console.log(`🗑️ Removed old backup: ${backup.id}`);
        } catch (error) {
          console.warn(`Could not remove backup ${backup.id}: ${error.message}`);
        }
      }
    }
  }

  /**
   * Utility functions
   */
  generateBackupId() {
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, -5);
    return `faf-backup-${timestamp}`;
  }

  async copyRecursive(src, dest, excludes = []) {
    const stat = fs.statSync(src);
    
    if (stat.isDirectory()) {
      if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
      }
      
      const items = fs.readdirSync(src);
      
      for (const item of items) {
        if (excludes.includes(item)) {
          continue;
        }
        
        const srcPath = path.join(src, item);
        const destPath = path.join(dest, item);
        
        await this.copyRecursive(srcPath, destPath, excludes);
      }
    } else {
      fs.copyFileSync(src, dest);
    }
  }

  createEnvironmentExample() {
    const envVars = [
      'NODE_ENV=production',
      'PORT=3000',
      'HTTPS=true',
      'APP_BASE_URL=https://yourdomain.com',
      'FRONTEND_URL=https://yourdomain.com',
      'COOKIE_DOMAIN=yourdomain.com',
      'MONGODB_URI=mongodb+srv://...',
      'SESSION_SECRET=your-session-secret',
      'LOGIN_ADMIN_USER=admin',
      'LOGIN_ADMIN_PASS=hashed-password',
      'FORM_ADMIN_NAME=admin',
      'CLOUDINARY_CLOUD_NAME=your-cloud-name',
      'CLOUDINARY_API_KEY=your-api-key',
      'CLOUDINARY_API_SECRET=your-api-secret'
    ];
    
    return envVars.join('\\n');
  }

  async saveBackupMetadata(backup) {
    const metadataDir = path.join(this.config.storagePath, 'metadata');
    if (!fs.existsSync(metadataDir)) {
      fs.mkdirSync(metadataDir, { recursive: true });
    }
    
    const metadataPath = path.join(metadataDir, `${backup.id}.json`);
    fs.writeFileSync(metadataPath, JSON.stringify(backup, null, 2));
  }

  async loadBackupMetadata(backupId) {
    const metadataPath = path.join(this.config.storagePath, 'metadata', `${backupId}.json`);
    
    if (!fs.existsSync(metadataPath)) {
      return null;
    }
    
    return JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Get backup status
   */
  getStatus() {
    return {
      enabled: this.config.enabled,
      isRunning: this.isRunning,
      currentBackup: this.currentBackup,
      schedule: this.config.schedule,
      retentionDays: this.config.retentionDays,
      storagePath: this.config.storagePath
    };
  }
}

module.exports = BackupSystem;