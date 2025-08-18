#!/usr/bin/env node

/**
 * FAF MIGRATION HELPER SCRIPT
 * ============================
 * 
 * Interactive helper script for running the FAF Response→Submission migration.
 * Provides guided execution, pre-migration checks, and post-migration validation.
 * 
 * Features:
 * - Interactive prompts for safe migration execution
 * - Pre-migration environment and data validation
 * - Real-time migration monitoring
 * - Post-migration verification and reporting
 * - Emergency rollback capabilities
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const readline = require('readline');
const { spawn, exec } = require('child_process');
const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

class MigrationHelper {
  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
  }

  // Utility methods
  colorize(text, color) {
    return `${colors[color]}${text}${colors.reset}`;
  }

  log(message, color = 'white') {
    console.log(this.colorize(message, color));
  }

  async question(prompt) {
    return new Promise((resolve) => {
      this.rl.question(this.colorize(prompt, 'blue'), resolve);
    });
  }

  async confirm(message) {
    const answer = await this.question(`${message} (y/N): `);
    return answer.toLowerCase().startsWith('y');
  }

  // Environment validation
  async validateEnvironment() {
    this.log('\n=== ENVIRONMENT VALIDATION ===', 'bold');
    
    const checks = [
      {
        name: 'MongoDB Connection',
        check: async () => {
          const mongoUri = process.env.MONGODB_URI;
          if (!mongoUri) {
            throw new Error('MONGODB_URI environment variable not set');
          }
          
          try {
            await mongoose.connect(mongoUri);
            await mongoose.connection.db.admin().ping();
            await mongoose.disconnect();
            return 'Connected successfully';
          } catch (error) {
            throw new Error(`Connection failed: ${error.message}`);
          }
        }
      },
      {
        name: 'Required Environment Variables',
        check: async () => {
          const required = ['MONGODB_URI', 'FORM_ADMIN_NAME'];
          const missing = required.filter(var_name => !process.env[var_name]);
          
          if (missing.length > 0) {
            throw new Error(`Missing variables: ${missing.join(', ')}`);
          }
          return `All required variables present: ${required.join(', ')}`;
        }
      },
      {
        name: 'Node.js Version',
        check: async () => {
          const version = process.version;
          const majorVersion = parseInt(version.slice(1).split('.')[0]);
          
          if (majorVersion < 14) {
            throw new Error(`Node.js ${version} not supported. Requires Node.js 14+`);
          }
          return `Node.js ${version} (supported)`;
        }
      },
      {
        name: 'Disk Space',
        check: async () => {
          return new Promise((resolve, reject) => {
            exec('df -h .', (error, stdout) => {
              if (error) {
                reject(new Error('Could not check disk space'));
                return;
              }
              
              const lines = stdout.trim().split('\\n');
              const data = lines[1].split(/\\s+/);
              const available = data[3];
              
              resolve(`Available: ${available}`);\n            });\n          });\n        }\n      },\n      {\n        name: 'Migration Script Existence',\n        check: async () => {\n          const scriptPath = path.join(__dirname, 'migrate-to-form-a-friend.js');\n          try {\n            await fs.access(scriptPath);\n            const stats = await fs.stat(scriptPath);\n            return `Found (${Math.round(stats.size / 1024)}KB)`;\n          } catch (error) {\n            throw new Error('Migration script not found');\n          }\n        }\n      }\n    ];\n    \n    let allPassed = true;\n    \n    for (const { name, check } of checks) {\n      process.stdout.write(`  ${name}... `);\n      \n      try {\n        const result = await check();\n        this.log(`✅ ${result}`, 'green');\n      } catch (error) {\n        this.log(`❌ ${error.message}`, 'red');\n        allPassed = false;\n      }\n    }\n    \n    if (!allPassed) {\n      this.log('\\n❌ Environment validation failed. Please fix the issues above.', 'red');\n      return false;\n    }\n    \n    this.log('\\n✅ Environment validation passed!', 'green');\n    return true;\n  }\n\n  // Data preview\n  async previewData() {\n    this.log('\\n=== DATA PREVIEW ===', 'bold');\n    \n    try {\n      const mongoUri = process.env.MONGODB_URI;\n      await mongoose.connect(mongoUri);\n      \n      // Import models dynamically\n      const Response = require('../backend/models/Response');\n      const User = require('../backend/models/User');\n      const Submission = require('../backend/models/Submission');\n      \n      const responseCount = await Response.countDocuments();\n      const userCount = await User.countDocuments();\n      const submissionCount = await Submission.countDocuments();\n      \n      // Get unique names from responses\n      const uniqueNames = await Response.distinct('name');\n      const adminResponses = await Response.countDocuments({ isAdmin: true });\n      const tokensCount = await Response.countDocuments({ token: { $exists: true, $ne: null } });\n      \n      // Get existing migrated users\n      const migratedUsers = await User.countDocuments({ 'migrationData.source': 'migration' });\n      \n      this.log(`  📊 Current Database State:`, 'yellow');\n      this.log(`     • Responses: ${responseCount}`);\n      this.log(`     • Unique names in responses: ${uniqueNames.length}`);\n      this.log(`     • Admin responses: ${adminResponses}`);\n      this.log(`     • Responses with tokens: ${tokensCount}`);\n      this.log(`     • Existing users: ${userCount}`);\n      this.log(`     • Previously migrated users: ${migratedUsers}`);\n      this.log(`     • Existing submissions: ${submissionCount}`);\n      \n      if (responseCount === 0) {\n        this.log('\\n⚠️  No Response documents found. Migration not needed.', 'yellow');\n        await mongoose.disconnect();\n        return false;\n      }\n      \n      if (migratedUsers > 0) {\n        this.log(`\\n⚠️  Found ${migratedUsers} previously migrated users.`, 'yellow');\n        const proceed = await this.confirm('This might be a partial re-migration. Continue?');\n        if (!proceed) {\n          await mongoose.disconnect();\n          return false;\n        }\n      }\n      \n      // Show sample data\n      const sampleResponses = await Response.find({}).limit(3).lean();\n      if (sampleResponses.length > 0) {\n        this.log(`\\n  📝 Sample Response data:`, 'yellow');\n        sampleResponses.forEach((resp, i) => {\n          this.log(`     ${i + 1}. Name: \"${resp.name}\", Month: ${resp.month}, Admin: ${resp.isAdmin}, Token: ${resp.token ? 'Yes' : 'No'}`);\n        });\n      }\n      \n      await mongoose.disconnect();\n      return true;\n    } catch (error) {\n      this.log(`❌ Error previewing data: ${error.message}`, 'red');\n      return false;\n    }\n  }\n\n  // Migration execution\n  async runMigration(dryRun = false) {\n    const mode = dryRun ? 'DRY-RUN' : 'PRODUCTION';\n    this.log(`\\n=== MIGRATION EXECUTION (${mode}) ===`, 'bold');\n    \n    const scriptPath = path.join(__dirname, 'migrate-to-form-a-friend.js');\n    const args = ['node', scriptPath];\n    \n    if (dryRun) {\n      args.push('--dry-run');\n    }\n    args.push('--verbose');\n    \n    return new Promise((resolve, reject) => {\n      this.log(`🚀 Starting migration script...`, 'blue');\n      this.log(`Command: ${args.join(' ')}`, 'blue');\n      \n      const migrationProcess = spawn(args[0], args.slice(1), {\n        stdio: 'inherit',\n        env: process.env\n      });\n      \n      migrationProcess.on('close', (code) => {\n        if (code === 0) {\n          this.log(`\\n✅ Migration ${mode} completed successfully!`, 'green');\n          resolve(true);\n        } else {\n          this.log(`\\n❌ Migration ${mode} failed with exit code ${code}`, 'red');\n          resolve(false);\n        }\n      });\n      \n      migrationProcess.on('error', (error) => {\n        this.log(`\\n❌ Migration process error: ${error.message}`, 'red');\n        reject(error);\n      });\n    });\n  }\n\n  // Post-migration verification\n  async verifyMigration() {\n    this.log('\\n=== POST-MIGRATION VERIFICATION ===', 'bold');\n    \n    try {\n      const mongoUri = process.env.MONGODB_URI;\n      await mongoose.connect(mongoUri);\n      \n      const Response = require('../backend/models/Response');\n      const User = require('../backend/models/User');\n      const Submission = require('../backend/models/Submission');\n      const Invitation = require('../backend/models/Invitation');\n      \n      // Count documents\n      const responseCount = await Response.countDocuments();\n      const userCount = await User.countDocuments({ 'migrationData.source': 'migration' });\n      const submissionCount = await Submission.countDocuments();\n      const invitationCount = await Invitation.countDocuments({ 'metadata.migrationSource': 'response_token' });\n      \n      this.log(`\\n  📊 Migration Results:`, 'yellow');\n      this.log(`     • Original responses: ${responseCount}`);\n      this.log(`     • Users created: ${userCount}`);\n      this.log(`     • Submissions created: ${submissionCount}`);\n      this.log(`     • Invitations created: ${invitationCount}`);\n      \n      // Verify data integrity\n      const issues = [];\n      \n      // Check if all responses were converted\n      if (submissionCount < responseCount) {\n        issues.push(`Submission count (${submissionCount}) is less than response count (${responseCount})`);\n      }\n      \n      // Check user-submission relationships\n      const orphanedSubmissions = await Submission.countDocuments({\n        userId: { $nin: await User.distinct('_id', { 'migrationData.source': 'migration' }) }\n      });\n      \n      if (orphanedSubmissions > 0) {\n        issues.push(`Found ${orphanedSubmissions} submissions without corresponding users`);\n      }\n      \n      // Check admin role assignment\n      const adminName = process.env.FORM_ADMIN_NAME;\n      if (adminName) {\n        const adminUser = await User.findOne({\n          'migrationData.legacyName': adminName,\n          'role': 'admin'\n        });\n        \n        if (!adminUser) {\n          issues.push(`Admin user not found or role not assigned correctly for \"${adminName}\"`);\n        }\n      }\n      \n      if (issues.length > 0) {\n        this.log('\\n⚠️  Verification Issues:', 'yellow');\n        issues.forEach(issue => this.log(`     • ${issue}`, 'yellow'));\n      } else {\n        this.log('\\n✅ Migration verification passed!', 'green');\n      }\n      \n      await mongoose.disconnect();\n      return issues.length === 0;\n    } catch (error) {\n      this.log(`❌ Error during verification: ${error.message}`, 'red');\n      return false;\n    }\n  }\n\n  // Show migration reports\n  async showReports() {\n    this.log('\\n=== MIGRATION REPORTS ===', 'bold');\n    \n    try {\n      const files = await fs.readdir('.');\n      const reportFiles = files.filter(file => file.startsWith('migration-report-'));\n      const logFiles = files.filter(file => file.startsWith('migration-logs-'));\n      \n      if (reportFiles.length === 0) {\n        this.log('  No migration reports found.', 'yellow');\n        return;\n      }\n      \n      // Show latest report\n      const latestReport = reportFiles.sort().pop();\n      this.log(`\\n  📋 Latest Migration Report: ${latestReport}`, 'blue');\n      \n      const reportContent = JSON.parse(await fs.readFile(latestReport, 'utf8'));\n      \n      this.log(`     • Migration ID: ${reportContent.migration.migrationId}`);\n      this.log(`     • Timestamp: ${reportContent.migration.timestamp}`);\n      this.log(`     • Total time: ${reportContent.migration.elapsedTime}s`);\n      this.log(`     • Users created: ${reportContent.migration.statistics.usersCreated}`);\n      this.log(`     • Submissions created: ${reportContent.migration.statistics.submissionsCreated}`);\n      this.log(`     • Invitations created: ${reportContent.migration.statistics.invitationsCreated}`);\n      this.log(`     • Errors: ${reportContent.migration.statistics.errorsEncountered}`);\n      \n      if (reportContent.dataIntegrity && !reportContent.dataIntegrity.passed) {\n        this.log('\\n  ⚠️  Data Integrity Issues:', 'yellow');\n        reportContent.dataIntegrity.issues.forEach(issue => {\n          this.log(`     • ${issue}`, 'yellow');\n        });\n      }\n      \n      if (reportContent.recommendations) {\n        this.log('\\n  💡 Recommendations:', 'blue');\n        reportContent.recommendations.forEach(rec => {\n          const icon = rec.priority === 'high' ? '🔴' : rec.priority === 'medium' ? '🟡' : '🟢';\n          this.log(`     ${icon} ${rec.message}`);\n        });\n      }\n      \n      this.log(`\\n  📁 All reports (${reportFiles.length}):`);\n      reportFiles.forEach(file => this.log(`     • ${file}`));\n      \n      if (logFiles.length > 0) {\n        this.log(`\\n  📄 Log files (${logFiles.length}):`);\n        logFiles.forEach(file => this.log(`     • ${file}`));\n      }\n      \n    } catch (error) {\n      this.log(`❌ Error reading reports: ${error.message}`, 'red');\n    }\n  }\n\n  // Emergency rollback\n  async emergencyRollback() {\n    this.log('\\n=== EMERGENCY ROLLBACK ===', 'bold');\n    this.log('⚠️  This will restore the database to pre-migration state', 'yellow');\n    \n    const confirmed = await this.confirm('Are you absolutely sure you want to perform a rollback?');\n    if (!confirmed) {\n      this.log('Rollback cancelled.', 'blue');\n      return;\n    }\n    \n    try {\n      // Look for backup directories\n      const files = await fs.readdir('.');\n      const backupDirs = [];\n      \n      for (const file of files) {\n        try {\n          const stat = await fs.stat(file);\n          if (stat.isDirectory() && file.startsWith('migration-backup-')) {\n            backupDirs.push(file);\n          }\n        } catch (err) {\n          // Ignore files we can't stat\n        }\n      }\n      \n      if (backupDirs.length === 0) {\n        this.log('❌ No backup directories found for rollback.', 'red');\n        return;\n      }\n      \n      // Show available backups\n      this.log('\\n  Available backups:');\n      backupDirs.sort().forEach((dir, i) => {\n        this.log(`     ${i + 1}. ${dir}`);\n      });\n      \n      const choice = await this.question('\\nSelect backup number to restore (or 0 to cancel): ');\n      const backupIndex = parseInt(choice) - 1;\n      \n      if (backupIndex < 0 || backupIndex >= backupDirs.length) {\n        this.log('Rollback cancelled.', 'blue');\n        return;\n      }\n      \n      const selectedBackup = backupDirs[backupIndex];\n      this.log(`\\n🔄 Restoring from backup: ${selectedBackup}`, 'blue');\n      \n      // Import and use backup manager\n      const { BackupManager, MigrationLogger } = require('./migrate-to-form-a-friend');\n      const logger = new MigrationLogger(true);\n      const backupManager = new BackupManager(logger);\n      \n      await backupManager.restoreBackup(selectedBackup, logger);\n      \n      this.log('\\n✅ Rollback completed successfully!', 'green');\n      this.log('⚠️  Please verify your data and restart your application.', 'yellow');\n      \n    } catch (error) {\n      this.log(`❌ Rollback failed: ${error.message}`, 'red');\n    }\n  }\n\n  // Main menu\n  async showMenu() {\n    this.log('\\n' + '='.repeat(60), 'bold');\n    this.log('    FAF MIGRATION HELPER - Form-a-Friend v2', 'bold');\n    this.log('='.repeat(60), 'bold');\n    \n    const options = [\n      '1. Validate Environment',\n      '2. Preview Data',\n      '3. Run Dry-Run Migration',\n      '4. Run Production Migration',\n      '5. Verify Migration',\n      '6. Show Migration Reports',\n      '7. Emergency Rollback',\n      '8. Exit'\n    ];\n    \n    this.log('\\n  Choose an option:');\n    options.forEach(option => this.log(`     ${option}`));\n    \n    const choice = await this.question('\\n  Enter your choice (1-8): ');\n    return parseInt(choice);\n  }\n\n  // Main execution loop\n  async run() {\n    this.log(this.colorize('\\n🚀 Welcome to the FAF Migration Helper!', 'green'));\n    this.log('This tool will guide you through the Response→Submission migration process.\\n');\n    \n    try {\n      while (true) {\n        const choice = await this.showMenu();\n        \n        switch (choice) {\n          case 1:\n            await this.validateEnvironment();\n            break;\n            \n          case 2:\n            await this.previewData();\n            break;\n            \n          case 3:\n            this.log('\\n📋 Running dry-run migration (no changes will be made)...', 'blue');\n            await this.runMigration(true);\n            break;\n            \n          case 4:\n            this.log('\\n⚠️  PRODUCTION MIGRATION - This will modify your database!', 'yellow');\n            const confirmed = await this.confirm('Are you sure you want to proceed?');\n            if (confirmed) {\n              await this.runMigration(false);\n              await this.verifyMigration();\n            } else {\n              this.log('Migration cancelled.', 'blue');\n            }\n            break;\n            \n          case 5:\n            await this.verifyMigration();\n            break;\n            \n          case 6:\n            await this.showReports();\n            break;\n            \n          case 7:\n            await this.emergencyRollback();\n            break;\n            \n          case 8:\n            this.log('\\n👋 Goodbye!', 'green');\n            this.rl.close();\n            return;\n            \n          default:\n            this.log('\\n❌ Invalid choice. Please select 1-8.', 'red');\n        }\n        \n        if (choice !== 8) {\n          await this.question('\\nPress Enter to continue...');\n        }\n      }\n    } catch (error) {\n      this.log(`\\n❌ Unexpected error: ${error.message}`, 'red');\n      this.rl.close();\n    }\n  }\n}\n\n// Run the helper if called directly\nif (require.main === module) {\n  const helper = new MigrationHelper();\n  helper.run().catch(console.error);\n}\n\nmodule.exports = MigrationHelper;