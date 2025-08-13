#!/usr/bin/env node

// Migration Rollback Script - Emergency rollback procedures
const mongoose = require('mongoose');
const readline = require('readline');
const Response = require('../models/Response');
const User = require('../models/User');
const SecureLogger = require('../utils/secureLogger');
require('dotenv').config();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

class MigrationRollback {
  constructor() {
    this.backup = {
      responses: [],
      users: [],
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Connect to database
   */
  async connect() {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ Connected to database');
      return true;
    } catch (error) {
      console.error('❌ Database connection failed:', error.message);
      return false;
    }
  }

  /**
   * Create backup before rollback
   */
  async createBackup() {
    console.log('\n📦 Creating backup before rollback...');
    
    try {
      // Backup migrated responses
      this.backup.responses = await Response.find({ 
        authMethod: 'user' 
      }).lean();
      
      // Backup users with migration data
      this.backup.users = await User.find({
        'migrationData.source': 'migration'
      }).lean();
      
      console.log(`✅ Backed up ${this.backup.responses.length} responses`);
      console.log(`✅ Backed up ${this.backup.users.length} users`);
      
      // Save backup to file
      const fs = require('fs');
      const backupFile = `./backup-${Date.now()}.json`;
      fs.writeFileSync(backupFile, JSON.stringify(this.backup, null, 2));
      console.log(`✅ Backup saved to ${backupFile}`);
      
      return true;
    } catch (error) {
      console.error('❌ Backup failed:', error.message);
      return false;
    }
  }

  /**
   * Rollback user-authenticated responses to legacy tokens
   */
  async rollbackResponses(options = {}) {
    const { dryRun = false, batchSize = 100 } = options;
    
    console.log('\n🔄 Starting response rollback...');
    if (dryRun) console.log('⚠️  DRY RUN MODE - No changes will be made');
    
    try {
      const session = await mongoose.startSession();
      await session.withTransaction(async () => {
        // Find all migrated responses
        const migratedResponses = await Response.find({ 
          authMethod: 'user',
          userId: { $exists: true }
        }).session(session);
        
        console.log(`Found ${migratedResponses.length} migrated responses`);
        
        let processed = 0;
        const TokenGenerator = require('../utils/tokenGenerator');
        
        for (let i = 0; i < migratedResponses.length; i += batchSize) {
          const batch = migratedResponses.slice(i, i + batchSize);
          
          for (const response of batch) {
            // Find original user to get name
            const user = await User.findById(response.userId).session(session);
            
            if (!dryRun) {
              // Generate new token for legacy mode
              const newToken = TokenGenerator.generateSecureToken();
              
              // Revert to legacy format
              await Response.updateOne(
                { _id: response._id },
                {
                  $set: {
                    authMethod: 'token',
                    token: newToken,
                    name: user ? user.username : 'Unknown User'
                  },
                  $unset: {
                    userId: 1
                  }
                },
                { session }
              );
            }
            
            processed++;
            if (processed % 100 === 0) {
              console.log(`Processed ${processed}/${migratedResponses.length} responses`);
            }
          }
        }
        
        console.log(`✅ Rolled back ${processed} responses`);
      });
      
      await session.endSession();
      return true;
    } catch (error) {
      console.error('❌ Response rollback failed:', error.message);
      return false;
    }
  }

  /**
   * Rollback user accounts created from migration
   */
  async rollbackUsers(options = {}) {
    const { dryRun = false, preserveAccounts = false } = options;
    
    console.log('\n🔄 Starting user rollback...');
    if (dryRun) console.log('⚠️  DRY RUN MODE - No changes will be made');
    
    try {
      // Find users created through migration
      const migratedUsers = await User.find({
        'migrationData.source': 'migration'
      });
      
      console.log(`Found ${migratedUsers.length} migrated users`);
      
      if (preserveAccounts) {
        console.log('ℹ️  Preserving user accounts (removing migration markers only)');
        
        if (!dryRun) {
          await User.updateMany(
            { 'migrationData.source': 'migration' },
            { $unset: { migrationData: 1 } }
          );
        }
      } else {
        console.log('⚠️  Deleting migrated user accounts');
        
        if (!dryRun) {
          const userIds = migratedUsers.map(u => u._id);
          await User.deleteMany({ _id: { $in: userIds } });
        }
      }
      
      console.log(`✅ Processed ${migratedUsers.length} users`);
      return true;
    } catch (error) {
      console.error('❌ User rollback failed:', error.message);
      return false;
    }
  }

  /**
   * Restore indexes to pre-migration state
   */
  async rollbackIndexes(options = {}) {
    const { dryRun = false } = options;
    
    console.log('\n🔄 Rolling back indexes...');
    if (dryRun) console.log('⚠️  DRY RUN MODE - No changes will be made');
    
    try {
      const collection = Response.collection;
      
      // Drop new indexes added for migration
      const indexesToDrop = [
        'userId_1_month_1',
        'authMethod_1_month_1'
      ];
      
      for (const indexName of indexesToDrop) {
        try {
          if (!dryRun) {
            await collection.dropIndex(indexName);
            console.log(`✅ Dropped index: ${indexName}`);
          } else {
            console.log(`Would drop index: ${indexName}`);
          }
        } catch (error) {
          if (error.code !== 27) { // Index not found is ok
            console.error(`⚠️  Failed to drop ${indexName}:`, error.message);
          }
        }
      }
      
      // Recreate original indexes
      const originalIndexes = [
        { token: 1 },
        { month: 1, isAdmin: 1 },
        { createdAt: 1 }
      ];
      
      for (const index of originalIndexes) {
        if (!dryRun) {
          await collection.createIndex(index);
          console.log(`✅ Created index:`, Object.keys(index).join('_'));
        } else {
          console.log(`Would create index:`, Object.keys(index).join('_'));
        }
      }
      
      return true;
    } catch (error) {
      console.error('❌ Index rollback failed:', error.message);
      return false;
    }
  }

  /**
   * Verify rollback integrity
   */
  async verifyRollback() {
    console.log('\n🔍 Verifying rollback integrity...');
    
    const checks = {
      noUserAuthResponses: false,
      allHaveTokens: false,
      noOrphanedData: false,
      constraintsValid: false
    };
    
    try {
      // Check no user auth responses remain
      const userAuthCount = await Response.countDocuments({ authMethod: 'user' });
      checks.noUserAuthResponses = userAuthCount === 0;
      console.log(`User auth responses: ${userAuthCount} ${checks.noUserAuthResponses ? '✅' : '❌'}`);
      
      // Check all responses have tokens
      const tokenlessCount = await Response.countDocuments({ 
        authMethod: 'token',
        token: { $exists: false }
      });
      checks.allHaveTokens = tokenlessCount === 0;
      console.log(`Responses without tokens: ${tokenlessCount} ${checks.allHaveTokens ? '✅' : '❌'}`);
      
      // Check for orphaned data
      const orphanedCount = await Response.countDocuments({
        userId: { $exists: true }
      });
      checks.noOrphanedData = orphanedCount === 0;
      console.log(`Orphaned userId references: ${orphanedCount} ${checks.noOrphanedData ? '✅' : '❌'}`);
      
      // Check constraints
      const duplicateAdmins = await Response.aggregate([
        { $match: { isAdmin: true } },
        { $group: { _id: '$month', count: { $sum: 1 } } },
        { $match: { count: { $gt: 1 } } }
      ]);
      checks.constraintsValid = duplicateAdmins.length === 0;
      console.log(`Duplicate admin months: ${duplicateAdmins.length} ${checks.constraintsValid ? '✅' : '❌'}`);
      
      const allPassed = Object.values(checks).every(v => v);
      
      if (allPassed) {
        console.log('\n✅ Rollback verification PASSED');
      } else {
        console.log('\n⚠️  Rollback verification FAILED - Manual intervention may be required');
      }
      
      return allPassed;
    } catch (error) {
      console.error('❌ Verification failed:', error.message);
      return false;
    }
  }

  /**
   * Interactive rollback menu
   */
  async interactiveRollback() {
    console.log('\n=================================');
    console.log('🔄 MIGRATION ROLLBACK UTILITY');
    console.log('=================================');
    console.log('\n⚠️  WARNING: This will revert the migration to legacy token system');
    console.log('Make sure you have a recent database backup!\n');
    
    const confirm = await this.prompt('Continue with rollback? (yes/no): ');
    if (confirm.toLowerCase() !== 'yes') {
      console.log('Rollback cancelled');
      return;
    }
    
    const mode = await this.prompt('\nSelect mode:\n1. Dry run (preview changes)\n2. Full rollback\n3. Partial rollback (keep user accounts)\nChoice (1-3): ');
    
    const dryRun = mode === '1';
    const preserveAccounts = mode === '3';
    
    // Create backup
    if (!dryRun) {
      const backupConfirm = await this.prompt('\nCreate backup before rollback? (yes/no): ');
      if (backupConfirm.toLowerCase() === 'yes') {
        await this.createBackup();
      }
    }
    
    // Execute rollback steps
    console.log('\n📋 Executing rollback plan...\n');
    
    // Step 1: Rollback responses
    await this.rollbackResponses({ dryRun });
    
    // Step 2: Rollback users
    await this.rollbackUsers({ dryRun, preserveAccounts });
    
    // Step 3: Rollback indexes
    await this.rollbackIndexes({ dryRun });
    
    // Step 4: Verify
    if (!dryRun) {
      await this.verifyRollback();
    }
    
    console.log('\n✅ Rollback process complete');
  }

  /**
   * Prompt helper
   */
  prompt(question) {
    return new Promise(resolve => {
      rl.question(question, answer => {
        resolve(answer);
      });
    });
  }

  /**
   * Cleanup
   */
  async cleanup() {
    rl.close();
    await mongoose.disconnect();
  }
}

// Main execution
async function main() {
  const rollback = new MigrationRollback();
  
  if (await rollback.connect()) {
    await rollback.interactiveRollback();
  }
  
  await rollback.cleanup();
  process.exit(0);
}

// Handle errors
process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error.message);
  process.exit(1);
});

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = MigrationRollback;