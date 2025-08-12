// Orphaned Data Cleanup Utility
const mongoose = require('mongoose');
const Response = require('../models/Response');
const User = require('../models/User');
const SecureLogger = require('./secureLogger');

class OrphanedDataCleanup {
  constructor() {
    this.cleanupStats = {
      orphanedResponses: 0,
      duplicateTokens: 0,
      inconsistentAuthMethods: 0,
      invalidUserReferences: 0,
      malformedData: 0,
      totalCleaned: 0
    };
  }

  /**
   * Run comprehensive orphaned data cleanup
   */
  async runCleanup(options = {}) {
    const { dryRun = true, batchSize = 100 } = options;
    
    SecureLogger.logInfo(`Starting orphaned data cleanup (dryRun: ${dryRun})`);
    console.log('\n🧹 ORPHANED DATA CLEANUP');
    console.log('========================');
    if (dryRun) console.log('⚠️  DRY RUN MODE - No changes will be made\n');
    
    const startTime = Date.now();
    
    try {
      // 1. Clean responses with invalid user references
      await this.cleanInvalidUserReferences({ dryRun, batchSize });
      
      // 2. Clean duplicate tokens
      await this.cleanDuplicateTokens({ dryRun, batchSize });
      
      // 3. Fix inconsistent auth methods
      await this.fixInconsistentAuthMethods({ dryRun, batchSize });
      
      // 4. Clean malformed data
      await this.cleanMalformedData({ dryRun, batchSize });
      
      // 5. Clean orphaned responses without proper identifiers
      await this.cleanOrphanedResponses({ dryRun, batchSize });
      
      const duration = Date.now() - startTime;
      
      console.log('\n📊 CLEANUP SUMMARY');
      console.log('==================');
      console.log(`Orphaned responses: ${this.cleanupStats.orphanedResponses}`);
      console.log(`Invalid user refs: ${this.cleanupStats.invalidUserReferences}`);
      console.log(`Duplicate tokens: ${this.cleanupStats.duplicateTokens}`);
      console.log(`Inconsistent auth: ${this.cleanupStats.inconsistentAuthMethods}`);
      console.log(`Malformed data: ${this.cleanupStats.malformedData}`);
      console.log(`Total cleaned: ${this.cleanupStats.totalCleaned}`);
      console.log(`Duration: ${duration}ms`);
      
      if (!dryRun) {
        SecureLogger.logInfo('Orphaned data cleanup completed', this.cleanupStats);
      }
      
      return this.cleanupStats;
    } catch (error) {
      SecureLogger.logError('Orphaned data cleanup failed', error);
      throw error;
    }
  }

  /**
   * Clean responses with invalid user references
   */
  async cleanInvalidUserReferences(options) {
    const { dryRun, batchSize } = options;
    console.log('🔍 Checking for invalid user references...');
    
    try {
      // Find responses with userId but authMethod = token (inconsistent)
      const invalidUserResponses = await Response.find({
        userId: { $exists: true, $ne: null },
        authMethod: 'token'
      });
      
      console.log(`Found ${invalidUserResponses.length} responses with invalid user references`);
      
      if (!dryRun && invalidUserResponses.length > 0) {
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
          for (let i = 0; i < invalidUserResponses.length; i += batchSize) {
            const batch = invalidUserResponses.slice(i, i + batchSize);
            
            for (const response of batch) {
              // Option 1: Remove userId if authMethod is token
              await Response.updateOne(
                { _id: response._id },
                { $unset: { userId: 1 } },
                { session }
              );
              
              this.cleanupStats.invalidUserReferences++;
              this.cleanupStats.totalCleaned++;
            }
          }
        });
        await session.endSession();
      } else {
        this.cleanupStats.invalidUserReferences = invalidUserResponses.length;
      }
      
      // Also check for responses with userId pointing to non-existent users
      const userResponses = await Response.find({
        userId: { $exists: true, $ne: null },
        authMethod: 'user'
      }).select('userId');
      
      if (userResponses.length > 0) {
        const userIds = [...new Set(userResponses.map(r => r.userId))];
        const existingUsers = await User.find({
          _id: { $in: userIds }
        }).select('_id');
        
        const existingUserIds = new Set(existingUsers.map(u => u._id.toString()));
        const invalidRefs = userResponses.filter(
          r => !existingUserIds.has(r.userId.toString())
        );
        
        console.log(`Found ${invalidRefs.length} responses with non-existent user references`);
        
        if (!dryRun && invalidRefs.length > 0) {
          // Convert to token-based responses or delete
          for (const response of invalidRefs) {
            await Response.deleteOne({ _id: response._id });
            this.cleanupStats.invalidUserReferences++;
            this.cleanupStats.totalCleaned++;
          }
        }
      }
      
    } catch (error) {
      console.error('❌ Failed to clean invalid user references:', error.message);
      throw error;
    }
  }

  /**
   * Clean duplicate tokens
   */
  async cleanDuplicateTokens(options) {
    const { dryRun, batchSize } = options;
    console.log('🔍 Checking for duplicate tokens...');
    
    try {
      const duplicates = await Response.aggregate([
        {
          $match: {
            token: { $exists: true, $ne: null, $ne: '' }
          }
        },
        {
          $group: {
            _id: '$token',
            count: { $sum: 1 },
            docs: { $push: '$$ROOT' }
          }
        },
        {
          $match: { count: { $gt: 1 } }
        }
      ]);
      
      console.log(`Found ${duplicates.length} duplicate token groups`);
      
      if (!dryRun && duplicates.length > 0) {
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
          for (const duplicate of duplicates) {
            // Keep the oldest response, remove others
            const sortedDocs = duplicate.docs.sort((a, b) => 
              new Date(a.createdAt) - new Date(b.createdAt)
            );
            
            // Remove all but the first (oldest)
            const toRemove = sortedDocs.slice(1);
            
            for (const doc of toRemove) {
              await Response.deleteOne({ _id: doc._id }, { session });
              this.cleanupStats.duplicateTokens++;
              this.cleanupStats.totalCleaned++;
            }
          }
        });
        await session.endSession();
      } else {
        this.cleanupStats.duplicateTokens = duplicates.reduce(
          (sum, dup) => sum + (dup.count - 1), 0
        );
      }
      
    } catch (error) {
      console.error('❌ Failed to clean duplicate tokens:', error.message);
      throw error;
    }
  }

  /**
   * Fix inconsistent auth methods
   */
  async fixInconsistentAuthMethods(options) {
    const { dryRun, batchSize } = options;
    console.log('🔍 Fixing inconsistent auth methods...');
    
    try {
      // Find responses with token but authMethod = user
      const tokenWithUserAuth = await Response.find({
        token: { $exists: true, $ne: null },
        authMethod: 'user'
      });
      
      console.log(`Found ${tokenWithUserAuth.length} token responses marked as user auth`);
      
      // Find responses with userId but authMethod = token
      const userWithTokenAuth = await Response.find({
        userId: { $exists: true, $ne: null },
        authMethod: 'token'
      });
      
      console.log(`Found ${userWithTokenAuth.length} user responses marked as token auth`);
      
      if (!dryRun) {
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
          // Fix token responses marked as user
          for (const response of tokenWithUserAuth) {
            await Response.updateOne(
              { _id: response._id },
              { $set: { authMethod: 'token' } },
              { session }
            );
            this.cleanupStats.inconsistentAuthMethods++;
            this.cleanupStats.totalCleaned++;
          }
          
          // Fix user responses marked as token
          for (const response of userWithTokenAuth) {
            // Verify user still exists
            const userExists = await User.exists({ _id: response.userId });
            if (userExists) {
              await Response.updateOne(
                { _id: response._id },
                { 
                  $set: { authMethod: 'user' },
                  $unset: { token: 1, name: 1 }
                },
                { session }
              );
            } else {
              // User doesn't exist, convert to token or delete
              await Response.deleteOne({ _id: response._id }, { session });
            }
            this.cleanupStats.inconsistentAuthMethods++;
            this.cleanupStats.totalCleaned++;
          }
        });
        await session.endSession();
      } else {
        this.cleanupStats.inconsistentAuthMethods = 
          tokenWithUserAuth.length + userWithTokenAuth.length;
      }
      
    } catch (error) {
      console.error('❌ Failed to fix inconsistent auth methods:', error.message);
      throw error;
    }
  }

  /**
   * Clean malformed data
   */
  async cleanMalformedData(options) {
    const { dryRun, batchSize } = options;
    console.log('🔍 Cleaning malformed data...');
    
    try {
      const issues = [];
      
      // Check for invalid month format
      const invalidMonths = await Response.find({
        month: { $not: /^\d{4}-\d{2}$/ }
      });
      issues.push(...invalidMonths.map(r => ({ 
        _id: r._id, 
        issue: 'invalid_month',
        month: r.month 
      })));
      
      // Check for empty responses array
      const emptyResponses = await Response.find({
        $or: [
          { responses: { $size: 0 } },
          { responses: { $exists: false } }
        ]
      });
      issues.push(...emptyResponses.map(r => ({ 
        _id: r._id, 
        issue: 'empty_responses' 
      })));
      
      // Check for missing authMethod
      const missingAuthMethod = await Response.find({
        authMethod: { $exists: false }
      });
      issues.push(...missingAuthMethod.map(r => ({ 
        _id: r._id, 
        issue: 'missing_auth_method' 
      })));
      
      console.log(`Found ${issues.length} malformed data issues`);
      
      if (!dryRun && issues.length > 0) {
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
          for (const issue of issues) {
            switch (issue.issue) {
              case 'invalid_month':
                // Try to parse date and fix or delete
                const currentMonth = new Date().toISOString().slice(0, 7);
                await Response.updateOne(
                  { _id: issue._id },
                  { $set: { month: currentMonth } },
                  { session }
                );
                break;
                
              case 'empty_responses':
              case 'missing_auth_method':
                // Delete responses without proper data
                await Response.deleteOne({ _id: issue._id }, { session });
                break;
            }
            
            this.cleanupStats.malformedData++;
            this.cleanupStats.totalCleaned++;
          }
        });
        await session.endSession();
      } else {
        this.cleanupStats.malformedData = issues.length;
      }
      
    } catch (error) {
      console.error('❌ Failed to clean malformed data:', error.message);
      throw error;
    }
  }

  /**
   * Clean orphaned responses without proper identifiers
   */
  async cleanOrphanedResponses(options) {
    const { dryRun, batchSize } = options;
    console.log('🔍 Cleaning orphaned responses...');
    
    try {
      // Find responses without proper identification
      const orphaned = await Response.find({
        $and: [
          {
            $or: [
              { token: { $exists: false } },
              { token: null },
              { token: '' }
            ]
          },
          {
            $or: [
              { userId: { $exists: false } },
              { userId: null }
            ]
          }
        ]
      });
      
      console.log(`Found ${orphaned.length} completely orphaned responses`);
      
      if (!dryRun && orphaned.length > 0) {
        // These responses have no way to be accessed, safe to delete
        for (const response of orphaned) {
          await Response.deleteOne({ _id: response._id });
          this.cleanupStats.orphanedResponses++;
          this.cleanupStats.totalCleaned++;
        }
      } else {
        this.cleanupStats.orphanedResponses = orphaned.length;
      }
      
    } catch (error) {
      console.error('❌ Failed to clean orphaned responses:', error.message);
      throw error;
    }
  }

  /**
   * Generate cleanup report
   */
  generateReport() {
    return {
      timestamp: new Date().toISOString(),
      stats: this.cleanupStats,
      recommendations: this.generateRecommendations()
    };
  }

  /**
   * Generate recommendations based on findings
   */
  generateRecommendations() {
    const recommendations = [];
    
    if (this.cleanupStats.totalCleaned > 0) {
      recommendations.push('Regular cleanup scheduled recommended to prevent data accumulation');
    }
    
    if (this.cleanupStats.duplicateTokens > 10) {
      recommendations.push('Consider implementing token uniqueness constraints');
    }
    
    if (this.cleanupStats.invalidUserReferences > 0) {
      recommendations.push('Review user deletion process to prevent orphaned references');
    }
    
    if (this.cleanupStats.malformedData > 0) {
      recommendations.push('Strengthen input validation to prevent malformed data');
    }
    
    return recommendations;
  }

  /**
   * Reset stats
   */
  resetStats() {
    this.cleanupStats = {
      orphanedResponses: 0,
      duplicateTokens: 0,
      inconsistentAuthMethods: 0,
      invalidUserReferences: 0,
      malformedData: 0,
      totalCleaned: 0
    };
  }
}

module.exports = OrphanedDataCleanup;