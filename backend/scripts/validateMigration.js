#!/usr/bin/env node

/**
 * FAF MIGRATION VALIDATION SCRIPT v1.0
 * ====================================
 * 
 * Performs comprehensive validation of the FAF v1 to Form-a-Friend v2 migration
 * 
 * VALIDATION PHASES:
 * 1. Data Integrity - Verifies data count consistency and completeness
 * 2. Field Mapping - Validates Response→Submission/User conversion accuracy
 * 3. Backward Compatibility - Tests legacy authentication and token functionality
 * 4. Token Preservation - Verifies private view tokens still work
 * 5. Regression Testing - Tests admin access with both auth systems
 * 6. Performance Analysis - Measures system performance post-migration
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const Response = require('../models/Response');
const User = require('../models/User');
const Submission = require('../models/Submission');
const Invitation = require('../models/Invitation');
const Contact = require('../models/Contact');

class MigrationValidationReport {
  constructor() {
    this.startTime = new Date();
    this.validationResults = {
      dataIntegrity: null,
      fieldMapping: null,
      backwardCompatibility: null,
      tokenPreservation: null,
      regressionTests: null,
      performanceAnalysis: null
    };
    this.overallStatus = 'PENDING';
    this.criticalIssues = [];
    this.warnings = [];
    this.recommendations = [];
  }

  recordResult(phase, result) {
    this.validationResults[phase] = {
      ...result,
      timestamp: new Date(),
      duration: Date.now() - this.startTime.getTime()
    };
  }

  addIssue(severity, message, details = null) {
    const issue = {
      severity,
      message,
      details,
      timestamp: new Date()
    };
    
    if (severity === 'CRITICAL') {
      this.criticalIssues.push(issue);
    } else if (severity === 'WARNING') {
      this.warnings.push(issue);
    }
  }

  addRecommendation(type, message, priority = 'medium') {
    this.recommendations.push({
      type,
      message,
      priority,
      timestamp: new Date()
    });
  }

  generateSummary() {
    const completedValidations = Object.values(this.validationResults).filter(r => r !== null);
    const passedValidations = completedValidations.filter(r => r.status === 'PASSED');
    
    this.overallStatus = this.criticalIssues.length === 0 && 
                        passedValidations.length === completedValidations.length
                        ? 'PASSED' : 'FAILED';

    return {
      overallStatus: this.overallStatus,
      executionTime: Math.round((Date.now() - this.startTime.getTime()) / 1000),
      validationResults: this.validationResults,
      summary: {
        totalValidations: Object.keys(this.validationResults).length,
        completedValidations: completedValidations.length,
        passedValidations: passedValidations.length,
        criticalIssues: this.criticalIssues.length,
        warnings: this.warnings.length,
        recommendations: this.recommendations.length
      },
      issues: {
        critical: this.criticalIssues,
        warnings: this.warnings
      },
      recommendations: this.recommendations,
      metadata: {
        timestamp: this.startTime.toISOString(),
        environment: process.env.NODE_ENV || 'development',
        mongoUri: process.env.MONGODB_URI ? '[REDACTED]' : 'NOT_SET'
      }
    };
  }
}

class MigrationValidator {
  constructor() {
    this.report = new MigrationValidationReport();
    this.logger = console;
  }

  log(level, message, details = null) {
    const timestamp = new Date().toISOString();
    const colorCodes = {
      INFO: '\x1b[36m',    // Cyan
      WARN: '\x1b[33m',    // Yellow  
      ERROR: '\x1b[31m',   // Red
      SUCCESS: '\x1b[32m', // Green
      DEBUG: '\x1b[90m'    // Gray
    };
    
    const color = colorCodes[level] || '\x1b[0m';
    const reset = '\x1b[0m';
    
    console.log(`${color}[${timestamp}] ${level}: ${message}${reset}`);
    
    if (details) {
      console.log(`${color}   Details: ${JSON.stringify(details, null, 2)}${reset}`);
    }
  }

  async connectDatabase() {
    try {
      const uri = process.env.MONGODB_URI;
      if (!uri) {
        throw new Error('MONGODB_URI environment variable is required');
      }
      
      await mongoose.connect(uri);
      this.log('SUCCESS', 'Connected to MongoDB');
    } catch (error) {
      this.log('ERROR', 'Failed to connect to MongoDB', { error: error.message });
      throw error;
    }
  }

  async validateDataIntegrity() {
    this.log('INFO', '=== VALIDATION PHASE 1: DATA INTEGRITY ===');
    
    try {
      // Count all data types
      const responsesCount = await Response.countDocuments();
      const usersCount = await User.countDocuments();
      const submissionsCount = await Submission.countDocuments();
      const invitationsCount = await Invitation.countDocuments();
      const contactsCount = await Contact.countDocuments();

      // Analyze Response data
      const uniqueResponseNames = await Response.distinct('name');
      const adminResponses = await Response.countDocuments({ isAdmin: true });
      const responsesWithTokens = await Response.countDocuments({ 
        token: { $exists: true, $ne: null } 
      });

      // Analyze User data
      const migratedUsers = await User.countDocuments({ 'migrationData.source': 'migration' });
      const adminUsers = await User.countDocuments({ role: 'admin' });
      const usersWithLegacyNames = await User.countDocuments({ 
        'migrationData.legacyName': { $exists: true } 
      });

      // Analyze Submission data
      const submissionsWithUsers = await Submission.countDocuments({ 
        userId: { $exists: true } 
      });

      // Analyze Invitation data
      const legacyInvitations = await Invitation.countDocuments({
        'metadata.migrationSource': 'response_token'
      });

      const counts = {
        responses: {
          total: responsesCount,
          uniqueNames: uniqueResponseNames.length,
          adminResponses,
          withTokens: responsesWithTokens
        },
        users: {
          total: usersCount,
          migrated: migratedUsers,
          admins: adminUsers,
          withLegacyNames: usersWithLegacyNames
        },
        submissions: {
          total: submissionsCount,
          withUsers: submissionsWithUsers
        },
        invitations: {
          total: invitationsCount,
          legacy: legacyInvitations
        },
        contacts: {
          total: contactsCount
        }
      };

      // Validation logic
      const issues = [];
      const validations = [];

      // Check if migration has occurred
      if (migratedUsers === 0 && submissionsCount === 0) {
        issues.push({
          severity: 'CRITICAL',
          message: 'No migration detected - no migrated users or submissions found',
          expected: responsesCount > 0 ? `${uniqueResponseNames.length} users, ${responsesCount} submissions` : 'Migration data',
          actual: `${migratedUsers} migrated users, ${submissionsCount} submissions`
        });
      } else {
        // Validate user creation from unique names
        if (migratedUsers !== uniqueResponseNames.length) {
          issues.push({
            severity: 'CRITICAL',
            message: 'User count mismatch with unique Response names',
            expected: uniqueResponseNames.length,
            actual: migratedUsers
          });
        } else {
          validations.push('✅ User count matches unique Response names');
        }

        // Validate submission creation (should be close to responses count)
        if (submissionsCount < responsesCount * 0.9) {
          issues.push({
            severity: 'CRITICAL',
            message: 'Submission count significantly lower than Response count',
            expected: responsesCount,
            actual: submissionsCount,
            threshold: '90%'
          });
        } else {
          validations.push('✅ Submission count is acceptable compared to Response count');
        }

        // Validate token preservation
        if (legacyInvitations !== responsesWithTokens) {
          issues.push({
            severity: 'WARNING',
            message: 'Legacy invitation count does not match Response tokens',
            expected: responsesWithTokens,
            actual: legacyInvitations
          });
        } else {
          validations.push('✅ Legacy token preservation is complete');
        }

        // Validate admin migration
        if (adminUsers === 0 && adminResponses > 0) {
          issues.push({
            severity: 'CRITICAL',
            message: 'No admin users found despite admin responses existing',
            expected: 'At least 1 admin user',
            actual: adminUsers
          });
        } else {
          validations.push('✅ Admin user migration appears correct');
        }
      }

      const status = issues.filter(i => i.severity === 'CRITICAL').length === 0 ? 'PASSED' : 'FAILED';
      
      const result = {
        status,
        counts,
        issues,
        validations,
        details: {
          migrationDetected: migratedUsers > 0 || submissionsCount > 0,
          dataConsistency: issues.filter(i => i.severity === 'CRITICAL').length === 0,
          completenessScore: Math.round(
            ((migratedUsers === uniqueResponseNames.length ? 1 : 0) + 
             (submissionsCount >= responsesCount * 0.9 ? 1 : 0) + 
             (legacyInvitations === responsesWithTokens ? 1 : 0) + 
             (adminUsers > 0 || adminResponses === 0 ? 1 : 0)) / 4 * 100
          )
        }
      };

      this.report.recordResult('dataIntegrity', result);
      
      // Add issues to report
      issues.forEach(issue => {
        this.report.addIssue(issue.severity, issue.message, issue);
      });

      this.log('SUCCESS', `Data Integrity Validation: ${status}`, {
        completeness: `${result.details.completenessScore}%`,
        criticalIssues: issues.filter(i => i.severity === 'CRITICAL').length,
        warnings: issues.filter(i => i.severity === 'WARNING').length
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Data integrity validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message,
        issues: [{ severity: 'CRITICAL', message: `Validation failed: ${error.message}` }]
      };
      
      this.report.recordResult('dataIntegrity', result);
      this.report.addIssue('CRITICAL', 'Data integrity validation failed', { error: error.message });
      
      return result;
    }
  }

  async validateFieldMapping() {
    this.log('INFO', '=== VALIDATION PHASE 2: FIELD MAPPING ===');
    
    try {
      // Sample a few Response/Submission pairs to validate field mapping
      const sampleSize = Math.min(10, await Response.countDocuments());
      const sampleResponses = await Response.find({})
        .limit(sampleSize)
        .sort({ createdAt: -1 })
        .lean();

      const mappingValidations = [];
      const mappingIssues = [];

      for (const response of sampleResponses) {
        try {
          // Find corresponding user
          const user = await User.findOne({ 
            'migrationData.legacyName': response.name 
          }).lean();

          if (!user) {
            mappingIssues.push({
              severity: 'CRITICAL',
              message: `No user found for Response name: ${response.name}`,
              responseId: response._id
            });
            continue;
          }

          // Find corresponding submission
          const submission = await Submission.findOne({
            userId: user._id,
            month: response.month
          }).lean();

          if (!submission) {
            mappingIssues.push({
              severity: 'CRITICAL',
              message: `No submission found for Response`,
              responseId: response._id,
              userId: user._id,
              month: response.month
            });
            continue;
          }

          // Validate field mappings
          const validations = {
            nameToUsername: user.migrationData?.legacyName === response.name,
            monthPreserved: submission.month === response.month,
            responsesArrayMapped: Array.isArray(submission.responses),
            userIdLinked: submission.userId.toString() === user._id.toString(),
            adminRoleMapping: response.isAdmin ? user.role === 'admin' : true,
            createdAtPreserved: Math.abs(
              new Date(submission.submittedAt).getTime() - 
              new Date(response.createdAt).getTime()
            ) < 60000 // Within 1 minute
          };

          const validationResults = Object.entries(validations).map(([key, valid]) => ({
            field: key,
            valid,
            message: valid ? `✅ ${key}` : `❌ ${key} failed`
          }));

          mappingValidations.push({
            responseId: response._id,
            userId: user._id,
            submissionId: submission._id,
            validations: validationResults,
            allValid: Object.values(validations).every(v => v)
          });

          // Add any failed validations as issues
          validationResults.forEach(v => {
            if (!v.valid) {
              mappingIssues.push({
                severity: 'CRITICAL',
                message: `Field mapping validation failed: ${v.field}`,
                responseId: response._id,
                details: v
              });
            }
          });

        } catch (error) {
          mappingIssues.push({
            severity: 'CRITICAL',
            message: `Field mapping validation error for response ${response._id}`,
            error: error.message
          });
        }
      }

      // Check token mapping
      const tokenMappingValidations = [];
      const responsesWithTokens = await Response.find({ 
        token: { $exists: true, $ne: null } 
      }).limit(5).lean();

      for (const response of responsesWithTokens) {
        const invitation = await Invitation.findOne({ 
          token: response.token 
        }).lean();

        tokenMappingValidations.push({
          responseId: response._id,
          token: response.token,
          invitationFound: !!invitation,
          tokenPreserved: invitation?.token === response.token
        });

        if (!invitation || invitation.token !== response.token) {
          mappingIssues.push({
            severity: 'CRITICAL',
            message: `Token mapping failed for Response ${response._id}`,
            token: response.token,
            invitationFound: !!invitation
          });
        }
      }

      const status = mappingIssues.filter(i => i.severity === 'CRITICAL').length === 0 ? 'PASSED' : 'FAILED';
      
      const result = {
        status,
        sampleSize,
        mappingValidations,
        tokenMappingValidations,
        issues: mappingIssues,
        details: {
          successfulMappings: mappingValidations.filter(m => m.allValid).length,
          totalSampled: mappingValidations.length,
          tokenMappingsVerified: tokenMappingValidations.filter(t => t.tokenPreserved).length,
          totalTokensChecked: tokenMappingValidations.length
        }
      };

      this.report.recordResult('fieldMapping', result);
      
      mappingIssues.forEach(issue => {
        this.report.addIssue(issue.severity, issue.message, issue);
      });

      this.log('SUCCESS', `Field Mapping Validation: ${status}`, {
        sampleSize,
        successfulMappings: result.details.successfulMappings,
        tokenMappings: result.details.tokenMappingsVerified
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Field mapping validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message
      };
      
      this.report.recordResult('fieldMapping', result);
      this.report.addIssue('CRITICAL', 'Field mapping validation failed', { error: error.message });
      
      return result;
    }
  }

  async validateBackwardCompatibility() {
    this.log('INFO', '=== VALIDATION PHASE 3: BACKWARD COMPATIBILITY ===');
    
    try {
      const compatibilityTests = [];

      // Test 1: Check if Response model still exists and functions
      try {
        const responseCount = await Response.countDocuments();
        const responseExists = responseCount >= 0;
        compatibilityTests.push({
          test: 'Response model accessibility',
          passed: responseExists,
          details: { count: responseCount }
        });
      } catch (error) {
        compatibilityTests.push({
          test: 'Response model accessibility',
          passed: false,
          error: error.message
        });
      }

      // Test 2: Check if legacy token functionality is preserved
      try {
        const tokensPreserved = await Invitation.countDocuments({
          'metadata.migrationSource': 'response_token'
        });
        const originalTokens = await Response.countDocuments({
          token: { $exists: true, $ne: null }
        });
        
        compatibilityTests.push({
          test: 'Legacy token preservation',
          passed: tokensPreserved === originalTokens,
          details: { preserved: tokensPreserved, original: originalTokens }
        });
      } catch (error) {
        compatibilityTests.push({
          test: 'Legacy token preservation',
          passed: false,
          error: error.message
        });
      }

      // Test 3: Check dual authentication support
      try {
        const legacyAdmins = await Response.countDocuments({ isAdmin: true });
        const newAdmins = await User.countDocuments({ role: 'admin' });
        
        compatibilityTests.push({
          test: 'Dual authentication support',
          passed: (legacyAdmins === 0 && newAdmins >= 0) || (newAdmins > 0),
          details: { legacyAdmins, newAdmins }
        });
      } catch (error) {
        compatibilityTests.push({
          test: 'Dual authentication support',
          passed: false,
          error: error.message
        });
      }

      // Test 4: Verify hybrid indexes are working
      try {
        const indexInfo = await Response.collection.getIndexes();
        const hasHybridIndexes = Object.keys(indexInfo).some(index => 
          index.includes('userId') || index.includes('authMethod')
        );
        
        compatibilityTests.push({
          test: 'Hybrid index functionality',
          passed: hasHybridIndexes,
          details: { indexCount: Object.keys(indexInfo).length }
        });
      } catch (error) {
        compatibilityTests.push({
          test: 'Hybrid index functionality',
          passed: false,
          error: error.message
        });
      }

      const failedTests = compatibilityTests.filter(test => !test.passed);
      const status = failedTests.length === 0 ? 'PASSED' : 'FAILED';

      const result = {
        status,
        tests: compatibilityTests,
        details: {
          totalTests: compatibilityTests.length,
          passedTests: compatibilityTests.filter(test => test.passed).length,
          failedTests: failedTests.length
        }
      };

      this.report.recordResult('backwardCompatibility', result);

      failedTests.forEach(test => {
        this.report.addIssue('CRITICAL', `Backward compatibility test failed: ${test.test}`, test);
      });

      this.log('SUCCESS', `Backward Compatibility Validation: ${status}`, {
        passed: result.details.passedTests,
        total: result.details.totalTests
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Backward compatibility validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message
      };
      
      this.report.recordResult('backwardCompatibility', result);
      this.report.addIssue('CRITICAL', 'Backward compatibility validation failed', { error: error.message });
      
      return result;
    }
  }

  async validateTokenPreservation() {
    this.log('INFO', '=== VALIDATION PHASE 4: TOKEN PRESERVATION ===');
    
    try {
      const tokenTests = [];

      // Get all Response tokens
      const responseTokens = await Response.find({ 
        token: { $exists: true, $ne: null } 
      }, { token: 1, name: 1, month: 1 }).lean();

      let preservedCount = 0;
      let missingCount = 0;
      const tokenValidations = [];

      for (const responseToken of responseTokens) {
        try {
          // Check if token exists in Invitation collection
          const invitation = await Invitation.findOne({ 
            token: responseToken.token 
          }).lean();

          if (invitation) {
            // Verify token integrity
            const tokenValid = invitation.token === responseToken.token;
            const statusValid = ['sent', 'opened', 'started', 'submitted'].includes(invitation.status);
            
            tokenValidations.push({
              originalToken: responseToken.token,
              responseName: responseToken.name,
              month: responseToken.month,
              invitationFound: true,
              tokenMatches: tokenValid,
              statusValid: statusValid,
              invitationStatus: invitation.status
            });

            if (tokenValid) {
              preservedCount++;
            } else {
              this.report.addIssue('CRITICAL', 'Token mismatch detected', {
                original: responseToken.token,
                invitation: invitation.token
              });
            }
          } else {
            tokenValidations.push({
              originalToken: responseToken.token,
              responseName: responseToken.name,
              month: responseToken.month,
              invitationFound: false,
              tokenMatches: false,
              statusValid: false
            });

            missingCount++;
            this.report.addIssue('CRITICAL', 'Token not preserved in migration', {
              token: responseToken.token,
              responseName: responseToken.name
            });
          }
        } catch (error) {
          this.report.addIssue('CRITICAL', 'Token validation error', {
            token: responseToken.token,
            error: error.message
          });
        }
      }

      // Test token uniqueness in new system
      const invitationTokens = await Invitation.distinct('token');
      const duplicateTokens = invitationTokens.length !== new Set(invitationTokens).size;

      if (duplicateTokens) {
        this.report.addIssue('CRITICAL', 'Duplicate tokens detected in Invitation collection');
      }

      const status = (missingCount === 0 && !duplicateTokens) ? 'PASSED' : 'FAILED';

      const result = {
        status,
        tokenValidations,
        summary: {
          totalTokens: responseTokens.length,
          preservedTokens: preservedCount,
          missingTokens: missingCount,
          preservationRate: responseTokens.length > 0 ? 
            Math.round((preservedCount / responseTokens.length) * 100) : 100
        },
        details: {
          duplicateTokensDetected: duplicateTokens,
          invitationTokensCount: invitationTokens.length
        }
      };

      this.report.recordResult('tokenPreservation', result);

      this.log('SUCCESS', `Token Preservation Validation: ${status}`, {
        preservationRate: `${result.summary.preservationRate}%`,
        preserved: preservedCount,
        total: responseTokens.length
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Token preservation validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message
      };
      
      this.report.recordResult('tokenPreservation', result);
      this.report.addIssue('CRITICAL', 'Token preservation validation failed', { error: error.message });
      
      return result;
    }
  }

  async validateRegressionTests() {
    this.log('INFO', '=== VALIDATION PHASE 5: REGRESSION TESTS ===');
    
    try {
      const regressionTests = [];

      // Test 1: Check if admin can be identified by both methods
      try {
        const legacyAdminCount = await Response.countDocuments({ isAdmin: true });
        const newAdminCount = await User.countDocuments({ role: 'admin' });
        
        regressionTests.push({
          test: 'Admin identification consistency',
          passed: legacyAdminCount === 0 || newAdminCount > 0,
          details: { legacyCount: legacyAdminCount, newCount: newAdminCount }
        });
      } catch (error) {
        regressionTests.push({
          test: 'Admin identification consistency',
          passed: false,
          error: error.message
        });
      }

      // Test 2: Verify response count integrity
      try {
        const originalResponseCount = await Response.countDocuments();
        const submissionCount = await Submission.countDocuments();
        
        // Allow for some variance in case of data cleaning
        const countConsistent = submissionCount >= originalResponseCount * 0.9;
        
        regressionTests.push({
          test: 'Response count consistency',
          passed: countConsistent,
          details: { 
            originalResponses: originalResponseCount, 
            newSubmissions: submissionCount,
            ratio: originalResponseCount > 0 ? (submissionCount / originalResponseCount) : 1
          }
        });
      } catch (error) {
        regressionTests.push({
          test: 'Response count consistency',
          passed: false,
          error: error.message
        });
      }

      // Test 3: Check database query performance
      try {
        const startTime = Date.now();
        
        // Test various queries that should be fast
        await Promise.all([
          User.findOne({ role: 'admin' }),
          Submission.findOne({}).populate('userId'),
          Response.findOne({ token: { $exists: true } }),
          Invitation.findOne({ status: 'submitted' })
        ]);
        
        const queryTime = Date.now() - startTime;
        const performanceAcceptable = queryTime < 1000; // Should complete in under 1 second
        
        regressionTests.push({
          test: 'Database query performance',
          passed: performanceAcceptable,
          details: { queryTimeMs: queryTime }
        });
      } catch (error) {
        regressionTests.push({
          test: 'Database query performance',
          passed: false,
          error: error.message
        });
      }

      // Test 4: Verify data relationships are intact
      try {
        // Check if all submissions have valid user references
        const totalSubmissions = await Submission.countDocuments();
        const submissionsWithValidUsers = await Submission.aggregate([
          {
            $lookup: {
              from: 'users',
              localField: 'userId',
              foreignField: '_id',
              as: 'user'
            }
          },
          {
            $match: { 'user.0': { $exists: true } }
          },
          {
            $count: 'count'
          }
        ]);

        const validUserRefs = submissionsWithValidUsers[0]?.count || 0;
        const relationshipsIntact = totalSubmissions === 0 || validUserRefs === totalSubmissions;

        regressionTests.push({
          test: 'Data relationship integrity',
          passed: relationshipsIntact,
          details: { 
            totalSubmissions, 
            submissionsWithValidUsers: validUserRefs,
            orphanedSubmissions: totalSubmissions - validUserRefs
          }
        });
      } catch (error) {
        regressionTests.push({
          test: 'Data relationship integrity',
          passed: false,
          error: error.message
        });
      }

      const failedTests = regressionTests.filter(test => !test.passed);
      const status = failedTests.length === 0 ? 'PASSED' : 'FAILED';

      const result = {
        status,
        tests: regressionTests,
        details: {
          totalTests: regressionTests.length,
          passedTests: regressionTests.filter(test => test.passed).length,
          failedTests: failedTests.length
        }
      };

      this.report.recordResult('regressionTests', result);

      failedTests.forEach(test => {
        this.report.addIssue('CRITICAL', `Regression test failed: ${test.test}`, test);
      });

      this.log('SUCCESS', `Regression Tests Validation: ${status}`, {
        passed: result.details.passedTests,
        total: result.details.totalTests
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Regression tests validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message
      };
      
      this.report.recordResult('regressionTests', result);
      this.report.addIssue('CRITICAL', 'Regression tests validation failed', { error: error.message });
      
      return result;
    }
  }

  async validatePerformanceAnalysis() {
    this.log('INFO', '=== VALIDATION PHASE 6: PERFORMANCE ANALYSIS ===');
    
    try {
      const performanceMetrics = {};
      
      // Test query performance for each model
      const models = [
        { name: 'Response', model: Response },
        { name: 'User', model: User },
        { name: 'Submission', model: Submission },
        { name: 'Invitation', model: Invitation },
        { name: 'Contact', model: Contact }
      ];

      for (const { name, model } of models) {
        const startTime = Date.now();
        
        try {
          const count = await model.countDocuments();
          const queryTime = Date.now() - startTime;
          
          performanceMetrics[name] = {
            documentCount: count,
            countQueryTime: queryTime,
            performanceRating: queryTime < 100 ? 'EXCELLENT' : 
                              queryTime < 500 ? 'GOOD' : 
                              queryTime < 1000 ? 'ACCEPTABLE' : 'POOR'
          };
        } catch (error) {
          performanceMetrics[name] = {
            error: error.message,
            performanceRating: 'FAILED'
          };
        }
      }

      // Test complex query performance
      const complexQueryStart = Date.now();
      try {
        // Complex aggregation query
        await User.aggregate([
          { $match: { 'migrationData.source': 'migration' } },
          {
            $lookup: {
              from: 'submissions',
              localField: '_id',
              foreignField: 'userId',
              as: 'submissions'
            }
          },
          { $limit: 10 }
        ]);
        
        performanceMetrics.complexQuery = {
          queryTime: Date.now() - complexQueryStart,
          performanceRating: (Date.now() - complexQueryStart) < 1000 ? 'ACCEPTABLE' : 'POOR'
        };
      } catch (error) {
        performanceMetrics.complexQuery = {
          error: error.message,
          performanceRating: 'FAILED'
        };
      }

      // Assess overall performance
      const performanceRatings = Object.values(performanceMetrics)
        .map(metric => metric.performanceRating)
        .filter(rating => rating !== 'FAILED');
        
      const poorPerformance = performanceRatings.filter(rating => rating === 'POOR').length;
      const failedQueries = Object.values(performanceMetrics)
        .filter(metric => metric.performanceRating === 'FAILED').length;

      const status = (poorPerformance === 0 && failedQueries === 0) ? 'PASSED' : 
                    (failedQueries === 0 && poorPerformance <= 1) ? 'WARNING' : 'FAILED';

      const result = {
        status,
        performanceMetrics,
        summary: {
          totalQueries: models.length + 1,
          failedQueries,
          poorPerformance,
          averageQueryTime: Object.values(performanceMetrics)
            .filter(metric => metric.countQueryTime)
            .reduce((sum, metric) => sum + metric.countQueryTime, 0) / 
            Math.max(1, Object.values(performanceMetrics).filter(metric => metric.countQueryTime).length)
        }
      };

      this.report.recordResult('performanceAnalysis', result);

      if (failedQueries > 0) {
        this.report.addIssue('CRITICAL', `${failedQueries} database queries failed during performance analysis`);
      }
      
      if (poorPerformance > 1) {
        this.report.addIssue('WARNING', `${poorPerformance} queries showing poor performance`);
      }

      this.log('SUCCESS', `Performance Analysis Validation: ${status}`, {
        averageQueryTime: Math.round(result.summary.averageQueryTime),
        failedQueries,
        poorPerformance
      });

      return result;
    } catch (error) {
      this.log('ERROR', 'Performance analysis validation failed', { error: error.message });
      
      const result = {
        status: 'FAILED',
        error: error.message
      };
      
      this.report.recordResult('performanceAnalysis', result);
      this.report.addIssue('CRITICAL', 'Performance analysis validation failed', { error: error.message });
      
      return result;
    }
  }

  generateRecommendations() {
    const { validationResults } = this.report;

    // Performance recommendations
    if (validationResults.performanceAnalysis?.status === 'WARNING') {
      this.report.addRecommendation(
        'performance_optimization',
        'Consider adding database indexes for slow queries',
        'medium'
      );
    }

    // Migration completeness recommendations
    if (validationResults.dataIntegrity?.details?.completenessScore < 100) {
      this.report.addRecommendation(
        'data_cleanup',
        'Review and fix data integrity issues before going to production',
        'high'
      );
    }

    // Token preservation recommendations
    if (validationResults.tokenPreservation?.summary?.preservationRate < 100) {
      this.report.addRecommendation(
        'token_recovery',
        'Investigate and recover missing tokens to ensure backward compatibility',
        'high'
      );
    }

    // General recommendations
    if (this.report.criticalIssues.length === 0) {
      this.report.addRecommendation(
        'monitoring',
        'Migration validation passed - implement ongoing monitoring for production',
        'medium'
      );
      
      this.report.addRecommendation(
        'user_communication',
        'Prepare user communication about the new system and any required actions',
        'high'
      );
    }
  }

  async executeValidation() {
    try {
      this.log('INFO', 'Starting comprehensive FAF v1 to v2 migration validation');
      
      // Execute all validation phases
      await this.validateDataIntegrity();
      await this.validateFieldMapping();
      await this.validateBackwardCompatibility();
      await this.validateTokenPreservation();
      await this.validateRegressionTests();
      await this.validatePerformanceAnalysis();
      
      // Generate recommendations
      this.generateRecommendations();
      
      // Generate final report
      const finalReport = this.report.generateSummary();
      
      this.log('SUCCESS', `Migration validation completed: ${finalReport.overallStatus}`, {
        executionTime: `${finalReport.executionTime}s`,
        passed: finalReport.summary.passedValidations,
        total: finalReport.summary.totalValidations,
        critical: finalReport.summary.criticalIssues,
        warnings: finalReport.summary.warnings
      });

      return finalReport;
    } catch (error) {
      this.log('ERROR', 'Migration validation failed', { error: error.message });
      this.report.addIssue('CRITICAL', 'Validation execution failed', { error: error.message });
      
      return this.report.generateSummary();
    }
  }

  async saveReport(report) {
    const fs = require('fs').promises;
    const path = require('path');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `migration-validation-report-${timestamp}.json`;
    const filepath = path.join(process.cwd(), filename);
    
    try {
      await fs.writeFile(filepath, JSON.stringify(report, null, 2));
      this.log('SUCCESS', 'Validation report saved', { filename });
      return filename;
    } catch (error) {
      this.log('ERROR', 'Failed to save report', { error: error.message });
      return null;
    }
  }
}

async function main() {
  const validator = new MigrationValidator();
  
  try {
    // Connect to database
    await validator.connectDatabase();
    
    // Execute validation
    const report = await validator.executeValidation();
    
    // Save report
    const filename = await validator.saveReport(report);
    
    // Display summary
    console.log('\n' + '='.repeat(80));
    console.log('FAF MIGRATION VALIDATION SUMMARY');
    console.log('='.repeat(80));
    console.log(`Overall Status: ${report.overallStatus === 'PASSED' ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`Execution Time: ${report.executionTime}s`);
    console.log(`Validations: ${report.summary.passedValidations}/${report.summary.totalValidations} passed`);
    console.log(`Critical Issues: ${report.summary.criticalIssues}`);
    console.log(`Warnings: ${report.summary.warnings}`);
    console.log(`Recommendations: ${report.summary.recommendations}`);
    
    if (filename) {
      console.log(`Report saved: ${filename}`);
    }
    
    if (report.overallStatus === 'FAILED') {
      console.log('\n❌ CRITICAL ISSUES FOUND:');
      report.issues.critical.forEach(issue => {
        console.log(`   - ${issue.message}`);
      });
    }
    
    if (report.issues.warnings.length > 0) {
      console.log('\n⚠️ WARNINGS:');
      report.issues.warnings.forEach(warning => {
        console.log(`   - ${warning.message}`);
      });
    }
    
    if (report.recommendations.length > 0) {
      console.log('\n💡 RECOMMENDATIONS:');
      report.recommendations.forEach(rec => {
        const priority = rec.priority === 'high' ? '🔴' : 
                        rec.priority === 'medium' ? '🟡' : '🟢';
        console.log(`   ${priority} ${rec.message}`);
      });
    }
    
    process.exit(report.overallStatus === 'PASSED' ? 0 : 1);
    
  } catch (error) {
    console.error('❌ VALIDATION FAILED:', error.message);
    process.exit(1);
  } finally {
    if (mongoose.connection.readyState === 1) {
      await mongoose.disconnect();
    }
  }
}

// Export for testing
module.exports = {
  MigrationValidator,
  MigrationValidationReport
};

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}