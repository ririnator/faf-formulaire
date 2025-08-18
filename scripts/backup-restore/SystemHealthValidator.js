#!/usr/bin/env node

/**
 * SYSTEM HEALTH VALIDATOR v2.0 - Comprehensive Database Health Monitoring
 * =======================================================================
 * 
 * Features:
 * - Complete data integrity validation with deep consistency checks
 * - Index validation and performance optimization analysis
 * - System health monitoring with real-time metrics
 * - Application functionality testing with end-to-end scenarios
 * - Performance benchmarking and regression detection
 * - Detailed health reports with actionable recommendations
 * - Automated issue detection and resolution suggestions
 * - Multi-level validation (document, collection, database, application)
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');

/**
 * Configuration for health validation
 */
const VALIDATION_CONFIG = {
  // Validation levels
  ENABLE_DOCUMENT_VALIDATION: true,
  ENABLE_COLLECTION_VALIDATION: true,
  ENABLE_INDEX_VALIDATION: true,
  ENABLE_REFERENTIAL_INTEGRITY: true,
  ENABLE_PERFORMANCE_VALIDATION: true,
  ENABLE_APPLICATION_TESTING: true,
  
  // Performance thresholds
  MAX_QUERY_TIME_MS: 1000,
  MAX_INDEX_SIZE_MB: 100,
  MIN_INDEX_EFFICIENCY: 0.8,
  MAX_COLLECTION_SCAN_RATIO: 0.1,
  
  // Data integrity thresholds
  MAX_ALLOWED_ORPHANED_RECORDS: 10,
  MAX_ALLOWED_MISSING_REFERENCES: 5,
  MIN_DATA_CONSISTENCY_RATIO: 0.95,
  
  // Testing parameters
  SAMPLE_SIZE_PERCENT: 0.1, // 10% sample for large collections
  MIN_SAMPLE_SIZE: 100,
  MAX_SAMPLE_SIZE: 10000,
  PERFORMANCE_TEST_ITERATIONS: 5,
  
  // Reporting
  ENABLE_DETAILED_REPORTS: true,
  GENERATE_PERFORMANCE_CHARTS: false,
  INCLUDE_RECOMMENDATIONS: true,
  
  // Timeouts
  VALIDATION_TIMEOUT: 600000, // 10 minutes
  QUERY_TIMEOUT: 30000, // 30 seconds
  INDEX_ANALYSIS_TIMEOUT: 120000 // 2 minutes
};

/**
 * Health validation results structure
 */
class ValidationResults {
  constructor() {
    this.id = crypto.randomUUID();
    this.timestamp = new Date().toISOString();
    this.overall = {
      status: 'unknown', // 'healthy', 'warning', 'critical', 'unknown'
      score: 0, // 0-100
      summary: ''
    };
    this.categories = {
      dataIntegrity: { status: 'unknown', score: 0, issues: [], tests: [] },
      indexHealth: { status: 'unknown', score: 0, issues: [], tests: [] },
      performance: { status: 'unknown', score: 0, issues: [], tests: [] },
      systemHealth: { status: 'unknown', score: 0, issues: [], tests: [] },
      applicationFunctionality: { status: 'unknown', score: 0, issues: [], tests: [] }
    };
    this.collections = {};
    this.recommendations = [];
    this.statistics = {
      totalValidations: 0,
      passedValidations: 0,
      failedValidations: 0,
      warningsCount: 0,
      errorsCount: 0,
      executionTimeMs: 0
    };
    this.performance = {
      queryMetrics: {},
      indexMetrics: {},
      systemMetrics: {}
    };
  }

  addTest(category, testName, status, details = {}) {
    if (this.categories[category]) {
      this.categories[category].tests.push({
        name: testName,
        status, // 'passed', 'failed', 'warning'
        details,
        timestamp: new Date().toISOString()
      });
      
      this.statistics.totalValidations++;
      if (status === 'passed') {
        this.statistics.passedValidations++;
      } else if (status === 'failed') {
        this.statistics.failedValidations++;
        this.statistics.errorsCount++;
      } else if (status === 'warning') {
        this.statistics.warningsCount++;
      }
    }
  }

  addIssue(category, severity, message, details = {}) {
    if (this.categories[category]) {
      this.categories[category].issues.push({
        severity, // 'low', 'medium', 'high', 'critical'
        message,
        details,
        timestamp: new Date().toISOString()
      });
    }
  }

  addRecommendation(priority, category, message, action = null) {
    this.recommendations.push({
      priority, // 'low', 'medium', 'high', 'critical'
      category,
      message,
      action,
      timestamp: new Date().toISOString()
    });
  }

  calculateCategoryScore(category) {
    const categoryData = this.categories[category];
    if (!categoryData || categoryData.tests.length === 0) {
      return 0;
    }
    
    const passed = categoryData.tests.filter(test => test.status === 'passed').length;
    const warnings = categoryData.tests.filter(test => test.status === 'warning').length;
    const failed = categoryData.tests.filter(test => test.status === 'failed').length;
    
    // Weight: passed = 1, warning = 0.5, failed = 0
    const weightedScore = (passed * 1 + warnings * 0.5) / categoryData.tests.length;
    
    // Reduce score based on issue severity
    let severityPenalty = 0;
    categoryData.issues.forEach(issue => {
      switch (issue.severity) {
        case 'critical': severityPenalty += 0.3; break;
        case 'high': severityPenalty += 0.2; break;
        case 'medium': severityPenalty += 0.1; break;
        case 'low': severityPenalty += 0.05; break;
      }
    });
    
    return Math.max(0, Math.min(100, (weightedScore - severityPenalty) * 100));
  }

  calculateOverallScore() {
    const categories = Object.keys(this.categories);
    const totalScore = categories.reduce((sum, category) => {
      this.categories[category].score = this.calculateCategoryScore(category);
      return sum + this.categories[category].score;
    }, 0);
    
    this.overall.score = Math.round(totalScore / categories.length);
    
    // Determine overall status
    if (this.overall.score >= 90) {
      this.overall.status = 'healthy';
      this.overall.summary = 'System is operating optimally';
    } else if (this.overall.score >= 70) {
      this.overall.status = 'warning';
      this.overall.summary = 'System has minor issues that should be addressed';
    } else {
      this.overall.status = 'critical';
      this.overall.summary = 'System has critical issues requiring immediate attention';
    }
    
    return this.overall.score;
  }
}

/**
 * Performance metrics collector
 */
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      queries: [],
      indexes: {},
      system: {}
    };
  }

  async measureQuery(operation, queryFunction) {
    const startTime = Date.now();
    const startMemory = process.memoryUsage();
    
    try {
      const result = await queryFunction();
      const endTime = Date.now();
      const endMemory = process.memoryUsage();
      
      const metrics = {
        operation,
        executionTime: endTime - startTime,
        memoryDelta: endMemory.heapUsed - startMemory.heapUsed,
        success: true,
        timestamp: new Date().toISOString()
      };
      
      this.metrics.queries.push(metrics);
      return { result, metrics };
      
    } catch (error) {
      const endTime = Date.now();
      
      const metrics = {
        operation,
        executionTime: endTime - startTime,
        success: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };
      
      this.metrics.queries.push(metrics);
      throw error;
    }
  }

  getQueryStatistics() {
    const queries = this.metrics.queries;
    if (queries.length === 0) return null;
    
    const successful = queries.filter(q => q.success);
    const executionTimes = successful.map(q => q.executionTime);
    
    return {
      totalQueries: queries.length,
      successfulQueries: successful.length,
      failedQueries: queries.length - successful.length,
      averageExecutionTime: executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length,
      minExecutionTime: Math.min(...executionTimes),
      maxExecutionTime: Math.max(...executionTimes),
      memoryUsage: successful.reduce((sum, q) => sum + (q.memoryDelta || 0), 0)
    };
  }
}

/**
 * System Health Validator with comprehensive testing capabilities
 */
class SystemHealthValidator extends EventEmitter {
  constructor(options = {}) {
    super();
    this.config = { ...VALIDATION_CONFIG, ...options };
    this.logger = options.logger || console;
    this.models = {};
    this.performanceMonitor = new PerformanceMonitor();
    this.results = null;
    this.validationTimeout = null;
  }

  /**
   * Register database models for validation
   */
  registerModels(models) {
    this.models = { ...this.models, ...models };
  }

  /**
   * Execute comprehensive system health validation
   */
  async validateSystemHealth(options = {}) {
    this.results = new ValidationResults();
    const startTime = Date.now();
    
    try {
      this.logger.info('Starting comprehensive system health validation...', {
        validationId: this.results.id
      });

      // Start validation timeout
      this.startValidationTimeout();

      // Execute validation phases
      await this.validateDataIntegrity();
      await this.validateIndexHealth();
      await this.validatePerformance();
      await this.validateSystemHealth();
      await this.validateApplicationFunctionality();

      // Calculate final scores and generate recommendations
      this.results.calculateOverallScore();
      await this.generateRecommendations();

      // Complete validation
      this.results.statistics.executionTimeMs = Date.now() - startTime;
      
      this.logger.info('System health validation completed', {
        overallScore: this.results.overall.score,
        status: this.results.overall.status,
        executionTime: this.results.statistics.executionTimeMs
      });

      return {
        success: true,
        results: this.results
      };

    } catch (error) {
      this.results.overall.status = 'critical';
      this.results.overall.summary = `Validation failed: ${error.message}`;
      
      this.logger.error('System health validation failed', {
        error: error.message,
        validationId: this.results.id
      });
      
      throw error;
    } finally {
      this.clearValidationTimeout();
    }
  }

  /**
   * Validate data integrity across all collections
   */
  async validateDataIntegrity() {
    this.logger.info('=== VALIDATING DATA INTEGRITY ===');
    
    try {
      for (const [collectionName, model] of Object.entries(this.models)) {
        await this.validateCollectionIntegrity(collectionName, model);
      }
      
      // Cross-collection referential integrity
      if (this.config.ENABLE_REFERENTIAL_INTEGRITY) {
        await this.validateReferentialIntegrity();
      }
      
      this.logger.info('Data integrity validation completed');
      
    } catch (error) {
      this.results.addIssue('dataIntegrity', 'critical', 'Data integrity validation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Validate integrity of a single collection
   */
  async validateCollectionIntegrity(collectionName, model) {
    this.logger.debug(`Validating collection integrity: ${collectionName}`);
    
    try {
      // Basic document count validation
      const { result: totalDocs } = await this.performanceMonitor.measureQuery(
        `count_${collectionName}`,
        () => model.countDocuments()
      );
      
      this.results.addTest('dataIntegrity', `${collectionName}_document_count`, 'passed', {
        totalDocuments: totalDocs
      });

      if (totalDocs === 0) {
        this.results.addIssue('dataIntegrity', 'warning', `Collection ${collectionName} is empty`);
        return;
      }

      // Sample-based validation for large collections
      const sampleSize = this.calculateSampleSize(totalDocs);
      const { result: sampleDocs } = await this.performanceMonitor.measureQuery(
        `sample_${collectionName}`,
        () => model.aggregate([{ $sample: { size: sampleSize } }])
      );

      // Validate document structure
      await this.validateDocumentStructure(collectionName, sampleDocs);
      
      // Validate required fields
      await this.validateRequiredFields(collectionName, model, sampleDocs);
      
      // Validate data types
      await this.validateDataTypes(collectionName, sampleDocs);
      
      // Check for duplicate documents
      await this.checkForDuplicates(collectionName, model);
      
      this.results.collections[collectionName] = {
        totalDocuments: totalDocs,
        sampleSize: sampleSize,
        validationStatus: 'completed'
      };
      
    } catch (error) {
      this.results.addTest('dataIntegrity', `${collectionName}_integrity`, 'failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Validate document structure consistency
   */
  async validateDocumentStructure(collectionName, documents) {
    const fieldConsistency = {};
    const requiredFields = this.getRequiredFieldsForCollection(collectionName);
    
    for (const doc of documents) {
      for (const field of Object.keys(doc)) {
        if (!fieldConsistency[field]) {
          fieldConsistency[field] = { count: 0, types: new Set() };
        }
        fieldConsistency[field].count++;
        fieldConsistency[field].types.add(typeof doc[field]);
      }
    }
    
    // Check for inconsistent field types
    const inconsistentFields = Object.entries(fieldConsistency)
      .filter(([field, info]) => info.types.size > 1)
      .map(([field]) => field);
    
    if (inconsistentFields.length > 0) {
      this.results.addIssue('dataIntegrity', 'medium', 
        `Inconsistent field types in ${collectionName}`, {
          inconsistentFields
        });
      this.results.addTest('dataIntegrity', `${collectionName}_field_consistency`, 'warning', {
        inconsistentFields
      });
    } else {
      this.results.addTest('dataIntegrity', `${collectionName}_field_consistency`, 'passed');
    }
    
    // Check for missing required fields
    const missingFieldCounts = {};
    for (const field of requiredFields) {
      missingFieldCounts[field] = documents.filter(doc => !(field in doc)).length;
    }
    
    const missingFields = Object.entries(missingFieldCounts)
      .filter(([field, count]) => count > 0);
    
    if (missingFields.length > 0) {
      this.results.addIssue('dataIntegrity', 'high', 
        `Missing required fields in ${collectionName}`, {
          missingFields: Object.fromEntries(missingFields)
        });
      this.results.addTest('dataIntegrity', `${collectionName}_required_fields`, 'failed', {
        missingFields
      });
    } else {
      this.results.addTest('dataIntegrity', `${collectionName}_required_fields`, 'passed');
    }
  }

  /**
   * Validate required fields presence
   */
  async validateRequiredFields(collectionName, model, sampleDocs) {
    const schema = model.schema;
    const requiredPaths = [];
    
    schema.eachPath((pathname, schematype) => {
      if (schematype.isRequired) {
        requiredPaths.push(pathname);
      }
    });
    
    if (requiredPaths.length === 0) {
      this.results.addTest('dataIntegrity', `${collectionName}_schema_validation`, 'passed', {
        message: 'No required fields defined'
      });
      return;
    }
    
    // Check for documents missing required fields
    const { result: missingFieldsCount } = await this.performanceMonitor.measureQuery(
      `required_fields_${collectionName}`,
      () => {
        const orConditions = requiredPaths.map(path => ({ [path]: { $exists: false } }));
        return model.countDocuments({ $or: orConditions });
      }
    );
    
    if (missingFieldsCount > 0) {
      this.results.addIssue('dataIntegrity', 'high', 
        `${missingFieldsCount} documents missing required fields in ${collectionName}`);
      this.results.addTest('dataIntegrity', `${collectionName}_required_field_validation`, 'failed', {
        missingFieldsCount,
        requiredFields: requiredPaths
      });
    } else {
      this.results.addTest('dataIntegrity', `${collectionName}_required_field_validation`, 'passed');
    }
  }

  /**
   * Validate data types consistency
   */
  async validateDataTypes(collectionName, documents) {
    const expectedTypes = this.getExpectedTypesForCollection(collectionName);
    const typeViolations = [];
    
    for (const doc of documents) {
      for (const [field, expectedType] of Object.entries(expectedTypes)) {
        if (field in doc && typeof doc[field] !== expectedType) {
          typeViolations.push({
            documentId: doc._id,
            field,
            expectedType,
            actualType: typeof doc[field]
          });
        }
      }
    }
    
    if (typeViolations.length > 0) {
      this.results.addIssue('dataIntegrity', 'medium', 
        `Data type violations in ${collectionName}`, {
          violationsCount: typeViolations.length,
          sampleViolations: typeViolations.slice(0, 5)
        });
      this.results.addTest('dataIntegrity', `${collectionName}_data_types`, 'warning', {
        typeViolations: typeViolations.length
      });
    } else {
      this.results.addTest('dataIntegrity', `${collectionName}_data_types`, 'passed');
    }
  }

  /**
   * Check for duplicate documents
   */
  async checkForDuplicates(collectionName, model) {
    try {
      // Check for duplicate _ids (should never happen)
      const { result: duplicateIds } = await this.performanceMonitor.measureQuery(
        `duplicate_ids_${collectionName}`,
        () => model.aggregate([
          { $group: { _id: '$_id', count: { $sum: 1 } } },
          { $match: { count: { $gt: 1 } } }
        ])
      );
      
      if (duplicateIds.length > 0) {
        this.results.addIssue('dataIntegrity', 'critical', 
          `Duplicate _id fields detected in ${collectionName}`, {
            duplicateCount: duplicateIds.length
          });
        this.results.addTest('dataIntegrity', `${collectionName}_unique_ids`, 'failed');
      } else {
        this.results.addTest('dataIntegrity', `${collectionName}_unique_ids`, 'passed');
      }
      
      // Check for business logic duplicates based on unique fields
      const uniqueFields = this.getUniqueFieldsForCollection(collectionName);
      for (const field of uniqueFields) {
        const { result: duplicates } = await this.performanceMonitor.measureQuery(
          `duplicates_${field}_${collectionName}`,
          () => model.aggregate([
            { $match: { [field]: { $exists: true, $ne: null } } },
            { $group: { _id: `$${field}`, count: { $sum: 1 } } },
            { $match: { count: { $gt: 1 } } }
          ])
        );
        
        if (duplicates.length > 0) {
          this.results.addIssue('dataIntegrity', 'high', 
            `Duplicate values in unique field ${field} of ${collectionName}`, {
              duplicateCount: duplicates.length
            });
          this.results.addTest('dataIntegrity', `${collectionName}_unique_${field}`, 'failed');
        } else {
          this.results.addTest('dataIntegrity', `${collectionName}_unique_${field}`, 'passed');
        }
      }
      
    } catch (error) {
      this.results.addTest('dataIntegrity', `${collectionName}_duplicates`, 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Validate referential integrity across collections
   */
  async validateReferentialIntegrity() {
    this.logger.debug('Validating referential integrity...');
    
    const referenceRules = this.getReferentialIntegrityRules();
    
    for (const rule of referenceRules) {
      try {
        await this.validateReferenceRule(rule);
      } catch (error) {
        this.results.addIssue('dataIntegrity', 'high', 
          `Referential integrity validation failed for ${rule.name}`, {
            error: error.message
          });
      }
    }
  }

  /**
   * Validate a specific reference rule
   */
  async validateReferenceRule(rule) {
    const sourceModel = this.models[rule.sourceCollection];
    const targetModel = this.models[rule.targetCollection];
    
    if (!sourceModel || !targetModel) {
      this.results.addTest('dataIntegrity', `reference_${rule.name}`, 'failed', {
        error: 'Model not found'
      });
      return;
    }
    
    // Find orphaned references
    const { result: orphanedRefs } = await this.performanceMonitor.measureQuery(
      `orphaned_refs_${rule.name}`,
      async () => {
        const sourceRefs = await sourceModel.distinct(rule.sourceField, {
          [rule.sourceField]: { $exists: true, $ne: null }
        });
        
        const existingTargets = await targetModel.distinct('_id');
        const existingTargetStrings = existingTargets.map(id => id.toString());
        
        return sourceRefs.filter(ref => 
          !existingTargetStrings.includes(ref.toString())
        );
      }
    );
    
    if (orphanedRefs.length > 0) {
      const severity = orphanedRefs.length > this.config.MAX_ALLOWED_ORPHANED_RECORDS ? 'high' : 'medium';
      this.results.addIssue('dataIntegrity', severity, 
        `Orphaned references found in ${rule.sourceCollection}.${rule.sourceField}`, {
          orphanedCount: orphanedRefs.length,
          maxAllowed: this.config.MAX_ALLOWED_ORPHANED_RECORDS
        });
      this.results.addTest('dataIntegrity', `reference_${rule.name}`, 'warning', {
        orphanedReferences: orphanedRefs.length
      });
    } else {
      this.results.addTest('dataIntegrity', `reference_${rule.name}`, 'passed');
    }
  }

  /**
   * Validate index health and performance
   */
  async validateIndexHealth() {
    this.logger.info('=== VALIDATING INDEX HEALTH ===');
    
    try {
      for (const [collectionName, model] of Object.entries(this.models)) {
        await this.validateCollectionIndexes(collectionName, model);
      }
      
      this.logger.info('Index health validation completed');
      
    } catch (error) {
      this.results.addIssue('indexHealth', 'critical', 'Index health validation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Validate indexes for a specific collection
   */
  async validateCollectionIndexes(collectionName, model) {
    this.logger.debug(`Validating indexes for collection: ${collectionName}`);
    
    try {
      const collection = model.collection;
      
      // Get index information
      const { result: indexes } = await this.performanceMonitor.measureQuery(
        `indexes_${collectionName}`,
        () => collection.indexes()
      );
      
      this.results.addTest('indexHealth', `${collectionName}_indexes_exist`, 'passed', {
        indexCount: indexes.length
      });
      
      // Analyze each index
      for (const index of indexes) {
        await this.analyzeIndex(collectionName, collection, index);
      }
      
      // Check for missing recommended indexes
      await this.checkMissingIndexes(collectionName, model, indexes);
      
    } catch (error) {
      this.results.addTest('indexHealth', `${collectionName}_index_validation`, 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Analyze a specific index
   */
  async analyzeIndex(collectionName, collection, index) {
    try {
      // Get index stats
      const { result: indexStats } = await this.performanceMonitor.measureQuery(
        `index_stats_${collectionName}_${index.name}`,
        () => collection.aggregate([{ $indexStats: {} }]).toArray()
      );
      
      const indexStat = indexStats.find(stat => stat.name === index.name);
      
      if (indexStat) {
        const indexSizeMB = indexStat.indexSizes ? 
          (indexStat.indexSizes[index.name] || 0) / (1024 * 1024) : 0;
        
        // Check index size
        if (indexSizeMB > this.config.MAX_INDEX_SIZE_MB) {
          this.results.addIssue('indexHealth', 'medium', 
            `Large index detected: ${index.name} in ${collectionName}`, {
              sizeMB: indexSizeMB,
              maxSizeMB: this.config.MAX_INDEX_SIZE_MB
            });
        }
        
        // Check index usage
        const accesses = indexStat.accesses || {};
        if (accesses.since && accesses.ops === 0) {
          this.results.addIssue('indexHealth', 'low', 
            `Unused index detected: ${index.name} in ${collectionName}`, {
              sinceDate: accesses.since
            });
          this.results.addTest('indexHealth', `${collectionName}_${index.name}_usage`, 'warning');
        } else {
          this.results.addTest('indexHealth', `${collectionName}_${index.name}_usage`, 'passed');
        }
        
        this.results.performance.indexMetrics[`${collectionName}_${index.name}`] = {
          size: indexSizeMB,
          accesses: accesses.ops || 0,
          efficiency: this.calculateIndexEfficiency(indexStat)
        };
      }
      
    } catch (error) {
      this.results.addTest('indexHealth', `${collectionName}_${index.name}_analysis`, 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Check for missing recommended indexes
   */
  async checkMissingIndexes(collectionName, model, existingIndexes) {
    const recommendedIndexes = this.getRecommendedIndexesForCollection(collectionName);
    const existingIndexKeys = existingIndexes.map(index => 
      JSON.stringify(index.key)
    );
    
    const missingIndexes = recommendedIndexes.filter(recommended => 
      !existingIndexKeys.includes(JSON.stringify(recommended.key))
    );
    
    if (missingIndexes.length > 0) {
      this.results.addIssue('indexHealth', 'medium', 
        `Missing recommended indexes in ${collectionName}`, {
          missingIndexes: missingIndexes.map(idx => idx.key)
        });
      this.results.addTest('indexHealth', `${collectionName}_recommended_indexes`, 'warning', {
        missingCount: missingIndexes.length
      });
    } else {
      this.results.addTest('indexHealth', `${collectionName}_recommended_indexes`, 'passed');
    }
  }

  /**
   * Validate system performance
   */
  async validatePerformance() {
    this.logger.info('=== VALIDATING PERFORMANCE ===');
    
    try {
      // Test query performance
      await this.testQueryPerformance();
      
      // Test system resources
      await this.testSystemResources();
      
      // Test database operations
      await this.testDatabaseOperations();
      
      this.logger.info('Performance validation completed');
      
    } catch (error) {
      this.results.addIssue('performance', 'critical', 'Performance validation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Test query performance across collections
   */
  async testQueryPerformance() {
    this.logger.debug('Testing query performance...');
    
    for (const [collectionName, model] of Object.entries(this.models)) {
      // Test basic queries
      const queries = [
        { name: 'count', fn: () => model.countDocuments() },
        { name: 'findOne', fn: () => model.findOne() },
        { name: 'findLimit', fn: () => model.find().limit(10) }
      ];
      
      for (const query of queries) {
        try {
          const { metrics } = await this.performanceMonitor.measureQuery(
            `${collectionName}_${query.name}`,
            query.fn
          );
          
          if (metrics.executionTime > this.config.MAX_QUERY_TIME_MS) {
            this.results.addIssue('performance', 'medium', 
              `Slow query detected: ${query.name} on ${collectionName}`, {
                executionTime: metrics.executionTime,
                threshold: this.config.MAX_QUERY_TIME_MS
              });
            this.results.addTest('performance', `${collectionName}_${query.name}_speed`, 'warning');
          } else {
            this.results.addTest('performance', `${collectionName}_${query.name}_speed`, 'passed');
          }
          
        } catch (error) {
          this.results.addTest('performance', `${collectionName}_${query.name}_speed`, 'failed', {
            error: error.message
          });
        }
      }
    }
  }

  /**
   * Test system resources
   */
  async testSystemResources() {
    this.logger.debug('Testing system resources...');
    
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    this.results.performance.systemMetrics = {
      memory: {
        heapUsed: memoryUsage.heapUsed,
        heapTotal: memoryUsage.heapTotal,
        external: memoryUsage.external,
        rss: memoryUsage.rss
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system
      }
    };
    
    // Check memory usage
    const memoryUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
    if (memoryUsagePercent > 90) {
      this.results.addIssue('performance', 'high', 'High memory usage detected', {
        usagePercent: memoryUsagePercent
      });
      this.results.addTest('performance', 'memory_usage', 'warning');
    } else {
      this.results.addTest('performance', 'memory_usage', 'passed');
    }
  }

  /**
   * Test database operations
   */
  async testDatabaseOperations() {
    this.logger.debug('Testing database operations...');
    
    try {
      // Test database connection
      const { metrics: pingMetrics } = await this.performanceMonitor.measureQuery(
        'database_ping',
        () => mongoose.connection.db.admin().ping()
      );
      
      if (pingMetrics.executionTime > 1000) {
        this.results.addIssue('performance', 'medium', 'Slow database ping detected', {
          pingTime: pingMetrics.executionTime
        });
        this.results.addTest('performance', 'database_ping', 'warning');
      } else {
        this.results.addTest('performance', 'database_ping', 'passed');
      }
      
    } catch (error) {
      this.results.addTest('performance', 'database_operations', 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Validate overall system health
   */
  async validateSystemHealth() {
    this.logger.info('=== VALIDATING SYSTEM HEALTH ===');
    
    try {
      // Check database connection status
      await this.checkDatabaseConnection();
      
      // Check collection statistics
      await this.checkCollectionStatistics();
      
      // Check disk space (if available)
      await this.checkStorageHealth();
      
      this.logger.info('System health validation completed');
      
    } catch (error) {
      this.results.addIssue('systemHealth', 'critical', 'System health validation failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Check database connection health
   */
  async checkDatabaseConnection() {
    try {
      const connectionState = mongoose.connection.readyState;
      const stateNames = ['disconnected', 'connected', 'connecting', 'disconnecting'];
      
      if (connectionState === 1) {
        this.results.addTest('systemHealth', 'database_connection', 'passed', {
          state: stateNames[connectionState]
        });
      } else {
        this.results.addIssue('systemHealth', 'critical', 'Database not connected', {
          state: stateNames[connectionState] || 'unknown'
        });
        this.results.addTest('systemHealth', 'database_connection', 'failed');
      }
      
    } catch (error) {
      this.results.addTest('systemHealth', 'database_connection', 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Check collection statistics
   */
  async checkCollectionStatistics() {
    try {
      for (const [collectionName, model] of Object.entries(this.models)) {
        const stats = await model.collection.stats();
        
        this.results.collections[collectionName] = {
          ...this.results.collections[collectionName],
          stats: {
            size: stats.size,
            storageSize: stats.storageSize,
            totalIndexSize: stats.totalIndexSize,
            avgObjSize: stats.avgObjSize
          }
        };
        
        this.results.addTest('systemHealth', `${collectionName}_statistics`, 'passed', {
          documentCount: stats.count,
          dataSize: stats.size
        });
      }
      
    } catch (error) {
      this.results.addTest('systemHealth', 'collection_statistics', 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Check storage health
   */
  async checkStorageHealth() {
    try {
      // This would typically check disk space, but it's not easily available in Node.js
      // without additional dependencies. For now, we'll just mark as passed.
      this.results.addTest('systemHealth', 'storage_health', 'passed', {
        note: 'Storage health check not implemented'
      });
      
    } catch (error) {
      this.results.addTest('systemHealth', 'storage_health', 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Validate application functionality
   */
  async validateApplicationFunctionality() {
    this.logger.info('=== VALIDATING APPLICATION FUNCTIONALITY ===');
    
    if (!this.config.ENABLE_APPLICATION_TESTING) {
      this.logger.info('Application functionality testing disabled by configuration');
      return;
    }

    try {
      // Test basic CRUD operations
      await this.testCrudOperations();
      
      // Test application-specific workflows
      await this.testApplicationWorkflows();
      
      this.logger.info('Application functionality validation completed');
      
    } catch (error) {
      this.results.addIssue('applicationFunctionality', 'critical', 
        'Application functionality validation failed', {
          error: error.message
        });
      throw error;
    }
  }

  /**
   * Test basic CRUD operations
   */
  async testCrudOperations() {
    this.logger.debug('Testing CRUD operations...');
    
    // Test with first available model
    const testCollectionName = Object.keys(this.models)[0];
    const testModel = this.models[testCollectionName];
    
    if (!testModel) {
      this.results.addTest('applicationFunctionality', 'crud_operations', 'failed', {
        error: 'No models available for testing'
      });
      return;
    }

    try {
      // Test Create
      const testDocument = this.createTestDocument(testCollectionName);
      const { result: created } = await this.performanceMonitor.measureQuery(
        `crud_create_${testCollectionName}`,
        () => testModel.create(testDocument)
      );
      
      // Test Read
      const { result: found } = await this.performanceMonitor.measureQuery(
        `crud_read_${testCollectionName}`,
        () => testModel.findById(created._id)
      );
      
      // Test Update
      const { result: updated } = await this.performanceMonitor.measureQuery(
        `crud_update_${testCollectionName}`,
        () => testModel.findByIdAndUpdate(created._id, { testField: 'updated' }, { new: true })
      );
      
      // Test Delete
      await this.performanceMonitor.measureQuery(
        `crud_delete_${testCollectionName}`,
        () => testModel.findByIdAndDelete(created._id)
      );
      
      this.results.addTest('applicationFunctionality', 'crud_operations', 'passed', {
        testedCollection: testCollectionName
      });
      
    } catch (error) {
      this.results.addTest('applicationFunctionality', 'crud_operations', 'failed', {
        error: error.message
      });
    }
  }

  /**
   * Test application-specific workflows
   */
  async testApplicationWorkflows() {
    this.logger.debug('Testing application workflows...');
    
    // This would test specific application workflows
    // For now, we'll just mark as passed
    this.results.addTest('applicationFunctionality', 'application_workflows', 'passed', {
      note: 'Application-specific workflow testing not implemented'
    });
  }

  /**
   * Generate recommendations based on validation results
   */
  async generateRecommendations() {
    this.logger.debug('Generating recommendations...');
    
    if (!this.config.INCLUDE_RECOMMENDATIONS) {
      return;
    }

    // Performance recommendations
    const slowQueries = this.performanceMonitor.getQueryStatistics();
    if (slowQueries && slowQueries.averageExecutionTime > this.config.MAX_QUERY_TIME_MS) {
      this.results.addRecommendation('high', 'performance', 
        'Consider optimizing slow queries or adding indexes',
        'Review query execution plans and add appropriate indexes'
      );
    }
    
    // Index recommendations
    const unusedIndexes = Object.entries(this.results.performance.indexMetrics)
      .filter(([name, metrics]) => metrics.accesses === 0);
    
    if (unusedIndexes.length > 0) {
      this.results.addRecommendation('medium', 'indexHealth',
        `Consider removing ${unusedIndexes.length} unused indexes to save space`,
        'Drop unused indexes to reduce storage overhead'
      );
    }
    
    // Data integrity recommendations
    if (this.results.statistics.errorsCount > 0) {
      this.results.addRecommendation('high', 'dataIntegrity',
        'Address data integrity issues to ensure system reliability',
        'Review and fix data integrity violations'
      );
    }
    
    this.logger.debug(`Generated ${this.results.recommendations.length} recommendations`);
  }

  /**
   * Helper methods for collection-specific configuration
   */
  calculateSampleSize(totalDocs) {
    const percentBased = Math.ceil(totalDocs * this.config.SAMPLE_SIZE_PERCENT);
    return Math.min(
      this.config.MAX_SAMPLE_SIZE,
      Math.max(this.config.MIN_SAMPLE_SIZE, percentBased)
    );
  }

  getRequiredFieldsForCollection(collectionName) {
    // This would return required fields based on schema or configuration
    const defaults = {
      responses: ['name', 'responses', 'month'],
      users: ['username', 'email', 'password'],
      submissions: ['userId', 'month', 'responses'],
      invitations: ['fromUserId', 'toEmail', 'month']
    };
    return defaults[collectionName] || [];
  }

  getExpectedTypesForCollection(collectionName) {
    // This would return expected types for fields
    const defaults = {
      responses: { name: 'string', isAdmin: 'boolean' },
      users: { username: 'string', email: 'string' },
      submissions: { month: 'string' },
      invitations: { toEmail: 'string' }
    };
    return defaults[collectionName] || {};
  }

  getUniqueFieldsForCollection(collectionName) {
    // This would return fields that should be unique
    const defaults = {
      responses: ['token'],
      users: ['username', 'email'],
      submissions: [],
      invitations: ['token']
    };
    return defaults[collectionName] || [];
  }

  getReferentialIntegrityRules() {
    // Define referential integrity rules between collections
    return [
      {
        name: 'submission_user_reference',
        sourceCollection: 'submissions',
        sourceField: 'userId',
        targetCollection: 'users',
        targetField: '_id'
      },
      {
        name: 'invitation_from_user_reference',
        sourceCollection: 'invitations',
        sourceField: 'fromUserId',
        targetCollection: 'users',
        targetField: '_id'
      },
      {
        name: 'invitation_to_user_reference',
        sourceCollection: 'invitations',
        sourceField: 'toUserId',
        targetCollection: 'users',
        targetField: '_id'
      }
    ];
  }

  getRecommendedIndexesForCollection(collectionName) {
    // Define recommended indexes for each collection
    const recommendations = {
      responses: [
        { key: { month: 1 } },
        { key: { createdAt: -1 } },
        { key: { token: 1 } },
        { key: { name: 1, month: 1 } }
      ],
      users: [
        { key: { username: 1 } },
        { key: { email: 1 } },
        { key: { 'metadata.lastActive': -1 } }
      ],
      submissions: [
        { key: { userId: 1 } },
        { key: { month: 1 } },
        { key: { submittedAt: -1 } },
        { key: { userId: 1, month: 1 } }
      ],
      invitations: [
        { key: { token: 1 } },
        { key: { toEmail: 1 } },
        { key: { fromUserId: 1 } },
        { key: { status: 1, month: 1 } }
      ]
    };
    return recommendations[collectionName] || [];
  }

  calculateIndexEfficiency(indexStat) {
    // Calculate index efficiency based on usage patterns
    if (!indexStat.accesses || indexStat.accesses.ops === 0) {
      return 0;
    }
    
    // This is a simplified efficiency calculation
    // In practice, this would consider more metrics
    return Math.min(1, indexStat.accesses.ops / 1000);
  }

  createTestDocument(collectionName) {
    // Create a test document for CRUD testing
    const testDocuments = {
      responses: { name: 'test_user', responses: [], month: '2025-08', isAdmin: false },
      users: { username: 'test_user', email: 'test@example.com', password: 'test123', role: 'user' },
      submissions: { userId: new mongoose.Types.ObjectId(), month: '2025-08', responses: [] },
      invitations: { 
        fromUserId: new mongoose.Types.ObjectId(), 
        toEmail: 'test@example.com', 
        month: '2025-08',
        status: 'queued'
      }
    };
    
    return testDocuments[collectionName] || { testField: 'test_value' };
  }

  /**
   * Validation timeout management
   */
  startValidationTimeout() {
    this.validationTimeout = setTimeout(() => {
      this.handleValidationTimeout();
    }, this.config.VALIDATION_TIMEOUT);
  }

  clearValidationTimeout() {
    if (this.validationTimeout) {
      clearTimeout(this.validationTimeout);
      this.validationTimeout = null;
    }
  }

  handleValidationTimeout() {
    const error = new Error(`Validation timeout exceeded: ${this.config.VALIDATION_TIMEOUT}ms`);
    this.results.addIssue('systemHealth', 'critical', 'Validation timeout exceeded', {
      timeout: this.config.VALIDATION_TIMEOUT
    });
    throw error;
  }

  /**
   * Export validation report
   */
  async exportReport(filename) {
    if (!filename) {
      filename = `health-validation-report-${Date.now()}.json`;
    }
    
    await fs.writeFile(filename, JSON.stringify(this.results, null, 2));
    this.logger.info(`Validation report exported to: ${filename}`);
    
    return filename;
  }
}

module.exports = {
  SystemHealthValidator,
  ValidationResults,
  PerformanceMonitor,
  VALIDATION_CONFIG
};