/**
 * Comprehensive Query Sanitization Security Tests
 * 
 * Tests advanced MongoDB query sanitization against NoSQL injection,
 * operator injection, regex attacks, and other query-based security vulnerabilities.
 * 
 * @author FAF Security Team
 * @version 2.0.0
 */

const {
  sanitizeMongoInput,
  sanitizeObjectId,
  sanitizeAggregationPipeline,
  isValidOperator,
  isValidFieldName,
  sanitizeString,
  sanitizeRegex,
  getSecurityEvents,
  clearSecurityEvents,
  CONFIG
} = require('../middleware/querySanitization');

const mongoose = require('mongoose');

describe('Query Sanitization Security Tests', () => {
  beforeEach(() => {
    // Clear security events before each test
    clearSecurityEvents();
  });

  describe('sanitizeMongoInput', () => {
    describe('NoSQL Injection Prevention', () => {
      test('should remove dangerous MongoDB operators', () => {
        const maliciousInput = {
          username: 'admin',
          password: { $ne: null },
          $where: 'this.username === "admin"',
          $expr: { $gt: ['$balance', 1000] }
        };

        const sanitized = sanitizeMongoInput(maliciousInput);
        
        expect(sanitized).toEqual({
          username: 'admin'
          // password field should be removed due to $ne operator
          // $where and $expr should be completely removed
        });
      });

      test('should prevent operator injection in nested objects', () => {
        const maliciousInput = {
          user: {
            profile: {
              $where: 'return true',
              name: 'test'
            }
          }
        };

        const sanitized = sanitizeMongoInput(maliciousInput);
        
        expect(sanitized).toEqual({
          user: {
            profile: {
              name: 'test'
            }
          }
        });
      });

      test('should prevent injection through arrays', () => {
        const maliciousInput = {
          tags: ['tag1', { $where: 'return true' }, 'tag2']
        };

        const sanitized = sanitizeMongoInput(maliciousInput);
        
        expect(sanitized.tags).toEqual(['tag1', {}, 'tag2']);
      });

      test('should handle complex nested injection attempts', () => {
        const maliciousInput = {
          $or: [
            { username: 'admin' },
            { $where: 'this.role === "admin"' }
          ],
          profile: {
            $expr: { $eq: ['$password', 'leaked'] },
            settings: {
              $where: 'return db.users.count() > 0'
            }
          }
        };

        const sanitized = sanitizeMongoInput(maliciousInput);
        
        // $or should be allowed as it's a valid operator, but nested $where should be removed
        expect(sanitized).toEqual({
          $or: [
            { username: 'admin' },
            {} // $where removed
          ],
          profile: {
            settings: {}
          }
        });
      });
    });

    describe('String Injection Prevention', () => {
      test('should sanitize dangerous string patterns', () => {
        const dangerousStrings = [
          'test; return db.collection.find()',
          'function() { return true; }',
          'javascript:alert("xss")',
          'eval(maliciousCode)',
          '$where: function() { return true }'
        ];

        dangerousStrings.forEach(str => {
          const sanitized = sanitizeString(str);
          expect(sanitized).not.toContain('function');
          expect(sanitized).not.toContain('javascript:');
          expect(sanitized).not.toContain('eval');
          expect(sanitized).not.toContain('$where:');
        });
      });

      test('should truncate overly long strings', () => {
        const longString = 'a'.repeat(20000);
        const sanitized = sanitizeString(longString);
        
        expect(sanitized.length).toBeLessThanOrEqual(CONFIG.MAX_STRING_LENGTH);
      });

      test('should preserve normal text content', () => {
        const normalText = 'This is a normal search query with accented characters: café résumé';
        const sanitized = sanitizeString(normalText);
        
        expect(sanitized).toBe(normalText);
      });
    });

    describe('Regex Injection Prevention', () => {
      test('should sanitize dangerous regex patterns', () => {
        const dangerousRegex = /(?=.*){100,}/; // ReDoS attack pattern
        const sanitized = sanitizeRegex(dangerousRegex);
        
        // Should be converted to a safer literal pattern
        expect(sanitized).toBeInstanceOf(RegExp);
        expect(sanitized.source).not.toContain('(?=');
      });

      test('should limit regex length', () => {
        const longRegexSource = 'a'.repeat(2000);
        const longRegex = new RegExp(longRegexSource);
        const sanitized = sanitizeRegex(longRegex);
        
        expect(sanitized.source.length).toBeLessThanOrEqual(CONFIG.MAX_REGEX_LENGTH);
      });

      test('should preserve safe regex patterns', () => {
        const safeRegex = /^[a-zA-Z0-9]+$/i;
        const sanitized = sanitizeRegex(safeRegex);
        
        expect(sanitized).toEqual(safeRegex);
      });
    });

    describe('Field Name Validation', () => {
      test('should reject protected field names', () => {
        const protectedFields = ['password', '__v', 'session', 'admin.password'];
        
        protectedFields.forEach(field => {
          expect(isValidFieldName(field)).toBe(false);
        });
      });

      test('should allow safe field names', () => {
        const safeFields = ['username', 'email', 'metadata.responseCount', 'profile.firstName'];
        
        safeFields.forEach(field => {
          expect(isValidFieldName(field)).toBe(true);
        });
      });

      test('should reject field injection attempts', () => {
        const maliciousFields = ['user.$where', 'profile.$expr', 'field.$function', 'bad$.$pattern'];
        
        maliciousFields.forEach(field => {
          expect(isValidFieldName(field)).toBe(false);
        });
      });
    });

    describe('Operator Validation', () => {
      test('should allow whitelisted operators', () => {
        const allowedOps = ['$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$and', '$or'];
        
        allowedOps.forEach(op => {
          expect(isValidOperator(op)).toBe(true);
        });
      });

      test('should block dangerous operators', () => {
        const dangerousOps = ['$where', '$expr', '$function', '$accumulator', '$merge', '$out'];
        
        dangerousOps.forEach(op => {
          expect(isValidOperator(op)).toBe(false);
        });
      });

      test('should block unknown operators', () => {
        const unknownOps = ['$custom', '$backdoor', '$evil'];
        
        unknownOps.forEach(op => {
          expect(isValidOperator(op)).toBe(false);
        });
      });
    });

    describe('Depth Protection', () => {
      test('should prevent deep recursion attacks', () => {
        // Create deeply nested object
        let deepObject = {};
        let current = deepObject;
        for (let i = 0; i < 20; i++) {
          current.nested = {};
          current = current.nested;
        }
        current.malicious = { $where: 'return true' };

        const sanitized = sanitizeMongoInput(deepObject);
        
        // Should truncate at max depth and prevent the malicious payload
        expect(JSON.stringify(sanitized).length).toBeLessThan(JSON.stringify(deepObject).length);
      });
    });

    describe('Array Protection', () => {
      test('should limit array size', () => {
        const largeArray = new Array(200).fill('item');
        const input = { tags: largeArray };
        
        const sanitized = sanitizeMongoInput(input);
        
        expect(sanitized.tags.length).toBeLessThanOrEqual(CONFIG.MAX_ARRAY_LENGTH);
      });

      test('should sanitize array elements', () => {
        const maliciousArray = [
          'safe_item',
          { $where: 'return true' },
          'another_safe_item'
        ];
        
        const sanitized = sanitizeMongoInput({ items: maliciousArray });
        
        expect(sanitized.items[0]).toBe('safe_item');
        expect(sanitized.items[1]).toEqual({});
        expect(sanitized.items[2]).toBe('another_safe_item');
      });
    });
  });

  describe('sanitizeObjectId', () => {
    test('should validate legitimate ObjectIds', () => {
      const validId = new mongoose.Types.ObjectId();
      const sanitized = sanitizeObjectId(validId.toString());
      
      expect(sanitized).toBe(validId.toString());
    });

    test('should reject invalid ObjectId formats', () => {
      const invalidIds = [
        'invalid',
        '123',
        '',
        null,
        undefined,
        { $ne: null },
        'id_with_injection{$where}'
      ];

      invalidIds.forEach(id => {
        const sanitized = sanitizeObjectId(id);
        expect(sanitized).toBeNull();
      });
    });

    test('should handle ObjectId objects', () => {
      const objectId = new mongoose.Types.ObjectId();
      const sanitized = sanitizeObjectId(objectId);
      
      expect(sanitized).toBe(objectId.toString());
    });

    test('should detect injection patterns in ObjectId strings', () => {
      const maliciousIds = [
        '507f1f77bcf86cd799439011{$where}',
        '507f1f77bcf86cd799439011$ne',
        '507f1f77bcf86cd799439011.constructor'
      ];

      maliciousIds.forEach(id => {
        const sanitized = sanitizeObjectId(id);
        expect(sanitized).toBeNull();
      });
    });
  });

  describe('sanitizeAggregationPipeline', () => {
    test('should allow safe aggregation stages', () => {
      const safePipeline = [
        { $match: { status: 'active' } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ];

      const sanitized = sanitizeAggregationPipeline(safePipeline);
      
      expect(sanitized).toHaveLength(4);
      expect(sanitized[0]).toHaveProperty('$match');
      expect(sanitized[1]).toHaveProperty('$group');
    });

    test('should block dangerous aggregation stages', () => {
      const dangerousPipeline = [
        { $match: { status: 'active' } },
        { $out: 'malicious_collection' },
        { $merge: { into: 'target_collection' } },
        { $where: 'return true' }
      ];

      const sanitized = sanitizeAggregationPipeline(dangerousPipeline);
      
      // Only $match should remain
      expect(sanitized).toHaveLength(1);
      expect(sanitized[0]).toHaveProperty('$match');
    });

    test('should handle invalid pipeline format', () => {
      const invalidPipelines = [
        'not_an_array',
        [{ $match: 'invalid' }, { multiple: 'keys', in: 'stage' }],
        null,
        undefined
      ];

      invalidPipelines.forEach(pipeline => {
        const sanitized = sanitizeAggregationPipeline(pipeline);
        expect(Array.isArray(sanitized)).toBe(true);
      });
    });
  });

  describe('Security Event Logging', () => {
    test('should log security events for suspicious activity', () => {
      // Clear events first
      clearSecurityEvents();

      // Trigger security events
      sanitizeMongoInput({ $where: 'malicious code' });
      sanitizeObjectId('invalid{injection}');
      isValidOperator('$dangerous');

      const events = getSecurityEvents();
      expect(events.length).toBeGreaterThan(0);
      
      // Check event structure
      events.forEach(event => {
        expect(event).toHaveProperty('timestamp');
        expect(event).toHaveProperty('event');
        expect(event).toHaveProperty('severity');
        expect(event).toHaveProperty('source', 'querySanitization');
      });
    });

    test('should categorize security events by severity', () => {
      clearSecurityEvents();

      // Trigger different severity events
      isValidOperator('$where'); // Critical
      sanitizeString('function() { return true; }'); // High
      sanitizeString('a'.repeat(15000)); // Medium

      const events = getSecurityEvents();
      const severities = events.map(e => e.severity);
      
      expect(severities).toContain('critical');
      expect(severities.some(s => ['high', 'medium'].includes(s))).toBe(true);
    });
  });

  describe('Edge Cases and Advanced Attacks', () => {
    test('should handle null and undefined inputs safely', () => {
      expect(sanitizeMongoInput(null)).toBeNull();
      expect(sanitizeMongoInput(undefined)).toBeUndefined();
      expect(sanitizeMongoInput('')).toBe('');
    });

    test('should handle Date objects correctly', () => {
      const date = new Date();
      const sanitized = sanitizeMongoInput({ createdAt: date });
      
      expect(sanitized.createdAt).toEqual(date);
    });

    test('should handle mixed data types', () => {
      const mixedInput = {
        string: 'test',
        number: 42,
        boolean: true,
        date: new Date(),
        objectId: new mongoose.Types.ObjectId(),
        array: [1, 'two', { three: 3 }],
        nested: {
          level2: {
            value: 'deep'
          }
        }
      };

      const sanitized = sanitizeMongoInput(mixedInput);
      
      expect(sanitized.string).toBe('test');
      expect(sanitized.number).toBe(42);
      expect(sanitized.boolean).toBe(true);
      expect(sanitized.date).toEqual(mixedInput.date);
      expect(sanitized.array).toHaveLength(3);
      expect(sanitized.nested.level2.value).toBe('deep');
    });

    test('should prevent prototype pollution attempts', () => {
      const pollutionAttempt = {
        '__proto__': { isAdmin: true },
        'constructor': { prototype: { isAdmin: true } },
        'prototype': { isAdmin: true }
      };

      const sanitized = sanitizeMongoInput(pollutionAttempt);
      
      // These fields should be safely handled
      expect(sanitized).toBeDefined();
      expect(Object.prototype.isAdmin).toBeUndefined();
    });

    test('should handle circular references gracefully', () => {
      const circularObj = { name: 'test' };
      circularObj.self = circularObj;

      // Should not throw an error and should return something safe
      expect(() => {
        const sanitized = sanitizeMongoInput(circularObj);
        expect(sanitized).toBeDefined();
      }).not.toThrow();
    });

    test('should handle Unicode and international characters', () => {
      const unicodeInput = {
        name: 'José María',
        description: '这是中文测试',
        emoji: '🔒🛡️',
        arabic: 'مرحبا'
      };

      const sanitized = sanitizeMongoInput(unicodeInput);
      
      expect(sanitized.name).toBe('José María');
      expect(sanitized.description).toBe('这是中文测试');
      expect(sanitized.emoji).toBe('🔒🛡️');
      expect(sanitized.arabic).toBe('مرحبا');
    });
  });

  describe('Performance and DoS Protection', () => {
    test('should handle large inputs without crashing', () => {
      const largeInput = {
        data: 'x'.repeat(50000),
        array: new Array(500).fill('item'),
        nested: {}
      };

      // Create deep nesting
      let current = largeInput.nested;
      for (let i = 0; i < 15; i++) {
        current.level = {};
        current = current.level;
      }

      expect(() => {
        const sanitized = sanitizeMongoInput(largeInput);
        expect(sanitized).toBeDefined();
      }).not.toThrow();
    });

    test('should limit processing time for complex inputs', () => {
      const start = Date.now();
      
      // Create complex nested structure
      const complexInput = {};
      for (let i = 0; i < 100; i++) {
        complexInput[`field_${i}`] = {
          [`nested_${i}`]: {
            array: new Array(100).fill(`item_${i}`),
            $malicious: 'should be removed'
          }
        };
      }

      const sanitized = sanitizeMongoInput(complexInput);
      const processingTime = Date.now() - start;

      expect(sanitized).toBeDefined();
      expect(processingTime).toBeLessThan(5000); // Should process within 5 seconds
    });
  });
});

describe('Integration with MongoDB Operations', () => {
  test('should work with real MongoDB query scenarios', () => {
    // Simulate common query patterns that could be attacked
    const userSearchQuery = {
      $or: [
        { username: { $regex: 'admin', $options: 'i' } },
        { email: { $regex: 'admin@', $options: 'i' } }
      ],
      isActive: true,
      $where: 'this.role === "admin"' // Malicious injection
    };

    const sanitized = sanitizeMongoInput(userSearchQuery);
    
    expect(sanitized).toHaveProperty('$or');
    expect(sanitized.isActive).toBe(true);
    expect(sanitized).not.toHaveProperty('$where');
  });

  test('should preserve valid aggregation pipelines', () => {
    const legitPipeline = [
      { $match: { category: 'electronics' } },
      { $group: { _id: '$brand', totalSales: { $sum: '$sales' } } },
      { $sort: { totalSales: -1 } },
      { $limit: 10 }
    ];

    const sanitized = sanitizeAggregationPipeline(legitPipeline);
    
    // Check structure is preserved
    expect(sanitized).toHaveLength(4);
    expect(sanitized[0]).toHaveProperty('$match');
    expect(sanitized[1]).toHaveProperty('$group');
    expect(sanitized[2]).toHaveProperty('$sort');
    expect(sanitized[3]).toHaveProperty('$limit');
  });

  test('should handle update operations safely', () => {
    const updateQuery = {
      $set: {
        lastActive: new Date(),
        'profile.settings': { theme: 'dark' }
      },
      $unset: { tempField: 1 },
      $where: 'return true' // Should be removed
    };

    const sanitized = sanitizeMongoInput(updateQuery);
    
    // Should preserve valid update operators
    expect(sanitized).toHaveProperty('$set');
    expect(sanitized).toHaveProperty('$unset');
    // Should remove dangerous operators
    expect(sanitized).not.toHaveProperty('$where');
    
    // Check that the nested structure is preserved
    expect(sanitized.$set).toHaveProperty('lastActive');
    expect(sanitized.$unset).toHaveProperty('tempField');
  });
});