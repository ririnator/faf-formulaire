// Deep Submission model testing - Validation, Boundary Testing, and Security
const Submission = require('../models/Submission');
const User = require('../models/User');
const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');

describe('Submission Model - Deep Testing', () => {
  let testUser;

  beforeEach(async () => {
    // Clean up collections
    await cleanupBetweenTests();
    
    // Create test user
    testUser = await User.create({
      username: 'testuser',
      email: 'test@example.com',
      password: 'testpassword'
    });
  });

  describe('Database Integration', () => {
    test('should save and retrieve submission successfully', async () => {
      const submissionData = {
        userId: testUser._id,
        month: '2025-01',
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Test answer 1' },
          { questionId: 'q2', type: 'photo', photoUrl: 'https://example.com/photo.jpg', photoCaption: 'Test photo' }
        ],
        freeText: 'This is free text content'
      };

      const submission = new Submission(submissionData);
      const savedSubmission = await submission.save();

      expect(savedSubmission._id).toBeDefined();
      expect(savedSubmission.userId.toString()).toBe(testUser._id.toString());
      expect(savedSubmission.month).toBe('2025-01');
      expect(savedSubmission.responses).toHaveLength(2);
      expect(savedSubmission.formVersion).toBe('v1');
      expect(savedSubmission.submittedAt).toBeInstanceOf(Date);
      expect(savedSubmission.lastModifiedAt).toBeInstanceOf(Date);
    });

    test('should enforce unique constraint on userId + month', async () => {
      const submissionData = {
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'First submission' }]
      };

      // First submission should save successfully
      const submission1 = new Submission(submissionData);
      await submission1.save();

      // Second submission with same userId + month should fail
      const submission2 = new Submission({
        ...submissionData,
        responses: [{ questionId: 'q1', type: 'text', answer: 'Second submission' }]
      });
      
      await expect(submission2.save()).rejects.toThrow(/duplicate key error/i);
    });

    test('should allow different months for same user', async () => {
      const baseData = {
        userId: testUser._id,
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test answer' }]
      };

      const submission1 = new Submission({ ...baseData, month: '2025-01' });
      const submission2 = new Submission({ ...baseData, month: '2025-02' });

      await submission1.save();
      await submission2.save(); // Should not throw

      expect(submission1.month).toBe('2025-01');
      expect(submission2.month).toBe('2025-02');
    });

    test('should allow different users for same month', async () => {
      const user2 = await User.create({
        username: 'testuser2',
        email: 'test2@example.com',
        password: 'testpassword'
      });

      const baseData = {
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test answer' }]
      };

      const submission1 = new Submission({ ...baseData, userId: testUser._id });
      const submission2 = new Submission({ ...baseData, userId: user2._id });

      await submission1.save();
      await submission2.save(); // Should not throw

      expect(submission1.userId.toString()).toBe(testUser._id.toString());
      expect(submission2.userId.toString()).toBe(user2._id.toString());
    });
  });

  describe('Validation and Security', () => {
    test('should validate month format correctly', async () => {
      const invalidFormats = [
        '2025/01',    // Wrong separator
        '25-01',      // Short year
        '2025-1',     // Single digit month
        '2025-13',    // Invalid month
        '2025-00',    // Invalid month
        'January-2025', // Text format
        '2025',       // Year only
        '',           // Empty
        null,
        undefined
      ];

      for (const invalidMonth of invalidFormats) {
        const submission = new Submission({
          userId: testUser._id,
          month: invalidMonth,
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }]
        });

        const error = submission.validateSync();
        expect(error.errors.month).toBeDefined();
      }
    });

    test('should accept valid month formats', async () => {
      const validFormats = [
        '2025-01', '2025-12', '2024-06', '2030-02'
      ];

      for (const validMonth of validFormats) {
        const submission = new Submission({
          userId: testUser._id,
          month: validMonth,
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }]
        });

        const error = submission.validateSync();
        expect(error?.errors?.month).toBeUndefined();
      }
    });

    test('should validate response type enum', async () => {
      const validTypes = ['text', 'photo', 'radio'];
      const invalidTypes = ['video', 'audio', 'file', '', null, undefined];

      // Test valid types
      for (const type of validTypes) {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: [{ questionId: 'q1', type: type, answer: 'Test' }]
        });

        const error = submission.validateSync();
        expect(error?.errors?.['responses.0.type']).toBeUndefined();
      }

      // Test invalid types
      for (const type of invalidTypes) {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: [{ questionId: 'q1', type: type, answer: 'Test' }]
        });

        const error = submission.validateSync();
        expect(error.errors['responses.0.type']).toBeDefined();
      }
    });

    test('should validate completion rate constraints', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
        completionRate: 150 // Over max
      });

      const error = submission.validateSync();
      expect(error.errors.completionRate).toBeDefined();

      // Test negative value
      submission.completionRate = -10;
      const error2 = submission.validateSync();
      expect(error2.errors.completionRate).toBeDefined();
    });

    test('should enforce maxlength constraints', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [{
          questionId: 'q1',
          type: 'text',
          answer: 'a'.repeat(10001), // Over 10000 limit
          photoCaption: 'b'.repeat(501) // Over 500 limit
        }],
        freeText: 'c'.repeat(5001) // Over 5000 limit
      });

      const error = submission.validateSync();
      expect(error.errors['responses.0.answer']).toBeDefined();
      expect(error.errors['responses.0.photoCaption']).toBeDefined();
      expect(error.errors.freeText).toBeDefined();
    });

    test('should handle XSS attempts in responses', async () => {
      const maliciousData = {
        userId: testUser._id,
        month: '2025-01',
        responses: [{
          questionId: 'q1',
          type: 'text',
          answer: '<script>alert("xss")</script>',
          photoUrl: 'javascript:alert("xss")',
          photoCaption: '"><img src=x onerror=alert(1)>'
        }],
        freeText: '<iframe src="javascript:alert(\'xss\')"></iframe>'
      };

      const submission = new Submission(maliciousData);
      await submission.save();

      // Data should be saved as-is (escaping handled at application level)
      expect(submission.responses[0].answer).toContain('<script>');
      expect(submission.responses[0].photoUrl).toContain('javascript:');
      expect(submission.freeText).toContain('<iframe>');
    });
  });

  describe('Boundary Conditions', () => {
    test('should handle minimum valid data', async () => {
      const minimalData = {
        userId: testUser._id,
        month: '2025-01',
        responses: [{ // Single response
          questionId: 'q',
          type: 'text',
          answer: 'A' // Single character
        }]
      };

      const submission = new Submission(minimalData);
      await submission.save();

      expect(submission.responses).toHaveLength(1);
      expect(submission.responses[0].answer).toBe('A');
      expect(submission.completionRate).toBe(10); // 1/10 * 100
      expect(submission.isComplete).toBe(false);
    });

    test('should handle maximum valid data', async () => {
      const maximalData = {
        userId: testUser._id,
        month: '2025-12',
        responses: Array(10).fill().map((_, i) => ({
          questionId: `question_${i}`,
          type: i % 2 === 0 ? 'text' : 'photo',
          answer: 'A'.repeat(10000), // Max answer length
          photoUrl: `https://example.com/photo${i}.jpg`,
          photoCaption: 'C'.repeat(500) // Max caption length
        })),
        freeText: 'F'.repeat(5000), // Max free text length
        formVersion: 'v1.0.0'
      };

      const submission = new Submission(maximalData);
      await submission.save();

      expect(submission.responses).toHaveLength(10);
      expect(submission.responses[0].answer).toHaveLength(10000);
      expect(submission.responses[0].photoCaption).toHaveLength(500);
      expect(submission.freeText).toHaveLength(5000);
      expect(submission.completionRate).toBe(100); // 10.5/10 * 100, capped at 100
      expect(submission.isComplete).toBe(true);
    });

    test('should handle empty responses array', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: []
      });

      await submission.save();
      
      expect(submission.responses).toHaveLength(0);
      expect(submission.completionRate).toBe(0);
      expect(submission.isComplete).toBe(false);
    });

    test('should handle mixed response types', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Text response' },
          { questionId: 'q2', type: 'photo', photoUrl: 'https://example.com/photo.jpg' },
          { questionId: 'q3', type: 'radio', answer: 'Option A' },
          { questionId: 'q4', type: 'text', answer: '' }, // Empty answer
          { questionId: 'q5', type: 'photo', photoUrl: '', photoCaption: 'Caption only' } // Empty URL
        ]
      });

      await submission.save();
      
      expect(submission.responses).toHaveLength(5);
      expect(submission.completionRate).toBe(30); // 3 completed / 10 * 100
    });
  });

  describe('Instance Methods', () => {
    describe('calculateCompletion Method', () => {
      test('should calculate completion correctly for mixed responses', async () => {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: [
            { questionId: 'q1', type: 'text', answer: 'Completed text' },
            { questionId: 'q2', type: 'text', answer: '' }, // Empty
            { questionId: 'q3', type: 'photo', photoUrl: 'https://example.com/photo.jpg' },
            { questionId: 'q4', type: 'photo', photoUrl: '' }, // Empty
            { questionId: 'q5', type: 'radio', answer: 'Selected option' }
          ],
          freeText: 'Some free text content'
        });

        const rate = submission.calculateCompletion();
        
        // 3 completed responses + 0.5 for freeText = 3.5
        // 3.5 / 10 * 100 = 35%
        expect(rate).toBe(35);
        expect(submission.completionRate).toBe(35);
        expect(submission.isComplete).toBe(false);
      });

      test('should cap completion at 100%', async () => {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: Array(12).fill().map((_, i) => ({ // More than 10 responses
            questionId: `q${i}`,
            type: 'text',
            answer: `Answer ${i}`
          })),
          freeText: 'Free text content'
        });

        const rate = submission.calculateCompletion();
        
        // Should be capped at 100%
        expect(rate).toBe(100);
        expect(submission.isComplete).toBe(true);
      });

      test('should handle freeText bonus correctly', async () => {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: Array(8).fill().map((_, i) => ({
            questionId: `q${i}`,
            type: 'text',
            answer: `Answer ${i}`
          })),
          freeText: '   ' // Only whitespace
        });

        const rate1 = submission.calculateCompletion();
        expect(rate1).toBe(80); // 8/10 * 100, no freeText bonus

        submission.freeText = 'Actual content';
        const rate2 = submission.calculateCompletion();
        expect(rate2).toBe(85); // 8.5/10 * 100, with freeText bonus
      });
    });

    describe('getPublicData Method', () => {
      test('should return only safe public data', async () => {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: [{ questionId: 'q1', type: 'text', answer: 'Public answer' }],
          freeText: 'Public free text',
          completionRate: 75,
          formVersion: 'v1'
        });

        const publicData = submission.getPublicData();

        // Should include public fields
        expect(publicData.month).toBe('2025-01');
        expect(publicData.responses).toHaveLength(1);
        expect(publicData.freeText).toBe('Public free text');
        expect(publicData.completionRate).toBe(75);
        expect(publicData.submittedAt).toBeInstanceOf(Date);

        // Should exclude sensitive fields
        expect(publicData.userId).toBeUndefined();
        expect(publicData._id).toBeUndefined();
        expect(publicData.__v).toBeUndefined();
        expect(publicData.lastModifiedAt).toBeUndefined();
        expect(publicData.formVersion).toBeUndefined();
      });

      test('should handle empty/null values in public data', async () => {
        const submission = new Submission({
          userId: testUser._id,
          month: '2025-01',
          responses: [],
          freeText: null,
          completionRate: 0
        });

        const publicData = submission.getPublicData();

        expect(publicData.responses).toEqual([]);
        expect(publicData.freeText).toBeNull();
        expect(publicData.completionRate).toBe(0);
      });
    });
  });

  describe('Pre-save Hook', () => {
    test('should automatically update lastModifiedAt on save', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Initial' }]
      });

      await submission.save();
      const initialModifiedAt = submission.lastModifiedAt;

      // Wait a bit then update
      await new Promise(resolve => setTimeout(resolve, 10));
      
      submission.responses[0].answer = 'Updated';
      await submission.save();

      expect(submission.lastModifiedAt).toBeInstanceOf(Date);
      expect(submission.lastModifiedAt.getTime()).toBeGreaterThan(initialModifiedAt.getTime());
    });

    test('should automatically recalculate completion on save', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
        completionRate: 0 // Manually set to incorrect value
      });

      await submission.save();

      // Pre-save hook should have corrected the completion rate
      expect(submission.completionRate).toBe(10); // 1/10 * 100
    });
  });

  describe('Performance Testing', () => {
    test('should handle bulk submission creation efficiently', async () => {
      const users = await User.insertMany(
        Array(50).fill().map((_, i) => ({
          username: `user${i}`,
          email: `user${i}@example.com`,
          password: 'password'
        }))
      );

      const submissionsData = users.map((user, i) => ({
        userId: user._id,
        month: '2025-01',
        responses: [
          { questionId: 'q1', type: 'text', answer: `Answer from user ${i}` },
          { questionId: 'q2', type: 'photo', photoUrl: `https://example.com/photo${i}.jpg` }
        ]
      }));

      const startTime = Date.now();
      
      await Submission.insertMany(submissionsData);
      
      const endTime = Date.now();
      const processingTime = endTime - startTime;
      
      // Should create 50 submissions in reasonable time (under 500ms)
      expect(processingTime).toBeLessThan(500);
      
      const count = await Submission.countDocuments({ month: '2025-01' });
      expect(count).toBe(50);
    });

    test('should query by indexed fields efficiently', async () => {
      // Create test data
      const submissions = Array(20).fill().map((_, i) => ({
        userId: testUser._id,
        month: `2025-${String(i % 12 + 1).padStart(2, '0')}`,
        responses: [{ questionId: 'q1', type: 'text', answer: `Answer ${i}` }]
      }));

      await Submission.insertMany(submissions);

      const startTime = Date.now();
      
      // Query using compound index (userId + month)
      const results = await Submission.find({
        userId: testUser._id
      }).sort({ submittedAt: -1 });
      
      const endTime = Date.now();
      const queryTime = endTime - startTime;
      
      // Should query quickly (under 50ms)
      expect(queryTime).toBeLessThan(50);
      expect(results).toHaveLength(20);
    });

    test('should aggregate monthly stats efficiently', async () => {
      // Create submissions for different months
      const submissions = [];
      for (let month = 1; month <= 12; month++) {
        for (let i = 0; i < 5; i++) {
          submissions.push({
            userId: testUser._id,
            month: `2025-${String(month).padStart(2, '0')}`,
            responses: Array(Math.floor(Math.random() * 10)).fill().map((_, j) => ({
              questionId: `q${j}`,
              type: 'text',
              answer: `Answer ${j}`
            }))
          });
        }
      }

      await Submission.insertMany(submissions);

      const startTime = Date.now();
      
      // Aggregate completion rates by month
      const aggregation = await Submission.aggregate([
        { $match: { userId: testUser._id } },
        { $group: {
          _id: '$month',
          avgCompletion: { $avg: '$completionRate' },
          count: { $sum: 1 }
        }},
        { $sort: { _id: 1 }}
      ]);
      
      const endTime = Date.now();
      const aggregationTime = endTime - startTime;
      
      // Should aggregate quickly (under 100ms)
      expect(aggregationTime).toBeLessThan(100);
      expect(aggregation).toHaveLength(12); // 12 months
      expect(aggregation[0].count).toBe(5); // 5 submissions per month
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed response data gracefully', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [
          { questionId: '', type: 'text', answer: 'Valid answer' }, // Empty questionId
          { questionId: null, type: 'text', answer: 'Another answer' }, // Null questionId
          { questionId: 'q1', type: 'text' }, // Missing answer
          { questionId: 'q2', type: 'photo' }, // Missing photoUrl
          {} // Completely empty response
        ]
      });

      // Should save but may have validation issues
      const error = submission.validateSync();
      if (error) {
        expect(error.errors['responses.2.type']).toBeDefined(); // Empty response lacks required type
      }
    });

    test('should handle concurrent submissions for same user/month', async () => {
      const submissionData = {
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }]
      };

      // Try to create two submissions simultaneously
      const submission1 = new Submission(submissionData);
      const submission2 = new Submission(submissionData);

      const promises = [submission1.save(), submission2.save()];
      
      // One should succeed, one should fail due to unique constraint
      const results = await Promise.allSettled(promises);
      
      const successes = results.filter(r => r.status === 'fulfilled');
      const failures = results.filter(r => r.status === 'rejected');
      
      expect(successes).toHaveLength(1);
      expect(failures).toHaveLength(1);
      expect(failures[0].reason.message).toMatch(/duplicate key error/i);
    });

    test('should handle large response arrays', async () => {
      const largeResponses = Array(100).fill().map((_, i) => ({
        questionId: `q${i}`,
        type: 'text',
        answer: `Answer ${i}`.repeat(100) // Large answers
      }));

      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: largeResponses
      });

      await submission.save();
      
      expect(submission.responses).toHaveLength(100);
      expect(submission.completionRate).toBe(100); // Capped at 100%
    });

    test('should handle null/undefined in responses gracefully', async () => {
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [
          { questionId: 'q1', type: 'text', answer: null },
          { questionId: 'q2', type: 'text', answer: undefined },
          { questionId: 'q3', type: 'photo', photoUrl: null, photoCaption: undefined }
        ],
        freeText: null
      });

      await submission.save();
      
      // calculateCompletion should handle nulls gracefully
      expect(submission.completionRate).toBe(0); // No valid responses
      expect(submission.isComplete).toBe(false);
      
      const publicData = submission.getPublicData();
      expect(publicData.freeText).toBeNull();
    });

    test('should handle timezone-aware dates correctly', async () => {
      const specificDate = new Date('2025-01-15T14:30:00.000Z');
      
      const submission = new Submission({
        userId: testUser._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
        submittedAt: specificDate
      });

      await submission.save();
      
      expect(submission.submittedAt).toEqual(specificDate);
      expect(submission.lastModifiedAt).toBeInstanceOf(Date);
    });
  });
});