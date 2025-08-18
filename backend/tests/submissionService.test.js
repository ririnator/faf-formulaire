const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const SubmissionService = require('../services/submissionServiceInstance');
const Submission = require('../models/Submission');
const User = require('../models/User');
const Invitation = require('../models/Invitation');

describe('SubmissionService Tests', () => {
  let testUser1, testUser2, testAdmin;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Créer des utilisateurs de test
    testUser1 = await User.create({
      username: 'user1',
      email: 'user1@example.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'user2',
      email: 'user2@example.com',
      password: 'password123'
    });

    testAdmin = await User.create({
      username: 'admin',
      email: 'admin@example.com',
      password: 'password123',
      role: 'admin'
    });
  });

  describe('createSubmission Method', () => {
    test('should create a new submission successfully', async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'This is my answer to question 1'
          },
          {
            questionId: 'q2',
            type: 'photo',
            photoUrl: 'https://example.com/photo.jpg',
            photoCaption: 'A beautiful sunset'
          }
        ],
        freeText: 'This is my free text response',
        month: '2025-01'
      };

      const result = await SubmissionService.createSubmission(testUser1._id, submissionData);

      expect(result.userId._id).toEqual(testUser1._id);
      expect(result.month).toBe('2025-01');
      expect(result.responses).toHaveLength(2);
      expect(result.freeText).toBe('This is my free text response');
      expect(result.completionRate).toBeGreaterThan(0);
    });

    test('should prevent duplicate submissions for same user and month', async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'First submission'
          }
        ],
        month: '2025-01'
      };

      // Créer première soumission
      await SubmissionService.createSubmission(testUser1._id, submissionData);

      // Tenter de créer une deuxième soumission
      await expect(
        SubmissionService.createSubmission(testUser1._id, {
          ...submissionData,
          responses: [{ questionId: 'q1', type: 'text', answer: 'Second submission' }]
        })
      ).rejects.toThrow('Une seule soumission par mois est autorisée');
    });

    test('should allow different users to submit for same month', async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'My answer'
          }
        ],
        month: '2025-01'
      };

      const result1 = await SubmissionService.createSubmission(testUser1._id, submissionData);
      const result2 = await SubmissionService.createSubmission(testUser2._id, submissionData);

      expect(result1.userId._id).toEqual(testUser1._id);
      expect(result2.userId._id).toEqual(testUser2._id);
      expect(result1.month).toBe(result2.month);
    });

    test('should handle invitation token correctly', async () => {
      // Créer une invitation
      const invitation = await Invitation.create({
        fromUserId: testUser2._id,
        toEmail: testUser1.email,
        month: '2025-01',
        token: 'test_invitation_token'
      });

      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Answer via invitation'
          }
        ],
        month: '2025-01',
        invitationToken: 'test_invitation_token'
      };

      const result = await SubmissionService.createSubmission(testUser1._id, submissionData);

      expect(result).toBeDefined();
      
      // Vérifier que l'invitation est marquée comme soumise
      const updatedInvitation = await Invitation.findById(invitation._id);
      expect(updatedInvitation.status).toBe('submitted');
      expect(updatedInvitation.submissionId).toEqual(result._id);
    });

    test('should validate submission data', async () => {
      // Test avec réponses manquantes
      await expect(
        SubmissionService.createSubmission(testUser1._id, {
          responses: [],
          month: '2025-01'
        })
      ).rejects.toThrow('Au moins une réponse est requise');

      // Test avec type invalide
      await expect(
        SubmissionService.createSubmission(testUser1._id, {
          responses: [
            {
              questionId: 'q1',
              type: 'invalid_type',
              answer: 'Test'
            }
          ],
          month: '2025-01'
        })
      ).rejects.toThrow('Type de réponse invalide');

      // Test avec réponse textuelle vide
      await expect(
        SubmissionService.createSubmission(testUser1._id, {
          responses: [
            {
              questionId: 'q1',
              type: 'text',
              answer: ''
            }
          ],
          month: '2025-01'
        })
      ).rejects.toThrow('Réponse textuelle requise');
    });

    test('should sanitize response data', async () => {
      const submissionData = {
        responses: [
          {
            questionId: '  q1  ',
            type: 'text',
            answer: '  This has extra spaces  '
          }
        ],
        freeText: '  Free text with spaces  ',
        month: '2025-01'
      };

      const result = await SubmissionService.createSubmission(testUser1._id, submissionData);

      expect(result.responses[0].questionId).toBe('q1');
      expect(result.responses[0].answer).toBe('This has extra spaces');
      expect(result.freeText).toBe('Free text with spaces');
    });
  });

  describe('updateSubmission Method', () => {
    let existingSubmission;

    beforeEach(async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Original answer'
          }
        ],
        month: '2025-01'
      };
      
      existingSubmission = await SubmissionService.createSubmission(testUser1._id, submissionData);
    });

    test('should update existing submission within 24h', async () => {
      const updateData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Updated answer'
          },
          {
            questionId: 'q2',
            type: 'text',
            answer: 'New question answer'
          }
        ],
        freeText: 'Updated free text'
      };

      const result = await SubmissionService.updateSubmission(
        testUser1._id, 
        '2025-01', 
        updateData
      );

      expect(result.responses).toHaveLength(2);
      expect(result.responses[0].answer).toBe('Updated answer');
      expect(result.freeText).toBe('Updated free text');
    });

    test('should reject update after 24h', async () => {
      // Simuler une soumission ancienne (modifier directement en DB)
      await Submission.findByIdAndUpdate(existingSubmission._id, {
        submittedAt: new Date(Date.now() - 25 * 60 * 60 * 1000) // 25 heures
      });

      await expect(
        SubmissionService.updateSubmission(testUser1._id, '2025-01', {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Too late' }]
        })
      ).rejects.toThrow('Modification non autorisée après 24h');
    });

    test('should reject update for non-existent submission', async () => {
      await expect(
        SubmissionService.updateSubmission(testUser1._id, '2024-12', {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }]
        })
      ).rejects.toThrow('Soumission non trouvée');
    });
  });

  describe('getSubmissionByUser Method', () => {
    beforeEach(async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Test answer'
          }
        ],
        month: '2025-01'
      };
      
      await SubmissionService.createSubmission(testUser1._id, submissionData);
    });

    test('should retrieve submission by user and month', async () => {
      const result = await SubmissionService.getSubmissionByUser(testUser1._id, '2025-01');

      expect(result).toBeDefined();
      expect(result.userId._id).toEqual(testUser1._id);
      expect(result.month).toBe('2025-01');
    });

    test('should return null for non-existent submission', async () => {
      const result = await SubmissionService.getSubmissionByUser(testUser1._id, '2024-12');
      expect(result).toBeNull();
    });
  });

  describe('compareSubmissions Method', () => {
    beforeEach(async () => {
      // Créer deux soumissions similaires
      const similarData1 = {
        responses: [
          {
            questionId: 'hobby',
            type: 'text',
            answer: 'I love reading books and playing guitar'
          },
          {
            questionId: 'food',
            type: 'text',
            answer: 'Pizza is my favorite food'
          }
        ],
        freeText: 'I enjoy outdoor activities and meeting new people',
        month: '2025-01'
      };

      const similarData2 = {
        responses: [
          {
            questionId: 'hobby',
            type: 'text',
            answer: 'Reading books is my passion, also playing music'
          },
          {
            questionId: 'food',
            type: 'text',
            answer: 'I really love pizza too'
          }
        ],
        freeText: 'I like outdoor activities and socializing with friends',
        month: '2025-01'
      };

      await SubmissionService.createSubmission(testUser1._id, similarData1);
      await SubmissionService.createSubmission(testUser2._id, similarData2);
    });

    test('should compare two submissions successfully', async () => {
      const comparison = await SubmissionService.compareSubmissions(
        testUser1._id, 
        testUser2._id, 
        '2025-01'
      );

      expect(comparison).toBeDefined();
      expect(comparison.month).toBe('2025-01');
      expect(comparison.user1).toBeDefined();
      expect(comparison.user2).toBeDefined();
      expect(comparison.analysis).toBeDefined();
      expect(comparison.compatibility).toBeDefined();
      expect(comparison.compatibility.overallScore).toBeGreaterThan(0);
    });

    test('should handle anonymized comparison', async () => {
      const comparison = await SubmissionService.compareSubmissions(
        testUser1._id, 
        testUser2._id, 
        '2025-01',
        { anonymize: true }
      );

      expect(comparison.user1.username).toBe('Utilisateur anonyme');
      expect(comparison.user2.username).toBe('Utilisateur anonyme');
      expect(comparison.metadata.anonymized).toBe(true);
    });

    test('should reject comparison when submission missing', async () => {
      await expect(
        SubmissionService.compareSubmissions(testUser1._id, testUser2._id, '2024-12')
      ).rejects.toThrow('soumission non trouvée');
    });

    test('should calculate compatibility scores', async () => {
      const comparison = await SubmissionService.compareSubmissions(
        testUser1._id, 
        testUser2._id, 
        '2025-01'
      );

      const compatibility = comparison.compatibility;
      expect(compatibility.overallScore).toBeGreaterThanOrEqual(0);
      expect(compatibility.overallScore).toBeLessThanOrEqual(100);
      expect(compatibility.details.responseAlignment).toBeDefined();
      expect(compatibility.details.communicationStyle).toBeDefined();
      expect(compatibility.matches).toBeDefined();
      expect(compatibility.recommendations).toBeDefined();
    });
  });

  describe('getSubmissions Method', () => {
    beforeEach(async () => {
      // Créer plusieurs soumissions de test
      const submissions = [
        {
          userId: testUser1._id,
          month: '2025-01',
          responses: [{ questionId: 'q1', type: 'text', answer: 'Answer 1' }]
        },
        {
          userId: testUser2._id,
          month: '2025-01',
          responses: [{ questionId: 'q1', type: 'text', answer: 'Answer 2' }]
        },
        {
          userId: testUser1._id,
          month: '2025-02',
          responses: [{ questionId: 'q1', type: 'text', answer: 'Answer 3' }]
        }
      ];

      for (const submissionData of submissions) {
        await SubmissionService.createSubmission(submissionData.userId, {
          responses: submissionData.responses,
          month: submissionData.month
        });
      }
    });

    test('should return paginated submissions', async () => {
      const result = await SubmissionService.getSubmissions({}, {
        page: 1,
        limit: 2
      });

      expect(result.submissions).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(3);
      expect(result.pagination.totalPages).toBe(2);
      expect(result.pagination.hasNext).toBe(true);
    });

    test('should filter by month', async () => {
      const result = await SubmissionService.getSubmissions({
        month: '2025-01'
      });

      expect(result.submissions).toHaveLength(2);
      expect(result.submissions.every(s => s.month === '2025-01')).toBe(true);
    });

    test('should filter by user', async () => {
      const result = await SubmissionService.getSubmissions({
        userId: testUser1._id
      });

      expect(result.submissions).toHaveLength(2);
      expect(result.submissions.every(s => s.userId._id.equals(testUser1._id))).toBe(true);
    });

    test('should return comprehensive stats', async () => {
      const result = await SubmissionService.getSubmissions();

      expect(result.stats).toBeDefined();
      expect(result.stats.basic).toBeDefined();
      expect(result.stats.basic.totalSubmissions).toBe(3);
      expect(result.stats.monthly).toBeDefined();
      expect(result.stats.completionDistribution).toBeDefined();
    });
  });

  describe('findMatches Method', () => {
    beforeEach(async () => {
      // Créer des soumissions avec différents niveaux de compatibilité
      const submissions = [
        {
          userId: testUser1._id,
          responses: [
            { questionId: 'hobby', type: 'text', answer: 'I love reading and music' }
          ],
          freeText: 'I enjoy quiet activities'
        },
        {
          userId: testUser2._id,
          responses: [
            { questionId: 'hobby', type: 'text', answer: 'Reading books and playing music are my hobbies' }
          ],
          freeText: 'I prefer calm and relaxing activities'
        }
      ];

      for (const submissionData of submissions) {
        await SubmissionService.createSubmission(submissionData.userId, {
          ...submissionData,
          month: '2025-01'
        });
      }
    });

    test('should find compatible matches', async () => {
      // Utiliser un seuil bas pour ce test simple
      const matches = await SubmissionService.findMatches(testUser1._id, '2025-01', {
        minCompatibility: 20 // Seuil assez bas pour le test
      });

      expect(matches).toHaveLength(1);
      expect(matches[0].user._id).toEqual(testUser2._id);
      expect(matches[0].compatibility).toBeDefined();
      expect(matches[0].compatibility.overallScore).toBeGreaterThan(0);
    });

    test('should respect minimum compatibility threshold', async () => {
      const matches = await SubmissionService.findMatches(testUser1._id, '2025-01', {
        minCompatibility: 90
      });

      // Avec un seuil très élevé, aucun match ne devrait être trouvé
      expect(matches).toHaveLength(0);
    });

    test('should limit number of matches', async () => {
      const matches = await SubmissionService.findMatches(testUser1._id, '2025-01', {
        limit: 1
      });

      expect(matches.length).toBeLessThanOrEqual(1);
    });

    test('should exclude specified users', async () => {
      const matches = await SubmissionService.findMatches(testUser1._id, '2025-01', {
        excludeUserIds: [testUser2._id]
      });

      expect(matches).toHaveLength(0);
    });
  });

  describe('Utility Methods', () => {
    test('getCurrentMonth should return current month', () => {
      const currentMonth = SubmissionService.getCurrentMonth();
      const expected = new Date().toISOString().slice(0, 7);
      expect(currentMonth).toBe(expected);
    });

    test('validateSubmissionData should validate correctly', () => {
      const validData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Valid answer'
          }
        ]
      };

      expect(() => {
        SubmissionService.validateSubmissionData(validData);
      }).not.toThrow();

      const invalidData = {
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'x'.repeat(10001) // Trop long
          }
        ]
      };

      expect(() => {
        SubmissionService.validateSubmissionData(invalidData);
      }).toThrow('Réponse trop longue');
    });

    test('sanitizeResponses should clean data', () => {
      const responses = [
        {
          questionId: '  q1  ',
          type: 'text',
          answer: '  Test answer  '
        }
      ];

      const sanitized = SubmissionService.sanitizeResponses(responses);

      expect(sanitized[0].questionId).toBe('q1');
      expect(sanitized[0].answer).toBe('Test answer');
    });

    test('calculateResponseSimilarity should work correctly', () => {
      const response1 = { type: 'text', answer: 'I love music' };
      const response2 = { type: 'text', answer: 'I love music too' };
      const response3 = { type: 'text', answer: 'I hate everything' };

      const similarity1 = SubmissionService.calculateResponseSimilarity(response1, response2);
      const similarity2 = SubmissionService.calculateResponseSimilarity(response1, response3);

      expect(similarity1).toBeGreaterThan(similarity2);
      expect(similarity1).toBeGreaterThan(0.5);
    });
  });

  describe('deleteSubmission Method', () => {
    let testSubmission;

    beforeEach(async () => {
      testSubmission = await SubmissionService.createSubmission(testUser1._id, {
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
        month: '2025-01'
      });
    });

    test('should allow admin to delete submission', async () => {
      const result = await SubmissionService.deleteSubmission(
        testSubmission._id, 
        testAdmin._id
      );

      expect(result).toBe(true);
      
      const deletedSubmission = await Submission.findById(testSubmission._id);
      expect(deletedSubmission).toBeNull();
    });

    test('should reject non-admin deletion', async () => {
      await expect(
        SubmissionService.deleteSubmission(testSubmission._id, testUser1._id)
      ).rejects.toThrow('Seuls les administrateurs');
    });

    test('should reject deletion of non-existent submission', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      await expect(
        SubmissionService.deleteSubmission(fakeId, testAdmin._id)
      ).rejects.toThrow('Soumission non trouvée');
    });
  });

  describe('getAvailableMonths Method', () => {
    beforeEach(async () => {
      // Créer des soumissions pour différents mois
      const months = ['2025-01', '2025-02', '2024-12'];
      
      for (const month of months) {
        await SubmissionService.createSubmission(testUser1._id, {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
          month
        });
      }
    });

    test('should return available months with labels', async () => {
      const months = await SubmissionService.getAvailableMonths();

      expect(months).toHaveLength(3);
      expect(months[0]).toHaveProperty('key');
      expect(months[0]).toHaveProperty('label');
      expect(months[0]).toHaveProperty('count');
      expect(months[0]).toHaveProperty('avgCompletion');
      
      // Vérifier le tri (plus récent en premier)
      expect(months[0].key).toBe('2025-02');
      expect(months[1].key).toBe('2025-01');
      expect(months[2].key).toBe('2024-12');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle non-existent user', async () => {
      const fakeUserId = new mongoose.Types.ObjectId();

      await expect(
        SubmissionService.createSubmission(fakeUserId, {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
          month: '2025-01'
        })
      ).rejects.toThrow('Utilisateur non trouvé');
    });

    test('should handle invalid invitation token', async () => {
      await expect(
        SubmissionService.createSubmission(testUser1._id, {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
          month: '2025-01',
          invitationToken: 'invalid_token'
        })
      ).rejects.toThrow('Token d\'invitation invalide');
    });

    test('should handle database errors gracefully', async () => {
      // Test avec un ObjectId invalide
      await expect(
        SubmissionService.getSubmissionByUser('invalid_id', '2025-01')
      ).rejects.toThrow();
    });

    test('should handle comparison with missing submissions', async () => {
      // Créer seulement une soumission
      await SubmissionService.createSubmission(testUser1._id, {
        responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
        month: '2025-01'
      });

      await expect(
        SubmissionService.compareSubmissions(testUser1._id, testUser2._id, '2025-01')
      ).rejects.toThrow('deuxième soumission non trouvée');
    });
  });
});