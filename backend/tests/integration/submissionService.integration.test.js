const mongoose = require('mongoose');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./setup-integration');

const SubmissionService = require('../../services/submissionService');
const Submission = require('../../models/Submission');
const User = require('../../models/User');
const Invitation = require('../../models/Invitation');

describe('SubmissionService - Tests d\'intégration', () => {
  
  let submissionService;
  let testUser1, testUser2, testUser3, testUser4;
  const currentMonth = new Date().toISOString().slice(0, 7);
  const lastMonth = new Date(new Date().setMonth(new Date().getMonth() - 1))
    .toISOString().slice(0, 7);

  beforeAll(async () => {
    await setupTestDatabase();
    
    

    // Initialiser le service avec config de test
    const config = {
      maxTextResponses: 8,
      maxPhotoResponses: 5,
      minCompletionRate: 50,
      maxQuestionTextLength: 500,
      maxAnswerTextLength: 10000,
      maxPhotoCaptionLength: 500,
      maxFreeTextLength: 5000
    };
    submissionService = new SubmissionService(config);
  });

  beforeEach(async () => {
    await cleanupDatabase();

    // Créer des utilisateurs de test avec des profils variés
    testUser1 = await User.create({
      username: 'alice',
      email: 'alice@test.com',
      password: 'password123',
      profile: {
        firstName: 'Alice',
        lastName: 'Johnson'
      }
    });

    testUser2 = await User.create({
      username: 'bob',
      email: 'bob@test.com',
      password: 'password123',
      profile: {
        firstName: 'Bob',
        lastName: 'Smith'
      }
    });

    testUser3 = await User.create({
      username: 'charlie',
      email: 'charlie@test.com',
      password: 'password123',
      profile: {
        firstName: 'Charlie',
        lastName: 'Brown'
      }
    });

    testUser4 = await User.create({
      username: 'diana',
      email: 'diana@test.com',
      password: 'password123',
      profile: {
        firstName: 'Diana',
        lastName: 'Wilson'
      }
    });
  });

  afterAll(async () => {
    await teardownTestDatabase();
    
    
  });

  describe('createSubmission', () => {
    it('devrait créer une soumission complète avec différents types de réponses', async () => {
      const submissionData = {
        responses: [
          {
            questionId: 'age',
            type: 'radio',
            answer: '25-30'
          },
          {
            questionId: 'hobbies',
            type: 'text',
            answer: 'J\'aime la lecture, le cinéma et les voyages'
          },
          {
            questionId: 'photo_profile',
            type: 'photo',
            photoUrl: 'https://res.cloudinary.com/test/image/upload/profile.jpg',
            photoCaption: 'Ma photo de profil'
          },
          {
            questionId: 'favorite_color',
            type: 'radio',
            answer: 'Bleu'
          }
        ],
        freeText: 'Je suis passionné par la technologie et j\'adore rencontrer de nouvelles personnes.',
        month: currentMonth
      };

      const metadata = {
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0'
      };

      const submission = await submissionService.createSubmission(
        testUser1._id,
        submissionData,
        metadata
      );

      expect(submission).toBeDefined();
      expect(submission.userId.toString()).toBe(testUser1._id.toString());
      expect(submission.responses).toHaveLength(4);
      expect(submission.freeText).toBe(submissionData.freeText);
      expect(submission.formVersion).toBe('v2');
      expect(submission.completionRate).toBeGreaterThan(0);
      expect(submission.isComplete).toBeDefined();
    });

    it('devrait empêcher les soumissions multiples pour le même mois', async () => {
      const submissionData = {
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Première soumission' }
        ],
        month: currentMonth
      };

      await submissionService.createSubmission(testUser1._id, submissionData);

      const duplicateData = {
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Tentative de doublon' }
        ],
        month: currentMonth
      };

      await expect(
        submissionService.createSubmission(testUser1._id, duplicateData)
      ).rejects.toThrow(/déjà soumis une réponse pour/);
    });

    it('devrait valider les limites de réponses par type', async () => {
      const tooManyTextResponses = Array.from({ length: 10 }, (_, i) => ({
        questionId: `text_${i}`,
        type: 'text',
        answer: `Réponse ${i}`
      }));

      await expect(
        submissionService.createSubmission(testUser1._id, {
          responses: tooManyTextResponses,
          month: currentMonth
        })
      ).rejects.toThrow('Maximum 8 réponses textuelles autorisées');
    });

    it('devrait lier une soumission à une invitation', async () => {
      // Créer une invitation d'abord
      const invitation = await Invitation.create({
        fromUserId: testUser2._id,
        toEmail: testUser1.email,
        toUserId: testUser1._id,
        month: currentMonth,
        token: 'invitation-token-123',
        status: 'opened'
      });

      const submissionData = {
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Réponse via invitation' }
        ],
        month: currentMonth,
        invitationToken: 'invitation-token-123'
      };

      const submission = await submissionService.createSubmission(
        testUser1._id,
        submissionData
      );

      expect(submission).toBeDefined();

      // Vérifier que l'invitation est marquée comme soumise
      const updatedInvitation = await Invitation.findById(invitation._id);
      expect(updatedInvitation.status).toBe('submitted');
    });

    it('devrait mettre à jour les statistiques utilisateur', async () => {
      const submissionData = {
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Test stats' }
        ],
        month: currentMonth
      };

      await submissionService.createSubmission(testUser1._id, submissionData);

      // Vérifier que les métadonnées utilisateur sont mises à jour
      const updatedUser = await User.findById(testUser1._id);
      expect(updatedUser.metadata.responseCount).toBe(1);
      expect(updatedUser.metadata.lastActive).toBeDefined();
    });
  });

  describe('updateSubmission', () => {
    let existingSubmission;

    beforeEach(async () => {
      existingSubmission = await submissionService.createSubmission(
        testUser1._id,
        {
          responses: [
            { questionId: 'original', type: 'text', answer: 'Réponse originale' }
          ],
          freeText: 'Texte original',
          month: currentMonth
        }
      );
    });

    it('devrait permettre la modification dans les 24h', async () => {
      const updateData = {
        responses: [
          { questionId: 'original', type: 'text', answer: 'Réponse modifiée' },
          { questionId: 'new', type: 'text', answer: 'Nouvelle réponse' }
        ],
        freeText: 'Texte modifié'
      };

      const updated = await submissionService.updateSubmission(
        testUser1._id,
        currentMonth,
        updateData
      );

      expect(updated.responses).toHaveLength(2);
      expect(updated.responses[0].answer).toBe('Réponse modifiée');
      expect(updated.freeText).toBe('Texte modifié');
    });

    it('devrait empêcher la modification après 24h', async () => {
      // Simuler une soumission ancienne
      existingSubmission.submittedAt = new Date(Date.now() - 25 * 60 * 60 * 1000);
      await existingSubmission.save();

      await expect(
        submissionService.updateSubmission(testUser1._id, currentMonth, {
          responses: [{ questionId: 'q1', type: 'text', answer: 'Tentative' }]
        })
      ).rejects.toThrow('Modification non autorisée après 24h');
    });
  });

  describe('compareSubmissions', () => {
    let submission1, submission2;

    beforeEach(async () => {
      // Créer des soumissions avec des réponses communes et différentes
      submission1 = await submissionService.createSubmission(
        testUser1._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '25-30' },
            { questionId: 'hobbies', type: 'text', answer: 'lecture, cinéma, sport' },
            { questionId: 'music', type: 'radio', answer: 'Rock' },
            { questionId: 'travel', type: 'text', answer: 'J\'adore voyager en Europe' }
          ],
          freeText: 'Je suis une personne sociale et curieuse.',
          month: currentMonth
        }
      );

      submission2 = await submissionService.createSubmission(
        testUser2._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '25-30' }, // Identique
            { questionId: 'hobbies', type: 'text', answer: 'lecture, voyage, cuisine' }, // Partiellement similaire
            { questionId: 'music', type: 'radio', answer: 'Jazz' }, // Différent
            { questionId: 'travel', type: 'text', answer: 'Je préfère les voyages en Asie' } // Différent
          ],
          freeText: 'Je suis plutôt introverti mais j\'aime découvrir.',
          month: currentMonth
        }
      );
    });

    it('devrait comparer deux soumissions et calculer la compatibilité', async () => {
      const comparison = await submissionService.compareSubmissions(
        testUser1._id,
        testUser2._id,
        currentMonth
      );

      expect(comparison).toBeDefined();
      expect(comparison.user1.username).toBe(testUser1.username);
      expect(comparison.user2.username).toBe(testUser2.username);
      expect(comparison.analysis).toBeDefined();
      expect(comparison.compatibility).toBeDefined();

      // Vérifier l'analyse
      expect(comparison.analysis.commonQuestions).toBe(4);
      expect(comparison.analysis.matches.length).toBeGreaterThanOrEqual(1); // Age identique
      expect(comparison.analysis.score).toBeGreaterThan(0);

      // Vérifier la compatibilité
      expect(comparison.compatibility.overallScore).toBeDefined();
      expect(comparison.compatibility.details.responseAlignment).toBeGreaterThan(0);
      expect(comparison.compatibility.matches.length).toBeGreaterThanOrEqual(1);
    });

    it('devrait anonymiser les données si demandé', async () => {
      const comparison = await submissionService.compareSubmissions(
        testUser1._id,
        testUser2._id,
        currentMonth,
        { anonymize: true }
      );

      expect(comparison.user1.username).toBe('Utilisateur anonyme');
      expect(comparison.user2.username).toBe('Utilisateur anonyme');
      expect(comparison.metadata.anonymized).toBe(true);
    });

    it('devrait gérer les soumissions manquantes', async () => {
      await expect(
        submissionService.compareSubmissions(
          testUser1._id,
          testUser3._id, // Pas de soumission
          currentMonth
        )
      ).rejects.toThrow('deuxième soumission non trouvée');
    });
  });

  describe('findMatches', () => {
    beforeEach(async () => {
      // Créer plusieurs soumissions avec des degrés de compatibilité variables
      const baseResponses = [
        { questionId: 'age', type: 'radio', answer: '25-30' },
        { questionId: 'location', type: 'radio', answer: 'Paris' }
      ];

      // Utilisateur 1 : profil de référence
      await submissionService.createSubmission(testUser1._id, {
        responses: [
          ...baseResponses,
          { questionId: 'hobbies', type: 'text', answer: 'lecture, cinéma, sport' },
          { questionId: 'personality', type: 'radio', answer: 'Extraverti' }
        ],
        freeText: 'J\'aime rencontrer de nouvelles personnes.',
        month: currentMonth
      });

      // Utilisateur 2 : très compatible
      await submissionService.createSubmission(testUser2._id, {
        responses: [
          ...baseResponses,
          { questionId: 'hobbies', type: 'text', answer: 'lecture, cinéma, musique' },
          { questionId: 'personality', type: 'radio', answer: 'Extraverti' }
        ],
        freeText: 'J\'adore les activités sociales.',
        month: currentMonth
      });

      // Utilisateur 3 : moyennement compatible
      await submissionService.createSubmission(testUser3._id, {
        responses: [
          ...baseResponses,
          { questionId: 'hobbies', type: 'text', answer: 'sport, nature, randonnée' },
          { questionId: 'personality', type: 'radio', answer: 'Ambivert' }
        ],
        freeText: 'J\'aime l\'aventure et les défis.',
        month: currentMonth
      });

      // Utilisateur 4 : peu compatible
      await submissionService.createSubmission(testUser4._id, {
        responses: [
          { questionId: 'age', type: 'radio', answer: '35-40' }, // Différent
          { questionId: 'location', type: 'radio', answer: 'Lyon' }, // Différent
          { questionId: 'hobbies', type: 'text', answer: 'jardinage, cuisine, lecture' },
          { questionId: 'personality', type: 'radio', answer: 'Introverti' }
        ],
        freeText: 'Je préfère les soirées calmes à la maison.',
        month: currentMonth
      });
    });

    it('devrait trouver des correspondances triées par compatibilité', async () => {
      const matches = await submissionService.findMatches(
        testUser1._id,
        currentMonth,
        { minCompatibility: 50 }
      );

      expect(matches.length).toBeGreaterThan(0);
      expect(matches.length).toBeLessThanOrEqual(3); // Exclut testUser1

      // Vérifier que les résultats sont triés par score décroissant
      for (let i = 1; i < matches.length; i++) {
        expect(matches[i-1].compatibility.overallScore)
          .toBeGreaterThanOrEqual(matches[i].compatibility.overallScore);
      }

      // Le premier match devrait être le plus compatible (testUser2)
      expect(matches[0].user.username).toBe('bob');
      expect(matches[0].compatibility.overallScore).toBeGreaterThan(60);
    });

    it('devrait respecter la limite de compatibilité minimale', async () => {
      const strictMatches = await submissionService.findMatches(
        testUser1._id,
        currentMonth,
        { minCompatibility: 80 }
      );

      // Seuls les très compatibles devraient être inclus
      expect(strictMatches.length).toBeLessThanOrEqual(1);
      if (strictMatches.length > 0) {
        expect(strictMatches[0].compatibility.overallScore).toBeGreaterThanOrEqual(80);
      }
    });

    it('devrait exclure certains utilisateurs si demandé', async () => {
      const matches = await submissionService.findMatches(
        testUser1._id,
        currentMonth,
        { excludeUserIds: [testUser2._id] }
      );

      expect(matches.every(m => m.user._id.toString() !== testUser2._id.toString()))
        .toBe(true);
    });

    it('devrait respecter la limite de résultats', async () => {
      const limitedMatches = await submissionService.findMatches(
        testUser1._id,
        currentMonth,
        { limit: 2 }
      );

      expect(limitedMatches.length).toBeLessThanOrEqual(2);
    });
  });

  describe('getSubmissions avec filtres avancés', () => {
    beforeEach(async () => {
      // Créer des soumissions avec différents taux de complétion et dates
      const submissionsData = [
        {
          userId: testUser1._id,
          month: currentMonth,
          responses: Array.from({ length: 5 }, (_, i) => ({
            questionId: `q${i}`,
            type: 'text',
            answer: `Answer ${i}`
          })),
          completionRate: 100,
          isComplete: true
        },
        {
          userId: testUser2._id,
          month: currentMonth,
          responses: Array.from({ length: 3 }, (_, i) => ({
            questionId: `q${i}`,
            type: 'text',
            answer: `Answer ${i}`
          })),
          completionRate: 60,
          isComplete: false
        },
        {
          userId: testUser3._id,
          month: lastMonth,
          responses: Array.from({ length: 4 }, (_, i) => ({
            questionId: `q${i}`,
            type: 'text',
            answer: `Answer ${i}`
          })),
          completionRate: 80,
          isComplete: true
        }
      ];

      await Submission.insertMany(submissionsData);
    });

    it('devrait filtrer par mois', async () => {
      const result = await submissionService.getSubmissions(
        { month: currentMonth }
      );

      expect(result.submissions.length).toBe(2);
      expect(result.submissions.every(s => s.month === currentMonth)).toBe(true);
    });

    it('devrait filtrer par taux de complétion minimum', async () => {
      const result = await submissionService.getSubmissions(
        { minCompletionRate: 80 }
      );

      expect(result.submissions.every(s => s.completionRate >= 80)).toBe(true);
    });

    it('devrait filtrer par statut de complétion', async () => {
      const result = await submissionService.getSubmissions(
        { isComplete: true }
      );

      expect(result.submissions.every(s => s.isComplete === true)).toBe(true);
    });

    it('devrait calculer les statistiques globales', async () => {
      const result = await submissionService.getSubmissions();

      expect(result.stats.basic.totalSubmissions).toBe(3);
      expect(result.stats.basic.completeSubmissions).toBe(2);
      expect(result.stats.basic.uniqueUsersCount).toBe(3);
      expect(result.stats.basic.avgCompletionRate).toBeGreaterThan(0);
    });
  });

  describe('Algorithmes de compatibilité', () => {
    it('devrait calculer correctement la similarité des réponses radio', async () => {
      const response1 = { type: 'radio', answer: 'Oui' };
      const response2 = { type: 'radio', answer: 'Oui' };
      const response3 = { type: 'radio', answer: 'Non' };

      const similarity1 = submissionService.calculateResponseSimilarity(response1, response2);
      const similarity2 = submissionService.calculateResponseSimilarity(response1, response3);

      expect(similarity1).toBe(1.0); // Identique
      expect(similarity2).toBe(0.0); // Différent
    });

    it('devrait calculer la similarité des réponses textuelles', async () => {
      const response1 = {
        type: 'text',
        answer: 'J\'aime la lecture et le cinéma'
      };
      const response2 = {
        type: 'text',
        answer: 'J\'adore lire et regarder des films'
      };
      const response3 = {
        type: 'text',
        answer: 'Je préfère le sport et la musique'
      };

      const similarity1 = submissionService.calculateResponseSimilarity(response1, response2);
      const similarity2 = submissionService.calculateResponseSimilarity(response1, response3);

      expect(similarity1).toBeGreaterThan(0.1); // Quelques mots communs
      expect(similarity2).toBeLessThan(similarity1); // Moins de mots communs
    });

    it('devrait analyser le style de communication', async () => {
      const text1 = 'Je suis quelqu\'un de très sociable qui aime rencontrer de nouvelles personnes et découvrir de nouveaux endroits.';
      const text2 = 'J\'adore les interactions sociales et explorer différents lieux avec des amis.';
      const text3 = 'Non.';

      const analysis1 = submissionService.analyzeCommunicationStyle(text1, text2);
      const analysis2 = submissionService.analyzeCommunicationStyle(text1, text3);

      expect(analysis1.score).toBeGreaterThan(analysis2.score);
      expect(analysis1.details.vocabularySimilarity).toBeGreaterThan(0);
      expect(analysis1.details.lengthSimilarity).toBeGreaterThan(analysis2.details.lengthSimilarity);
    });
  });

  describe('Scénarios d\'intégration complets', () => {
    it('Scénario 1: Système de matching complet avec recommandations', async () => {
      // 1. Créer un profil utilisateur détaillé
      const detailedProfile = await submissionService.createSubmission(
        testUser1._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '25-30' },
            { questionId: 'location', type: 'radio', answer: 'Paris' },
            { questionId: 'education', type: 'radio', answer: 'Master' },
            { questionId: 'hobbies', type: 'text', answer: 'lecture, cinéma, voyages, photographie' },
            { questionId: 'personality', type: 'radio', answer: 'Extraverti' },
            { questionId: 'values', type: 'text', answer: 'famille, authenticité, créativité, aventure' },
            { questionId: 'goals', type: 'text', answer: 'développer ma carrière, voyager plus, apprendre de nouvelles langues' }
          ],
          freeText: 'Je suis passionné par la découverte de nouvelles cultures et j\'aime partager des expériences enrichissantes avec des personnes ouvertes d\'esprit.',
          month: currentMonth
        }
      );

      // 2. Créer plusieurs profils potentiels avec des niveaux de compatibilité variés
      const potentialMatches = [
        {
          user: testUser2,
          responses: [
            { questionId: 'age', type: 'radio', answer: '25-30' },
            { questionId: 'location', type: 'radio', answer: 'Paris' },
            { questionId: 'education', type: 'radio', answer: 'Master' },
            { questionId: 'hobbies', type: 'text', answer: 'lecture, théâtre, voyages, art' },
            { questionId: 'personality', type: 'radio', answer: 'Extraverti' },
            { questionId: 'values', type: 'text', answer: 'famille, créativité, découverte, authenticité' },
            { questionId: 'goals', type: 'text', answer: 'explorer de nouveaux pays, développer ma créativité' }
          ],
          freeText: 'J\'adore explorer le monde et rencontrer des gens avec qui partager des aventures authentiques.',
          expectedCompatibility: 85
        },
        {
          user: testUser3,
          responses: [
            { questionId: 'age', type: 'radio', answer: '30-35' },
            { questionId: 'location', type: 'radio', answer: 'Lyon' },
            { questionId: 'education', type: 'radio', answer: 'Licence' },
            { questionId: 'hobbies', type: 'text', answer: 'sport, nature, lecture' },
            { questionId: 'personality', type: 'radio', answer: 'Ambivert' },
            { questionId: 'values', type: 'text', answer: 'équilibre, nature, simplicité' },
            { questionId: 'goals', type: 'text', answer: 'avoir un mode de vie équilibré, être proche de la nature' }
          ],
          freeText: 'Je cherche l\'équilibre entre vie professionnelle et personnelle.',
          expectedCompatibility: 60
        }
      ];

      // 3. Créer les soumissions pour les matches potentiels
      for (const match of potentialMatches) {
        await submissionService.createSubmission(
          match.user._id,
          {
            responses: match.responses,
            freeText: match.freeText,
            month: currentMonth
          }
        );
      }

      // 4. Trouver les correspondances
      const matches = await submissionService.findMatches(
        testUser1._id,
        currentMonth,
        { minCompatibility: 50 }
      );

      expect(matches.length).toBe(2);

      // 5. Vérifier que les scores de compatibilité sont cohérents
      const bestMatch = matches.find(m => m.user.username === 'bob');
      const okayMatch = matches.find(m => m.user.username === 'charlie');

      expect(bestMatch.compatibility.overallScore)
        .toBeGreaterThan(okayMatch.compatibility.overallScore);

      // 6. Analyser les détails de compatibilité du meilleur match
      expect(bestMatch.compatibility.matches.length).toBeGreaterThan(2);
      expect(bestMatch.compatibility.recommendations.length).toBeGreaterThan(0);

      // 7. Comparer en détail les deux meilleures correspondances
      const detailedComparison = await submissionService.compareSubmissions(
        testUser1._id,
        bestMatch.user._id,
        currentMonth
      );

      expect(detailedComparison.compatibility.overallScore).toBeGreaterThan(70);
      expect(detailedComparison.analysis.commonQuestions).toBe(7);
    });

    it('Scénario 2: Gestion complète du cycle de vie d\'une soumission', async () => {
      // 1. Créer une invitation
      const invitation = await Invitation.create({
        fromUserId: testUser2._id,
        toEmail: testUser1.email,
        toUserId: testUser1._id,
        month: currentMonth,
        token: 'lifecycle-token-123',
        status: 'opened'
      });

      // 2. Créer une soumission partielle
      const initialSubmission = await submissionService.createSubmission(
        testUser1._id,
        {
          responses: [
            { questionId: 'name', type: 'text', answer: 'Alice' },
            { questionId: 'age', type: 'radio', answer: '25-30' }
          ],
          month: currentMonth,
          invitationToken: 'lifecycle-token-123'
        }
      );

      expect(initialSubmission.completionRate).toBeLessThan(100);
      expect(initialSubmission.isComplete).toBe(false);

      // 3. Modifier la soumission pour l'enrichir
      const updatedSubmission = await submissionService.updateSubmission(
        testUser1._id,
        currentMonth,
        {
          responses: [
            { questionId: 'name', type: 'text', answer: 'Alice Johnson' },
            { questionId: 'age', type: 'radio', answer: '25-30' },
            { questionId: 'location', type: 'radio', answer: 'Paris' },
            { questionId: 'hobbies', type: 'text', answer: 'lecture, cinéma' },
            { questionId: 'personality', type: 'radio', answer: 'Extraverti' }
          ],
          freeText: 'J\'ai complété ma soumission avec plus de détails.'
        }
      );

      expect(updatedSubmission.responses.length).toBe(5);
      expect(updatedSubmission.completionRate).toBeGreaterThan(80);
      expect(updatedSubmission.freeText).toContain('complété');

      // 4. Vérifier que l'invitation est marquée comme soumise
      const finalInvitation = await Invitation.findById(invitation._id);
      expect(finalInvitation.status).toBe('submitted');

      // 5. Créer d'autres soumissions pour tester le matching
      await submissionService.createSubmission(testUser2._id, {
        responses: [
          { questionId: 'name', type: 'text', answer: 'Bob' },
          { questionId: 'age', type: 'radio', answer: '25-30' },
          { questionId: 'location', type: 'radio', answer: 'Paris' },
          { questionId: 'hobbies', type: 'text', answer: 'cinéma, sport' },
          { questionId: 'personality', type: 'radio', answer: 'Extraverti' }
        ],
        month: currentMonth
      });

      // 6. Tester le matching avec la soumission complétée
      const matches = await submissionService.findMatches(
        testUser1._id,
        currentMonth
      );

      expect(matches.length).toBe(1);
      expect(matches[0].user.username).toBe('bob');
      expect(matches[0].compatibility.overallScore).toBeGreaterThan(60);

      // 7. Obtenir les statistiques globales
      const stats = await submissionService.getSubmissionStats();

      expect(stats.basic.totalSubmissions).toBe(2);
      expect(stats.basic.uniqueUsersCount).toBe(2);
      expect(stats.monthly.find(m => m._id === currentMonth)).toBeDefined();
    });

    it('Scénario 3: Analyse de compatibilité multi-dimensionnelle', async () => {
      // Créer des profils avec des dimensions de compatibilité spécifiques
      const profiles = [
        {
          user: testUser1,
          name: 'Alice',
          dimensions: {
            social: 'extraverti',
            interests: 'culture',
            lifestyle: 'urbain',
            values: 'aventure'
          }
        },
        {
          user: testUser2,
          name: 'Bob',
          dimensions: {
            social: 'extraverti',
            interests: 'culture',
            lifestyle: 'urbain',
            values: 'stabilité'
          }
        },
        {
          user: testUser3,
          name: 'Charlie',
          dimensions: {
            social: 'introverti',
            interests: 'nature',
            lifestyle: 'rural',
            values: 'simplicité'
          }
        }
      ];

      // Créer les soumissions basées sur ces dimensions
      for (const profile of profiles) {
        await submissionService.createSubmission(profile.user._id, {
          responses: [
            { questionId: 'personality', type: 'radio', answer: profile.dimensions.social },
            { questionId: 'interests', type: 'radio', answer: profile.dimensions.interests },
            { questionId: 'lifestyle', type: 'radio', answer: profile.dimensions.lifestyle },
            { questionId: 'values', type: 'radio', answer: profile.dimensions.values },
            { questionId: 'bio', type: 'text', answer: `Je suis ${profile.name} et j'aime le ${profile.dimensions.interests}` }
          ],
          freeText: `Mon style de vie est plutôt ${profile.dimensions.lifestyle} et je suis quelqu'un de ${profile.dimensions.social}.`,
          month: currentMonth
        });
      }

      // Analyser les compatibilités
      const aliceBobComparison = await submissionService.compareSubmissions(
        testUser1._id, // Alice
        testUser2._id, // Bob
        currentMonth
      );

      const aliceCharlieComparison = await submissionService.compareSubmissions(
        testUser1._id, // Alice
        testUser3._id, // Charlie
        currentMonth
      );

      // Alice et Bob devraient être plus compatibles (3 dimensions communes)
      expect(aliceBobComparison.compatibility.overallScore)
        .toBeGreaterThan(aliceCharlieComparison.compatibility.overallScore);

      // Vérifier les détails de compatibilité
      expect(aliceBobComparison.compatibility.matches.length)
        .toBeGreaterThan(aliceCharlieComparison.compatibility.matches.length);

      // Tester le système de recommandations
      expect(aliceBobComparison.compatibility.recommendations.length).toBeGreaterThan(0);
      
      const highMatchRecommendation = aliceBobComparison.compatibility.recommendations
        .find(r => r.type === 'high_match' || r.type === 'good_match');
      
      expect(highMatchRecommendation).toBeDefined();
    });
  });
});