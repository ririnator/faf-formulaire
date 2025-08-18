const mongoose = require('mongoose');
const User = require('../models/User');

describe('User Model - Enrichissements selon DATA-MODELS.md', () => {
  beforeEach(async () => {
    // Nettoyer les données de test
    await User.deleteMany({});
  });

  describe('Champs preferences', () => {
    it('devrait créer un utilisateur avec les préférences par défaut', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const user = await User.create(userData);

      expect(user.preferences).toBeDefined();
      expect(user.preferences.sendTime).toBe('18:00');
      expect(user.preferences.timezone).toBe('Europe/Paris');
      expect(user.preferences.sendDay).toBe(5);
      expect(user.preferences.reminderSettings.firstReminder).toBe(true);
      expect(user.preferences.reminderSettings.secondReminder).toBe(true);
      expect(user.preferences.reminderSettings.reminderChannel).toBe('email');
      expect(user.preferences.emailTemplate).toBe('friendly');
    });

    it('devrait valider le format de sendTime', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        preferences: {
          sendTime: 'invalid-time'
        }
      };

      await expect(User.create(userData)).rejects.toThrow('Format heure invalide (HH:MM)');
    });

    it('devrait valider les enum pour emailTemplate', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        preferences: {
          emailTemplate: 'invalid-template'
        }
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('devrait permettre de mettre à jour les préférences', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      const newPreferences = {
        sendTime: '20:00',
        timezone: 'America/New_York',
        emailTemplate: 'professional'
      };

      await user.updatePreferences(newPreferences);

      expect(user.preferences.sendTime).toBe('20:00');
      expect(user.preferences.timezone).toBe('America/New_York');
      expect(user.preferences.emailTemplate).toBe('professional');
    });
  });

  describe('Champs statistics', () => {
    it('devrait créer un utilisateur avec les statistiques par défaut', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const user = await User.create(userData);

      expect(user.statistics).toBeDefined();
      expect(user.statistics.totalSubmissions).toBe(0);
      expect(user.statistics.totalContacts).toBe(0);
      expect(user.statistics.averageResponseRate).toBe(0);
      expect(user.statistics.joinedCycles).toBe(0);
    });

    it('devrait permettre d\'incrémenter les soumissions', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      await user.incrementSubmissions();
      await user.incrementSubmissions();

      expect(user.statistics.totalSubmissions).toBe(2);
    });

    it('devrait permettre d\'incrémenter les contacts', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      await user.incrementContacts();
      await user.incrementContacts();
      await user.incrementContacts();

      expect(user.statistics.totalContacts).toBe(3);
    });

    it('devrait mettre à jour le taux de réponse et le meilleur mois', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      await user.updateResponseRate(75, '2025-01');
      expect(user.statistics.averageResponseRate).toBe(75);
      expect(user.statistics.bestResponseMonth.month).toBe('2025-01');
      expect(user.statistics.bestResponseMonth.rate).toBe(75);

      // Mettre à jour avec un meilleur taux
      await user.updateResponseRate(90, '2025-02');
      expect(user.statistics.averageResponseRate).toBe(90);
      expect(user.statistics.bestResponseMonth.month).toBe('2025-02');
      expect(user.statistics.bestResponseMonth.rate).toBe(90);

      // Tenter avec un taux plus faible (ne devrait pas changer bestResponseMonth)
      await user.updateResponseRate(60, '2025-03');
      expect(user.statistics.averageResponseRate).toBe(60);
      expect(user.statistics.bestResponseMonth.month).toBe('2025-02');
      expect(user.statistics.bestResponseMonth.rate).toBe(90);
    });

    it('devrait permettre d\'incrémenter les cycles rejoints', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      await user.incrementJoinedCycles();
      expect(user.statistics.joinedCycles).toBe(1);
    });
  });

  describe('Champs migrationData', () => {
    it('devrait avoir migrationData avec source par défaut', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      expect(user.migrationData).toBeDefined();
      expect(user.migrationData.source).toBe('registration');
    });

    it('devrait permettre de marquer un utilisateur comme migré', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        migrationData: {
          legacyName: 'Ancien Nom',
          migratedAt: new Date(),
          source: 'migration'
        }
      });

      expect(user.migrationData.legacyName).toBe('Ancien Nom');
      expect(user.migrationData.source).toBe('migration');
      expect(user.migrationData.migratedAt).toBeDefined();
    });
  });

  describe('Méthodes d\'instance enrichies', () => {
    it('devrait retourner les paramètres de notification', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      const settings = user.getNotificationSettings();

      expect(settings).toHaveProperty('sendTime');
      expect(settings).toHaveProperty('timezone');
      expect(settings).toHaveProperty('sendDay');
      expect(settings).toHaveProperty('reminderSettings');
      expect(settings).toHaveProperty('emailTemplate');
      expect(settings).toHaveProperty('customMessage');
    });

    it('devrait inclure les nouveaux champs dans toPublicJSON', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      });

      const publicData = user.toPublicJSON();

      expect(publicData).toHaveProperty('preferences');
      expect(publicData).toHaveProperty('statistics');
      expect(publicData).toHaveProperty('migrationData');
      expect(publicData).not.toHaveProperty('password');
      
      // Vérifier la compatibilité backward avec displayName
      expect(publicData.displayName).toBe(user.username);
    });
  });

  describe('Validation des contraintes', () => {
    it('devrait valider sendDay entre 1 et 28', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        preferences: {
          sendDay: 35 // Invalid
        }
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('devrait valider la longueur maximale de customMessage', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        preferences: {
          customMessage: 'x'.repeat(501) // Trop long
        }
      };

      await expect(User.create(userData)).rejects.toThrow();
    });

    it('devrait valider les enum pour reminderChannel', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        preferences: {
          reminderSettings: {
            reminderChannel: 'invalid-channel'
          }
        }
      };

      await expect(User.create(userData)).rejects.toThrow();
    });
  });
});