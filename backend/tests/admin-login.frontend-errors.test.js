/**
 * Tests pour valider la gestion des messages d'erreur 
 * dans la page admin-login.html
 * 
 * Tests les nouveaux paramètres d'erreur: error, timeout, security
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs').promises;

const app = require('../app');

describe('Admin Login Frontend Error Handling', () => {

  describe('Error Parameter Display', () => {
    
    test('should serve admin-login page with error parameter', async () => {
      const response = await request(app)
        .get('/admin-login?error=1')
        .expect(200);

      expect(response.text).toContain('Admin Login - FAF');
      expect(response.headers['content-type']).toMatch(/text\/html/);
    });

    test('should serve admin-login page with timeout parameter', async () => {
      const response = await request(app)
        .get('/admin-login?timeout=1')
        .expect(200);

      expect(response.text).toContain('Admin Login - FAF');
      expect(response.headers['content-type']).toMatch(/text\/html/);
    });

    test('should serve admin-login page with security parameter', async () => {
      const response = await request(app)
        .get('/admin-login?security=1')
        .expect(200);

      expect(response.text).toContain('Admin Login - FAF');
      expect(response.headers['content-type']).toMatch(/text\/html/);
    });

    test('should serve admin-login page with multiple parameters', async () => {
      const response = await request(app)
        .get('/admin-login?error=1&timeout=1')
        .expect(200);

      expect(response.text).toContain('Admin Login - FAF');
    });

  });

  describe('HTML Content Validation', () => {

    let htmlContent;

    beforeAll(async () => {
      // Lire le fichier HTML pour les tests de contenu
      const htmlPath = path.join(__dirname, '../../frontend/public/admin-login.html');
      htmlContent = await fs.readFile(htmlPath, 'utf8');
    });

    test('should contain error message div', () => {
      expect(htmlContent).toContain('id="errorMessage"');
      expect(htmlContent).toContain('class="error-message"');
    });

    test('should contain form with correct action', () => {
      expect(htmlContent).toContain('action="/admin-login"');
      expect(htmlContent).toContain('method="post"');
    });

    test('should contain JavaScript for error handling', () => {
      expect(htmlContent).toContain('URLSearchParams');
      expect(htmlContent).toContain("urlParams.get('error')");
      expect(htmlContent).toContain("urlParams.get('timeout')");
      expect(htmlContent).toContain("urlParams.get('security')");
    });

    test('should contain appropriate error messages', () => {
      expect(htmlContent).toContain('Identifiants invalides');
      expect(htmlContent).toContain('Session expirée');
      expect(htmlContent).toContain('Problème de sécurité détecté');
    });

    test('should contain navigation links', () => {
      expect(htmlContent).toContain('href="/login"');
      expect(htmlContent).toContain('href="/auth-choice"');
      expect(htmlContent).toContain('nouveau système');
    });

  });

  describe('Form Structure Validation', () => {

    test('should have proper form fields', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      // Vérifier les champs requis
      expect(html).toContain('name="username"');
      expect(html).toContain('name="password"');
      expect(html).toContain('type="password"');
      expect(html).toContain('required');
      expect(html).toContain('autocomplete="username"');
      expect(html).toContain('autocomplete="current-password"');
    });

    test('should have proper security attributes', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      // Vérifier les attributs de sécurité
      expect(html).toContain('autocomplete');
      expect(html).toContain('required');
    });

  });

  describe('JavaScript Error Handling Logic', () => {

    test('should handle error parameter in URL', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      // Vérifier que le JavaScript gère les paramètres d'URL
      expect(html).toContain("if (urlParams.get('error') === '1')");
      expect(html).toContain("errorDiv.textContent = 'Identifiants invalides");
      expect(html).toContain("errorDiv.style.display = 'block'");
    });

    test('should handle timeout parameter in URL', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain("urlParams.get('timeout') === '1'");
      expect(html).toContain("Session expirée");
    });

    test('should handle security parameter in URL', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain("urlParams.get('security') === '1'");
      expect(html).toContain("Problème de sécurité détecté");
    });

    test('should have proper conditional logic', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      // Vérifier la structure if/else if
      expect(html).toContain("if (urlParams.get('error') === '1')");
      expect(html).toContain("} else if (urlParams.get('timeout') === '1')");
      expect(html).toContain("} else if (urlParams.get('security') === '1')");
    });

  });

  describe('CSS and Styling', () => {

    test('should have error message styling', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain('.error-message');
      expect(html).toContain('display: none'); // Hidden by default
    });

    test('should have responsive design', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain('@media');
      expect(html).toContain('viewport');
    });

  });

  describe('Security and Accessibility', () => {

    test('should have proper meta tags', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain('charset="UTF-8"');
      expect(html).toContain('lang="fr"');
    });

    test('should have proper labels for accessibility', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      expect(html).toContain('<label for="username"');
      expect(html).toContain('<label for="password"');
    });

    test('should contain nonce placeholder for CSP', async () => {
      const response = await request(app)
        .get('/admin-login')
        .expect(200);

      const html = response.text;

      // Le nonce devrait être remplacé par le TemplateRenderer ou contenir le placeholder
      expect(html).toMatch(/nonce="[^"]+"|{{nonce}}/);
    });

  });

});