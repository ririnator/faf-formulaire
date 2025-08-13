/**
 * Test pour vérifier qu'il n'y a pas de boucle infinie sur la page login
 * Suite à la correction du problème de rafraîchissement constant
 */

const request = require('supertest');
const app = require('../app');
const cheerio = require('cheerio');

describe('🔄 Login Page Infinite Loop Prevention', () => {
  test('login page should not contain auto-redirect logic', async () => {
    const response = await request(app).get('/login');
    
    expect(response.status).toBe(200);
    
    const $ = cheerio.load(response.text);
    const scriptContent = $('script[nonce]').text();
    
    // Vérifier que les fonctions problématiques de vérification automatique ont été supprimées
    expect(scriptContent).not.toContain('checkAuthStatus');
    expect(scriptContent).not.toContain('/api/auth/me');
    expect(scriptContent).not.toContain('DOMContentLoaded');
    
    // Vérifier qu'il n'y a pas de redirection automatique au chargement
    expect(scriptContent).not.toContain('window.addEventListener(\'DOMContentLoaded\'');
    
    // Les redirections POST-LOGIN sont OK (dans setTimeout après connexion réussie)
    expect(scriptContent).toContain('setTimeout'); // Redirection après connexion OK
    
    // Vérifier que le commentaire explicatif est présent
    expect(scriptContent).toContain('Auto-redirect removed to prevent infinite loop');
    
    // Vérifier que la logique de connexion normale est toujours présente
    expect(scriptContent).toContain('loginForm');
    expect(scriptContent).toContain('addEventListener');
    expect(scriptContent).toContain('clearErrors');
  });

  test('login page should be accessible without redirects when not authenticated', async () => {
    const response = await request(app).get('/login');
    
    expect(response.status).toBe(200);
    expect(response.headers.location).toBeUndefined();
    
    const $ = cheerio.load(response.text);
    expect($('title').text()).toContain('Connexion');
    expect($('form').length).toBe(1); // Le formulaire de connexion doit être présent
  });

  test('login page should handle registered parameter without issues', async () => {
    const response = await request(app).get('/login?registered=1');
    
    expect(response.status).toBe(200);
    expect(response.headers.location).toBeUndefined();
    
    const $ = cheerio.load(response.text);
    expect($('title').text()).toContain('Connexion');
  });

  test('login page should have proper form submission logic', async () => {
    const response = await request(app).get('/login');
    const $ = cheerio.load(response.text);
    const scriptContent = $('script[nonce]').text();
    
    // Vérifier que la logique de soumission est correcte
    expect(scriptContent).toContain('fetch(\'/api/auth/login\'');
    expect(scriptContent).toContain('credentials: \'include\'');
    expect(scriptContent).toContain('JSON.stringify(formData)');
    
    // Vérifier que les redirections post-login sont toujours présentes (dans le handler de formulaire)
    expect(scriptContent).toContain('if (result.user.role === \'admin\')');
    expect(scriptContent).toContain('setTimeout');
    expect(scriptContent).toContain('response.ok'); // Dans le contexte de la réponse fetch
  });

  test('login form should have proper validation without auto-redirect', async () => {
    const response = await request(app).get('/login');
    const $ = cheerio.load(response.text);
    
    // Vérifier que tous les champs nécessaires sont présents
    expect($('input[name="login"]').length).toBe(1);
    expect($('input[name="password"]').length).toBe(1);
    expect($('button[type="submit"]').length).toBe(1);
    
    // Vérifier que les conteneurs d'erreur sont présents
    expect($('.error-message').length).toBeGreaterThan(0);
    
    // Vérifier que les éléments de feedback sont présents
    expect($('.success-message').length).toBe(1);
    expect($('.loading').length).toBe(1);
  });
});