/**
 * Test pour vérifier que la redirection vers /admin fonctionne après connexion
 * Suite à la correction du middleware ensureAdmin pour supporter le nouveau système d'auth
 */

const request = require('supertest');
const app = require('../app');
const User = require('../models/User');
describe('🔄 Admin Redirect After Login', () => {
  let adminUser;

  beforeEach(async () => {
    // Nettoyer la base et créer un utilisateur admin de test
    await User.deleteMany({});
    
    adminUser = await User.create({
      username: 'testadmin',
      email: 'admin@test.com',
      password: 'AdminPass123!',
      role: 'admin'
    });
  });

  afterEach(async () => {
    await User.deleteMany({});
  });

  test('login should create session with admin user', async () => {
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        login: 'testadmin',
        password: 'AdminPass123!'
      })
      .expect(200);

    expect(loginResponse.body.message).toBe('Connexion réussie');
    expect(loginResponse.body.user.role).toBe('admin');
    expect(loginResponse.body.user.username).toBe('testadmin');
    
    // Vérifier que les cookies de session sont définis
    expect(loginResponse.headers['set-cookie']).toBeDefined();
  });

  test('admin route should be accessible after login', async () => {
    // D'abord se connecter
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        login: 'testadmin',
        password: 'AdminPass123!'
      })
      .expect(200);

    // Extraire les cookies
    const cookies = loginResponse.headers['set-cookie'];

    // Ensuite accéder à /admin avec les cookies de session
    const adminResponse = await request(app)
      .get('/admin')
      .set('Cookie', cookies)
      .expect(200);

    // Vérifier que la page admin est retournée (pas une redirection)
    expect(adminResponse.text).toContain('<title>'); // Page HTML valide
    expect(adminResponse.text).toContain('admin'); // Contenu admin
  });

  test('dashboard route should redirect to admin after login', async () => {
    // D'abord se connecter
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        login: 'testadmin',
        password: 'AdminPass123!'
      })
      .expect(200);

    // Extraire les cookies
    const cookies = loginResponse.headers['set-cookie'];

    // Ensuite accéder à /dashboard avec les cookies de session
    const dashboardResponse = await request(app)
      .get('/dashboard')
      .set('Cookie', cookies)
      .expect(302); // Redirection

    expect(dashboardResponse.headers.location).toBe('/admin');
  });

  test('admin route should redirect to login when not authenticated', async () => {
    const response = await request(app)
      .get('/admin')
      .expect(302); // Redirection vers login

    expect(response.headers.location).toBe('/admin-login');
  });

  test('regular user should not access admin routes', async () => {
    // Créer un utilisateur normal
    const regularUser = await User.create({
      username: 'testuser',
      email: 'user@test.com',
      password: 'UserPass123!',
      role: 'user' // Rôle normal, pas admin
    });

    // Se connecter en tant qu'utilisateur normal
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        login: 'testuser',
        password: 'UserPass123!'
      })
      .expect(200);

    const cookies = loginResponse.headers['set-cookie'];

    // Essayer d'accéder à /admin (devrait être refusé)
    const adminResponse = await request(app)
      .get('/admin')
      .set('Cookie', cookies)
      .expect(302); // Redirection refusée

    expect(adminResponse.headers.location).toBe('/admin-login');
  });
});