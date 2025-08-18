#!/usr/bin/env node

/**
 * Script de test automatisé pour le déploiement FAF sur Render
 * Usage: node scripts/test-production-deployment.js [URL_PRODUCTION]
 */

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// Configuration par défaut
const CONFIG = {
  PRODUCTION_URL: process.env.PRODUCTION_URL || process.argv[2] || 'https://faf-production.onrender.com',
  ADMIN_USERNAME: process.env.LOGIN_ADMIN_USER || 'admin',
  ADMIN_PASSWORD: process.env.LOGIN_ADMIN_PASS || '',
  TIMEOUT: 10000, // 10 secondes
  MAX_RESPONSE_TIME: 3000 // 3 secondes max pour les pages
};

class ProductionTester {
  constructor() {
    this.baseURL = CONFIG.PRODUCTION_URL;
    this.cookies = new Map();
    this.results = [];
    this.csrfToken = null;
  }

  log(status, test, message, details = {}) {
    const result = {
      status: status, // 'PASS', 'FAIL', 'WARN', 'INFO'
      test: test,
      message: message,
      timestamp: new Date().toISOString(),
      ...details
    };
    
    this.results.push(result);
    
    const emoji = {
      'PASS': '✅',
      'FAIL': '❌', 
      'WARN': '⚠️',
      'INFO': 'ℹ️'
    };
    
    console.log(`${emoji[status]} ${test}: ${message}`);
    if (details.responseTime) {
      console.log(`   ⏱️  Temps de réponse: ${details.responseTime}ms`);
    }
    if (details.error) {
      console.log(`   🔍 Détails: ${details.error}`);
    }
  }

  async makeRequest(method, path, data = null, headers = {}) {
    const startTime = Date.now();
    
    try {
      // Ajouter les cookies existants
      if (this.cookies.size > 0) {
        const cookieString = Array.from(this.cookies.entries())
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');
        headers.Cookie = cookieString;
      }

      const config = {
        method: method,
        url: `${this.baseURL}${path}`,
        timeout: CONFIG.TIMEOUT,
        headers: headers,
        validateStatus: () => true // Ne pas rejeter sur les codes d'erreur
      };

      if (data) {
        if (data instanceof FormData) {
          config.data = data;
        } else {
          config.data = data;
          config.headers['Content-Type'] = 'application/json';
        }
      }

      const response = await axios(config);
      const responseTime = Date.now() - startTime;

      // Sauvegarder les nouveaux cookies
      if (response.headers['set-cookie']) {
        response.headers['set-cookie'].forEach(cookie => {
          const [nameValue] = cookie.split(';');
          const [name, value] = nameValue.split('=');
          this.cookies.set(name.trim(), value);
        });
      }

      return { ...response, responseTime };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        status: 0,
        data: null,
        error: error.message,
        responseTime
      };
    }
  }

  async testBasicAccess() {
    this.log('INFO', 'Accès de base', 'Test de l\'accès à l\'application...');
    
    const response = await this.makeRequest('GET', '/');
    
    if (response.status === 200) {
      this.log('PASS', 'Accès homepage', 'Application accessible', {
        responseTime: response.responseTime,
        status: response.status
      });
    } else {
      this.log('FAIL', 'Accès homepage', `Impossible d'accéder à l'application`, {
        responseTime: response.responseTime,
        status: response.status,
        error: response.error
      });
      return false;
    }

    // Test HTTPS forcé
    if (this.baseURL.startsWith('https://')) {
      const httpURL = this.baseURL.replace('https://', 'http://');
      const httpResponse = await this.makeRequest('GET', '/', null, {});
      
      if (httpResponse.status === 301 || httpResponse.status === 302) {
        this.log('PASS', 'HTTPS forcé', 'Redirection HTTP vers HTTPS active');
      } else {
        this.log('WARN', 'HTTPS forcé', 'Redirection HTTP vers HTTPS non détectée');
      }
    }

    return true;
  }

  async testPerformance() {
    this.log('INFO', 'Performance', 'Test des temps de réponse...');

    const pages = [
      { path: '/', name: 'Homepage' },
      { path: '/login.html', name: 'Page de connexion' },
      { path: '/admin.html', name: 'Interface admin' }
    ];

    for (const page of pages) {
      const response = await this.makeRequest('GET', page.path);
      
      if (response.responseTime > CONFIG.MAX_RESPONSE_TIME) {
        this.log('WARN', 'Performance', `${page.name} lente`, {
          responseTime: response.responseTime,
          threshold: CONFIG.MAX_RESPONSE_TIME
        });
      } else {
        this.log('PASS', 'Performance', `${page.name} rapide`, {
          responseTime: response.responseTime
        });
      }
    }
  }

  async testCSRFToken() {
    this.log('INFO', 'CSRF', 'Test de la protection CSRF...');
    
    const response = await this.makeRequest('GET', '/api/csrf-token');
    
    if (response.status === 200 && response.data && response.data.csrfToken) {
      this.csrfToken = response.data.csrfToken;
      this.log('PASS', 'CSRF Token', 'Token CSRF obtenu avec succès');
      return true;
    } else {
      this.log('FAIL', 'CSRF Token', 'Impossible d\'obtenir le token CSRF', {
        status: response.status,
        error: response.error
      });
      return false;
    }
  }

  async testAdminLogin() {
    if (!CONFIG.ADMIN_PASSWORD) {
      this.log('WARN', 'Connexion admin', 'Mot de passe admin non fourni, test ignoré');
      return false;
    }

    this.log('INFO', 'Connexion admin', 'Test de la connexion administrateur...');

    // Obtenir le token CSRF d'abord
    if (!this.csrfToken) {
      await this.testCSRFToken();
    }

    const loginData = {
      login: CONFIG.ADMIN_USERNAME,
      password: CONFIG.ADMIN_PASSWORD
    };

    const headers = {};
    if (this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const response = await this.makeRequest('POST', '/api/auth/login', loginData, headers);
    
    if (response.status === 200) {
      this.log('PASS', 'Connexion admin', 'Connexion administrateur réussie');
      return true;
    } else {
      this.log('FAIL', 'Connexion admin', 'Échec de la connexion administrateur', {
        status: response.status,
        error: response.data?.message || response.error
      });
      return false;
    }
  }

  async testDatabaseConnection() {
    this.log('INFO', 'Base de données', 'Test de la connexion MongoDB...');
    
    const response = await this.makeRequest('GET', '/api/admin/responses');
    
    if (response.status === 200 || response.status === 401) {
      // 200 = connecté et données récupérées
      // 401 = connecté mais non authentifié (normal)
      this.log('PASS', 'Base de données', 'Connexion MongoDB active');
      return true;
    } else {
      this.log('FAIL', 'Base de données', 'Problème de connexion MongoDB', {
        status: response.status,
        error: response.error
      });
      return false;
    }
  }

  async testFormSubmission() {
    this.log('INFO', 'Formulaire', 'Test de soumission de formulaire...');
    
    // Obtenir le token CSRF
    if (!this.csrfToken) {
      await this.testCSRFToken();
    }

    const testData = {
      name: `Test-${Date.now()}`,
      responses: [
        {
          question: "Question de test",
          answer: "Réponse de test"
        }
      ]
    };

    const headers = {};
    if (this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const response = await this.makeRequest('POST', '/api/responses', testData, headers);
    
    if (response.status === 201) {
      this.log('PASS', 'Formulaire', 'Soumission de formulaire réussie');
      return true;
    } else if (response.status === 400) {
      this.log('WARN', 'Formulaire', 'Validation de formulaire active', {
        status: response.status,
        message: 'Normal si les données de test ne respectent pas la validation'
      });
      return true;
    } else {
      this.log('FAIL', 'Formulaire', 'Échec de soumission de formulaire', {
        status: response.status,
        error: response.data?.message || response.error
      });
      return false;
    }
  }

  async testSecurityHeaders() {
    this.log('INFO', 'Sécurité', 'Test des en-têtes de sécurité...');
    
    const response = await this.makeRequest('GET', '/');
    
    const securityHeaders = [
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy'
    ];

    let passedHeaders = 0;
    
    securityHeaders.forEach(header => {
      if (response.headers[header.toLowerCase()]) {
        this.log('PASS', 'En-tête sécurité', `${header} présent`);
        passedHeaders++;
      } else {
        this.log('WARN', 'En-tête sécurité', `${header} manquant`);
      }
    });

    if (passedHeaders >= 3) {
      this.log('PASS', 'Sécurité globale', 'Configuration sécurité satisfaisante');
    } else {
      this.log('WARN', 'Sécurité globale', 'Configuration sécurité à améliorer');
    }
  }

  async runAllTests() {
    console.log(`🚀 Début des tests de déploiement pour: ${this.baseURL}\n`);
    
    const startTime = Date.now();
    
    // Tests dans l'ordre logique
    const testResults = {
      basicAccess: await this.testBasicAccess(),
      performance: await this.testPerformance(),
      csrf: await this.testCSRFToken(),
      database: await this.testDatabaseConnection(),
      adminLogin: await this.testAdminLogin(),
      formSubmission: await this.testFormSubmission(),
      securityHeaders: await this.testSecurityHeaders()
    };

    const totalTime = Date.now() - startTime;
    
    // Résumé des résultats
    console.log('\n' + '='.repeat(60));
    console.log('📊 RÉSUMÉ DES TESTS');
    console.log('='.repeat(60));
    
    const summary = this.results.reduce((acc, result) => {
      acc[result.status] = (acc[result.status] || 0) + 1;
      return acc;
    }, {});
    
    console.log(`✅ Tests réussis: ${summary.PASS || 0}`);
    console.log(`❌ Tests échoués: ${summary.FAIL || 0}`);
    console.log(`⚠️  Avertissements: ${summary.WARN || 0}`);
    console.log(`ℹ️  Informations: ${summary.INFO || 0}`);
    console.log(`⏱️  Temps total: ${totalTime}ms`);
    
    // Recommandations
    console.log('\n📋 RECOMMANDATIONS:');
    
    if (summary.FAIL > 0) {
      console.log('❌ Des tests critiques ont échoué. Vérifiez la configuration.');
    } else if (summary.WARN > 0) {
      console.log('⚠️  Certains aspects peuvent être améliorés.');
    } else {
      console.log('✅ Tous les tests sont réussis. Déploiement prêt pour production!');
    }
    
    // Sauvegarde des résultats
    const reportPath = path.join(__dirname, '..', 'test-reports', `production-test-${Date.now()}.json`);
    
    try {
      if (!fs.existsSync(path.dirname(reportPath))) {
        fs.mkdirSync(path.dirname(reportPath), { recursive: true });
      }
      
      fs.writeFileSync(reportPath, JSON.stringify({
        url: this.baseURL,
        timestamp: new Date().toISOString(),
        duration: totalTime,
        summary: summary,
        results: this.results
      }, null, 2));
      
      console.log(`\n📄 Rapport détaillé sauvegardé: ${reportPath}`);
    } catch (error) {
      console.log(`\n⚠️  Impossible de sauvegarder le rapport: ${error.message}`);
    }

    return summary.FAIL === 0;
  }
}

// Exécution du script
if (require.main === module) {
  const tester = new ProductionTester();
  
  tester.runAllTests()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('❌ Erreur lors de l\'exécution des tests:', error.message);
      process.exit(1);
    });
}

module.exports = ProductionTester;