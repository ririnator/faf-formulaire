/**
 * FAF Admin Module - Multi-Tenant JWT Authentication
 * Module ES6 pour l'interface admin avec authentification JWT
 */

// ========================================
// CONSTANTS
// ========================================

const API_BASE = '/api';
const AUTH_TOKEN_KEY = 'faf_token';

// ========================================
// ADMIN API - Gestion des appels API
// ========================================

export const AdminAPI = {
  /**
   * Récupère le JWT depuis localStorage
   */
  getJWT() {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  },

  /**
   * Stocke le JWT dans localStorage
   */
  setJWT(token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
  },

  /**
   * Supprime le JWT
   */
  clearJWT() {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  },

  /**
   * Vérifie l'authentification JWT (client-side)
   * Décode le JWT pour extraire les infos admin
   * Redirige vers /auth/login.html si invalide
   * @returns {Promise<Object|null>} - { id, username, email } ou null
   */
  async checkAuth() {
    const token = this.getJWT();

    if (!token) {
      console.warn('Aucun token JWT trouvé, redirection login...');
      window.location.href = '/auth/login.html';
      return null;
    }

    try {
      // Décoder le JWT côté client (sans vérifier la signature, sera vérifiée côté serveur)
      const payload = JSON.parse(atob(token.split('.')[1]));

      // Vérifier l'expiration
      if (payload.exp && payload.exp * 1000 < Date.now()) {
        throw new Error('Token expiré');
      }

      // Retourner les infos depuis le payload
      return {
        id: payload.sub,
        username: payload.username,
        email: payload.email
      };

    } catch (error) {
      console.error('Erreur décodage JWT:', error);
      this.clearJWT();
      window.location.href = '/auth/login.html';
      return null;
    }
  },

  /**
   * Déconnexion - supprime le JWT et redirige
   */
  logout() {
    this.clearJWT();
    window.location.href = '/auth/login.html';
  },

  /**
   * Effectue une requête API authentifiée
   * @param {string} endpoint - URL de l'API (ex: '/api/admin/dashboard')
   * @param {Object} options - Options fetch (method, body, etc.)
   * @returns {Promise<Object|null>} - Données JSON ou null si erreur
   */
  async request(endpoint, options = {}) {
    const token = this.getJWT();

    if (!token) {
      console.error('Aucun token JWT pour la requête');
      window.location.href = '/auth/login.html';
      return null;
    }

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...options.headers
    };

    try {
      const response = await fetch(endpoint, {
        ...options,
        headers
      });

      // Si 401, rediriger vers login
      if (response.status === 401) {
        console.warn('Token expiré ou invalide, redirection...');
        this.clearJWT();
        window.location.href = '/auth/login.html';
        return null;
      }

      // Si 402, rediriger vers page de paiement
      if (response.status === 402) {
        console.warn('Paiement requis, redirection...');
        window.location.href = '/auth/payment-required.html';
        return null;
      }

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Erreur réseau' }));
        throw new Error(error.error || `Erreur ${response.status}`);
      }

      return await response.json();

    } catch (error) {
      console.error(`Erreur API ${endpoint}:`, error);
      UI.showAlert(error.message || 'Erreur lors de la requête', 'error');
      return null;
    }
  }
};

// ========================================
// UTILS - Fonctions utilitaires
// ========================================

export const Utils = {
  /**
   * Formate une date ISO en format français
   * @param {string} isoDate - Date au format ISO
   * @returns {string} - "14 octobre 2025 à 10h30"
   */
  formatDate(isoDate) {
    if (!isoDate) return 'Date inconnue';

    const date = new Date(isoDate);

    if (isNaN(date.getTime())) {
      return 'Date invalide';
    }

    const options = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    };

    return date.toLocaleDateString('fr-FR', options).replace(':', 'h');
  },

  /**
   * Formate un mois YYYY-MM en texte français
   * @param {string} monthStr - "2025-10"
   * @returns {string} - "Octobre 2025"
   */
  formatMonth(monthStr) {
    if (!monthStr || !/^\d{4}-\d{2}$/.test(monthStr)) {
      return 'Mois invalide';
    }

    const [year, month] = monthStr.split('-');
    const date = new Date(`${year}-${month}-01`);

    const monthName = date.toLocaleDateString('fr-FR', { month: 'long' });
    const capitalizedMonth = monthName.charAt(0).toUpperCase() + monthName.slice(1);

    return `${capitalizedMonth} ${year}`;
  },

  /**
   * Décode les entités HTML (sécurisé)
   * @param {string} text - Texte avec entités HTML
   * @returns {string} - Texte décodé
   */
  unescapeHTML(text) {
    if (!text) return '';

    const textarea = document.createElement('textarea');
    textarea.innerHTML = text;
    return textarea.value;
  },

  /**
   * Tronque un texte avec ellipses
   * @param {string} text - Texte à tronquer
   * @param {number} maxLength - Longueur max
   * @returns {string}
   */
  truncate(text, maxLength = 50) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  }
};

// ========================================
// UI - Gestion de l'interface utilisateur
// ========================================

export const UI = {
  /**
   * Affiche un message d'alerte
   * @param {string} message - Message à afficher
   * @param {string} type - 'success' | 'error' | 'info'
   */
  showAlert(message, type = 'info') {
    const alertEl = document.getElementById('alertMessage');

    if (!alertEl) {
      console.warn('Element #alertMessage introuvable');
      alert(message); // Fallback
      return;
    }

    // Reset classes
    alertEl.className = 'mb-4 p-4 rounded-lg';

    // Appliquer le style selon le type
    if (type === 'success') {
      alertEl.classList.add('bg-green-100', 'text-green-800', 'border', 'border-green-400');
    } else if (type === 'error') {
      alertEl.classList.add('bg-red-100', 'text-red-800', 'border', 'border-red-400');
    } else {
      alertEl.classList.add('bg-blue-100', 'text-blue-800', 'border', 'border-blue-400');
    }

    alertEl.textContent = message;
    alertEl.classList.remove('hidden');

    // Auto-hide après 5 secondes
    setTimeout(() => {
      alertEl.classList.add('hidden');
    }, 5000);
  },

  /**
   * Initialise le header admin (username, boutons)
   * @param {Object} admin - { id, username, email }
   */
  initAdminHeader(admin) {
    // Afficher le username
    const usernameEl = document.getElementById('adminUsername');
    if (usernameEl) {
      usernameEl.textContent = admin.username;
    }

    // Bouton "Mon formulaire" - copie le lien
    const myFormBtn = document.getElementById('myFormBtn');
    if (myFormBtn) {
      myFormBtn.addEventListener('click', () => {
        const formLink = `${window.location.origin}/form/${admin.username}`;
        navigator.clipboard.writeText(formLink)
          .then(() => {
            this.showAlert('Lien copié dans le presse-papier ! 📋', 'success');
          })
          .catch((err) => {
            console.error('Erreur copie:', err);
            // Fallback pour navigateurs anciens
            const textarea = document.createElement('textarea');
            textarea.value = formLink;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
              document.execCommand('copy');
              this.showAlert('Lien copié dans le presse-papier ! 📋', 'success');
            } catch (e) {
              this.showAlert('Impossible de copier le lien automatiquement', 'error');
            }
            document.body.removeChild(textarea);
          });
      });
    }

    // Bouton déconnexion
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        AdminAPI.logout();
      });
    }
  }
};

// ========================================
// CHARTS - Gestion des graphiques Chart.js
// ========================================

export const Charts = {
  /**
   * Crée un graphique camembert (pie chart)
   * @param {string} canvasId - ID du canvas
   * @param {Object} data - { "ça va": 5, "a connu meilleur mois": 3 }
   * @returns {Chart|null}
   */
  createPieChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);

    if (!canvas) {
      console.error(`Canvas #${canvasId} introuvable`);
      return null;
    }

    // Vérifier que Chart.js est chargé
    if (typeof Chart === 'undefined') {
      console.error('Chart.js non chargé');
      return null;
    }

    const labels = Object.keys(data);
    const values = Object.values(data);

    // Palette de couleurs
    const colors = [
      '#3B82F6', // blue-500
      '#10B981', // green-500
      '#F59E0B', // amber-500
      '#EF4444', // red-500
      '#8B5CF6', // violet-500
      '#EC4899', // pink-500
      '#14B8A6', // teal-500
      '#F97316'  // orange-500
    ];

    return new Chart(canvas, {
      type: 'pie',
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors.slice(0, labels.length),
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 15,
              font: {
                size: 12
              }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.parsed || 0;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
  }
};
