/**
 * FAF Admin Module - Module ES6 unifié pour l'interface d'administration
 * Remplace admin-utils.js et core-utils.js avec une architecture modulaire
 */

// =============================================================================
// CONSTANTES ET CONFIGURATION
// =============================================================================

// Constante partagée pour le décodage sécurisé des entités HTML
export const SAFE_HTML_ENTITIES = {
  '&#x27;': "'",
  '&#39;': "'",
  '&apos;': "'",
  '&quot;': '"',
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&nbsp;': ' ',
  '&eacute;': 'é',
  '&egrave;': 'è',
  '&ecirc;': 'ê',
  '&agrave;': 'à',
  '&acirc;': 'â',
  '&ugrave;': 'ù',
  '&ucirc;': 'û',
  '&icirc;': 'î',
  '&ocirc;': 'ô',
  '&ccedil;': 'ç'
};

// Domaines d'images de confiance pour la validation de sécurité
const TRUSTED_IMAGE_DOMAINS = [
  'res.cloudinary.com',
  'images.unsplash.com',
  'via.placeholder.com'
];

// =============================================================================
// API ET GESTION DES REQUÊTES
// =============================================================================

export class AdminAPI {
  static csrfToken = null;

  /**
   * Récupère le token CSRF depuis l'API
   */
  static async fetchCSRFToken() {
    try {
      const response = await fetch('/api/admin/csrf-token', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.csrfToken = data.token;
        return this.csrfToken;
      }
      
      console.error('Impossible de récupérer le token CSRF');
      return null;
    } catch (error) {
      console.error('Erreur récupération token CSRF:', error);
      return null;
    }
  }

  /**
   * Gestion standardisée des erreurs API avec redirection automatique si session expirée
   */
  static async handleAPIError(response, defaultMessage = 'Une erreur est survenue') {
    if (response.status === 401) {
      UI.showAlert("Session expirée. Redirection vers la connexion...", 'error');
      setTimeout(() => window.location.href = '/login', 2000);
      return true;
    }
    
    if (!response.ok) {
      try {
        const errorData = await response.json();
        const errorMessage = errorData.error || errorData.message || defaultMessage;
        UI.showAlert(`Erreur ${response.status}: ${errorMessage}`, 'error');
      } catch {
        UI.showAlert(`${defaultMessage} (${response.status})`, 'error');
      }
      return true;
    }
    
    return false;
  }

  /**
   * Effectue une requête API avec gestion automatique d'erreurs et CSRF
   */
  static async request(url, options = {}, errorMessage = 'Erreur de communication') {
    try {
      const fetchOptions = {
        credentials: 'include',
        ...options
      };
      
      // Ajouter le token CSRF pour les opérations sensibles
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase())) {
        if (!this.csrfToken) {
          await this.fetchCSRFToken();
        }
        
        if (this.csrfToken) {
          fetchOptions.headers = {
            ...fetchOptions.headers,
            'x-csrf-token': this.csrfToken
          };
        }
      }
      
      const response = await fetch(url, fetchOptions);
      
      // Si erreur CSRF, récupérer un nouveau token et réessayer
      if (response.status === 403) {
        const errorData = await response.json().catch(() => ({}));
        if (errorData.code === 'CSRF_TOKEN_INVALID' || errorData.code === 'CSRF_TOKEN_MISSING') {
          console.log('Token CSRF invalide, récupération d\'un nouveau token...');
          await this.fetchCSRFToken();
          
          if (this.csrfToken) {
            fetchOptions.headers = {
              ...fetchOptions.headers,
              'x-csrf-token': this.csrfToken
            };
            
            // Réessayer la requête avec le nouveau token
            const retryResponse = await fetch(url, fetchOptions);
            if (await this.handleAPIError(retryResponse, errorMessage)) {
              return null;
            }
            return await retryResponse.json();
          }
        }
      }
      
      // Gérer les erreurs API
      if (await this.handleAPIError(response, errorMessage)) {
        return null;
      }
      
      return await response.json();
    } catch (error) {
      console.error(`Erreur fetch ${url}:`, error);
      UI.showAlert(`${errorMessage}: ${error.message}`, 'error');
      return null;
    }
  }

  /**
   * Initialise l'API (récupère le token CSRF)
   */
  static async init() {
    await this.fetchCSRFToken();
  }
}

// =============================================================================
// UTILITAIRES GÉNÉRAUX
// =============================================================================

export const Utils = {
  /**
   * Décode les entités HTML en utilisant une liste blanche sécurisée
   */
  unescapeHTML(text) {
    if (!text || typeof text !== 'string') return text || '';
    
    let result = text;
    for (const [entity, char] of Object.entries(SAFE_HTML_ENTITIES)) {
      result = result.replace(new RegExp(entity, 'g'), char);
    }
    
    return result;
  },

  /**
   * Échappe les caractères HTML pour éviter XSS
   */
  escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  /**
   * Formate une date au format français
   */
  formatDate(date) {
    const d = new Date(date);
    return d.toLocaleString('fr-FR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  },

  /**
   * Debounce function pour limiter les appels
   */
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  /**
   * Valide si une URL d'image est de confiance
   */
  isTrustedImageUrl(url) {
    if (!url || typeof url !== 'string') return false;
    
    try {
      const urlObj = new URL(url);
      
      // Force HTTPS seulement
      if (urlObj.protocol !== 'https:') return false;
      
      // Vérifie si le domaine est dans la liste blanche
      const hostname = urlObj.hostname.toLowerCase();
      const isTrustedDomain = TRUSTED_IMAGE_DOMAINS.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      if (!isTrustedDomain) return false;
      
      // Gestion spéciale pour les URLs Cloudinary
      const pathname = urlObj.pathname.toLowerCase();
      if (hostname === 'res.cloudinary.com' || hostname.endsWith('.cloudinary.com')) {
        return pathname.includes('/image/upload/');
      } else {
        // Pour les autres domaines, vérifier l'extension
        const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        return validExtensions.some(ext => pathname.includes(ext));
      }
    } catch (e) {
      return false;
    }
  }
};

// =============================================================================
// INTERFACE UTILISATEUR
// =============================================================================

export const UI = {
  /**
   * Gestion des messages d'alerte avec auto-hide
   */
  showAlert(message, type = 'error', alertId = 'alertMessage') {
    const alertDiv = document.getElementById(alertId);
    if (!alertDiv) {
      console.error(`Élément d'alerte avec ID '${alertId}' non trouvé`);
      // Fallback vers alert navigateur
      alert(message);
      return;
    }
    
    const baseClasses = 'mb-4 p-4 rounded-lg';
    const typeClasses = type === 'error' 
      ? 'bg-red-100 text-red-700 border border-red-300'
      : 'bg-green-100 text-green-700 border border-green-300';
    
    alertDiv.className = `${baseClasses} ${typeClasses}`;
    alertDiv.textContent = message;
    alertDiv.classList.remove('hidden');
    
    // Auto-hide après 5 secondes
    setTimeout(() => {
      alertDiv.classList.add('hidden');
    }, 5000);
  },

  /**
   * Fonction d'alerte simplifiée pour les cas d'urgence (compatibilité)
   */
  coreAlert(message, type = 'error') {
    this.showAlert(message, type);
  },

  /**
   * Crée et affiche une lightbox pour une image
   */
  createLightbox(imageSrc, imageAlt = '', caption = '', config = {}) {
    const overlay = document.createElement('div');
    overlay.className = 'lightbox-overlay';

    // Bouton fermer
    const closeBtn = document.createElement('div');
    closeBtn.className = 'close-btn';
    closeBtn.textContent = '×';
    closeBtn.onclick = () => document.body.removeChild(overlay);
    overlay.appendChild(closeBtn);

    // Image agrandie
    const bigImg = document.createElement('img');
    bigImg.src = imageSrc;
    bigImg.alt = imageAlt;
    bigImg.style.maxWidth = config.maxWidth || '90%';
    bigImg.style.maxHeight = config.maxHeight || '90%';
    bigImg.style.objectFit = 'contain';
    overlay.appendChild(bigImg);

    // Légende si fournie
    if (caption) {
      const captionDiv = document.createElement('div');
      captionDiv.className = 'lightbox-caption';
      captionDiv.style.textAlign = 'center';
      captionDiv.textContent = caption;
      overlay.appendChild(captionDiv);
    }

    // Fermeture par clic en dehors de l'image
    overlay.addEventListener('click', e => {
      if (e.target === overlay) document.body.removeChild(overlay);
    });

    document.body.appendChild(overlay);
  }
};

// =============================================================================
// COMPOSANTS GRAPHIQUES
// =============================================================================

export const Charts = {
  /**
   * Crée un graphique en camembert (pie chart)
   */
  createPieChart(items, config = {}) {
    const freq = {}, userMap = {};
    items.forEach(({ user, answer }) => {
      freq[answer] = (freq[answer] || 0) + 1;
      (userMap[answer] = userMap[answer] || []).push(user);
    });

    const labels = [], data = [], bg = [];
    Object.entries(freq).forEach(([ans, cnt]) => {
      labels.push(`${ans} (${userMap[ans].join(', ')})`);
      data.push(cnt);

      // Couleurs fixes
      let color = "rgba(254, 153,   0, 1)"; // orange par défaut
      if (ans === "ça va")             color = "rgba( 50, 101, 204, 1)";
      else if (ans === "WE'RE BARACK") color = "rgba( 13, 150,  24, 1)";
      else if (ans === "ITS JOEVER")   color = "rgba(220,  55,  17, 1)";
      else if (ans.startsWith("a connu meilleur mois")) 
                                      color = "rgba(254, 153,   0, 1)";
      bg.push(color);
    });

    // Créer le wrapper et le canvas
    const wrapper = document.createElement('div');
    wrapper.className = "flex items-center gap-4";
    const canvas = document.createElement('canvas');
    canvas.width  = config.chartWidth || 1100;
    canvas.height = config.chartHeight || 320;
    wrapper.appendChild(canvas);

    new Chart(canvas, {
      type: 'pie',
      data: { labels, datasets: [{ data, backgroundColor: bg }] },
      options: { responsive: false, plugins: { legend: { position: 'right' } } }
    });

    return wrapper;
  },

  /**
   * Crée un élément liste avec gestion des images
   */
  createAnswersList(items, config = {}) {
    const ul = document.createElement('ul');
    ul.className = "list-disc pl-5";

    items.forEach(({ user, answer }) => {
      const li = document.createElement('li');
      
      const isImage = Utils.isTrustedImageUrl(answer);

      if (isImage) {
        // Miniature cliquable
        const img = document.createElement('img');
        img.src = answer;
        img.alt = `Image de ${user}`;
        img.className = `${config.thumbnailSize || 'w-16 h-16'} object-cover inline-block mr-2 border cursor-pointer`;
        
        // Gestion erreur de chargement image avec fallback configuré
        img.onerror = function() {
          if (!this.dataset.fallbackApplied) {
            this.dataset.fallbackApplied = 'true';
            this.src = config.fallbackSvg || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0yNCAyOEMyNiAyNiAyOCAyNiAzMCAyOEMzMiAzMCAzNCAzMCAzNiAyOEMzOCAyNiA0MCAyNiA0MiAyOFY0MEgyMlYyOFoiIGZpbGw9IiNEMUQ1REIiLz4KPHA+SW1hZ2UgaW5kaXNwb25pYmxlPC9wPgo8L3N2Zz4K';
            this.alt = `Image indisponible (${user})`;
            this.title = 'Image Cloudinary inaccessible';
          }
        };

        // Ouverture de la lightbox quand on clique
        img.onclick = () => {
          UI.createLightbox(answer, img.alt, user, {
            maxWidth: config.lightboxMaxSize || '90%',
            maxHeight: config.lightboxMaxSize || '90%'
          });
        };

        li.appendChild(img);
        li.appendChild(document.createTextNode(` ${user}`));
      } else {
        // Décoder les entités HTML pour un affichage correct
        li.textContent = `${user} : ${Utils.unescapeHTML(answer)}`;
      }

      ul.appendChild(li);
    });

    return ul;
  }
};

// =============================================================================
// INITIALISATION AUTOMATIQUE
// =============================================================================

// Auto-initialisation si on est dans un navigateur
if (typeof window !== 'undefined') {
  // Rendre disponible globalement pour compatibilité
  window.AdminAPI = AdminAPI;
  window.Utils = Utils;
  window.UI = UI;
  window.Charts = Charts;
  window.SAFE_HTML_ENTITIES = SAFE_HTML_ENTITIES;
  
  // Fonctions globales pour compatibilité descendante
  window.unescapeHTML = Utils.unescapeHTML;
  window.showAlert = UI.showAlert;
  window.coreAlert = UI.coreAlert;
  
  // Initialisation automatique au chargement
  document.addEventListener('DOMContentLoaded', () => {
    AdminAPI.init();
  });
}