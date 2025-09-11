/**
 * FAF Admin Module - Module ES6 unifié pour l'interface d'administration
 * Remplace admin-utils.js et core-utils.js avec une architecture modulaire
 */

// =============================================================================
// CONSTANTES ET CONFIGURATION
// =============================================================================

// Constante partagée pour le décodage sécurisé des entités HTML
export const SAFE_HTML_ENTITIES = {
  '&#x2F;': '/',  // Ajout pour décoder les slashes dans les URLs Cloudinary
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
    // Afficher l'état de chargement
    UI.showLoading(true, 'Traitement en cours...');
    
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
    } finally {
      // Cacher l'état de chargement
      UI.showLoading(false);
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
   * Version améliorée pour Safari avec gestion des URLs Cloudinary
   */
  unescapeHTML(text) {
    if (!text || typeof text !== 'string') return text || '';
    
    let result = text;
    
    // IMPORTANT: Décoder les slashes en premier pour les URLs
    // Safari a des problèmes avec les URLs contenant &#x2F;
    result = result.replace(/&#x2F;/g, '/');
    result = result.replace(/&#47;/g, '/');
    result = result.replace(/&sol;/g, '/');
    
    // ROBUSTESSE: Décoder directement les apostrophes les plus communes AVANT le loop
    // Cela garantit que même en cas de problème avec SAFE_HTML_ENTITIES, ça marche
    result = result.replace(/&#x27;/g, "'");  // Hexadecimal apostrophe
    result = result.replace(/&#39;/g, "'");   // Decimal apostrophe
    result = result.replace(/&apos;/g, "'");  // Named apostrophe
    
    // Ensuite décoder les autres entités HTML
    const entities = SAFE_HTML_ENTITIES;
    for (let entity in entities) {
      if (entities.hasOwnProperty(entity) && 
          entity !== '&#x2F;' && 
          entity !== '&#x27;' && 
          entity !== '&#39;' && 
          entity !== '&apos;') { // Skip déjà traités
        const char = entities[entity];
        // Échapper les caractères spéciaux regex
        const escapedEntity = entity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        result = result.replace(new RegExp(escapedEntity, 'g'), char);
      }
    }
    
    // Nettoyage final pour toutes les URLs (pas seulement Cloudinary)
    result = result.trim();
    
    // Si c'est une URL Cloudinary, s'assurer qu'elle est bien formée
    if (result.includes('cloudinary.com')) {
      try {
        const url = new URL(result);
        // S'assurer que le protocole est HTTPS pour Cloudinary
        if (url.hostname.includes('cloudinary.com') && url.protocol === 'http:') {
          url.protocol = 'https:';
          result = url.toString();
        }
      } catch (e) {
        // Si l'URL n'est pas valide après décodage
        console.warn('🔧 URL Cloudinary malformée après décodage:', result);
      }
    }
    
    return result;
  },

  /**
   * Échappe les caractères HTML pour éviter XSS
   */
  escapeHTML(text) {
    if (!text || typeof text !== 'string') return text || '';
    
    const escapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;'
    };
    
    return text.replace(/[&<>"'\/]/g, (char) => escapeMap[char]);
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
   * Formate un mois au format français (YYYY-MM -> Mois YYYY)
   */
  formatMonth(monthString) {
    if (!monthString || typeof monthString !== 'string') return monthString || '';
    
    const monthNames = {
      '01': 'Janvier',
      '02': 'Février', 
      '03': 'Mars',
      '04': 'Avril',
      '05': 'Mai',
      '06': 'Juin',
      '07': 'Juillet',
      '08': 'Août',
      '09': 'Septembre',
      '10': 'Octobre',
      '11': 'Novembre',
      '12': 'Décembre'
    };
    
    // Format attendu: "YYYY-MM" -> "Mois YYYY"
    const parts = monthString.split('-');
    if (parts.length === 2) {
      const year = parts[0];
      const month = parts[1];
      const monthName = monthNames[month];
      
      if (monthName) {
        return `${monthName} ${year}`;
      }
    }
    
    // Si le format n'est pas reconnu, retourner tel quel
    return monthString;
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
    
    // Vérifier d'abord si ça ressemble à une URL avant d'essayer de la parser
    if (!url.startsWith('http://') && !url.startsWith('https://')) return false;
    
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
      const pathname = urlObj.pathname;
      if (hostname === 'res.cloudinary.com' || hostname.endsWith('.cloudinary.com')) {
        // Cloudinary URLs pattern: /[cloud_name]/image/upload/[version]/[path]
        // ou /[cloud_name]/image/upload/[path]
        return pathname.includes('/image/upload/');
      } else {
        // Pour les autres domaines, vérifier l'extension (case insensitive)
        const pathLower = pathname.toLowerCase();
        const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        return validExtensions.some(ext => pathLower.includes(ext));
      }
    } catch (e) {
      // Silently return false for invalid URLs (expected for text content)
      return false;
    }
  }
};

// =============================================================================
// INTERFACE UTILISATEUR
// =============================================================================

export const UI = {
  /**
   * Gestion des états de chargement
   */
  showLoading(show = true, message = 'Chargement en cours...') {
    let overlay = document.getElementById('loadingOverlay');
    
    if (!overlay) {
      // Créer l'overlay de chargement s'il n'existe pas
      overlay = document.createElement('div');
      overlay.id = 'loadingOverlay';
      overlay.className = 'loading-overlay hidden';
      
      // Créer le contenu sans innerHTML pour éviter XSS
      const content = document.createElement('div');
      content.className = 'loading-content';
      
      const spinner = document.createElement('div');
      spinner.className = 'loading-spinner';
      content.appendChild(spinner);
      
      const text = document.createElement('div');
      text.className = 'loading-text';
      text.textContent = message;
      content.appendChild(text);
      
      overlay.appendChild(content);
      document.body.appendChild(overlay);
    }
    
    if (show) {
      overlay.classList.remove('hidden');
      // Mettre à jour le message si fourni
      const textEl = overlay.querySelector('.loading-text');
      if (textEl) textEl.textContent = message;
    } else {
      overlay.classList.add('hidden');
    }
  },

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
    closeBtn.onclick = () => {
      if (overlay.parentNode) {
        document.body.removeChild(overlay);
      }
    };
    overlay.appendChild(closeBtn);

    // Image agrandie avec corrections Safari
    const bigImg = document.createElement('img');
    
    // Safari Fix: Utiliser setAttribute() et paramètres CORS
    bigImg.setAttribute('src', imageSrc);
    bigImg.setAttribute('alt', imageAlt);
    bigImg.setAttribute('crossorigin', 'anonymous');
    bigImg.setAttribute('loading', 'eager');
    
    bigImg.style.maxWidth = config.maxWidth || '90%';
    bigImg.style.maxHeight = config.maxHeight || '90%';
    bigImg.style.objectFit = 'contain';
    
    // Safari Fix: Gestion d'erreur pour lightbox
    bigImg.onerror = () => {
      console.error('🚨 Safari - Lightbox image failed:', imageSrc);
      // Remplacer par un message d'erreur plutôt qu'une image fallback
      const errorDiv = document.createElement('div');
      errorDiv.className = 'text-white text-center p-8';
      
      // Créer les éléments sans innerHTML pour éviter XSS
      const icon = document.createElement('div');
      icon.className = 'text-4xl mb-4';
      icon.textContent = '⚠️';
      
      const title = document.createElement('div');
      title.className = 'text-xl mb-2';
      title.textContent = 'Image indisponible';
      
      const captionDiv = document.createElement('div');
      captionDiv.className = 'text-sm opacity-75';
      captionDiv.textContent = caption || imageAlt;
      
      const details = document.createElement('div');
      details.className = 'text-xs opacity-50 mt-4';
      details.textContent = 'Safari - Problème de chargement Cloudinary';
      
      errorDiv.appendChild(icon);
      errorDiv.appendChild(title);
      errorDiv.appendChild(captionDiv);
      errorDiv.appendChild(details);
      
      bigImg.style.display = 'none';
      overlay.insertBefore(errorDiv, bigImg);
    };
    
    overlay.appendChild(bigImg);

    // Légende si fournie
    if (caption) {
      const captionDiv = document.createElement('div');
      captionDiv.className = 'lightbox-caption';
      captionDiv.style.textAlign = 'center';
      captionDiv.textContent = caption;
      overlay.appendChild(captionDiv);
    }

    // Fermeture par clic en dehors de l'image (Safari compatible)
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay && overlay.parentNode) {
        document.body.removeChild(overlay);
      }
    });

    // Fermeture par touche Escape (Safari)
    const escapeHandler = function(e) {
      if (e.key === 'Escape' && overlay.parentNode) {
        document.body.removeChild(overlay);
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);

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
      // Décoder les entités HTML sécurisées pour l'affichage du graphique
      // IMPORTANT: Utiliser Utils.unescapeHTML qui gère tous les cas
      let decodedAnswer = answer;
      
      // Si la réponse contient des entités HTML, les décoder
      if (answer && answer.includes('&')) {
        decodedAnswer = Utils.unescapeHTML(answer);
      }
      
      // Backup: Si Utils.unescapeHTML ne fonctionne pas, décoder manuellement
      if (decodedAnswer.includes('&#')) {
        decodedAnswer = decodedAnswer
          .replace(/&#39;/g, "'")    // &#39; → ' (apostrophe decimal)
          .replace(/&#x27;/g, "'")   // &#x27; → ' (apostrophe hexadecimal)  
          .replace(/&apos;/g, "'")   // &apos; → ' (apostrophe named)
          .replace(/&quot;/g, '"')   // &quot; → " (guillemet)
          .replace(/&amp;/g, '&')    // &amp; → & (ampersand)
          .replace(/&nbsp;/g, ' ');  // &nbsp; → ' ' (espace insécable)
      }
      
      decodedAnswer = decodedAnswer.trim();
      
      freq[decodedAnswer] = (freq[decodedAnswer] || 0) + 1;
      (userMap[decodedAnswer] = userMap[decodedAnswer] || []).push(user);
    });

    const labels = [], data = [], bg = [];
    Object.entries(freq).forEach(([ans, cnt]) => {
      labels.push(`${ans} (${userMap[ans].join(', ')})`);
      data.push(cnt);

      // Couleurs fixes (maintenant avec réponses décodées)
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
      
      // DEBUG: Log détaillé pour Safari
      const decodedAnswer = Utils.unescapeHTML(answer);
      
      // Log uniquement si c'est une URL ou s'il y a eu un changement
      if (decodedAnswer.includes('http') || answer !== decodedAnswer) {
        const isValidImage = (decodedAnswer.startsWith('http://') || decodedAnswer.startsWith('https://')) ? Utils.isTrustedImageUrl(decodedAnswer) : false;
        console.log(`🔍 [${user}] URL:`, {
          original: answer.substring(0, 100) + (answer.length > 100 ? '...' : ''),
          decoded: decodedAnswer.substring(0, 100) + (decodedAnswer.length > 100 ? '...' : ''),
          isValidImage: isValidImage
        });
        
        // Si c'est une URL mais pas reconnue comme image valide, afficher pourquoi
        if (decodedAnswer.includes('cloudinary') && !isValidImage) {
          console.warn(`⚠️ URL Cloudinary non reconnue comme image valide:`, decodedAnswer);
        }
      }
      
      // La variable decodedAnswer est déjà définie par le debug ci-dessus
      const isImage = (decodedAnswer.startsWith('http://') || decodedAnswer.startsWith('https://')) ? Utils.isTrustedImageUrl(decodedAnswer) : false;

      if (isImage) {
        // Miniature cliquable avec corrections Safari
        const img = document.createElement('img');
        
        // Safari Fix 1: Utiliser setAttribute() au lieu d'assignation directe
        // IMPORTANT: Ne PAS faire decodeURIComponent sur l'URL car elle est déjà valide
        img.setAttribute('src', decodedAnswer);
        img.setAttribute('alt', `Image de ${user}`);
        img.className = `${config.thumbnailSize || 'w-16 h-16'} object-cover inline-block mr-2 border cursor-pointer`;
        
        // Safari Fix 2: Ajouter crossorigin pour les domaines tiers
        img.setAttribute('crossorigin', 'anonymous');
        
        // Safari Fix 3: Force le chargement immédiat
        img.setAttribute('loading', 'eager');
        
        // Safari Fix 4: Gestion erreur améliorée avec timeout
        let errorHandled = false;
        const handleError = function() {
          if (errorHandled) return;
          errorHandled = true;
          
          console.warn('🚨 Safari - Image Cloudinary failed to load:', decodedAnswer);
          this.setAttribute('src', config.fallbackSvg || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0yNCAyOEMyNiAyNiAyOCAyNiAzMCAyOEMzMiAzMCAzNCAzMCAzNiAyOEMzOCAyNiA0MCAyNiA0MiAyOFY0MEgyMlYyOFoiIGZpbGw9IiNEMUQ1REIiLz4KPHA+SW1hZ2UgaW5kaXNwb25pYmxlPC9wPgo8L3N2Zz4K');
          this.setAttribute('alt', `Image indisponible (${user})`);
          this.setAttribute('title', 'Image Cloudinary inaccessible sur Safari');
        };
        
        img.onerror = handleError;
        
        // Safari Fix 5: Timeout de sécurité (Safari peut ne pas déclencher onerror)
        setTimeout(() => {
          if (!img.complete && !errorHandled) {
            console.warn('⏰ Safari - Image timeout:', decodedAnswer);
            handleError.call(img);
          }
        }, 5000);

        // Ouverture de la lightbox avec vérification de l'image
        img.onclick = () => {
          if (!errorHandled && img.complete && img.naturalHeight !== 0) {
            UI.createLightbox(decodedAnswer, img.alt, user, {
              maxWidth: config.lightboxMaxSize || '90%',
              maxHeight: config.lightboxMaxSize || '90%'
            });
          } else {
            UI.showAlert(`Image indisponible pour ${user}`, 'error');
          }
        };

        li.appendChild(img);
        li.appendChild(document.createTextNode(` ${user}`));
      } else {
        // Afficher le texte décodé
        li.textContent = `${user} : ${decodedAnswer}`;
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