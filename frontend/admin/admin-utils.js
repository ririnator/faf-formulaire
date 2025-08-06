/**
 * Utilitaires communs pour l'interface d'administration
 * Évite la duplication de code entre admin.html et admin_gestion.html
 */

// Variable globale pour stocker le token CSRF
let csrfToken = null;

/**
 * Gestion des messages d'alerte avec auto-hide
 * @param {string} message - Message à afficher
 * @param {string} type - Type d'alerte ('error' | 'success')
 * @param {string} alertId - ID du div d'alerte (défaut: 'alertMessage')
 */
function showAlert(message, type = 'error', alertId = 'alertMessage') {
  const alertDiv = document.getElementById(alertId);
  if (!alertDiv) {
    console.error(`Élément d'alerte avec ID '${alertId}' non trouvé`);
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
}

/**
 * Gestion standardisée des erreurs API avec redirection automatique si session expirée
 * @param {Response} response - Réponse fetch
 * @param {string} defaultMessage - Message d'erreur par défaut
 * @returns {Promise<boolean>} - true si erreur traitée, false sinon
 */
async function handleAPIError(response, defaultMessage = 'Une erreur est survenue') {
  if (response.status === 401) {
    showAlert("Session expirée. Redirection vers la connexion...", 'error');
    setTimeout(() => window.location.href = '/login', 2000);
    return true;
  }
  
  if (!response.ok) {
    try {
      const errorData = await response.json();
      const errorMessage = errorData.error || errorData.message || defaultMessage;
      showAlert(`Erreur ${response.status}: ${errorMessage}`, 'error');
    } catch {
      showAlert(`${defaultMessage} (${response.status})`, 'error');
    }
    return true;
  }
  
  return false;
}

/**
 * Récupère le token CSRF depuis l'API
 * @returns {Promise<string|null>} - Token CSRF ou null si erreur
 */
async function fetchCSRFToken() {
  try {
    const response = await fetch('/api/admin/csrf-token', {
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.json();
      csrfToken = data.token;
      return csrfToken;
    }
    
    console.error('Impossible de récupérer le token CSRF');
    return null;
  } catch (error) {
    console.error('Erreur récupération token CSRF:', error);
    return null;
  }
}

/**
 * Effectue une requête API avec gestion automatique d'erreurs et CSRF
 * @param {string} url - URL de l'API
 * @param {Object} options - Options fetch
 * @param {string} errorMessage - Message d'erreur personnalisé
 * @returns {Promise<Object|null>} - Données JSON ou null si erreur
 */
async function fetchWithErrorHandling(url, options = {}, errorMessage = 'Erreur de communication') {
  try {
    // Ajouter credentials par défaut
    const fetchOptions = {
      credentials: 'include',
      ...options
    };
    
    // Ajouter le token CSRF pour les opérations sensibles
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase())) {
      if (!csrfToken) {
        await fetchCSRFToken();
      }
      
      if (csrfToken) {
        fetchOptions.headers = {
          ...fetchOptions.headers,
          'x-csrf-token': csrfToken
        };
      }
    }
    
    const response = await fetch(url, fetchOptions);
    
    // Si erreur CSRF, récupérer un nouveau token et réessayer
    if (response.status === 403) {
      const errorData = await response.json().catch(() => ({}));
      if (errorData.code === 'CSRF_TOKEN_INVALID' || errorData.code === 'CSRF_TOKEN_MISSING') {
        console.log('Token CSRF invalide, récupération d\'un nouveau token...');
        await fetchCSRFToken();
        
        if (csrfToken) {
          fetchOptions.headers = {
            ...fetchOptions.headers,
            'x-csrf-token': csrfToken
          };
          
          // Réessayer la requête avec le nouveau token
          const retryResponse = await fetch(url, fetchOptions);
          if (await handleAPIError(retryResponse, errorMessage)) {
            return null;
          }
          return await retryResponse.json();
        }
      }
    }
    
    // Gérer les erreurs API
    if (await handleAPIError(response, errorMessage)) {
      return null;
    }
    
    return await response.json();
  } catch (error) {
    console.error(`Erreur fetch ${url}:`, error);
    showAlert(`${errorMessage}: ${error.message}`, 'error');
    return null;
  }
}

/**
 * Échappe les caractères HTML pour éviter XSS
 * @param {string} text - Texte à échapper
 * @returns {string} - Texte échappé
 */
function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Décode les entités HTML en utilisant la constante partagée de core-utils
 * Cette fonction utilise SAFE_HTML_ENTITIES si disponible, sinon fallback
 * @param {string} text - Texte contenant des entités HTML
 * @returns {string} - Texte avec entités décodées
 */
function unescapeHTML(text) {
  // Utiliser la fonction de core-utils si disponible
  if (typeof window !== 'undefined' && typeof window.unescapeHTML === 'function') {
    return window.unescapeHTML(text);
  }
  
  // Fallback basique si core-utils n'est pas chargé
  if (!text || typeof text !== 'string') return text || '';
  
  return text
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

/**
 * Formate une date au format français
 * @param {string|Date} date - Date à formater
 * @returns {string} - Date formatée
 */
function formatDateFR(date) {
  const d = new Date(date);
  return d.toLocaleString('fr-FR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Debounce function pour limiter les appels
 * @param {Function} func - Fonction à debouncer
 * @param {number} wait - Délai en ms
 * @returns {Function} - Fonction debouncée
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Crée un graphique en camembert (pie chart)
 * @param {Array} items - Tableau d'objets { user, answer }
 * @param {Object} config - Configuration { chartWidth, chartHeight }
 * @returns {HTMLElement} - Élément wrapper contenant le canvas
 */
function createPieChart(items, config = {}) {
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
}

/**
 * Crée un élément liste avec gestion des images
 * @param {Array} items - Tableau d'objets { user, answer }
 * @param {Object} config - Configuration pour les images
 * @returns {HTMLElement} - Élément ul avec les items
 */
function createAnswersList(items, config = {}) {
  const ul = document.createElement('ul');
  ul.className = "list-disc pl-5";

  // 🔒 SECURITY: Use same trusted domain validation as view.html
  const TRUSTED_IMAGE_DOMAINS = [
    'res.cloudinary.com',           // Cloudinary CDN (notre service upload)
    'images.unsplash.com',          // Unsplash (si utilisé pour placeholder)
    'via.placeholder.com',          // Placeholder service (si nécessaire)
  ];

  // Fonction de validation sécurisée des images (même logique que view.html)
  function isTrustedImageUrl(url) {
    if (!url || typeof url !== 'string') return false;
    
    try {
      const urlObj = new URL(url);
      
      // 1. Force HTTPS only
      if (urlObj.protocol !== 'https:') return false;
      
      // 2. Check if domain is in whitelist
      const hostname = urlObj.hostname.toLowerCase();
      const isTrustedDomain = TRUSTED_IMAGE_DOMAINS.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      if (!isTrustedDomain) return false;
      
      // 3. Special handling for Cloudinary URLs (don't always have extensions)
      const pathname = urlObj.pathname.toLowerCase();
      if (hostname === 'res.cloudinary.com' || hostname.endsWith('.cloudinary.com')) {
        // Cloudinary URLs follow pattern: /cloud_name/image/upload/...
        // They're trusted if they match the domain, regardless of extension
        return pathname.includes('/image/upload/');
      } else {
        // For other domains, verify file extension for images
        const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        const hasValidExtension = validExtensions.some(ext => 
          pathname.includes(ext)
        );
        if (!hasValidExtension) return false;
      }
      
      return true;
    } catch (e) {
      // Invalid URL format
      return false;
    }
  }

  items.forEach(({ user, answer }) => {
    const li = document.createElement('li');
    
    // DEBUG: Log pour comprendre pourquoi les images d'août ne s'affichent pas
    if (answer && (answer.includes('http') || answer.includes('cloudinary'))) {
      console.log(`🖼️ Image candidate: ${user} -> ${answer.substring(0, 100)}...`);
      console.log(`🔍 isTrustedImageUrl result:`, isTrustedImageUrl(answer));
    }
    
    // 🔒 SECURITY: Use trusted image validation instead of regex
    const isImage = isTrustedImageUrl(answer);

    if (isImage) {
      // Miniature cliquable
      const img = document.createElement('img');
      img.src = answer;
      img.alt = `Image de ${user}`;
      img.className = `${config.thumbnailSize || 'w-16 h-16'} object-cover inline-block mr-2 border cursor-pointer`;
      
      // Gestion erreur de chargement image avec fallback configuré
      img.onerror = function() {
        // Éviter les tentatives de rechargement en boucle
        if (!this.dataset.fallbackApplied) {
          this.dataset.fallbackApplied = 'true';
          this.src = config.fallbackSvg || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0yNCAyOEMyNiAyNiAyOCAyNiAzMCAyOEMzMiAzMCAzNCAzMCAzNiAyOEMzOCAyNiA0MCAyNiA0MiAyOFY0MEgyMlYyOFoiIGZpbGw9IiNEMUQ1REIiLz4KPHA+SW1hZ2UgaW5kaXNwb25pYmxlPC9wPgo8L3N2Zz4K';
          this.alt = `Image indisponible (${user})`;
          this.title = 'Image Cloudinary inaccessible';
        }
      };

      // Ouverture de la lightbox quand on clique
      img.onclick = () => {
        createLightbox(answer, img.alt, user, {
          maxWidth: config.lightboxMaxSize || '90%',
          maxHeight: config.lightboxMaxSize || '90%'
        });
      };

      li.appendChild(img);
      li.appendChild(document.createTextNode(` ${user}`));
    } else {
      // Décoder les entités HTML pour un affichage correct
      li.textContent = `${user} : ${unescapeHTML(answer)}`;
    }

    ul.appendChild(li);
  });

  return ul;
}

/**
 * Crée et affiche une lightbox pour une image
 * @param {string} imageSrc - URL de l'image à afficher
 * @param {string} imageAlt - Texte alternatif de l'image
 * @param {string} caption - Légende à afficher
 * @param {Object} config - Configuration optionnelle { maxWidth, maxHeight }
 */
function createLightbox(imageSrc, imageAlt = '', caption = '', config = {}) {
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
    captionDiv.textContent = caption; // Utilise textContent pour éviter XSS
    overlay.appendChild(captionDiv);
  }

  // Fermeture par clic en dehors de l'image
  overlay.addEventListener('click', e => {
    if (e.target === overlay) document.body.removeChild(overlay);
  });

  document.body.appendChild(overlay);
}

/**
 * Initialise les utilitaires admin (récupère le token CSRF)
 * À appeler au chargement de chaque page admin
 */
async function initAdminUtils() {
  await fetchCSRFToken();
}

// Auto-initialisation si on est dans un navigateur
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', initAdminUtils);
}

// Export pour usage en module (si supporté)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    showAlert,
    handleAPIError,
    fetchWithErrorHandling,
    fetchCSRFToken,
    escapeHTML,
    unescapeHTML,
    formatDateFR,
    debounce,
    createPieChart,
    createAnswersList,
    createLightbox,
    initAdminUtils
  };
}