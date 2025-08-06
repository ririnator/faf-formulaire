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
    formatDateFR,
    debounce,
    initAdminUtils
  };
}