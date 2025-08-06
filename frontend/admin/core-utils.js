/**
 * Utilitaires essentiels chargés de manière synchrone
 * Contient uniquement les fonctions critiques pour éviter les problèmes d'initialisation
 */

// Constante partagée pour le décodage sécurisé des entités HTML
const SAFE_HTML_ENTITIES = {
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

/**
 * Décode les entités HTML en utilisant une liste blanche sécurisée
 * @param {string} text - Texte contenant des entités HTML
 * @returns {string} - Texte avec entités décodées
 */
function unescapeHTML(text) {
  if (!text || typeof text !== 'string') return text || '';
  
  let result = text;
  for (const [entity, char] of Object.entries(SAFE_HTML_ENTITIES)) {
    result = result.replace(new RegExp(entity, 'g'), char);
  }
  
  return result;
}

/**
 * Fonction d'alerte simplifiée pour les cas d'urgence
 * @param {string} message - Message à afficher
 * @param {string} type - Type d'alerte ('error' | 'success')
 */
function coreAlert(message, type = 'error') {
  const alertDiv = document.getElementById('alertMessage');
  if (alertDiv) {
    const baseClasses = 'mb-4 p-4 rounded-lg';
    const typeClasses = type === 'error' 
      ? 'bg-red-100 text-red-700 border border-red-300'
      : 'bg-green-100 text-green-700 border border-green-300';
    alertDiv.className = `${baseClasses} ${typeClasses}`;
    alertDiv.textContent = message;
    alertDiv.classList.remove('hidden');
  } else {
    alert(message); // Dernier recours
  }
}

// Export global pour compatibilité navigateur
if (typeof window !== 'undefined') {
  window.unescapeHTML = unescapeHTML;
  window.coreAlert = coreAlert;
  window.SAFE_HTML_ENTITIES = SAFE_HTML_ENTITIES;
}

// Export module pour Node.js (si nécessaire)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    unescapeHTML,
    coreAlert,
    SAFE_HTML_ENTITIES
  };
}