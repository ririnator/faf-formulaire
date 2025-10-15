/**
 * Shared utility for question normalization
 * Ensures consistency across the application for question matching and grouping
 */

/**
 * Normalise une question pour comparaison et regroupement
 * - Supprime les accents et caractères diacritiques
 * - Convertit en minuscules
 * - Supprime la ponctuation
 * - Normalise les espaces
 * - Supprime les caractères de contrôle
 * 
 * @param {string} question - La question à normaliser
 * @returns {string} - Question normalisée pour comparaison
 */
function normalizeQuestion(question) {
  if (!question || typeof question !== 'string') return '';
  
  const normalized = question
    .trim()
    .replace(/\s+/g, ' ')  // Remplacer espaces multiples par un seul
    .toLowerCase()
    // Supprimer caractères invisibles/contrôle
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '')
    // Normaliser accents Unicode (NFD puis supprimer diacritiques)
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    // Supprimer ponctuation mais garder lettres/nombres/espaces
    .replace(/[^\p{L}\p{N}\s]/gu, '')
    .trim();
    
  // Debug détaillé pour diagnostiquer (STRICTEMENT développement local)
  if (process.env.NODE_ENV === 'development' && !process.env.RENDER && process.env.DEBUG_NORMALIZATION) {
    const questionHex = Array.from(question).map(c => `${c}(${c.charCodeAt(0).toString(16)})`).join(' ');
    console.log(`🔍 Normalisation: "${question.substring(0, 50)}..." → "${normalized.substring(0, 50)}..."`);
  }
  
  return normalized;
}

/**
 * Version legacy de normalisation pour la compatibilité
 * @deprecated Utiliser normalizeQuestion à la place
 */
function normalizeForComparison(question) {
  return normalizeQuestion(question);
}

/**
 * Teste si deux questions sont considérées comme identiques après normalisation
 * @param {string} question1 - Première question
 * @param {string} question2 - Deuxième question  
 * @returns {boolean} - true si les questions sont équivalentes
 */
function areQuestionsEquivalent(question1, question2) {
  return normalizeQuestion(question1) === normalizeQuestion(question2);
}

/**
 * Trouve l'index d'une question dans un tableau de questions de référence
 * @param {string} question - Question à rechercher
 * @param {string[]} referenceQuestions - Tableau de questions de référence
 * @returns {number} - Index trouvé ou -1 si non trouvé
 */
function findQuestionIndex(question, referenceQuestions) {
  const normalizedQuestion = normalizeQuestion(question);
  return referenceQuestions.findIndex(refQ => normalizeQuestion(refQ) === normalizedQuestion);
}

module.exports = {
  normalizeQuestion,
  normalizeForComparison, // Pour compatibilité descendante
  areQuestionsEquivalent,
  findQuestionIndex
};