/**
 * Helpers pour générer des données de test valides
 */

const { QUESTIONS } = require('../../utils/questions');

/**
 * Génère un array de réponses valides (10 réponses obligatoires)
 * @param {Object} overrides - Personnalisations optionnelles
 * @returns {Array} Array de 10 réponses
 */
function createValidResponses(overrides = {}) {
  const defaultResponses = [
    { question: QUESTIONS[0].question, answer: overrides.q1 || 'ça va' },
    { question: QUESTIONS[1].question, answer: overrides.q2 || 'Un mois tranquille' },
    { question: QUESTIONS[2].question, answer: overrides.q3 || 'https://res.cloudinary.com/test/photo1.jpg' },
    { question: QUESTIONS[3].question, answer: overrides.q4 || 'Une super série' },
    { question: QUESTIONS[4].question, answer: overrides.q5 || 'https://res.cloudinary.com/test/photo2.jpg' },
    { question: QUESTIONS[5].question, answer: overrides.q6 || 'Un moment sympa entre amis' },
    { question: QUESTIONS[6].question, answer: overrides.q7 || 'https://res.cloudinary.com/test/screenshot.jpg' },
    { question: QUESTIONS[7].question, answer: overrides.q8 || 'Une rencontre inattendue' },
    { question: QUESTIONS[8].question, answer: overrides.q9 || 'https://open.spotify.com/track/123' },
    { question: QUESTIONS[9].question, answer: overrides.q10 || 'Rien de spécial ce mois-ci' }
  ];

  // Ajouter la question 11 optionnelle si spécifiée
  if (overrides.q11) {
    defaultResponses.push({
      question: QUESTIONS[10].question,
      answer: overrides.q11
    });
  }

  return defaultResponses;
}

/**
 * Génère un token unique de 64 caractères
 * @returns {string} Token unique
 */
function generateUniqueToken() {
  const randomPart = Math.random().toString(36).substring(2);
  const timestampPart = Date.now().toString(36);
  const token = (randomPart + timestampPart + randomPart).substring(0, 64);
  return token.padEnd(64, '0'); // S'assurer que c'est exactement 64 chars
}

module.exports = {
  createValidResponses,
  generateUniqueToken
};
