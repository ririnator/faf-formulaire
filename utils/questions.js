/**
 * Questions du formulaire FAF
 * Liste centralisée des 11 questions du formulaire mensuel
 */

const QUESTIONS = [
  {
    id: 'q1',
    type: 'radio',
    question: 'En rapide, comment ça va ?',
    options: ['ça va', 'a connu meilleur mois', 'ITS JOEVER', "WE'RE BARACK"],
    required: true
  },
  {
    id: 'q2',
    type: 'textarea',
    question: 'Possibilité d\'ajouter un peu plus de détails...',
    maxLength: 10000,
    required: true
  },
  {
    id: 'q3',
    type: 'file',
    question: 'Photo de toi ce mois-ci',
    accept: 'image/*',
    required: true
  },
  {
    id: 'q4',
    type: 'text',
    question: 'Une chose qui t\'a fait kiffer ce mois-ci ? (série, jeu, bouquin, vidéo...)',
    maxLength: 500,
    required: true
  },
  {
    id: 'q5',
    type: 'file',
    question: 'Une photo du meilleur moment du mois',
    accept: 'image/*',
    required: true
  },
  {
    id: 'q6',
    type: 'textarea',
    question: 'Un truc sympa qui t\'est arrivé ce mois-ci ?',
    maxLength: 10000,
    required: true
  },
  {
    id: 'q7',
    type: 'file',
    question: 'Screenshot le plus intéressant du mois',
    accept: 'image/*',
    required: true
  },
  {
    id: 'q8',
    type: 'textarea',
    question: 'La chose la plus random qui t\'est arrivée ce mois-ci ?',
    maxLength: 10000,
    required: true
  },
  {
    id: 'q9',
    type: 'text',
    question: 'Ta musique du mois (lien Spotify/YouTube)',
    maxLength: 500,
    required: true
  },
  {
    id: 'q10',
    type: 'textarea',
    question: 'Un truc que tu veux partager avec le groupe ?',
    maxLength: 10000,
    required: true
  },
  {
    id: 'q11',
    type: 'file',
    question: 'Photo bonus (optionnelle)',
    accept: 'image/*',
    required: false
  }
];

/**
 * Récupère la liste des questions du formulaire
 * @returns {Array} Liste des questions
 */
function getQuestions() {
  return QUESTIONS;
}

/**
 * Récupère une question spécifique par son ID
 * @param {string} questionId - ID de la question
 * @returns {Object|null} Question ou null si non trouvée
 */
function getQuestionById(questionId) {
  return QUESTIONS.find(q => q.id === questionId) || null;
}

/**
 * Valide que toutes les questions requises ont été répondues
 * @param {Array} responses - Réponses soumises
 * @returns {Object} { valid: boolean, missing: Array }
 */
function validateRequiredQuestions(responses) {
  const requiredQuestions = QUESTIONS.filter(q => q.required);
  const answeredQuestions = responses.map(r => r.question);

  const missing = requiredQuestions
    .filter(q => !answeredQuestions.includes(q.question))
    .map(q => q.question);

  return {
    valid: missing.length === 0,
    missing
  };
}

module.exports = {
  QUESTIONS,
  getQuestions,
  getQuestionById,
  validateRequiredQuestions
};
