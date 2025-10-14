/**
 * API Route: GET /api/form/[username]
 *
 * Permet de récupérer le formulaire d'un admin spécifique
 * Route publique (pas d'authentification requise)
 */

const { createClient } = require('../../config/supabase');
const { getQuestions } = require('../../utils/questions');

/**
 * Handler principal de la route
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'GET') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  try {
    // 2. Extraire le username depuis l'URL
    // Pour Vercel : req.query.username
    // Pour Next.js : req.query.username
    const username = req.query.username;

    if (!username) {
      return res.status(400).json({
        success: false,
        error: 'Username parameter is required'
      });
    }

    // 3. Normaliser le username (lowercase, trim)
    const normalizedUsername = username.toLowerCase().trim();

    // 4. Validation basique du format username
    const usernameRegex = /^[a-z0-9_-]{3,20}$/;
    if (!usernameRegex.test(normalizedUsername)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid username format'
      });
    }

    // 5. Connexion à Supabase
    const supabase = createClient();

    // 6. Chercher l'admin par username
    const { data: admin, error: adminError } = await supabase
      .from('admins')
      .select('id, username')
      .eq('username', normalizedUsername)
      .single();

    // 7. Gérer les erreurs
    if (adminError) {
      if (adminError.code === 'PGRST116') {
        // Aucun résultat trouvé
        return res.status(404).json({
          success: false,
          error: 'Admin not found',
          message: `Le formulaire de "${normalizedUsername}" n'existe pas`
        });
      }

      // Autre erreur Supabase
      console.error('Supabase error:', adminError);
      return res.status(500).json({
        success: false,
        error: 'Database error'
      });
    }

    // 8. Récupérer les questions du formulaire
    const questions = getQuestions();

    // 9. Construire la réponse
    const response = {
      success: true,
      admin: {
        username: admin.username,
        formUrl: `/form/${admin.username}`
      },
      questions: questions,
      metadata: {
        totalQuestions: questions.length,
        requiredQuestions: questions.filter(q => q.required).length,
        optionalQuestions: questions.filter(q => !q.required).length
      }
    };

    // 10. Retourner la réponse
    return res.status(200).json(response);

  } catch (error) {
    // Gestion globale des erreurs
    console.error('Error in /api/form/[username]:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Une erreur est survenue lors de la récupération du formulaire'
    });
  }
}

module.exports = handler;
