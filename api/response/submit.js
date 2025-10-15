/**
 * API Route: POST /api/response/submit
 *
 * Permet la soumission de réponses au formulaire d'un admin
 * Route publique avec rate limiting et validation stricte
 */

const { createClient } = require('../../config/supabase');
const { generateToken } = require('../../utils/tokens');
const {
  validateName,
  validateResponses,
  validateHoneypot
} = require('../../utils/validation');
const { createRateLimiter } = require('../../middleware/rateLimit');

// Rate limiter : 3 soumissions / 15 minutes
const rateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: 'Vous avez soumis trop de formulaires. Réessayez dans 15 minutes.'
});

/**
 * Handler principal de la route
 */
async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  // 2. Appliquer le rate limiting
  const rateLimitResult = rateLimiter(req, res, null);
  if (rateLimitResult !== undefined) {
    // Le rate limiter a déjà envoyé une réponse
    return rateLimitResult;
  }

  try {
    // 3. Extraire les données du body
    const { username, name, responses, website } = req.body;

    // 4. Validation honeypot (anti-spam)
    if (!validateHoneypot(website)) {
      return res.status(400).json({
        success: false,
        error: 'Spam detected',
        message: 'Votre soumission a été détectée comme spam'
      });
    }

    // 5. Validation des champs requis
    if (!username || !name || !responses) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        message: 'Veuillez remplir tous les champs obligatoires'
      });
    }

    // 6. Validation du nom
    const nameValidation = validateName(name);
    if (!nameValidation.valid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid name',
        message: nameValidation.error
      });
    }

    // 7. Validation des réponses
    const responsesValidation = validateResponses(responses);
    if (!responsesValidation.valid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid responses',
        message: 'Certaines réponses sont invalides',
        details: responsesValidation.errors
      });
    }

    // 8. Connexion Supabase
    const supabase = createClient();

    // 9. Lookup admin par username
    const normalizedUsername = username.toLowerCase().trim();
    const { data: admin, error: adminError } = await supabase
      .from('admins')
      .select('id, username')
      .eq('username', normalizedUsername)
      .single();

    if (adminError || !admin) {
      return res.status(404).json({
        success: false,
        error: 'Admin not found',
        message: `Le formulaire de "${normalizedUsername}" n'existe pas`
      });
    }

    // 10. Déterminer si c'est l'admin qui répond (is_owner)
    const cleanName = name.trim();
    const isOwner = cleanName.toLowerCase() === admin.username.toLowerCase();

    // 11. Générer le mois actuel (YYYY-MM)
    const now = new Date();
    const month = now.toISOString().slice(0, 7); // "2025-01"

    // 12. Si c'est l'admin, vérifier qu'il n'a pas déjà répondu ce mois
    if (isOwner) {
      const { data: existingOwnerResponse } = await supabase
        .from('responses')
        .select('id')
        .eq('owner_id', admin.id)
        .eq('month', month)
        .eq('is_owner', true)
        .single();

      if (existingOwnerResponse) {
        return res.status(409).json({
          success: false,
          error: 'Already submitted',
          message: 'Vous avez déjà rempli votre formulaire ce mois-ci'
        });
      }
    }

    // 13. Générer un token (seulement si ce n'est pas l'admin)
    const token = isOwner ? null : generateToken();

    // 14. Préparer les données à insérer
    const responseData = {
      owner_id: admin.id,
      name: cleanName,
      responses: responsesValidation.cleaned, // Réponses nettoyées et échappées
      month: month,
      is_owner: isOwner,
      token: token
    };

    // 15. Insérer dans Supabase
    const { data: insertedResponse, error: insertError } = await supabase
      .from('responses')
      .insert(responseData)
      .select()
      .single();

    if (insertError) {
      console.error('Supabase insert error:', insertError);

      // Gestion d'erreur spécifique pour la contrainte unique
      if (insertError.code === '23505') {
        return res.status(409).json({
          success: false,
          error: 'Duplicate submission',
          message: 'Vous avez déjà soumis une réponse ce mois-ci'
        });
      }

      return res.status(500).json({
        success: false,
        error: 'Database error',
        message: 'Une erreur est survenue lors de l\'enregistrement'
      });
    }

    // 16. Construire la réponse
    const response = {
      success: true,
      message: 'Réponse enregistrée avec succès !',
      userName: cleanName,
      adminName: admin.username
    };

    // 17. Ajouter le lien privé (seulement pour les non-admins)
    if (!isOwner && token) {
      // Construire l'URL de base dynamiquement depuis la requête
      const protocol = req.headers['x-forwarded-proto'] || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
      const baseUrl = `${protocol}://${host}`;

      response.link = `${baseUrl}/view/${token}`;
    }

    // 18. Retourner la réponse
    return res.status(201).json(response);

  } catch (error) {
    // Gestion globale des erreurs
    console.error('Error in /api/response/submit:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Une erreur est survenue lors du traitement de votre formulaire'
    });
  }
}

module.exports = handler;
