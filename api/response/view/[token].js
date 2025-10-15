/**
 * API Route: GET /api/response/view/[token]
 * Description: Récupère une comparaison privée "Ami vs Admin" via un token unique
 *
 * Flow:
 * 1. Valider le format du token
 * 2. Récupérer la réponse utilisateur par token
 * 3. Récupérer le owner_id et le mois
 * 4. Récupérer la réponse admin (owner_id + is_owner=true + même mois)
 * 5. Récupérer le username de l'admin
 * 6. Retourner les deux réponses en format comparatif
 *
 * Étape 5 du développement multi-tenant
 */

const { createClient } = require('../../../config/supabase');
const { isValidToken } = require('../../../utils/tokens');

/**
 * Handler principal de la route
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
    // 2. Extraire le token de l'URL
    const { token } = req.query;

    // 3. Validation du format du token
    if (!token || typeof token !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Token is required'
      });
    }

    if (!isValidToken(token)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid token format'
      });
    }

    // 4. Créer le client Supabase (service role pour bypass RLS)
    const supabase = createClient();

    // 5. Récupérer la réponse utilisateur par token
    const { data: userResponse, error: userError } = await supabase
      .from('responses')
      .select('id, owner_id, name, responses, month, created_at')
      .eq('token', token)
      .single();

    if (userError || !userResponse) {
      console.error('Error fetching user response:', userError);
      return res.status(404).json({
        success: false,
        error: 'Token not found',
        message: 'Ce lien est invalide ou a expiré.'
      });
    }

    // 6. Récupérer la réponse de l'admin (même owner_id + is_owner=true + même mois)
    const { data: adminResponse, error: adminError } = await supabase
      .from('responses')
      .select('name, responses, month')
      .eq('owner_id', userResponse.owner_id)
      .eq('is_owner', true)
      .eq('month', userResponse.month)
      .single();

    if (adminError || !adminResponse) {
      console.error('Error fetching admin response:', adminError);
      return res.status(404).json({
        success: false,
        error: 'Admin response not found',
        message: 'L\'administrateur n\'a pas encore rempli son formulaire pour ce mois.'
      });
    }

    // 7. Récupérer le username de l'admin
    const { data: adminInfo, error: adminInfoError } = await supabase
      .from('admins')
      .select('username')
      .eq('id', userResponse.owner_id)
      .single();

    if (adminInfoError || !adminInfo) {
      console.error('Error fetching admin info:', adminInfoError);
      return res.status(500).json({
        success: false,
        error: 'Failed to fetch admin info'
      });
    }

    // 8. Formater le mois pour affichage (2025-01 → Janvier 2025)
    const monthName = formatMonthName(userResponse.month);

    // 9. Retourner la comparaison
    return res.status(200).json({
      success: true,
      user: {
        name: userResponse.name,
        responses: userResponse.responses,
        month: userResponse.month,
        createdAt: userResponse.created_at
      },
      admin: {
        name: adminResponse.name,
        responses: adminResponse.responses,
        month: adminResponse.month
      },
      adminUsername: adminInfo.username,
      monthName: monthName
    });

  } catch (error) {
    console.error('View API error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Une erreur est survenue lors de la récupération des données.'
    });
  }
}

/**
 * Formate un mois YYYY-MM en format lisible
 * @param {string} month - Format YYYY-MM (ex: "2025-01")
 * @returns {string} - Format lisible (ex: "Janvier 2025")
 */
function formatMonthName(month) {
  const months = {
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

  const [year, monthNum] = month.split('-');
  const monthName = months[monthNum] || monthNum;

  return `${monthName} ${year}`;
}

// Export pour Vercel et tests
module.exports = handler;
module.exports.default = handler;
