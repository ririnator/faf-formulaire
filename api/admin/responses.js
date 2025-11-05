/**
 * GET /api/admin/responses
 *
 * Liste paginée des réponses d'un admin
 * Authentifié via JWT + Paywall protection
 * Filtrage optionnel par mois
 * Pagination configurable
 */

const { withPaymentRequired } = require('../../middleware/payment');
const { supabaseAdmin } = require('../../utils/supabase');

async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 2. adminId est déjà disponible via withPaymentRequired middleware
    const adminId = req.adminId;

    // 3. Extraire les paramètres de query
    const { month, page = '1', limit = '50', search } = req.query;

    // Valider les paramètres
    if (month && !/^\d{4}-\d{2}$/.test(month)) {
      return res.status(400).json({ error: 'Invalid month format. Expected YYYY-MM' });
    }

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    if (isNaN(pageNum) || pageNum < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
      return res.status(400).json({ error: 'Invalid limit. Must be between 1 and 100' });
    }

    // 4. Utiliser le client Supabase admin
    const supabase = supabaseAdmin;

    // 5. Construire la requête avec filtres
    let responsesQuery = supabase
      .from('responses')
      .select('*', { count: 'exact' })
      .eq('owner_id', adminId)
      .order('created_at', { ascending: false });

    // Filtrer par mois si spécifié
    if (month) {
      responsesQuery = responsesQuery.eq('month', month);
    }

    // Filtrer par recherche si spécifié
    if (search && search.trim()) {
      responsesQuery = responsesQuery.ilike('name', `%${search.trim()}%`);
    }

    // Appliquer la pagination
    const offset = (pageNum - 1) * limitNum;
    responsesQuery = responsesQuery.range(offset, offset + limitNum - 1);

    // 6. Exécuter la requête
    const { data: responses, error: responsesError, count } = await responsesQuery;

    if (responsesError) {
      console.error('Error fetching responses:', responsesError);
      return res.status(500).json({ error: 'Error fetching responses' });
    }

    // 7. Calculer les métadonnées de pagination
    const totalPages = Math.ceil(count / limitNum);

    // 8. Retourner les données
    return res.status(200).json({
      success: true,
      responses: responses || [],
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: count,
        totalPages
      }
    });

  } catch (error) {
    console.error('Responses list error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = withPaymentRequired(handler);