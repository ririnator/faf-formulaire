/**
 * GET /api/admin/dashboard
 *
 * Récupère les statistiques et réponses du dashboard admin
 * Authentifié via JWT + Paywall protection
 * Filtrage optionnel par mois
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

    // 3. Extraire le paramètre de mois (optionnel)
    const { month } = req.query;

    // Valider le format du mois si fourni
    if (month && !/^\d{4}-\d{2}$/.test(month)) {
      return res.status(400).json({ error: 'Invalid month format. Expected YYYY-MM' });
    }

    // 4. Utiliser le client Supabase admin
    const supabase = supabaseAdmin;

    // 5. Construire la requête de base (filtré par owner_id)
    let responsesQuery = supabase
      .from('responses')
      .select('*')
      .eq('owner_id', adminId)
      .order('created_at', { ascending: false });

    // Filtrer par mois si spécifié
    if (month) {
      responsesQuery = responsesQuery.eq('month', month);
    }

    // Exécuter la requête
    const { data: allResponses, error: responsesError } = await responsesQuery;

    if (responsesError) {
      console.error('Error fetching responses:', responsesError);
      return res.status(500).json({ error: 'Error fetching responses' });
    }

    // 6. Séparer les réponses admin vs amis
    const adminResponses = allResponses.filter(r => r.is_owner === true);
    const friendResponses = allResponses.filter(r => r.is_owner === false);

    // 7. Calculer les statistiques
    const stats = {
      totalResponses: friendResponses.length,
      currentMonth: month || new Date().toISOString().slice(0, 7),
      responseRate: '0%',
      question1Distribution: {}
    };

    // Calculer la distribution de la question 1 (camembert)
    if (friendResponses.length > 0) {
      const question1Answers = friendResponses
        .map(r => {
          const responses = r.responses || [];
          const firstResponse = responses[0];
          return firstResponse ? firstResponse.answer : null;
        })
        .filter(answer => answer !== null);

      // Compter les occurrences de chaque réponse
      question1Answers.forEach(answer => {
        stats.question1Distribution[answer] = (stats.question1Distribution[answer] || 0) + 1;
      });
    }

    // 7b. Agréger toutes les réponses par question (nouveau)
    const questionsSummary = [];
    if (friendResponses.length > 0) {
      // Trouver la réponse avec le plus de questions (pour capturer toutes les questions)
      const responseWithMostQuestions = friendResponses.reduce((max, r) => {
        const rLength = (r.responses || []).length;
        const maxLength = (max.responses || []).length;
        return rLength > maxLength ? r : max;
      }, friendResponses[0]);

      const questions = responseWithMostQuestions.responses || [];

      questions.forEach((q, index) => {
        const allAnswersForQuestion = friendResponses
          .map(r => {
            const response = (r.responses || [])[index];
            return response ? {
              name: r.name,
              answer: response.answer
            } : null;
          })
          .filter(a => a !== null);

        questionsSummary.push({
          question: q.question,
          answers: allAnswersForQuestion
        });
      });
    }

    // Calculer le taux d'évolution (comparer avec le mois précédent)
    if (month) {
      const [year, monthNum] = month.split('-').map(Number);
      const prevMonth = monthNum === 1
        ? `${year - 1}-12`
        : `${year}-${String(monthNum - 1).padStart(2, '0')}`;

      const { data: prevMonthResponses } = await supabase
        .from('responses')
        .select('id', { count: 'exact' })
        .eq('owner_id', adminId)
        .eq('month', prevMonth)
        .eq('is_owner', false);

      const prevCount = prevMonthResponses?.length || 0;
      const currentCount = friendResponses.length;

      if (prevCount > 0) {
        const rate = Math.round(((currentCount - prevCount) / prevCount) * 100);
        stats.responseRate = rate > 0 ? `+${rate}%` : `${rate}%`;
      }
    }

    // 8. Récupérer la liste des mois disponibles
    const { data: monthsData } = await supabase
      .from('responses')
      .select('month')
      .eq('owner_id', adminId)
      .order('month', { ascending: false });

    const months = [...new Set(monthsData?.map(r => r.month) || [])];

    // 9. Formatter les réponses pour le frontend
    const responses = friendResponses.map(r => {
      const firstAnswer = r.responses && r.responses[0] ? r.responses[0].answer : '';
      return {
        id: r.id,
        name: r.name,
        createdAt: r.created_at,
        preview: firstAnswer.length > 50 ? firstAnswer.slice(0, 50) + '...' : firstAnswer
      };
    });

    // 10. Retourner les données
    return res.status(200).json({
      success: true,
      stats,
      responses,
      months,
      adminHasFilled: adminResponses.length > 0,
      questionsSummary // Nouveau champ avec toutes les questions/réponses
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = withPaymentRequired(handler);