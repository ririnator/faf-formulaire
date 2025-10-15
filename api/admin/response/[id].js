/**
 * GET/PATCH/DELETE /api/admin/response/[id]
 *
 * Gestion d'une réponse individuelle
 * - GET: Récupérer les détails d'une réponse
 * - PATCH: Modifier une réponse
 * - DELETE: Supprimer une réponse
 *
 * Authentifié via JWT
 * RLS de Supabase vérifie automatiquement owner_id
 */

const { verifyToken } = require('../../../utils/jwt');
const { supabaseAdmin } = require('../../../utils/supabase');
const { escapeHtml, validateResponses, isCloudinaryUrl } = require('../../../utils/validation');

async function handler(req, res) {
  try {
    // 1. Vérifier le JWT
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized - Missing token' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded || !decoded.sub) {
      return res.status(401).json({ error: 'Unauthorized - Invalid or expired token' });
    }

    const adminId = decoded.sub;

    // 2. Extraire l'ID de la réponse depuis l'URL
    const { id } = req.query;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid response ID' });
    }

    // 3. Utiliser le client Supabase admin
    const supabase = supabaseAdmin;

    // 4. Router selon la méthode HTTP
    switch (req.method) {
      case 'GET':
        return await handleGet(supabase, adminId, id, res);

      case 'PATCH':
        return await handlePatch(supabase, adminId, id, req.body, res);

      case 'DELETE':
        return await handleDelete(supabase, adminId, id, res);

      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }

  } catch (error) {
    console.error('Response handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * GET - Récupérer une réponse
 */
async function handleGet(supabase, adminId, responseId, res) {
  const { data: response, error } = await supabase
    .from('responses')
    .select('*')
    .eq('id', responseId)
    .eq('owner_id', adminId) // Vérifier que l'admin possède cette réponse
    .single();

  if (error || !response) {
    return res.status(404).json({ error: 'Response not found or access denied' });
  }

  return res.status(200).json({
    success: true,
    response
  });
}

/**
 * PATCH - Modifier une réponse
 */
async function handlePatch(supabase, adminId, responseId, body, res) {
  // 1. Vérifier que la réponse existe et appartient à l'admin
  const { data: existingResponse, error: fetchError } = await supabase
    .from('responses')
    .select('*')
    .eq('id', responseId)
    .eq('owner_id', adminId)
    .single();

  if (fetchError || !existingResponse) {
    return res.status(404).json({ error: 'Response not found or access denied' });
  }

  // 2. Extraire les champs à mettre à jour
  const { name, responses } = body;

  // 3. Valider les données si fournies
  const updates = {};

  if (name !== undefined) {
    if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
      return res.status(400).json({ error: 'Name must be between 2 and 100 characters' });
    }
    updates.name = escapeHtml(name.trim());
  }

  if (responses !== undefined) {
    if (!Array.isArray(responses)) {
      return res.status(400).json({ error: 'Responses must be an array' });
    }

    // Valider le format des réponses
    const validation = validateResponses(responses);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Échapper les réponses (préserver les URLs Cloudinary)
    const escapedResponses = responses.map(r => ({
      question: escapeHtml(r.question),
      answer: isCloudinaryUrl(r.answer) ? r.answer : escapeHtml(r.answer)
    }));

    updates.responses = escapedResponses;
  }

  // 4. Si aucun champ à mettre à jour
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  // 5. Mettre à jour dans Supabase
  const { data: updatedResponse, error: updateError } = await supabase
    .from('responses')
    .update(updates)
    .eq('id', responseId)
    .eq('owner_id', adminId)
    .select()
    .single();

  if (updateError) {
    console.error('Update error:', updateError);
    return res.status(500).json({ error: 'Error updating response' });
  }

  return res.status(200).json({
    success: true,
    response: updatedResponse
  });
}

/**
 * DELETE - Supprimer une réponse
 */
async function handleDelete(supabase, adminId, responseId, res) {
  // 1. Vérifier que la réponse existe et appartient à l'admin
  const { data: existingResponse, error: fetchError } = await supabase
    .from('responses')
    .select('id')
    .eq('id', responseId)
    .eq('owner_id', adminId)
    .single();

  if (fetchError || !existingResponse) {
    return res.status(404).json({ error: 'Response not found or access denied' });
  }

  // 2. Supprimer la réponse
  const { error: deleteError } = await supabase
    .from('responses')
    .delete()
    .eq('id', responseId)
    .eq('owner_id', adminId);

  if (deleteError) {
    console.error('Delete error:', deleteError);
    return res.status(500).json({ error: 'Error deleting response' });
  }

  // 3. Retourner succès avec message
  return res.status(200).json({
    success: true,
    message: 'Réponse supprimée avec succès'
  });
}

module.exports = handler;
