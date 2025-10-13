-- ============================================
-- FAF Multi-Tenant - Correction RLS Policy
-- ============================================
-- Ce script supprime la policy trop permissive "select_by_token_public"
-- À exécuter après avoir appliqué 01_create_tables.sql et 02_create_rls.sql

-- ============================================
-- Problème identifié
-- ============================================
-- La policy "select_by_token_public" permettait à tous les utilisateurs anonymes
-- de voir TOUTES les réponses ayant un token (non-null), au lieu de filtrer
-- par un token spécifique.
--
-- Exemple du problème:
-- SELECT * FROM responses WHERE token IS NOT NULL;
-- → Retourne TOUTES les réponses (breach de sécurité)
--
-- Au lieu de:
-- SELECT * FROM responses WHERE token = 'abc123...';
-- → Retourne uniquement la réponse correspondante

-- ============================================
-- Solution
-- ============================================
-- Supprimer la policy problématique
DROP POLICY IF EXISTS "select_by_token_public" ON responses;

-- ============================================
-- Architecture corrigée
-- ============================================
-- L'accès public via token se fera via service_role côté backend API:
--
-- // Dans /api/response/view/[token].js
-- const { supabaseAdmin } = require('./utils/supabase');
--
-- const { data } = await supabaseAdmin
--   .from('responses')
--   .select('*')
--   .eq('token', req.params.token)
--   .single();
--
-- Service role bypass RLS de manière sécurisée et filtre par token spécifique

-- ============================================
-- Vérification
-- ============================================
-- Vérifier que la policy a été supprimée
SELECT
  tablename,
  policyname,
  cmd
FROM pg_policies
WHERE tablename = 'responses'
ORDER BY policyname;

-- Résultat attendu (5 policies, sans select_by_token_public):
-- tablename  | policyname              | cmd
-- -----------+-------------------------+--------
-- responses  | delete_own_responses    | DELETE
-- responses  | insert_own_responses    | INSERT
-- responses  | insert_public_responses | INSERT
-- responses  | select_own_responses    | SELECT
-- responses  | update_own_responses    | UPDATE

-- ============================================
-- Test d'isolation
-- ============================================
-- Vérifier que les utilisateurs anonymes ne peuvent plus voir les réponses
-- (Doit retourner 0 résultats en utilisant anon key)

-- Note: Ce test ne peut pas être exécuté directement ici car il nécessite
-- un contexte auth.role() = 'anon'. Exécuter les tests Node.js à la place:
-- npm test -- tests/supabase-connection.test.js

-- ============================================
-- Confirmation
-- ============================================
SELECT 'Policy "select_by_token_public" successfully dropped' AS status;
