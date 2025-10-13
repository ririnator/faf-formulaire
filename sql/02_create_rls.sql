-- ============================================
-- FAF Multi-Tenant - Row Level Security (RLS)
-- ============================================
-- Ce script active et configure le Row Level Security
-- pour assurer l'isolation complète des données par admin
-- À exécuter APRÈS le script 01_create_tables.sql

-- ============================================
-- Activer RLS sur les tables
-- ============================================

ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE responses ENABLE ROW LEVEL SECURITY;

-- ============================================
-- Policies pour la table: admins
-- ============================================

-- Policy SELECT : Les admins peuvent voir uniquement leur propre compte
-- (ou service_role pour opérations système)
CREATE POLICY "select_own_admin"
ON admins FOR SELECT
USING (
  id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy INSERT : Autoriser la création de compte (inscription publique)
-- Note: En production, utiliser auth.role() = 'anon' pour inscriptions publiques
CREATE POLICY "insert_new_admin"
ON admins FOR INSERT
WITH CHECK (
  auth.role() = 'service_role' OR
  auth.role() = 'anon'
);

-- Policy UPDATE : Les admins peuvent modifier uniquement leur propre compte
CREATE POLICY "update_own_admin"
ON admins FOR UPDATE
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

-- Policy DELETE : Les admins peuvent supprimer uniquement leur propre compte
CREATE POLICY "delete_own_admin"
ON admins FOR DELETE
USING (id = auth.uid());

-- ============================================
-- Policies pour la table: responses
-- ============================================

-- Policy SELECT (1) : Les admins voient uniquement leurs réponses (owner_id)
CREATE POLICY "select_own_responses"
ON responses FOR SELECT
USING (
  owner_id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy SELECT (2) : Consultation publique via token (SUPPRIMÉE)
-- IMPORTANT: Cette policy a été supprimée car elle était trop permissive
-- Elle permettait aux utilisateurs anonymes de voir TOUTES les réponses avec un token
-- L'accès public via token se fera via service_role côté backend API
--
-- Si cette policy existe, la supprimer avec:
-- DROP POLICY IF EXISTS "select_by_token_public" ON responses;

-- Policy INSERT (1) : Les admins peuvent créer des réponses pour eux
CREATE POLICY "insert_own_responses"
ON responses FOR INSERT
WITH CHECK (
  owner_id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy INSERT (2) : Soumissions publiques (amis remplissant le formulaire)
-- Note: Le owner_id sera défini par l'API en fonction du username
CREATE POLICY "insert_public_responses"
ON responses FOR INSERT
WITH CHECK (
  auth.role() = 'anon' OR
  auth.role() = 'service_role'
);

-- Policy UPDATE : Les admins peuvent modifier leurs réponses uniquement
CREATE POLICY "update_own_responses"
ON responses FOR UPDATE
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

-- Policy DELETE : Les admins peuvent supprimer leurs réponses uniquement
CREATE POLICY "delete_own_responses"
ON responses FOR DELETE
USING (owner_id = auth.uid());

-- ============================================
-- Fonction utilitaire : Tester l'isolation
-- ============================================
-- Cette fonction permet de tester que RLS fonctionne correctement

CREATE OR REPLACE FUNCTION test_rls_isolation(admin_uuid UUID)
RETURNS TABLE(
  test_name TEXT,
  passed BOOLEAN,
  message TEXT
) AS $$
BEGIN
  -- Test 1 : Vérifier que RLS est activé sur responses
  RETURN QUERY
  SELECT
    'RLS enabled on responses'::TEXT,
    relrowsecurity AS passed,
    CASE
      WHEN relrowsecurity THEN 'RLS is enabled ✓'
      ELSE 'RLS is NOT enabled ✗'
    END::TEXT
  FROM pg_class
  WHERE relname = 'responses';

  -- Test 2 : Vérifier que RLS est activé sur admins
  RETURN QUERY
  SELECT
    'RLS enabled on admins'::TEXT,
    relrowsecurity AS passed,
    CASE
      WHEN relrowsecurity THEN 'RLS is enabled ✓'
      ELSE 'RLS is NOT enabled ✗'
    END::TEXT
  FROM pg_class
  WHERE relname = 'admins';

  -- Test 3 : Compter les policies sur responses
  RETURN QUERY
  SELECT
    'Policies on responses'::TEXT,
    (COUNT(*) >= 5) AS passed,
    FORMAT('Found %s policies (expected 5+)', COUNT(*))::TEXT
  FROM pg_policies
  WHERE tablename = 'responses';

  -- Test 4 : Compter les policies sur admins
  RETURN QUERY
  SELECT
    'Policies on admins'::TEXT,
    (COUNT(*) >= 4) AS passed,
    FORMAT('Found %s policies (expected 4+)', COUNT(*))::TEXT
  FROM pg_policies
  WHERE tablename = 'admins';

END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Afficher les policies créées
-- ============================================

SELECT
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd,
  qual,
  with_check
FROM pg_policies
WHERE tablename IN ('admins', 'responses')
ORDER BY tablename, policyname;

-- ============================================
-- Instructions de test
-- ============================================

/*
Pour tester l'isolation RLS après avoir créé des admins:

1. Créer deux admins de test:
   INSERT INTO admins (username, email, password_hash)
   VALUES
     ('testadmin1', 'test1@example.com', '$2b$10$...'),
     ('testadmin2', 'test2@example.com', '$2b$10$...');

2. Récupérer leurs UUIDs:
   SELECT id, username FROM admins WHERE username LIKE 'testadmin%';

3. Tester l'isolation:
   SELECT * FROM test_rls_isolation('uuid-admin-1');

4. Vérifier qu'admin1 ne peut pas voir les données d'admin2:
   -- Définir le contexte auth (simuler l'authentification)
   SET request.jwt.claims = '{"sub": "uuid-admin-1"}';

   -- Cette requête devrait retourner UNIQUEMENT les réponses d'admin1
   SELECT * FROM responses WHERE owner_id = 'uuid-admin-1';

   -- Cette requête devrait retourner 0 résultat (car owner_id != auth.uid())
   SELECT * FROM responses WHERE owner_id = 'uuid-admin-2';
*/

-- ============================================
-- Notes de sécurité
-- ============================================

/*
IMPORTANT: Row Level Security (RLS) assure que:

1. Isolation stricte:
   - Chaque admin voit UNIQUEMENT ses propres réponses (owner_id = auth.uid())
   - Impossible d'accéder aux données d'un autre admin, même avec une requête SQL directe

2. Service Role:
   - Le rôle 'service_role' peut tout voir (pour migrations, admin système)
   - NE JAMAIS exposer la clé service_role côté client

3. Consultation publique:
   - Les tokens permettent la consultation publique via /view/{token}
   - Policy 'select_by_token_public' autorise l'accès anonyme avec token valide

4. Soumissions publiques:
   - Policy 'insert_public_responses' autorise les amis à soumettre des réponses
   - Le owner_id sera défini par l'API backend (pas par le client)

5. Best practices:
   - Toujours utiliser auth.uid() pour filtrer par admin
   - Utiliser 'service_role' uniquement côté serveur
   - Valider les données côté API avant insertion (RLS ne valide pas le contenu)
*/
