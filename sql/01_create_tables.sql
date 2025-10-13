-- ============================================
-- FAF Multi-Tenant - Création des tables
-- ============================================
-- Ce script crée les tables principales pour la version multi-tenant
-- À exécuter dans le SQL Editor de Supabase

-- ============================================
-- Table: admins
-- ============================================
-- Stocke les comptes des administrateurs (créateurs de formulaires)

CREATE TABLE IF NOT EXISTS admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9_-]{3,20}$'),
  email TEXT UNIQUE NOT NULL CHECK (email ~ '^[^@]+@[^@]+\.[^@]+$'),
  password_hash TEXT NOT NULL CHECK (char_length(password_hash) >= 50),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes pour performance
CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);
CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);

-- Commentaires
COMMENT ON TABLE admins IS 'Table des administrateurs (créateurs de formulaires)';
COMMENT ON COLUMN admins.id IS 'UUID unique de l''administrateur';
COMMENT ON COLUMN admins.username IS 'Nom d''utilisateur unique (3-20 caractères, lowercase, alphanumériques + tirets/underscores)';
COMMENT ON COLUMN admins.email IS 'Email unique (pour récupération de mot de passe)';
COMMENT ON COLUMN admins.password_hash IS 'Hash bcrypt du mot de passe (min 50 caractères)';

-- ============================================
-- Fonction: update_updated_at()
-- ============================================
-- Met à jour automatiquement le champ updated_at

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger pour updated_at sur admins
CREATE TRIGGER trigger_admins_updated_at
BEFORE UPDATE ON admins
FOR EACH ROW
EXECUTE FUNCTION update_updated_at();

-- ============================================
-- Table: responses
-- ============================================
-- Stocke les réponses aux formulaires

CREATE TABLE IF NOT EXISTS responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 100),
  responses JSONB NOT NULL,
  month TEXT NOT NULL CHECK (month ~ '^\d{4}-\d{2}$'),
  is_owner BOOLEAN DEFAULT false,
  token TEXT UNIQUE CHECK (token IS NULL OR char_length(token) = 64),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes pour performance
CREATE INDEX IF NOT EXISTS idx_responses_owner ON responses(owner_id);
CREATE INDEX IF NOT EXISTS idx_responses_token ON responses(token) WHERE token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_responses_month ON responses(month);
CREATE INDEX IF NOT EXISTS idx_responses_owner_month ON responses(owner_id, month);
CREATE INDEX IF NOT EXISTS idx_responses_created ON responses(created_at DESC);

-- Contrainte unique : un admin ne peut avoir qu'une seule réponse par mois
CREATE UNIQUE INDEX IF NOT EXISTS idx_owner_month_unique
ON responses(owner_id, month)
WHERE is_owner = true;

-- Commentaires
COMMENT ON TABLE responses IS 'Table des réponses aux formulaires (isolées par owner_id)';
COMMENT ON COLUMN responses.id IS 'UUID unique de la réponse';
COMMENT ON COLUMN responses.owner_id IS 'UUID de l''admin propriétaire (avec CASCADE DELETE)';
COMMENT ON COLUMN responses.name IS 'Nom de la personne qui a rempli (2-100 caractères)';
COMMENT ON COLUMN responses.responses IS 'Array JSONB des réponses: [{"question": "...", "answer": "..."}]';
COMMENT ON COLUMN responses.month IS 'Mois au format YYYY-MM (ex: 2025-01)';
COMMENT ON COLUMN responses.is_owner IS 'true si c''est la réponse de l''admin lui-même, false pour les amis';
COMMENT ON COLUMN responses.token IS 'Token unique de 64 caractères (null pour l''admin)';

-- ============================================
-- Fonction: validate_responses_format()
-- ============================================
-- Valide le format JSONB du champ responses

CREATE OR REPLACE FUNCTION validate_responses_format()
RETURNS TRIGGER AS $$
BEGIN
  -- Vérifier que responses est un array
  IF jsonb_typeof(NEW.responses) != 'array' THEN
    RAISE EXCEPTION 'responses must be a JSON array';
  END IF;

  -- Vérifier que chaque élément a question et answer
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(NEW.responses) AS elem
    WHERE NOT (elem ? 'question' AND elem ? 'answer')
  ) THEN
    RAISE EXCEPTION 'Each response must have question and answer fields';
  END IF;

  -- Vérifier le nombre de réponses (10-11 questions)
  IF jsonb_array_length(NEW.responses) < 10 OR jsonb_array_length(NEW.responses) > 11 THEN
    RAISE EXCEPTION 'Responses array must contain 10-11 elements';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger pour validation du format
CREATE TRIGGER trigger_validate_responses
BEFORE INSERT OR UPDATE ON responses
FOR EACH ROW
EXECUTE FUNCTION validate_responses_format();

-- ============================================
-- Vérification finale
-- ============================================

-- Afficher les tables créées
SELECT
  table_name,
  (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public'
  AND table_name IN ('admins', 'responses')
ORDER BY table_name;

-- Afficher les indexes créés
SELECT
  tablename,
  indexname,
  indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename IN ('admins', 'responses')
ORDER BY tablename, indexname;
