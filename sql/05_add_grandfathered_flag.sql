-- ============================================
-- FAF Multi-Tenant - Grandfathered Accounts
-- ============================================
-- Ajoute un flag pour les comptes avec accès gratuit permanent
-- (fondateurs, beta testers, etc.)

-- ============================================
-- Ajouter la colonne is_grandfathered
-- ============================================

ALTER TABLE admins
ADD COLUMN IF NOT EXISTS is_grandfathered BOOLEAN DEFAULT false;

-- Créer un index pour les requêtes de vérification de paiement
CREATE INDEX IF NOT EXISTS idx_admins_grandfathered ON admins(is_grandfathered);

-- Commentaire
COMMENT ON COLUMN admins.is_grandfathered IS 'Accès gratuit permanent (fondateurs, beta testers, etc.)';

-- ============================================
-- Mettre à jour la fonction check_payment_status
-- ============================================
-- Modifier la fonction pour inclure les comptes grandfathered

CREATE OR REPLACE FUNCTION check_payment_status(admin_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  status TEXT;
  end_date TIMESTAMPTZ;
  grandfathered BOOLEAN;
BEGIN
  SELECT payment_status, subscription_end_date, is_grandfathered
  INTO status, end_date, grandfathered
  FROM admins
  WHERE id = admin_id;

  -- Accès actif si:
  -- - is_grandfathered = true OU
  -- - payment_status = 'active' OU
  -- - subscription_end_date dans le futur
  RETURN (grandfathered = true) OR (status = 'active') OR (end_date IS NOT NULL AND end_date > now());
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION check_payment_status IS 'Vérifie si un admin a un accès valide (payé ou grandfathered)';

-- ============================================
-- Vérification finale
-- ============================================

-- Afficher la structure de la table admins
SELECT
  column_name,
  data_type,
  column_default,
  is_nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'admins'
  AND column_name IN ('payment_status', 'is_grandfathered')
ORDER BY ordinal_position;

-- Compter les comptes grandfathered
SELECT
  COUNT(*) FILTER (WHERE is_grandfathered = true) as grandfathered_count,
  COUNT(*) FILTER (WHERE payment_status = 'active') as paid_count,
  COUNT(*) as total_count
FROM admins;
