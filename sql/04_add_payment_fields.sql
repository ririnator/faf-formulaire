-- ============================================
-- FAF Multi-Tenant - Ajout des champs de paiement
-- ============================================
-- Ce script ajoute les champs nécessaires pour Stripe
-- À exécuter dans le SQL Editor de Supabase

-- ============================================
-- Ajouter les colonnes de paiement à la table admins
-- ============================================

ALTER TABLE admins
ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT,
ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'pending' CHECK (payment_status IN ('pending', 'active', 'cancelled', 'failed')),
ADD COLUMN IF NOT EXISTS subscription_end_date TIMESTAMPTZ;

-- Indexes pour performance
CREATE INDEX IF NOT EXISTS idx_admins_stripe_customer ON admins(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_admins_payment_status ON admins(payment_status);

-- Commentaires
COMMENT ON COLUMN admins.stripe_customer_id IS 'ID client Stripe (cus_xxx)';
COMMENT ON COLUMN admins.stripe_subscription_id IS 'ID abonnement Stripe (sub_xxx)';
COMMENT ON COLUMN admins.payment_status IS 'Statut du paiement: pending (défaut), active, cancelled, failed';
COMMENT ON COLUMN admins.subscription_end_date IS 'Date de fin d''abonnement (pour gérer les annulations)';

-- ============================================
-- Fonction: check_payment_status()
-- ============================================
-- Fonction helper pour vérifier si un admin a un accès payé actif

CREATE OR REPLACE FUNCTION check_payment_status(admin_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
  status TEXT;
  end_date TIMESTAMPTZ;
BEGIN
  SELECT payment_status, subscription_end_date
  INTO status, end_date
  FROM admins
  WHERE id = admin_id;

  -- Accès actif si status = 'active' OU si subscription_end_date dans le futur
  RETURN (status = 'active') OR (end_date IS NOT NULL AND end_date > now());
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION check_payment_status IS 'Vérifie si un admin a un accès payé valide';

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
ORDER BY ordinal_position;

-- Afficher les nouveaux indexes
SELECT
  indexname,
  indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'admins'
  AND indexname LIKE 'idx_admins_%'
ORDER BY indexname;
