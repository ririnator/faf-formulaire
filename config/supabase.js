/**
 * Configuration Supabase
 *
 * Gère la connexion à la base de données Supabase
 */

const { createClient: createSupabaseClient } = require('@supabase/supabase-js');

// Vérifier que les variables d'environnement sont définies
if (!process.env.SUPABASE_URL) {
  throw new Error('SUPABASE_URL environment variable is not defined');
}

if (!process.env.SUPABASE_SERVICE_KEY) {
  throw new Error('SUPABASE_SERVICE_KEY environment variable is not defined');
}

/**
 * Crée un client Supabase avec le service role key
 * Permet d'outrepasser le RLS pour les opérations admin
 *
 * @returns {Object} Client Supabase
 */
function createClient() {
  return createSupabaseClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );
}

/**
 * Crée un client Supabase avec une clé anon (pour les opérations publiques)
 * Respecte les policies RLS
 *
 * @returns {Object} Client Supabase
 */
function createAnonClient() {
  if (!process.env.SUPABASE_ANON_KEY) {
    throw new Error('SUPABASE_ANON_KEY environment variable is not defined');
  }

  return createSupabaseClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );
}

/**
 * Crée un client Supabase authentifié avec un JWT
 * Pour les opérations authentifiées d'un admin spécifique
 *
 * @param {string} jwt - Token JWT de l'admin
 * @returns {Object} Client Supabase avec auth
 */
function createAuthenticatedClient(jwt) {
  if (!process.env.SUPABASE_ANON_KEY) {
    throw new Error('SUPABASE_ANON_KEY environment variable is not defined');
  }

  const client = createSupabaseClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );

  // Définir le JWT pour cette session
  client.auth.setSession({
    access_token: jwt,
    refresh_token: ''
  });

  return client;
}

module.exports = {
  createClient,
  createAnonClient,
  createAuthenticatedClient
};
