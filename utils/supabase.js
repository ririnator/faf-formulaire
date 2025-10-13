/**
 * FAF Multi-Tenant - Supabase Client
 *
 * Configuration centralisée du client Supabase pour l'accès à la base de données.
 * Ce module exporte différents clients selon le contexte (auth, service_role).
 */

const { createClient } = require('@supabase/supabase-js');

// Validation des variables d'environnement
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL) {
  throw new Error('SUPABASE_URL is not defined in environment variables');
}

if (!SUPABASE_ANON_KEY) {
  throw new Error('SUPABASE_ANON_KEY is not defined in environment variables');
}

if (!SUPABASE_SERVICE_KEY) {
  console.warn('⚠️  SUPABASE_SERVICE_KEY is not defined (required for admin operations)');
}

/**
 * Client Supabase avec clé anonyme (anon)
 *
 * Utilisation:
 * - Soumissions publiques de formulaires
 * - Consultation publique via token (/view/{token})
 * - Opérations qui respectent RLS
 *
 * RLS: Activé automatiquement
 */
const supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

/**
 * Client Supabase avec clé service_role
 *
 * Utilisation:
 * - Opérations d'administration (migrations, scripts)
 * - Création de comptes admin
 * - Accès complet à toutes les données (bypass RLS)
 *
 * ⚠️  ATTENTION: Ne JAMAIS exposer ce client côté client
 * ⚠️  Utiliser UNIQUEMENT côté serveur pour opérations sensibles
 *
 * RLS: Bypass automatique (role = 'service_role')
 */
const supabaseAdmin = SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    })
  : null;

/**
 * Créer un client Supabase avec contexte d'authentification JWT
 *
 * @param {string} jwtToken - Token JWT de l'admin authentifié
 * @returns {Object} Client Supabase avec contexte auth
 *
 * Utilisation:
 * - Dashboard admin authentifié
 * - API endpoints protégés
 * - Opérations limitées par RLS (owner_id = auth.uid())
 *
 * Exemple:
 * ```js
 * const adminClient = createAuthenticatedClient(req.headers.authorization);
 * const { data } = await adminClient.from('responses').select('*');
 * // Retourne uniquement les réponses où owner_id = admin.id (via RLS)
 * ```
 */
function createAuthenticatedClient(jwtToken) {
  if (!jwtToken) {
    throw new Error('JWT token is required for authenticated client');
  }

  // Supprimer le préfixe "Bearer " si présent
  const token = jwtToken.replace(/^Bearer\s+/i, '');

  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: {
      headers: {
        Authorization: `Bearer ${token}`
      }
    },
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });
}

/**
 * Tester la connexion Supabase
 *
 * @returns {Promise<Object>} Résultat du test avec détails
 *
 * Teste:
 * - Connexion au serveur Supabase
 * - Accès aux tables (admins, responses)
 * - Validation RLS
 */
async function testConnection() {
  const results = {
    success: false,
    url: SUPABASE_URL,
    tests: []
  };

  try {
    // Test 1: Vérifier la connexion (ping)
    const { error: pingError } = await supabaseClient
      .from('admins')
      .select('count', { count: 'exact', head: true });

    results.tests.push({
      name: 'Connection',
      passed: !pingError,
      error: pingError?.message
    });

    if (pingError) {
      return results;
    }

    // Test 2: Vérifier l'accès à la table admins
    const { error: adminsError } = await supabaseClient
      .from('admins')
      .select('*')
      .limit(1);

    results.tests.push({
      name: 'Access table admins',
      passed: !adminsError,
      error: adminsError?.message
    });

    // Test 3: Vérifier l'accès à la table responses
    const { error: responsesError } = await supabaseClient
      .from('responses')
      .select('*')
      .limit(1);

    results.tests.push({
      name: 'Access table responses',
      passed: !responsesError,
      error: responsesError?.message
    });

    // Test 4: Vérifier RLS (doit retourner 0 résultats sans auth)
    const { data: rlsData, error: rlsError } = await supabaseClient
      .from('responses')
      .select('*');

    results.tests.push({
      name: 'RLS enabled (expected 0 results without auth)',
      passed: !rlsError && rlsData.length === 0,
      error: rlsError?.message,
      details: `Returned ${rlsData?.length || 0} rows`
    });

    // Test 5: Vérifier service_role bypass RLS (si disponible)
    if (supabaseAdmin) {
      const { data: adminData, error: adminError } = await supabaseAdmin
        .from('responses')
        .select('count', { count: 'exact', head: true });

      results.tests.push({
        name: 'Service role bypass RLS',
        passed: !adminError,
        error: adminError?.message,
        details: `Service role can access all data`
      });
    }

    // Déterminer le succès global
    results.success = results.tests.every(test => test.passed);

  } catch (err) {
    results.tests.push({
      name: 'Global error',
      passed: false,
      error: err.message
    });
  }

  return results;
}

/**
 * Récupérer les informations d'un admin par son JWT
 *
 * @param {string} jwtToken - Token JWT de l'admin
 * @returns {Promise<Object|null>} Admin data ou null
 */
async function getAdminFromJWT(jwtToken) {
  try {
    const client = createAuthenticatedClient(jwtToken);

    // Décoder le JWT pour obtenir l'UUID (sub claim)
    const [, payload] = jwtToken.split('.');
    const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
    const adminId = decoded.sub || decoded.admin_id;

    if (!adminId) {
      return null;
    }

    // Récupérer l'admin depuis Supabase
    const { data, error } = await client
      .from('admins')
      .select('id, username, email, created_at')
      .eq('id', adminId)
      .single();

    if (error) {
      console.error('Error fetching admin:', error);
      return null;
    }

    return data;
  } catch (err) {
    console.error('Error decoding JWT:', err);
    return null;
  }
}

module.exports = {
  supabaseClient,        // Client anonyme (RLS activé)
  supabaseAdmin,         // Client admin (bypass RLS)
  createAuthenticatedClient,  // Factory pour client avec JWT
  testConnection,        // Test de connexion
  getAdminFromJWT        // Récupérer admin depuis JWT
};
