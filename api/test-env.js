/**
 * Test endpoint pour vérifier les variables d'environnement
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    return res.status(200).json({
      success: true,
      env: {
        hasJwtSecret: !!process.env.JWT_SECRET,
        hasSupabaseUrl: !!process.env.SUPABASE_URL,
        hasSupabaseKey: !!process.env.SUPABASE_SERVICE_KEY,
        jwtSecretLength: process.env.JWT_SECRET?.length || 0,
        supabaseUrlStart: process.env.SUPABASE_URL?.substring(0, 20) || 'missing',
        nodeEnv: process.env.NODE_ENV || 'not set'
      }
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
      stack: error.stack
    });
  }
};
