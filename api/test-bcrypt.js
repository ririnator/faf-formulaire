/**
 * Test endpoint pour vérifier bcrypt
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const bcrypt = require('bcrypt');

    const testHash = await bcrypt.hash('test123', 10);
    const isValid = await bcrypt.compare('test123', testHash);

    return res.status(200).json({
      success: true,
      bcryptWorks: isValid,
      hashLength: testHash.length
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
      stack: error.stack,
      name: error.name
    });
  }
};
