const bcrypt = require('bcrypt');
const EnvironmentConfig = require('../config/environment');

function ensureAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/login');
}

async function authenticateAdmin(req, res, next) {
  const { username, password } = req.body;
  const config = EnvironmentConfig.getConfig();
  const { user: adminUser, password: adminPass } = config.admin;
  
  if (username === adminUser && await bcrypt.compare(password, adminPass)) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  
  return res.redirect('/login?error=1');
}

function logout(req, res) {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
}

module.exports = {
  ensureAdmin,
  authenticateAdmin,
  logout
};