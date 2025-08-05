const bcrypt = require('bcrypt');

const LOGIN_ADMIN_USER = process.env.LOGIN_ADMIN_USER;
const LOGIN_ADMIN_PASS = process.env.LOGIN_ADMIN_PASS;

function ensureAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/login');
}

async function authenticateAdmin(req, res, next) {
  const { username, password } = req.body;
  
  if (username === LOGIN_ADMIN_USER && await bcrypt.compare(password, LOGIN_ADMIN_PASS)) {
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