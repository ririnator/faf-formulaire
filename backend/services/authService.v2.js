const bcrypt = require('bcrypt');

class AuthService {
  constructor(config) {
    this.config = config;
  }

  async validateAdminCredentials(username, password) {
    const { user: adminUser, password: adminPass } = this.config.admin;

    if (!adminUser || !adminPass) {
      throw new Error('Credentials admin non configurées');
    }

    const isValidUser = username === adminUser;
    const isValidPass = await bcrypt.compare(password, adminPass);

    return isValidUser && isValidPass;
  }

  createAdminSession(req) {
    req.session.isAdmin = true;
    req.session.loginTime = new Date();
  }

  destroySession(req) {
    return new Promise((resolve) => {
      req.session.destroy(() => {
        resolve();
      });
    });
  }

  isAuthenticated(req) {
    return !!req.session?.isAdmin;
  }

  getSessionInfo(req) {
    if (!this.isAuthenticated(req)) {
      return null;
    }

    return {
      isAdmin: true,
      loginTime: req.session.loginTime,
      sessionId: req.sessionID
    };
  }
}

module.exports = AuthService;