const bcrypt = require('bcrypt');
const EnvironmentConfig = require('../config/environment');

class AuthService {
  static async validateAdminCredentials(username, password) {
    const config = EnvironmentConfig.getConfig();
    const { user: adminUser, password: adminPass } = config.admin;

    if (!adminUser || !adminPass) {
      throw new Error('Credentials admin non configurées');
    }

    const isValidUser = username === adminUser;
    const isValidPass = await bcrypt.compare(password, adminPass);

    return isValidUser && isValidPass;
  }

  static createAdminSession(req) {
    req.session.isAdmin = true;
    req.session.loginTime = new Date();
  }

  static destroySession(req) {
    return new Promise((resolve) => {
      req.session.destroy(() => {
        resolve();
      });
    });
  }

  static isAuthenticated(req) {
    return !!req.session?.isAdmin;
  }

  static getSessionInfo(req) {
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