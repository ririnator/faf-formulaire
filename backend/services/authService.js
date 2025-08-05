const bcrypt = require('bcrypt');

class AuthService {
  static async validateAdminCredentials(username, password) {
    const adminUser = process.env.LOGIN_ADMIN_USER;
    const adminPass = process.env.LOGIN_ADMIN_PASS;

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