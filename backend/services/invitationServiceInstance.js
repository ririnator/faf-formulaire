// Singleton instance of InvitationService for backward compatibility
const InvitationService = require('./invitationService');

// Create a singleton instance
const invitationServiceInstance = new InvitationService();

// Export the instance as default for direct method access
module.exports = invitationServiceInstance;