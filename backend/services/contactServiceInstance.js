// Singleton instance of ContactService for backward compatibility
const ContactService = require('./contactService');

// Create a singleton instance
const contactServiceInstance = new ContactService();

// Export the instance as default for direct method access
module.exports = contactServiceInstance;