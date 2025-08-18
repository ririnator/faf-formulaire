// Singleton instance of HandshakeService for backward compatibility
const HandshakeService = require('./handshakeService');

// Create a singleton instance
const handshakeServiceInstance = new HandshakeService();

// Export the instance as default for direct method access
module.exports = handshakeServiceInstance;