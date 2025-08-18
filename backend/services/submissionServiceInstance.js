// Singleton instance of SubmissionService for backward compatibility
const SubmissionService = require('./submissionService');

// Create a singleton instance
const submissionServiceInstance = new SubmissionService();

// Export the instance as default for direct method access
module.exports = submissionServiceInstance;