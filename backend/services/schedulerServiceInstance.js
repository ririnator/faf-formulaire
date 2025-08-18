const ServiceFactory = require('./serviceFactory');

// Create and export scheduler service instance
const serviceFactory = ServiceFactory.create();
const schedulerService = serviceFactory.getSchedulerService();

// Initialize with required service dependencies
async function initializeSchedulerService() {
  try {
    const services = {
      invitationService: serviceFactory.getInvitationService(),
      contactService: serviceFactory.getContactService(),
      emailService: serviceFactory.getEmailService(),
      realTimeMetrics: null // Can be initialized later if needed
    };

    await schedulerService.initialize(services);
    return schedulerService;
  } catch (error) {
    console.error('Failed to initialize SchedulerService:', error);
    throw error;
  }
}

module.exports = {
  schedulerService,
  initializeSchedulerService
};