// Global test setup for production-ready test suite
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

const setupGlobalDatabase = async () => {
  try {
    // Close existing connections
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }

    // Create new in-memory MongoDB instance
    mongoServer = await MongoMemoryServer.create({
      instance: {
        port: undefined,
        dbName: 'faf-test-global'
      }
    });
    
    const mongoUri = mongoServer.getUri();
    
    // Connect with optimized settings for testing
    await mongoose.connect(mongoUri, {
      maxPoolSize: 1,
      bufferCommands: false
    });

    console.log('✅ Global MongoDB test instance ready');
    
  } catch (error) {
    console.error('❌ Failed to setup global test database:', error);
    throw error;
  }
};

const cleanupGlobalDatabase = async () => {
  try {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.dropDatabase();
      await mongoose.connection.close();
    }
    
    if (mongoServer) {
      await mongoServer.stop();
    }
    
    console.log('✅ Global test database cleaned up');
  } catch (error) {
    console.error('❌ Error cleaning up test database:', error);
  }
};

const cleanupBetweenTests = async () => {
  if (mongoose.connection.readyState === 1) {
    const collections = mongoose.connection.collections;
    const promises = Object.values(collections).map(collection => 
      collection.deleteMany({}).catch(() => {}) // Ignore errors
    );
    await Promise.allSettled(promises);
  }
};

module.exports = {
  setupGlobalDatabase,
  cleanupGlobalDatabase,
  cleanupBetweenTests,
  getMongoUri: () => mongoServer?.getUri()
};