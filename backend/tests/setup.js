const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

beforeAll(async () => {
  // Start in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri);
}, 30000); // Increased timeout for DB setup

afterAll(async () => {
  // Clean up database and connections
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  }
  if (mongoServer) {
    await mongoServer.stop();
  }
}, 30000);

afterEach(async () => {
  // Quick cleanup after each test
  if (mongoose.connection.readyState === 1) {
    const collections = mongoose.connection.collections;
    const promises = [];
    for (const key in collections) {
      promises.push(collections[key].deleteMany({}));
    }
    await Promise.all(promises);
  }
}, 10000);