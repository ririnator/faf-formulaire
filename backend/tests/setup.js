const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

beforeAll(async () => {
  // Start in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri);
});

afterAll(async () => {
  // Clean up
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  await mongoServer.stop();
});

afterEach(async () => {
  // Clean up after each test
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
});