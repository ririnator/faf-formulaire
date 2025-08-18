#!/usr/bin/env node

/**
 * Simple MongoDB connection test
 */

const mongoose = require('mongoose');
require('dotenv').config();

async function testConnection() {
  try {
    console.log('Testing MongoDB connection...');
    
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      throw new Error('MONGODB_URI environment variable is required');
    }
    
    console.log('MongoDB URI pattern:', uri.replace(/\/\/.*@/, '//<credentials>@'));
    
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    });
    
    console.log('✅ Connected to MongoDB successfully');
    
    // Try to get database info
    const admin = mongoose.connection.db.admin();
    const info = await admin.serverStatus();
    
    console.log('Database info:');
    console.log('- MongoDB version:', info.version);
    console.log('- Database name:', mongoose.connection.name);
    
    // List collections
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log('- Collections:', collections.map(c => c.name));
    
    await mongoose.disconnect();
    console.log('✅ Connection test completed successfully');
    
  } catch (error) {
    console.error('❌ Connection test failed:', error.message);
    process.exit(1);
  }
}

testConnection();