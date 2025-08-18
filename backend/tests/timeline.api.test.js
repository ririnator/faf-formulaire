// Simple Timeline API Test
// Tests the timeline API endpoint functionality in isolation

const request = require('supertest');
const express = require('express');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

// Import models and routes directly
const User = require('../models/User');
const Contact = require('../models/Contact');
const Submission = require('../models/Submission');
const Handshake = require('../models/Handshake');
const submissionRoutes = require('../routes/submissionRoutes');

describe('Timeline API Tests', () => {
  let mongoServer;
  let app;
  let testUser;
  let testContactUser;
  
  beforeAll(async () => {
    // Setup in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    
    await mongoose.connect(mongoUri);
  });
  
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    await mongoServer.stop();
  });
  
  beforeEach(async () => {
    // Clean up before each test
    await Promise.all([
      User.deleteMany({}),
      Contact.deleteMany({}),
      Submission.deleteMany({}),
      Handshake.deleteMany({})
    ]);
    
    // Create test users
    testUser = await User.create({
      username: 'testuser',
      email: 'test@example.com',
      password: 'hashedpassword',
      role: 'user',
      metadata: { isActive: true }
    });
    
    testContactUser = await User.create({
      username: 'contactuser',
      email: 'contact@example.com',
      password: 'hashedpassword',
      role: 'user',
      metadata: { isActive: true }
    });
    
    // Create test contact
    await Contact.create({
      ownerId: testUser._id,
      email: 'contact@example.com',
      firstName: 'Contact',
      lastName: 'User',
      contactUserId: testContactUser._id,
      status: 'active'
    });
    
    // Create accepted handshake
    await Handshake.create({
      requesterId: testUser._id,
      targetId: testContactUser._id,
      status: 'accepted',
      acceptedAt: new Date()
    });
    
    // Create test submissions
    const currentDate = new Date();
    for (let i = 0; i < 3; i++) {
      const date = new Date(currentDate);
      date.setMonth(date.getMonth() - i);
      const month = date.toISOString().slice(0, 7);
      
      await Submission.create({
        userId: testContactUser._id,
        month: month,
        responses: [
          { questionId: 'Question 1', type: 'text', answer: `Answer 1 for ${month}` },
          { questionId: 'Question 2', type: 'photo', answer: 'Photo answer', photoUrl: 'https://example.com/photo.jpg' }
        ],
        freeText: `Free text for ${month}`,
        completionRate: 90 - (i * 10),
        isComplete: true,
        submittedAt: new Date(date.getFullYear(), date.getMonth(), 15)
      });
    }
    
    // Setup Express app with minimal middleware
    app = express();
    app.use(express.json());
    
    // Mock authentication middleware
    app.use((req, res, next) => {
      req.currentUser = {
        id: testUser._id.toString(),
        username: testUser.username,
        email: testUser.email,
        role: testUser.role
      };
      req.authMethod = 'user';
      next();
    });
    
    // Use submission routes
    app.use('/api/submissions', submissionRoutes);
  });
  
  describe('GET /api/submissions/timeline/:contactId', () => {
    it('should return timeline data', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.timeline).toBeDefined();
      expect(Array.isArray(response.body.timeline)).toBe(true);
      expect(response.body.timeline.length).toBeGreaterThan(0);
      
      // Check timeline item structure
      const firstItem = response.body.timeline[0];
      expect(firstItem).toHaveProperty('month');
      expect(firstItem).toHaveProperty('monthLabel');
      expect(firstItem).toHaveProperty('completionRate');
      expect(firstItem).toHaveProperty('engagementLevel');
      expect(firstItem).toHaveProperty('status');
    });
    
    it('should include engagement statistics when requested', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      expect(response.body.engagementStats).toBeDefined();
      const stats = response.body.engagementStats;
      
      expect(stats).toHaveProperty('totalSubmissions');
      expect(stats).toHaveProperty('averageCompletionRate');
      expect(stats).toHaveProperty('engagementScore');
      expect(stats).toHaveProperty('activityLevel');
      expect(stats.totalSubmissions).toBe(3);
    });
    
    it('should calculate engagement levels correctly', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      const timeline = response.body.timeline;
      timeline.forEach(item => {
        expect(['excellent', 'high', 'medium', 'low', 'minimal']).toContain(item.engagementLevel);
      });
    });
    
    it('should support pagination', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}?limit=2&page=1`)
        .expect(200);
      
      expect(response.body.timeline.length).toBeLessThanOrEqual(2);
      expect(response.body.pagination).toBeDefined();
    });
    
    it('should include response previews', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      const firstItem = response.body.timeline[0];
      expect(firstItem.responsePreview).toBeDefined();
      expect(Array.isArray(firstItem.responsePreview)).toBe(true);
      
      if (firstItem.responsePreview.length > 0) {
        const preview = firstItem.responsePreview[0];
        expect(preview).toHaveProperty('question');
        expect(preview).toHaveProperty('hasAnswer');
        expect(preview).toHaveProperty('type');
      }
    });
    
    it('should format month labels in French', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      const timeline = response.body.timeline;
      timeline.forEach(item => {
        expect(item.monthLabel).toMatch(/janvier|février|mars|avril|mai|juin|juillet|août|septembre|octobre|novembre|décembre/);
        expect(item.monthLabel).toMatch(/\d{4}/); // Should contain year
      });
    });
  });
  
  describe('Timeline Statistics Functions', () => {
    it('should calculate engagement statistics correctly', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      
      // Test specific calculations
      expect(stats.totalSubmissions).toBe(3);
      expect(stats.averageCompletionRate).toBe(80); // (90 + 80 + 70) / 3
      expect(stats.consistencyRate).toBe(100); // All submissions are complete
      expect(stats.engagementScore).toBe(90); // (80 + 100) / 2
      
      // Test trend calculation
      expect(['improving', 'declining', 'stable']).toContain(stats.engagementTrend);
      
      // Test activity level
      expect(['very-active', 'active', 'moderate', 'inactive']).toContain(stats.activityLevel);
    });
    
    it('should generate monthly activity data', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      expect(stats.monthlyActivity).toBeDefined();
      expect(Array.isArray(stats.monthlyActivity)).toBe(true);
      expect(stats.monthlyActivity.length).toBe(3);
      
      stats.monthlyActivity.forEach(activity => {
        expect(activity).toHaveProperty('month');
        expect(activity).toHaveProperty('label');
        expect(activity).toHaveProperty('submissions');
        expect(activity).toHaveProperty('averageCompletionRate');
      });
    });
    
    it('should generate completion trend data', async () => {
      const response = await request(app)
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      expect(stats.completionTrends).toBeDefined();
      expect(Array.isArray(stats.completionTrends)).toBe(true);
      
      stats.completionTrends.forEach(trend => {
        expect(trend).toHaveProperty('month');
        expect(trend).toHaveProperty('label');
        expect(trend).toHaveProperty('completionRate');
        expect(trend).toHaveProperty('isComplete');
      });
    });
  });
});