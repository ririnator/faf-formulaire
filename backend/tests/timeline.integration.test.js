// Timeline Integration Tests
// Tests the comprehensive timeline functionality including API endpoints and engagement statistics

const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const User = require('../models/User');
const Contact = require('../models/Contact');
const Submission = require('../models/Submission');
const Handshake = require('../models/Handshake');
const { createApp } = require('../app');

describe('Timeline Integration Tests', () => {
  let mongoServer;
  let app;
  let testUser;
  let testContact;
  let testContactUser;
  let agent;
  
  beforeAll(async () => {
    // Setup in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    
    await mongoose.connect(mongoUri);
    
    // Create app
    app = createApp();
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
    testContact = await Contact.create({
      ownerId: testUser._id,
      email: 'contact@example.com',
      firstName: 'Contact',
      lastName: 'User',
      contactUserId: testContactUser._id,
      status: 'active',
      tracking: {
        invitationsSent: 5,
        responsesReceived: 4,
        responseRate: 80,
        lastInteractionAt: new Date()
      }
    });
    
    // Create accepted handshake
    await Handshake.create({
      requesterId: testUser._id,
      responderId: testContactUser._id,
      status: 'accepted',
      acceptedAt: new Date()
    });
    
    // Create test submissions for different months
    const currentDate = new Date();
    const months = [];
    
    // Generate last 6 months
    for (let i = 0; i < 6; i++) {
      const date = new Date(currentDate);
      date.setMonth(date.getMonth() - i);
      const month = date.toISOString().slice(0, 7);
      months.push(month);
    }
    
    // Create submissions with varying completion rates
    for (let i = 0; i < months.length; i++) {
      const month = months[i];
      const completionRate = 100 - (i * 15); // Declining engagement over time
      const responseCount = Math.max(3, 10 - i); // Fewer responses over time
      
      await Submission.create({
        userId: testContactUser._id,
        month: month,
        responses: Array(responseCount).fill(null).map((_, idx) => ({
          questionId: `Question ${idx + 1}`,
          type: idx % 3 === 0 ? 'photo' : 'text',
          answer: `Answer ${idx + 1} for ${month}`,
          photoUrl: idx % 3 === 0 ? 'https://example.com/photo.jpg' : undefined
        })),
        freeText: i % 2 === 0 ? `Free text for ${month}` : undefined,
        completionRate: completionRate,
        isComplete: completionRate >= 80,
        submittedAt: new Date(date.getFullYear(), date.getMonth(), 15) // Mid month
      });
    }
    
    // Setup authenticated session
    agent = request.agent(app);
    
    // Mock session for authenticated requests
    jest.spyOn(require('../middleware/hybridAuth'), 'requireUserAuth').mockImplementation((req, res, next) => {
      req.currentUser = {
        id: testUser._id.toString(),
        username: testUser.username,
        email: testUser.email,
        role: testUser.role
      };
      req.authMethod = 'user';
      next();
    });
    
    jest.spyOn(require('../middleware/hybridAuth'), 'detectAuthMethod').mockImplementation((req, res, next) => {
      req.authMethod = 'user';
      next();
    });
    
    jest.spyOn(require('../middleware/hybridAuth'), 'enrichUserData').mockImplementation((req, res, next) => {
      req.currentUser = {
        id: testUser._id.toString(),
        username: testUser.username,
        email: testUser.email,
        role: testUser.role
      };
      next();
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
  });
  
  describe('Timeline API Endpoint', () => {
    it('should retrieve timeline data with engagement statistics', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.timeline).toBeDefined();
      expect(response.body.engagementStats).toBeDefined();
      expect(response.body.contact).toBeDefined();
      
      // Verify timeline structure
      const timeline = response.body.timeline;
      expect(Array.isArray(timeline)).toBe(true);
      expect(timeline.length).toBeGreaterThan(0);
      
      // Check timeline item structure
      const firstItem = timeline[0];
      expect(firstItem).toHaveProperty('month');
      expect(firstItem).toHaveProperty('monthLabel');
      expect(firstItem).toHaveProperty('completionRate');
      expect(firstItem).toHaveProperty('engagementLevel');
      expect(firstItem).toHaveProperty('responsePreview');
      expect(firstItem).toHaveProperty('status');
    });
    
    it('should include comprehensive engagement statistics', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      expect(stats).toBeDefined();
      
      // Check required statistics
      expect(stats).toHaveProperty('totalSubmissions');
      expect(stats).toHaveProperty('averageCompletionRate');
      expect(stats).toHaveProperty('consistencyRate');
      expect(stats).toHaveProperty('engagementTrend');
      expect(stats).toHaveProperty('activityLevel');
      expect(stats).toHaveProperty('monthlyActivity');
      expect(stats).toHaveProperty('completionTrends');
      
      // Verify statistics values
      expect(stats.totalSubmissions).toBe(6);
      expect(stats.averageCompletionRate).toBeGreaterThan(0);
      expect(stats.engagementTrend).toMatch(/improving|declining|stable/);
      
      // Check chart data
      expect(Array.isArray(stats.monthlyActivity)).toBe(true);
      expect(Array.isArray(stats.completionTrends)).toBe(true);
    });
    
    it('should calculate engagement levels correctly', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      const timeline = response.body.timeline;
      
      // Check that engagement levels are assigned based on completion rates
      timeline.forEach(item => {
        expect(item.engagementLevel).toMatch(/excellent|high|medium|low|minimal/);
        
        if (item.completionRate >= 90) {
          expect(item.engagementLevel).toBe('excellent');
        } else if (item.completionRate >= 75) {
          expect(item.engagementLevel).toBe('high');
        } else if (item.completionRate >= 50) {
          expect(item.engagementLevel).toBe('medium');
        } else if (item.completionRate >= 25) {
          expect(item.engagementLevel).toBe('low');
        } else {
          expect(item.engagementLevel).toBe('minimal');
        }
      });
    });
    
    it('should support pagination', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}?limit=3&page=1`)
        .expect(200);
      
      expect(response.body.timeline.length).toBeLessThanOrEqual(3);
      expect(response.body.pagination).toBeDefined();
      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(3);
    });
    
    it('should include response previews', async () => {
      const response = await agent
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
    
    it('should calculate time differences between submissions', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(200);
      
      const timeline = response.body.timeline;
      
      // Check that subsequent items have time differences
      for (let i = 1; i < timeline.length; i++) {
        const item = timeline[i];
        if (item.timeFromPrevious) {
          expect(item.timeFromPrevious).toHaveProperty('days');
          expect(item.timeFromPrevious).toHaveProperty('description');
          expect(typeof item.timeFromPrevious.days).toBe('number');
          expect(typeof item.timeFromPrevious.description).toBe('string');
        }
      }
    });
    
    it('should require handshake permission', async () => {
      // Create a user without handshake
      const unauthorizedUser = await User.create({
        username: 'unauthorized',
        email: 'unauth@example.com',
        password: 'hashedpassword',
        role: 'user'
      });
      
      // Mock unauthorized session
      jest.spyOn(require('../middleware/hybridAuth'), 'requireUserAuth').mockImplementation((req, res, next) => {
        req.currentUser = {
          id: unauthorizedUser._id.toString(),
          username: unauthorizedUser.username,
          email: unauthorizedUser.email,
          role: unauthorizedUser.role
        };
        next();
      });
      
      await agent
        .get(`/api/submissions/timeline/${testContactUser._id}`)
        .expect(403);
    });
    
    it('should handle invalid contact ID', async () => {
      const invalidId = new mongoose.Types.ObjectId();
      
      await agent
        .get(`/api/submissions/timeline/${invalidId}`)
        .expect(403); // Should fail permission check
    });
  });
  
  describe('Timeline Frontend Integration', () => {
    it('should serve timeline HTML page', async () => {
      const response = await agent
        .get('/admin/timeline.html')
        .expect(200);
      
      expect(response.text).toContain('Timeline Contact');
      expect(response.text).toContain('Chart.js');
      expect(response.text).toContain('timeline-container');
    });
  });
  
  describe('Engagement Statistics Calculation', () => {
    it('should calculate streaks correctly', async () => {
      // Create consecutive monthly submissions
      const user = await User.create({
        username: 'streakuser',
        email: 'streak@example.com',
        password: 'hashedpassword',
        role: 'user'
      });
      
      const baseDate = new Date();
      for (let i = 0; i < 4; i++) {
        const date = new Date(baseDate);
        date.setMonth(date.getMonth() - i);
        const month = date.toISOString().slice(0, 7);
        
        await Submission.create({
          userId: user._id,
          month: month,
          responses: [{ questionId: 'Q1', type: 'text', answer: 'A1' }],
          completionRate: 100,
          isComplete: true
        });
      }
      
      // Create contact and handshake
      const contact = await Contact.create({
        ownerId: testUser._id,
        email: 'streak@example.com',
        contactUserId: user._id,
        status: 'active'
      });
      
      await Handshake.create({
        requesterId: testUser._id,
        responderId: user._id,
        status: 'accepted'
      });
      
      const response = await agent
        .get(`/api/submissions/timeline/${user._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      expect(stats.streaks).toBeDefined();
      expect(stats.streaks.current).toBeGreaterThan(0);
      expect(stats.streaks.longest).toBeGreaterThan(0);
    });
    
    it('should calculate response type preferences', async () => {
      const response = await agent
        .get(`/api/submissions/timeline/${testContactUser._id}?includeStats=true`)
        .expect(200);
      
      const stats = response.body.engagementStats;
      expect(stats.responseTypeStats).toBeDefined();
      expect(stats.responseTypeStats.text).toBeDefined();
      expect(stats.responseTypeStats.photo).toBeDefined();
      expect(stats.responseTypeStats.freeText).toBeDefined();
      
      // Check that percentages are calculated
      Object.values(stats.responseTypeStats).forEach(typeStats => {
        expect(typeStats).toHaveProperty('count');
        expect(typeStats).toHaveProperty('total');
        expect(typeStats).toHaveProperty('percentage');
        expect(typeStats.percentage).toBeGreaterThanOrEqual(0);
        expect(typeStats.percentage).toBeLessThanOrEqual(100);
      });
    });
  });
});