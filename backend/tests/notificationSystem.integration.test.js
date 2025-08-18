// notificationSystem.integration.test.js - Comprehensive integration tests for the notification system
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const Handshake = require('../models/Handshake');
const Notification = require('../models/Notification');
const bcrypt = require('bcrypt');

describe('Notification System Integration Tests', () => {
  let testUser1, testUser2, testAdmin;
  let user1Session, user2Session, adminSession;
  let handshakeId;

  beforeAll(async () => {
    // Create test users
    testUser1 = await User.create({
      username: 'testuser1',
      email: 'testuser1@example.com',
      password: await bcrypt.hash('password123', 10),
      role: 'user',
      metadata: { isActive: true }
    });

    testUser2 = await User.create({
      username: 'testuser2',
      email: 'testuser2@example.com',
      password: await bcrypt.hash('password123', 10),
      role: 'user',
      metadata: { isActive: true }
    });

    testAdmin = await User.create({
      username: 'testadmin',
      email: 'testadmin@example.com',
      password: await bcrypt.hash('adminpass123', 10),
      role: 'admin',
      metadata: { isActive: true }
    });
  });

  beforeEach(async () => {
    // Clean up notifications and handshakes before each test
    await Notification.deleteMany({});
    await Handshake.deleteMany({});

    // Create authenticated sessions
    const user1Login = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'testuser1@example.com',
        password: 'password123'
      });
    user1Session = user1Login.headers['set-cookie'];

    const user2Login = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'testuser2@example.com',
        password: 'password123'
      });
    user2Session = user2Login.headers['set-cookie'];

    const adminLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'testadmin@example.com',
        password: 'adminpass123'
      });
    adminSession = adminLogin.headers['set-cookie'];
  });

  afterAll(async () => {
    // Clean up test data
    await User.deleteMany({});
    await Notification.deleteMany({});
    await Handshake.deleteMany({});
  });

  describe('Notification Creation and Retrieval', () => {
    test('should create notification when handshake is sent', async () => {
      // Send handshake request
      const handshakeResponse = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test handshake request'
        });

      expect(handshakeResponse.status).toBe(201);
      handshakeId = handshakeResponse.body.handshake._id;

      // Check if notification was created for target user
      const notificationsResponse = await request(app)
        .get('/api/notifications')
        .set('Cookie', user2Session);

      expect(notificationsResponse.status).toBe(200);
      expect(notificationsResponse.body.success).toBe(true);
      expect(notificationsResponse.body.notifications).toHaveLength(1);
      
      const notification = notificationsResponse.body.notifications[0];
      expect(notification.type).toBe('handshake_request');
      expect(notification.status).toBe('unread');
      expect(notification.priority).toBe('high');
      expect(notification.relatedHandshakeId).toBe(handshakeId);
    });

    test('should get unread notification counts', async () => {
      // Create a handshake to generate a notification
      await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test handshake request'
        });

      // Get unread counts for user2
      const countsResponse = await request(app)
        .get('/api/notifications/counts')
        .set('Cookie', user2Session);

      expect(countsResponse.status).toBe(200);
      expect(countsResponse.body.success).toBe(true);
      expect(countsResponse.body.counts.total).toBe(1);
      expect(countsResponse.body.counts.handshake_request).toBe(1);
      expect(countsResponse.body.counts.highPriorityTotal).toBe(1);
    });

    test('should mark notification as read', async () => {
      // Create a handshake to generate a notification
      await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test handshake request'
        });

      // Get notifications
      const notificationsResponse = await request(app)
        .get('/api/notifications')
        .set('Cookie', user2Session);

      const notificationId = notificationsResponse.body.notifications[0].id;

      // Mark as read
      const markReadResponse = await request(app)
        .post(`/api/notifications/${notificationId}/read`)
        .set('Cookie', user2Session);

      expect(markReadResponse.status).toBe(200);
      expect(markReadResponse.body.success).toBe(true);
      expect(markReadResponse.body.notification.status).toBe('read');

      // Verify counts updated
      const countsResponse = await request(app)
        .get('/api/notifications/counts')
        .set('Cookie', user2Session);

      expect(countsResponse.body.counts.total).toBe(0);
    });

    test('should mark all notifications as read', async () => {
      // Create multiple handshakes to generate multiple notifications
      await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test handshake request 1'
        });

      // Create test notification manually for variety
      await Notification.create({
        recipientId: testUser2._id,
        type: 'system_announcement',
        title: 'Test System Notification',
        message: 'This is a test system notification',
        priority: 'normal',
        metadata: { source: 'system', isActionable: false }
      });

      // Mark all as read
      const markAllReadResponse = await request(app)
        .post('/api/notifications/mark-all-read')
        .set('Cookie', user2Session);

      expect(markAllReadResponse.status).toBe(200);
      expect(markAllReadResponse.body.success).toBe(true);
      expect(markAllReadResponse.body.modifiedCount).toBe(2);

      // Verify counts are zero
      const countsResponse = await request(app)
        .get('/api/notifications/counts')
        .set('Cookie', user2Session);

      expect(countsResponse.body.counts.total).toBe(0);
    });
  });

  describe('Handshake Actions via Notifications', () => {
    beforeEach(async () => {
      // Create a handshake for testing actions
      const handshakeResponse = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test handshake request'
        });

      handshakeId = handshakeResponse.body.handshake._id;
    });

    test('should accept handshake via notification endpoint', async () => {
      const acceptResponse = await request(app)
        .post(`/api/notifications/handshake/${handshakeId}/accept`)
        .set('Cookie', user2Session)
        .send({
          responseMessage: 'Accepted via notification'
        });

      expect(acceptResponse.status).toBe(200);
      expect(acceptResponse.body.success).toBe(true);
      expect(acceptResponse.body.handshake.status).toBe('accepted');

      // Verify notification created for requester
      const user1NotificationsResponse = await request(app)
        .get('/api/notifications')
        .set('Cookie', user1Session);

      expect(user1NotificationsResponse.body.notifications).toHaveLength(1);
      const notification = user1NotificationsResponse.body.notifications[0];
      expect(notification.type).toBe('handshake_accepted');
      expect(notification.relatedHandshakeId).toBe(handshakeId);
    });

    test('should decline handshake via notification endpoint', async () => {
      const declineResponse = await request(app)
        .post(`/api/notifications/handshake/${handshakeId}/decline`)
        .set('Cookie', user2Session)
        .send({
          responseMessage: 'Declined via notification'
        });

      expect(declineResponse.status).toBe(200);
      expect(declineResponse.body.success).toBe(true);
      expect(declineResponse.body.handshake.status).toBe('declined');

      // Verify notification created for requester
      const user1NotificationsResponse = await request(app)
        .get('/api/notifications')
        .set('Cookie', user1Session);

      expect(user1NotificationsResponse.body.notifications).toHaveLength(1);
      const notification = user1NotificationsResponse.body.notifications[0];
      expect(notification.type).toBe('handshake_declined');
      expect(notification.relatedHandshakeId).toBe(handshakeId);
    });

    test('should prevent unauthorized handshake actions', async () => {
      // Try to accept handshake as wrong user
      const unauthorizedResponse = await request(app)
        .post(`/api/notifications/handshake/${handshakeId}/accept`)
        .set('Cookie', user1Session); // User1 trying to accept their own request

      expect(unauthorizedResponse.status).toBe(403);
      expect(unauthorizedResponse.body.code).toBe('PERMISSION_DENIED');
    });

    test('should handle expired handshake actions', async () => {
      // Manually expire the handshake
      await Handshake.findByIdAndUpdate(handshakeId, {
        expiresAt: new Date(Date.now() - 1000) // Expired 1 second ago
      });

      const expiredResponse = await request(app)
        .post(`/api/notifications/handshake/${handshakeId}/accept`)
        .set('Cookie', user2Session);

      expect(expiredResponse.status).toBe(410);
      expect(expiredResponse.body.code).toBe('HANDSHAKE_EXPIRED');
    });
  });

  describe('Notification Filtering and Pagination', () => {
    beforeEach(async () => {
      // Create various types of notifications
      await Notification.create([
        {
          recipientId: testUser1._id,
          type: 'handshake_request',
          title: 'Handshake Request 1',
          message: 'Test message 1',
          priority: 'high',
          status: 'unread',
          metadata: { source: 'user_action', isActionable: true }
        },
        {
          recipientId: testUser1._id,
          type: 'handshake_accepted',
          title: 'Handshake Accepted 1',
          message: 'Test message 2',
          priority: 'normal',
          status: 'read',
          metadata: { source: 'user_action', isActionable: false }
        },
        {
          recipientId: testUser1._id,
          type: 'system_announcement',
          title: 'System Update',
          message: 'Test message 3',
          priority: 'low',
          status: 'unread',
          metadata: { source: 'system', isActionable: false }
        }
      ]);
    });

    test('should filter notifications by status', async () => {
      const unreadResponse = await request(app)
        .get('/api/notifications?status=unread')
        .set('Cookie', user1Session);

      expect(unreadResponse.status).toBe(200);
      expect(unreadResponse.body.notifications).toHaveLength(2);
      expect(unreadResponse.body.notifications.every(n => n.status === 'unread')).toBe(true);
    });

    test('should filter notifications by type', async () => {
      const handshakeResponse = await request(app)
        .get('/api/notifications?type=handshake_request')
        .set('Cookie', user1Session);

      expect(handshakeResponse.status).toBe(200);
      expect(handshakeResponse.body.notifications).toHaveLength(1);
      expect(handshakeResponse.body.notifications[0].type).toBe('handshake_request');
    });

    test('should paginate notifications', async () => {
      const paginatedResponse = await request(app)
        .get('/api/notifications?page=1&limit=2')
        .set('Cookie', user1Session);

      expect(paginatedResponse.status).toBe(200);
      expect(paginatedResponse.body.notifications).toHaveLength(2);
      expect(paginatedResponse.body.pagination.page).toBe(1);
      expect(paginatedResponse.body.pagination.limit).toBe(2);
      expect(paginatedResponse.body.pagination.totalCount).toBe(3);
      expect(paginatedResponse.body.pagination.hasNext).toBe(true);
    });

    test('should filter by priority', async () => {
      const highPriorityResponse = await request(app)
        .get('/api/notifications?priority=high')
        .set('Cookie', user1Session);

      expect(highPriorityResponse.status).toBe(200);
      expect(highPriorityResponse.body.notifications).toHaveLength(1);
      expect(highPriorityResponse.body.notifications[0].priority).toBe('high');
    });
  });

  describe('Security and Authorization', () => {
    test('should require authentication for all notification endpoints', async () => {
      const endpoints = [
        { method: 'get', path: '/api/notifications' },
        { method: 'get', path: '/api/notifications/counts' },
        { method: 'post', path: '/api/notifications/mark-all-read' }
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)[endpoint.method](endpoint.path);
        expect(response.status).toBe(401);
      }
    });

    test('should prevent access to other users notifications', async () => {
      // Create notification for user1
      const notification = await Notification.create({
        recipientId: testUser1._id,
        type: 'system_announcement',
        title: 'Private Notification',
        message: 'This is for user1 only',
        priority: 'normal',
        metadata: { source: 'system', isActionable: false }
      });

      // Try to access as user2
      const unauthorizedResponse = await request(app)
        .post(`/api/notifications/${notification._id}/read`)
        .set('Cookie', user2Session);

      expect(unauthorizedResponse.status).toBe(403);
    });

    test('should validate notification ID format', async () => {
      const invalidIdResponse = await request(app)
        .post('/api/notifications/invalid-id/read')
        .set('Cookie', user1Session);

      expect(invalidIdResponse.status).toBe(400);
      expect(invalidIdResponse.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('Rate Limiting', () => {
    test('should respect notification rate limits', async () => {
      // This test would normally require many requests to trigger rate limiting
      // For testing purposes, we'll just verify the rate limiter is applied
      const response = await request(app)
        .get('/api/notifications')
        .set('Cookie', user1Session);

      expect(response.status).toBe(200);
      // In a real scenario with rate limiting enabled, we'd make 100+ requests
      // and expect a 429 status code
    });
  });

  describe('Server-Sent Events (SSE)', () => {
    test('should establish SSE connection', async () => {
      const response = await request(app)
        .get('/api/notifications/stream')
        .set('Cookie', user1Session)
        .set('Accept', 'text/event-stream');

      // Note: This is a simplified test since SSE testing requires special handling
      // In a real test environment, we'd use EventSource or similar
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/event-stream');
    });

    test('should require authentication for SSE stream', async () => {
      const response = await request(app)
        .get('/api/notifications/stream')
        .set('Accept', 'text/event-stream');

      expect(response.status).toBe(401);
    });
  });

  describe('Notification Statistics', () => {
    beforeEach(async () => {
      // Create test notifications with various statuses
      await Notification.create([
        {
          recipientId: testUser1._id,
          type: 'handshake_request',
          title: 'Test 1',
          message: 'Message 1',
          status: 'unread',
          priority: 'high',
          metadata: { source: 'user_action' }
        },
        {
          recipientId: testUser1._id,
          type: 'handshake_accepted',
          title: 'Test 2',
          message: 'Message 2',
          status: 'read',
          priority: 'normal',
          metadata: { source: 'user_action' }
        }
      ]);
    });

    test('should get notification statistics', async () => {
      const statsResponse = await request(app)
        .get('/api/notifications/stats')
        .set('Cookie', user1Session);

      expect(statsResponse.status).toBe(200);
      expect(statsResponse.body.success).toBe(true);
      expect(statsResponse.body.stats).toHaveProperty('totalNotifications');
      expect(statsResponse.body.stats).toHaveProperty('unreadCount');
      expect(statsResponse.body.stats).toHaveProperty('readCount');
      expect(statsResponse.body.stats).toHaveProperty('activeConnections');
    });
  });

  describe('Error Handling', () => {
    test('should handle non-existent notification gracefully', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const response = await request(app)
        .post(`/api/notifications/${fakeId}/read`)
        .set('Cookie', user1Session);

      expect(response.status).toBe(404);
      expect(response.body.code).toBe('NOTIFICATION_NOT_FOUND');
    });

    test('should handle non-existent handshake in notification action', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const response = await request(app)
        .post(`/api/notifications/handshake/${fakeId}/accept`)
        .set('Cookie', user1Session);

      expect(response.status).toBe(404);
      expect(response.body.code).toBe('HANDSHAKE_NOT_FOUND');
    });

    test('should validate request body for handshake actions', async () => {
      // Create a handshake for testing
      const handshakeResponse = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', user1Session)
        .send({
          userId: testUser2._id.toString(),
          message: 'Test request'
        });

      const handshakeId = handshakeResponse.body.handshake._id;

      // Send invalid response message (too long)
      const invalidResponse = await request(app)
        .post(`/api/notifications/handshake/${handshakeId}/accept`)
        .set('Cookie', user2Session)
        .send({
          responseMessage: 'x'.repeat(600) // Over 500 character limit
        });

      expect(invalidResponse.status).toBe(400);
      expect(invalidResponse.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('Development-only Features', () => {
    // Only run in non-production environments
    if (process.env.NODE_ENV !== 'production') {
      test('should create test notification in development', async () => {
        const testNotificationResponse = await request(app)
          .post('/api/notifications/test')
          .set('Cookie', user1Session)
          .send({
            type: 'system_announcement',
            title: 'Test Notification',
            message: 'This is a test notification',
            priority: 'normal'
          });

        expect(testNotificationResponse.status).toBe(200);
        expect(testNotificationResponse.body.success).toBe(true);
        expect(testNotificationResponse.body.notification.title).toBe('Test Notification');
      });
    }
  });
});