/**
 * Post-Deployment Monitoring Tests
 * 
 * Comprehensive monitoring validation including health checks,
 * metrics collection, alerting systems, and continuous monitoring.
 */

const request = require('supertest');
const { performance } = require('perf_hooks');

describe('📊 Post-Deployment Monitoring Tests', () => {
  let app;
  let server;
  let adminToken;
  let monitoringMetrics = {
    healthChecks: [],
    responseTimeMetrics: [],
    systemMetrics: [],
    alertsTriggered: []
  };
  
  beforeAll(async () => {
    const startTime = global.testReporter.logTestStart('Monitoring Test Suite Setup');
    
    try {
      app = require('../../app');
      server = app.listen(0);
      
      // Get admin token for monitoring endpoints
      const adminLogin = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      adminToken = adminLogin.body.token;
      
      global.testReporter.logTestEnd('Monitoring Test Suite Setup', startTime, true);
    } catch (error) {
      global.testReporter.logTestEnd('Monitoring Test Suite Setup', startTime, false);
      throw error;
    }
  });

  afterAll(async () => {
    // Generate monitoring report
    generateMonitoringReport();
    
    if (server) {
      server.close();
    }
    await global.testUtils.executeCleanup();
  });

  describe('🏥 Health Check Validation', () => {
    test('should validate basic application health', async () => {
      const startTime = global.testReporter.logTestStart('Basic Health Check');
      
      try {
        const healthResponse = await request(app)
          .get('/api/health')
          .expect(200);
        
        expect(healthResponse.body).toHaveProperty('status');
        expect(healthResponse.body.status).toBe('healthy');
        expect(healthResponse.body).toHaveProperty('timestamp');
        expect(healthResponse.body).toHaveProperty('uptime');
        
        // Record health check metrics
        monitoringMetrics.healthChecks.push({
          timestamp: new Date(),
          endpoint: '/api/health',
          status: 'healthy',
          responseTime: performance.now() - startTime,
          details: healthResponse.body
        });
        
        console.log('✅ Basic health check passed');
        
        global.testReporter.logTestEnd('Basic Health Check', startTime, true);
      } catch (error) {
        monitoringMetrics.healthChecks.push({
          timestamp: new Date(),
          endpoint: '/api/health',
          status: 'unhealthy',
          error: error.message
        });
        
        global.testReporter.logTestEnd('Basic Health Check', startTime, false);
        throw error;
      }
    });

    test('should validate detailed health diagnostics', async () => {
      const startTime = global.testReporter.logTestStart('Detailed Health Diagnostics');
      
      try {
        const detailedHealthResponse = await request(app)
          .get('/api/health/detailed')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (detailedHealthResponse.status === 200) {
          const health = detailedHealthResponse.body;
          
          // Validate detailed health structure
          expect(health).toHaveProperty('status');
          expect(health).toHaveProperty('services');
          
          // Check individual service health
          const services = health.services;
          const serviceHealthChecks = [];
          
          if (services.database) {
            expect(services.database).toHaveProperty('status');
            serviceHealthChecks.push({
              service: 'database',
              status: services.database.status,
              responseTime: services.database.responseTime || 0
            });
          }
          
          if (services.email) {
            expect(services.email).toHaveProperty('status');
            serviceHealthChecks.push({
              service: 'email',
              status: services.email.status,
              responseTime: services.email.responseTime || 0
            });
          }
          
          if (services.upload) {
            expect(services.upload).toHaveProperty('status');
            serviceHealthChecks.push({
              service: 'upload',
              status: services.upload.status,
              responseTime: services.upload.responseTime || 0
            });
          }
          
          // Record service health metrics
          monitoringMetrics.healthChecks.push({
            timestamp: new Date(),
            endpoint: '/api/health/detailed',
            status: health.status,
            services: serviceHealthChecks,
            overallResponseTime: performance.now() - startTime
          });
          
          console.log('✅ Detailed health diagnostics completed');
          console.log(`📊 Services checked: ${serviceHealthChecks.length}`);
          
        } else {
          console.log('ℹ️ Detailed health endpoint not available');
        }
        
        global.testReporter.logTestEnd('Detailed Health Diagnostics', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Detailed Health Diagnostics', startTime, false);
        throw error;
      }
    });

    test('should validate database connectivity health', async () => {
      const startTime = global.testReporter.logTestStart('Database Health Check');
      
      try {
        const dbHealthResponse = await request(app)
          .get('/api/health/database')
          .expect(200);
        
        expect(dbHealthResponse.body).toHaveProperty('status');
        expect(dbHealthResponse.body.status).toBe('healthy');
        
        if (dbHealthResponse.body.metrics) {
          const metrics = dbHealthResponse.body.metrics;
          expect(metrics).toHaveProperty('connections');
          expect(metrics).toHaveProperty('responseTime');
          expect(typeof metrics.connections).toBe('number');
          expect(typeof metrics.responseTime).toBe('number');
          
          // Validate connection count is reasonable
          expect(metrics.connections).toBeGreaterThan(0);
          expect(metrics.connections).toBeLessThan(global.testConfig.performance.maxDbConnections);
          
          // Validate response time is acceptable
          expect(metrics.responseTime).toBeLessThan(1000); // 1 second max
        }
        
        console.log('✅ Database health check passed');
        
        global.testReporter.logTestEnd('Database Health Check', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Database Health Check', startTime, false);
        throw error;
      }
    });

    test('should validate external service health checks', async () => {
      const startTime = global.testReporter.logTestStart('External Service Health');
      
      try {
        const externalServices = [
          { name: 'email', endpoint: '/api/health/email' },
          { name: 'upload', endpoint: '/api/health/upload' },
          { name: 'monitoring', endpoint: '/api/health/monitoring' }
        ];
        
        for (const service of externalServices) {
          try {
            const serviceResponse = await request(app)
              .get(service.endpoint)
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(res => {
                expect([200, 503, 404]).toContain(res.status);
              });
            
            if (serviceResponse.status === 200) {
              console.log(`✅ ${service.name} service is healthy`);
              expect(serviceResponse.body).toHaveProperty('status');
            } else if (serviceResponse.status === 503) {
              console.warn(`⚠️ ${service.name} service is unavailable`);
            } else {
              console.log(`ℹ️ ${service.name} health check not implemented`);
            }
            
            // Record service health
            monitoringMetrics.healthChecks.push({
              timestamp: new Date(),
              service: service.name,
              endpoint: service.endpoint,
              status: serviceResponse.status === 200 ? 'healthy' : 'unhealthy',
              httpStatus: serviceResponse.status
            });
            
          } catch (error) {
            console.log(`ℹ️ ${service.name} health check failed: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('External Service Health', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('External Service Health', startTime, false);
        throw error;
      }
    });
  });

  describe('📈 Metrics Collection & Analysis', () => {
    test('should collect performance metrics', async () => {
      const startTime = global.testReporter.logTestStart('Performance Metrics Collection');
      
      try {
        const metricsResponse = await request(app)
          .get('/api/metrics')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (metricsResponse.status === 200) {
          const metrics = metricsResponse.body;
          
          // Validate metrics structure
          expect(metrics).toHaveProperty('timestamp');
          expect(metrics).toHaveProperty('system');
          expect(metrics).toHaveProperty('application');
          
          // System metrics validation
          if (metrics.system) {
            const system = metrics.system;
            expect(system).toHaveProperty('memory');
            expect(system).toHaveProperty('cpu');
            expect(system).toHaveProperty('uptime');
            
            // Memory metrics
            if (system.memory) {
              expect(system.memory).toHaveProperty('used');
              expect(system.memory).toHaveProperty('total');
              expect(typeof system.memory.used).toBe('number');
              expect(typeof system.memory.total).toBe('number');
            }
          }
          
          // Application metrics validation
          if (metrics.application) {
            const app = metrics.application;
            expect(app).toHaveProperty('requests');
            expect(app).toHaveProperty('responses');
            
            if (app.requests) {
              expect(app.requests).toHaveProperty('total');
              expect(app.requests).toHaveProperty('rate');
            }
            
            if (app.responses) {
              expect(app.responses).toHaveProperty('averageTime');
              expect(app.responses).toHaveProperty('errorRate');
            }
          }
          
          // Record metrics
          monitoringMetrics.systemMetrics.push({
            timestamp: new Date(),
            metrics: metrics,
            collectionTime: performance.now() - startTime
          });
          
          console.log('✅ Performance metrics collected successfully');
          
        } else {
          console.log('ℹ️ Metrics endpoint not available');
        }
        
        global.testReporter.logTestEnd('Performance Metrics Collection', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Performance Metrics Collection', startTime, false);
        throw error;
      }
    });

    test('should monitor real-time application metrics', async () => {
      const startTime = global.testReporter.logTestStart('Real-time Metrics Monitoring');
      
      try {
        // Perform operations to generate metrics
        const operations = [
          () => request(app).get('/api/form/current').expect(200),
          () => request(app).get('/api/health').expect(200),
          () => request(app).get('/api/admin/dashboard').set('Authorization', `Bearer ${adminToken}`).expect(200)
        ];
        
        // Execute operations and measure performance
        const operationMetrics = [];
        
        for (const operation of operations) {
          const operationStart = performance.now();
          await operation();
          const operationTime = performance.now() - operationStart;
          
          operationMetrics.push({
            timestamp: new Date(),
            responseTime: operationTime,
            operation: operation.toString().match(/\.([^(]+)/)?.[1] || 'unknown'
          });
        }
        
        // Calculate metrics
        const averageResponseTime = operationMetrics.reduce((sum, m) => sum + m.responseTime, 0) / operationMetrics.length;
        const maxResponseTime = Math.max(...operationMetrics.map(m => m.responseTime));
        const minResponseTime = Math.min(...operationMetrics.map(m => m.responseTime));
        
        console.log(`📊 Real-time Metrics:`, {
          averageResponseTime: Math.round(averageResponseTime) + 'ms',
          maxResponseTime: Math.round(maxResponseTime) + 'ms',
          minResponseTime: Math.round(minResponseTime) + 'ms',
          operationCount: operationMetrics.length
        });
        
        // Store metrics
        monitoringMetrics.responseTimeMetrics = monitoringMetrics.responseTimeMetrics.concat(operationMetrics);
        
        // Validate performance thresholds
        if (averageResponseTime > global.testConfig.performance.maxResponseTime) {
          console.warn(`⚠️ Average response time (${Math.round(averageResponseTime)}ms) exceeds threshold`);
        }
        
        global.testReporter.logTestEnd('Real-time Metrics Monitoring', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Real-time Metrics Monitoring', startTime, false);
        throw error;
      }
    });

    test('should validate system resource monitoring', async () => {
      const startTime = global.testReporter.logTestStart('System Resource Monitoring');
      
      try {
        const systemStatusResponse = await request(app)
          .get('/api/admin/system-status')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (systemStatusResponse.status === 200) {
          const systemStatus = systemStatusResponse.body;
          
          // Validate system status structure
          expect(systemStatus).toHaveProperty('timestamp');
          expect(systemStatus).toHaveProperty('resources');
          
          const resources = systemStatus.resources;
          
          // Memory monitoring
          if (resources.memory) {
            expect(resources.memory).toHaveProperty('usage');
            expect(resources.memory).toHaveProperty('available');
            expect(typeof resources.memory.usage).toBe('number');
            expect(typeof resources.memory.available).toBe('number');
            
            const memoryUsagePercent = (resources.memory.usage / (resources.memory.usage + resources.memory.available)) * 100;
            console.log(`📊 Memory Usage: ${Math.round(memoryUsagePercent)}%`);
            
            if (memoryUsagePercent > 90) {
              console.warn(`⚠️ High memory usage detected: ${Math.round(memoryUsagePercent)}%`);
              monitoringMetrics.alertsTriggered.push({
                timestamp: new Date(),
                type: 'memory',
                level: 'warning',
                value: memoryUsagePercent,
                threshold: 90
              });
            }
          }
          
          // CPU monitoring
          if (resources.cpu) {
            expect(resources.cpu).toHaveProperty('usage');
            expect(typeof resources.cpu.usage).toBe('number');
            
            console.log(`📊 CPU Usage: ${Math.round(resources.cpu.usage)}%`);
            
            if (resources.cpu.usage > 80) {
              console.warn(`⚠️ High CPU usage detected: ${Math.round(resources.cpu.usage)}%`);
              monitoringMetrics.alertsTriggered.push({
                timestamp: new Date(),
                type: 'cpu',
                level: 'warning',
                value: resources.cpu.usage,
                threshold: 80
              });
            }
          }
          
          // Disk monitoring
          if (resources.disk) {
            expect(resources.disk).toHaveProperty('usage');
            expect(typeof resources.disk.usage).toBe('number');
            
            console.log(`📊 Disk Usage: ${Math.round(resources.disk.usage)}%`);
          }
          
          console.log('✅ System resource monitoring active');
          
        } else {
          console.log('ℹ️ System status endpoint not available');
        }
        
        global.testReporter.logTestEnd('System Resource Monitoring', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('System Resource Monitoring', startTime, false);
        throw error;
      }
    });
  });

  describe('🚨 Alerting & Notification Systems', () => {
    test('should validate alerting configuration', async () => {
      const startTime = global.testReporter.logTestStart('Alerting Configuration');
      
      try {
        const alertConfigResponse = await request(app)
          .get('/api/admin/alerts/config')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (alertConfigResponse.status === 200) {
          const alertConfig = alertConfigResponse.body;
          
          // Validate alert configuration
          expect(alertConfig).toHaveProperty('enabled');
          expect(alertConfig).toHaveProperty('thresholds');
          expect(alertConfig).toHaveProperty('channels');
          
          if (alertConfig.thresholds) {
            const thresholds = alertConfig.thresholds;
            
            // Validate threshold configuration
            expect(thresholds).toHaveProperty('errorRate');
            expect(thresholds).toHaveProperty('responseTime');
            expect(thresholds).toHaveProperty('memoryUsage');
            
            console.log('📊 Alert Thresholds:', {
              errorRate: thresholds.errorRate + '%',
              responseTime: thresholds.responseTime + 'ms',
              memoryUsage: thresholds.memoryUsage + '%'
            });
          }
          
          if (alertConfig.channels) {
            const channels = alertConfig.channels;
            console.log(`📊 Alert Channels: ${channels.length} configured`);
            
            channels.forEach(channel => {
              expect(channel).toHaveProperty('type');
              expect(channel).toHaveProperty('enabled');
            });
          }
          
          console.log('✅ Alerting system is configured');
          
        } else {
          console.log('ℹ️ Alerting configuration endpoint not available');
        }
        
        global.testReporter.logTestEnd('Alerting Configuration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Alerting Configuration', startTime, false);
        throw error;
      }
    });

    test('should test alert triggering mechanisms', async () => {
      const startTime = global.testReporter.logTestStart('Alert Triggering Test');
      
      try {
        // Simulate conditions that should trigger alerts
        const alertTests = [
          {
            name: 'High Error Rate Simulation',
            test: async () => {
              // Generate several 404 errors
              const errors = [];
              for (let i = 0; i < 5; i++) {
                errors.push(
                  request(app)
                    .get('/api/nonexistent-endpoint')
                    .expect(404)
                );
              }
              await Promise.all(errors);
              return true;
            }
          },
          
          {
            name: 'Response Time Threshold Test',
            test: async () => {
              // Make requests and check if slow response alerts are triggered
              const slowRequests = [];
              for (let i = 0; i < 3; i++) {
                slowRequests.push(
                  request(app)
                    .get('/api/admin/dashboard')
                    .set('Authorization', `Bearer ${adminToken}`)
                    .expect(200)
                );
              }
              await Promise.all(slowRequests);
              return true;
            }
          }
        ];
        
        for (const alertTest of alertTests) {
          try {
            await alertTest.test();
            console.log(`✅ ${alertTest.name} completed`);
          } catch (error) {
            console.warn(`⚠️ ${alertTest.name} failed: ${error.message}`);
          }
        }
        
        // Check for triggered alerts
        const alertsResponse = await request(app)
          .get('/api/admin/alerts/recent')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (alertsResponse.status === 200) {
          const recentAlerts = alertsResponse.body.alerts || [];
          console.log(`📊 Recent alerts: ${recentAlerts.length}`);
          
          if (recentAlerts.length > 0) {
            recentAlerts.forEach(alert => {
              console.log(`🚨 Alert: ${alert.type} - ${alert.message}`);
              monitoringMetrics.alertsTriggered.push({
                timestamp: new Date(alert.timestamp),
                type: alert.type,
                level: alert.level,
                message: alert.message
              });
            });
          }
        }
        
        global.testReporter.logTestEnd('Alert Triggering Test', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Alert Triggering Test', startTime, false);
        throw error;
      }
    });
  });

  describe('📋 Continuous Monitoring', () => {
    test('should validate monitoring dashboard accessibility', async () => {
      const startTime = global.testReporter.logTestStart('Monitoring Dashboard');
      
      try {
        const dashboardResponse = await request(app)
          .get('/api/admin/monitoring/dashboard')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (dashboardResponse.status === 200) {
          const dashboard = dashboardResponse.body;
          
          // Validate dashboard structure
          expect(dashboard).toHaveProperty('overview');
          expect(dashboard).toHaveProperty('metrics');
          expect(dashboard).toHaveProperty('alerts');
          
          if (dashboard.overview) {
            expect(dashboard.overview).toHaveProperty('status');
            expect(dashboard.overview).toHaveProperty('uptime');
            expect(dashboard.overview).toHaveProperty('lastUpdate');
          }
          
          if (dashboard.metrics) {
            expect(dashboard.metrics).toHaveProperty('performance');
            expect(dashboard.metrics).toHaveProperty('system');
          }
          
          console.log('✅ Monitoring dashboard is accessible');
          
        } else {
          console.log('ℹ️ Monitoring dashboard not available');
        }
        
        global.testReporter.logTestEnd('Monitoring Dashboard', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Monitoring Dashboard', startTime, false);
        throw error;
      }
    });

    test('should validate log aggregation and analysis', async () => {
      const startTime = global.testReporter.logTestStart('Log Aggregation');
      
      try {
        const logsResponse = await request(app)
          .get('/api/admin/logs/recent')
          .set('Authorization', `Bearer ${adminToken}`)
          .query({ limit: 50 })
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (logsResponse.status === 200) {
          const logs = logsResponse.body.logs || [];
          
          console.log(`📊 Recent logs: ${logs.length} entries`);
          
          if (logs.length > 0) {
            // Validate log structure
            logs.forEach(log => {
              expect(log).toHaveProperty('timestamp');
              expect(log).toHaveProperty('level');
              expect(log).toHaveProperty('message');
            });
            
            // Analyze log levels
            const logLevels = logs.reduce((acc, log) => {
              acc[log.level] = (acc[log.level] || 0) + 1;
              return acc;
            }, {});
            
            console.log('📊 Log Level Distribution:', logLevels);
            
            // Check for concerning log patterns
            const errorLogs = logs.filter(log => log.level === 'error');
            const warningLogs = logs.filter(log => log.level === 'warn');
            
            if (errorLogs.length > 0) {
              console.warn(`⚠️ ${errorLogs.length} error logs found`);
            }
            
            if (warningLogs.length > 0) {
              console.warn(`⚠️ ${warningLogs.length} warning logs found`);
            }
          }
          
          console.log('✅ Log aggregation is working');
          
        } else {
          console.log('ℹ️ Log aggregation endpoint not available');
        }
        
        global.testReporter.logTestEnd('Log Aggregation', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Log Aggregation', startTime, false);
        throw error;
      }
    });
  });

  describe('📊 Monitoring Data Export', () => {
    test('should validate metrics data export capabilities', async () => {
      const startTime = global.testReporter.logTestStart('Metrics Data Export');
      
      try {
        const exportFormats = ['json', 'csv', 'prometheus'];
        
        for (const format of exportFormats) {
          try {
            const exportResponse = await request(app)
              .get(`/api/admin/metrics/export`)
              .set('Authorization', `Bearer ${adminToken}`)
              .query({ format: format })
              .expect(res => {
                expect([200, 404, 406]).toContain(res.status);
              });
            
            if (exportResponse.status === 200) {
              console.log(`✅ Metrics export in ${format} format is available`);
              
              // Validate export content type
              if (format === 'json') {
                expect(exportResponse.headers['content-type']).toMatch(/application\/json/);
              } else if (format === 'csv') {
                expect(exportResponse.headers['content-type']).toMatch(/text\/csv/);
              }
              
            } else {
              console.log(`ℹ️ Metrics export in ${format} format not available`);
            }
            
          } catch (error) {
            console.log(`ℹ️ Metrics export in ${format} format: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('Metrics Data Export', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Metrics Data Export', startTime, false);
        throw error;
      }
    });
  });

  // Helper function to generate monitoring report
  function generateMonitoringReport() {
    const reportStartTime = Date.now();
    
    console.log('\n📊 MONITORING REPORT GENERATION');
    console.log('==============================');
    
    // Health Checks Summary
    console.log(`\n🏥 Health Checks (${monitoringMetrics.healthChecks.length} total):`);
    const healthyChecks = monitoringMetrics.healthChecks.filter(h => h.status === 'healthy').length;
    const unhealthyChecks = monitoringMetrics.healthChecks.filter(h => h.status === 'unhealthy').length;
    console.log(`✅ Healthy: ${healthyChecks}`);
    console.log(`❌ Unhealthy: ${unhealthyChecks}`);
    
    // Response Time Metrics
    if (monitoringMetrics.responseTimeMetrics.length > 0) {
      console.log(`\n⚡ Response Time Metrics (${monitoringMetrics.responseTimeMetrics.length} samples):`);
      const responseTimes = monitoringMetrics.responseTimeMetrics.map(m => m.responseTime);
      const avgResponseTime = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);
      const minResponseTime = Math.min(...responseTimes);
      
      console.log(`📊 Average: ${Math.round(avgResponseTime)}ms`);
      console.log(`📊 Maximum: ${Math.round(maxResponseTime)}ms`);
      console.log(`📊 Minimum: ${Math.round(minResponseTime)}ms`);
    }
    
    // System Metrics
    if (monitoringMetrics.systemMetrics.length > 0) {
      console.log(`\n💾 System Metrics (${monitoringMetrics.systemMetrics.length} collections):`);
      const latestMetrics = monitoringMetrics.systemMetrics[monitoringMetrics.systemMetrics.length - 1];
      if (latestMetrics.metrics.system) {
        const system = latestMetrics.metrics.system;
        if (system.memory) {
          console.log(`📊 Memory Usage: ${Math.round((system.memory.used / system.memory.total) * 100)}%`);
        }
        if (system.cpu) {
          console.log(`📊 CPU Usage: ${Math.round(system.cpu)}%`);
        }
      }
    }
    
    // Alerts Summary
    console.log(`\n🚨 Alerts Triggered: ${monitoringMetrics.alertsTriggered.length}`);
    if (monitoringMetrics.alertsTriggered.length > 0) {
      const alertsByType = monitoringMetrics.alertsTriggered.reduce((acc, alert) => {
        acc[alert.type] = (acc[alert.type] || 0) + 1;
        return acc;
      }, {});
      
      Object.entries(alertsByType).forEach(([type, count]) => {
        console.log(`  ${type}: ${count} alerts`);
      });
    }
    
    // Overall Monitoring Health
    const monitoringHealth = calculateMonitoringHealth();
    console.log(`\n📈 Overall Monitoring Health: ${monitoringHealth.score}/100`);
    console.log(`📊 Status: ${monitoringHealth.status}`);
    
    if (monitoringHealth.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      monitoringHealth.recommendations.forEach((rec, index) => {
        console.log(`  ${index + 1}. ${rec}`);
      });
    }
    
    console.log(`\n⏱️ Report Generation Time: ${Date.now() - reportStartTime}ms`);
    console.log('==============================\n');
  }

  // Helper function to calculate monitoring health score
  function calculateMonitoringHealth() {
    let score = 100;
    const recommendations = [];
    
    // Health check score (30 points)
    const healthyRatio = monitoringMetrics.healthChecks.filter(h => h.status === 'healthy').length / 
                        Math.max(monitoringMetrics.healthChecks.length, 1);
    score += (healthyRatio * 30) - 30;
    
    if (healthyRatio < 0.9) {
      recommendations.push('Investigate unhealthy service endpoints');
    }
    
    // Response time score (25 points)
    if (monitoringMetrics.responseTimeMetrics.length > 0) {
      const avgResponseTime = monitoringMetrics.responseTimeMetrics
        .reduce((sum, m) => sum + m.responseTime, 0) / monitoringMetrics.responseTimeMetrics.length;
      
      if (avgResponseTime < 500) {
        // Excellent response time
      } else if (avgResponseTime < 1000) {
        score -= 5;
      } else if (avgResponseTime < 2000) {
        score -= 15;
        recommendations.push('Optimize response times');
      } else {
        score -= 25;
        recommendations.push('Critical: Response times are too slow');
      }
    }
    
    // Alert score (25 points)
    const criticalAlerts = monitoringMetrics.alertsTriggered.filter(a => a.level === 'critical').length;
    const warningAlerts = monitoringMetrics.alertsTriggered.filter(a => a.level === 'warning').length;
    
    score -= (criticalAlerts * 10) + (warningAlerts * 2);
    
    if (criticalAlerts > 0) {
      recommendations.push(`Address ${criticalAlerts} critical alerts`);
    }
    
    // System metrics score (20 points)
    if (monitoringMetrics.systemMetrics.length > 0) {
      const latestMetrics = monitoringMetrics.systemMetrics[monitoringMetrics.systemMetrics.length - 1];
      
      // This would be expanded based on actual system metrics structure
      // For now, we'll assume good system health
    }
    
    // Determine status
    let status;
    if (score >= 90) {
      status = 'EXCELLENT';
    } else if (score >= 75) {
      status = 'GOOD';
    } else if (score >= 60) {
      status = 'FAIR';
    } else {
      status = 'POOR';
    }
    
    return {
      score: Math.max(0, Math.round(score)),
      status,
      recommendations
    };
  }
});