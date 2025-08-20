# Statistics Rate Limiting Security Implementation

## Overview

This document describes the comprehensive statistics rate limiting security implementation for the FAF (Form-a-Friend) application, designed to prevent abuse of resource-intensive analytics operations while maintaining admin dashboard functionality.

## Security Requirements Addressed

### 1. **Prevent Analytics-based DoS Attacks**
- Specialized rate limiters for different computational complexity levels
- Granular control over statistics endpoint access patterns
- Protection against automated statistics scraping

### 2. **Computational Resource Protection**
- Heavy analytics operations limited to 10 requests per hour
- Global statistics queries limited to 12 requests per 45 minutes  
- Real-time monitoring limited to 30 requests per 5 minutes
- Admin summaries limited to 20 requests per 30 minutes

### 3. **Maintain Admin Dashboard Responsiveness**
- Simple statistics allowed 40 requests per 10 minutes
- Performance monitoring status checks properly rate limited
- Graduated limits based on actual computational cost

## Implementation Components

### Rate Limiting Middleware (`middleware/rateLimiting.js`)

#### Statistics-Specific Rate Limiters

```javascript
// Simple statistics (basic counts, status summaries)
const statsSimpleLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutes
  max: 40, // 40 simple stats requests per 10 minutes
  message: { success: false, error: "Trop de demandes de statistiques simples. Réessayez plus tard.", code: 'SIMPLE_STATS_RATE_LIMIT_EXCEEDED' }
});

// Complex admin summary statistics (aggregation pipelines, complex queries)
const statsAdminSummaryLimiter = rateLimit({
  windowMs: 30 * 60 * 1000,  // 30 minutes
  max: 20, // 20 admin summary requests per 30 minutes
  message: { success: false, error: "Limite de résumés admin atteinte. Réessayez plus tard.", code: 'ADMIN_SUMMARY_RATE_LIMIT_EXCEEDED' }
});

// Heavy computational analytics (performance monitoring, deep analysis)
const statsHeavyAnalyticsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 10, // 10 heavy analytics requests per hour
  message: { success: false, error: "Limite d'analyses lourdes atteinte. Réessayez dans 1 heure.", code: 'HEAVY_ANALYTICS_RATE_LIMIT_EXCEEDED' }
});

// Real-time monitoring and metrics (frequent updates)
const statsRealTimeMonitoringLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,   // 5 minutes
  max: 30, // 30 real-time monitoring requests per 5 minutes
  message: { success: false, error: "Limite de monitoring temps réel atteinte. Réessayez plus tard.", code: 'REALTIME_MONITORING_RATE_LIMIT_EXCEEDED' }
});

// Comparison and correlation analytics (cross-data analysis)
const statsComparisonLimiter = rateLimit({
  windowMs: 20 * 60 * 1000,  // 20 minutes
  max: 15, // 15 comparison requests per 20 minutes
  message: { success: false, error: "Limite d'analyses comparatives atteinte. Réessayez plus tard.", code: 'COMPARISON_STATS_RATE_LIMIT_EXCEEDED' }
});

// Global statistics across all entities (database-wide queries)
const statsGlobalLimiter = rateLimit({
  windowMs: 45 * 60 * 1000,  // 45 minutes
  max: 12, // 12 global stats requests per 45 minutes
  message: { success: false, error: "Limite de statistiques globales atteinte. Réessayez plus tard.", code: 'GLOBAL_STATS_RATE_LIMIT_EXCEEDED' }
});

// Performance and system statistics (resource intensive)
const statsPerformanceLimiter = rateLimit({
  windowMs: 30 * 60 * 1000,  // 30 minutes
  max: 8, // 8 performance stats requests per 30 minutes
  message: { success: false, error: "Limite de statistiques de performance atteinte. Réessayez plus tard.", code: 'PERFORMANCE_STATS_RATE_LIMIT_EXCEEDED' }
});
```

### Statistics Monitoring System (`middleware/statisticsMonitoring.js`)

#### Features

1. **Real-time Access Tracking**
   - Monitors usage patterns by endpoint and user
   - Tracks IP-based and user-based access history
   - Records response times and computational complexity

2. **Suspicious Pattern Detection**
   - High frequency access detection (>10 requests/minute)
   - Suspicious user agent identification (bots, scrapers, automation tools)
   - Rapid endpoint switching detection (>10 different endpoints in 5 minutes)
   - Concurrent request monitoring (>3 concurrent requests)

3. **Security Event Logging**
   - Comprehensive logging of suspicious access patterns
   - Performance alerts for slow statistics queries (>30 seconds)
   - Structured logging with severity levels
   - Production-ready log file management

4. **Performance Monitoring**
   - Average response time tracking per endpoint
   - Error rate monitoring
   - Unique user and IP tracking
   - Automatic cleanup of old monitoring data (24-hour retention)

#### Alert Thresholds

```javascript
alertThresholds: {
  maxRequestsPerMinute: 10,
  maxConcurrentRequests: 3,
  maxResponseTime: 30000, // 30 seconds
  suspiciousUserAgentPatterns: [
    /bot/i, /crawler/i, /scraper/i, /python/i, 
    /curl/i, /wget/i, /postman/i
  ]
}
```

## Protected Endpoints

### Admin Dashboard Statistics

| Endpoint | Rate Limiter | Limit | Window | Monitoring |
|----------|--------------|-------|--------|------------|
| `GET /api/admin/summary` | `statsAdminSummaryLimiter` | 20 requests | 30 minutes | `trackAdminSummary` |
| `GET /api/admin/cleanup/status` | `statsSimpleLimiter` | 40 requests | 10 minutes | `trackSimpleStats` |
| `GET /api/admin/statistics-monitoring/status` | `statsSimpleLimiter` | 40 requests | 10 minutes | `trackSimpleStats` |

### Performance Monitoring

| Endpoint | Rate Limiter | Limit | Window | Monitoring |
|----------|--------------|-------|--------|------------|
| `GET /api/admin/performance/status` | `statsPerformanceLimiter` | 8 requests | 30 minutes | `trackPerformanceStats` |
| `GET /api/admin/performance/summary` | `statsHeavyAnalyticsLimiter` | 10 requests | 1 hour | `trackHeavyAnalytics` |
| `GET /api/admin/performance/realtime` | `statsRealTimeMonitoringLimiter` | 30 requests | 5 minutes | `trackRealTimeMonitoring` |
| `GET /api/admin/performance/slow-queries` | `statsHeavyAnalyticsLimiter` | 10 requests | 1 hour | `trackHeavyAnalytics` |
| `GET /api/admin/performance/hybrid-indexes` | `statsHeavyAnalyticsLimiter` | 10 requests | 1 hour | `trackHeavyAnalytics` |
| `GET /api/admin/performance/alerts` | `statsRealTimeMonitoringLimiter` | 30 requests | 5 minutes | `trackRealTimeMonitoring` |
| `GET /api/admin/performance/export` | `searchExportLimiter` | 5 requests | 1 hour | N/A |

### Global Statistics

| Endpoint | Rate Limiter | Limit | Window | Monitoring |
|----------|--------------|-------|--------|------------|
| `GET /api/contacts/stats/global` | `statsGlobalLimiter` | 12 requests | 45 minutes | `trackGlobalStats` |

### Simple Statistics

| Endpoint | Rate Limiter | Limit | Window | Monitoring |
|----------|--------------|-------|--------|------------|
| `GET /api/contacts/:id/stats` | `statsSimpleLimiter` | 40 requests | 10 minutes | `trackSimpleStats` |
| `GET /api/handshakes/stats` | `statsSimpleLimiter` | 40 requests | 10 minutes | `trackSimpleStats` |
| `GET /api/invitations/stats` | `statsSimpleLimiter` | 40 requests | 10 minutes | `trackSimpleStats` |

### Comparison Analytics

| Endpoint | Rate Limiter | Limit | Window | Monitoring |
|----------|--------------|-------|--------|------------|
| `GET /api/submissions/comparison/:contactId/:month` | `statsComparisonLimiter` | 15 requests | 20 minutes | `trackComparison` |

## Statistics Monitoring Dashboard

### Management Endpoints

| Endpoint | Method | Description | Security |
|----------|--------|-------------|----------|
| `/api/admin/statistics-monitoring/status` | GET | Get monitoring metrics and statistics | Admin + Simple Stats Rate Limit |
| `/api/admin/statistics-monitoring/config` | PUT | Update monitoring configuration | Admin Only |
| `/api/admin/statistics-monitoring/reset` | POST | Reset monitoring data | Admin Only |

### Monitoring Data Structure

```javascript
{
  monitoring: {
    totalRequests: number,
    recentRequests: number,      // Last hour
    uniqueIPs: number,
    uniqueUsers: number,
    trackedEndpoints: number,
    suspiciousPatterns: number
  },
  endpoints: [
    {
      endpoint: string,
      type: string,              // endpoint classification
      totalRequests: number,
      averageResponseTime: number,
      errorRate: number,         // percentage
      uniqueUsers: number,
      uniqueIPs: number,
      lastAccessed: string       // ISO timestamp
    }
  ],
  thresholds: {
    maxRequestsPerMinute: number,
    maxConcurrentRequests: number,
    maxResponseTime: number,
    suspiciousUserAgentPatterns: array
  }
}
```

## Security Features

### 1. **Graduated Rate Limiting**
- **Simple Operations**: 40 requests per 10 minutes
- **Complex Aggregations**: 20 requests per 30 minutes  
- **Heavy Analytics**: 10 requests per 1 hour
- **Global Queries**: 12 requests per 45 minutes
- **Real-time Monitoring**: 30 requests per 5 minutes
- **Performance Stats**: 8 requests per 30 minutes
- **Comparison Analytics**: 15 requests per 20 minutes

### 2. **Suspicious Pattern Detection**
- **High Frequency**: >10 requests per minute from single IP
- **Bot Detection**: Identifies automated tools via User-Agent
- **Rapid Switching**: >10 different endpoints in 5 minutes
- **Concurrent Abuse**: >3 simultaneous requests from single IP

### 3. **Security Event Logging**
- Structured logging with severity levels
- Automatic log file management for production
- Real-time security alerts
- Performance degradation warnings

### 4. **Memory Management**
- Automatic cleanup of old monitoring data (24-hour retention)
- LRU cache eviction for memory leak prevention
- Configurable cache size limits (50 entries max)
- Periodic cleanup every 10 minutes

## Error Response Format

All rate limiters return consistent error responses:

```javascript
{
  success: false,
  error: "Descriptive error message in French",
  code: "SPECIFIC_RATE_LIMIT_CODE",
  retryAfter: number  // seconds
}
```

### Error Codes
- `SIMPLE_STATS_RATE_LIMIT_EXCEEDED`
- `ADMIN_SUMMARY_RATE_LIMIT_EXCEEDED`
- `HEAVY_ANALYTICS_RATE_LIMIT_EXCEEDED`
- `REALTIME_MONITORING_RATE_LIMIT_EXCEEDED`
- `COMPARISON_STATS_RATE_LIMIT_EXCEEDED`
- `GLOBAL_STATS_RATE_LIMIT_EXCEEDED`
- `PERFORMANCE_STATS_RATE_LIMIT_EXCEEDED`

## Configuration Management

### Environment-Aware Operation
- **Test Environment**: Rate limiting disabled via `NODE_ENV=test`
- **Development**: Full rate limiting with debug logging
- **Production**: Optimized limits with security logging

### Dynamic Configuration
Statistics monitoring thresholds can be updated via admin API:

```javascript
PUT /api/admin/statistics-monitoring/config
{
  config: {
    maxRequestsPerMinute: 5,
    maxResponseTime: 20000,
    maxConcurrentRequests: 2
  }
}
```

## Testing and Validation

### Test Coverage
- Rate limiter configuration validation
- Admin dashboard protection testing
- Global statistics protection verification
- Simple statistics appropriate limiting
- Comparison analytics protection
- Statistics monitoring system validation
- Security event logging verification
- Performance impact assessment

### Test File
Comprehensive test suite in `tests/statistics-rate-limiting.test.js` covering:
- Rate limiting behavior across different endpoint types
- Statistics monitoring system functionality
- Security event detection and logging
- Admin dashboard protection
- Performance impact validation

## Security Benefits

### 1. **DoS Attack Prevention**
- Prevents analytics-based denial of service attacks
- Protects against automated scraping of statistics
- Limits resource consumption by malicious actors

### 2. **Performance Protection**
- Ensures admin dashboards remain responsive
- Prevents database overload from complex analytics queries
- Maintains system stability under load

### 3. **Monitoring and Alerting**
- Real-time detection of suspicious access patterns
- Comprehensive logging for security analysis
- Automated alerts for performance degradation

### 4. **Operational Intelligence**
- Detailed metrics on statistics endpoint usage
- User behavior analysis for capacity planning
- Performance optimization insights

## Implementation Impact

### Minimal Performance Overhead
- Lightweight monitoring with intelligent sampling
- Efficient memory management with automatic cleanup
- Optimized data structures for fast pattern detection

### Enhanced Security Posture
- Multi-layered protection against analytics abuse
- Proactive threat detection and response
- Comprehensive audit trail for security analysis

### Administrative Control
- Granular rate limiting control per endpoint type
- Real-time monitoring dashboard for administrators
- Dynamic configuration updates without restart

This implementation provides comprehensive protection for statistics and analytics endpoints while maintaining the functionality and responsiveness required for legitimate admin operations.