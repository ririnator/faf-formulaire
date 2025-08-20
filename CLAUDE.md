# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Form-a-Friend v2** is a complete social form-sharing platform with symmetric monthly interactions, user authentication, contact management, and automated invitation systems. The project has evolved significantly from the original FAF v1 to include:

- **Backend**: Enterprise-grade Node.js/Express server with MongoDB and microservices architecture
- **Frontend**: Universal dashboard system with role-based interfaces and mobile-first design
- **Email Service**: Multi-provider email system with automated scheduling and webhooks (Resend/Postmark)
- **Contact System**: Advanced contact management with handshake workflows and CSV import
- **Automation**: Scheduler service with monthly cycles, reminders, and batch processing
- **Security**: Advanced threat detection, session monitoring, and performance alerting
- **Migration System**: Complete data migration tools from FAF v1 to Form-a-Friend v2

## Development Commands

### Backend Development
```bash
cd backend
npm install          # Install dependencies (includes helmet for security)
npm start           # Start production server (node app.js)
npm run dev         # Start development server with nodemon
npm test            # Run all backend tests
npm run test:watch  # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
npm run test:dynamic # Run dynamic option integration tests
npm run test:frontend # Run frontend tests
npm run test:frontend:watch # Run frontend tests in watch mode
npm run test:frontend:coverage # Run frontend tests with coverage
npm run test:form   # Test form locally
npm run test:all    # Run all backend and frontend tests
npm run test:all:coverage # Run all tests with coverage

# New specialized test suites
npm run test:auth          # Authentication and security tests
npm run test:migration     # Migration system tests
npm run test:security      # Comprehensive security tests
npm run test:scheduler     # Scheduler service tests
npm run test:staging       # Staging environment tests
npm run test:post-deployment # Post-deployment validation tests
npm run test:production    # Production readiness tests

# Scheduler operations
npm run scheduler          # Run scheduler service
npm run scheduler:demo     # Demo scheduler functionality
```


### Frontend Architecture
The frontend is now a sophisticated universal dashboard system with:
- **Universal Dashboard**: Role-based interfaces accessible to all authenticated users
- **Mobile-First Design**: Responsive layouts optimized for all devices
- **Landing Page System**: auth-choice.html as entry point for new users
- **Public Pages**: Served from `frontend/public/` for anonymous users
- **Admin Interface**: Advanced admin dashboard from `frontend/admin/`
- **User Dashboard**: Personal dashboard system from `frontend/dashboard/`
- **No Build Process**: Static files served directly by Express with advanced caching

### Development vs Production Configuration
- **Development** (`NODE_ENV=development` or unset): 
  - Session cookies: `sameSite: 'lax'`, `secure: false` (works with HTTP localhost)
  - Request body parsing: 10MB limit with Express native parsers
  - Suitable for local development without HTTPS certificates
- **Production** (`NODE_ENV=production`):
  - Session cookies: `sameSite: 'none'`, `secure: true` (requires HTTPS)
  - Enhanced security headers via Helmet.js with strict CSP
  - Optimized for cross-origin requests and secure deployment
- **Testing**: Environment-agnostic with 38+ security tests covering all scenarios

## Architecture

### Backend Structure (`backend/`)
- `app.js` - Main Express server with enterprise security, microservices integration, and Form-a-Friend v2 routing
- **Models** (`models/`) - Complete Form-a-Friend v2 data architecture:
  - `User.js` - User authentication with roles, profiles, and metadata
  - `Submission.js` - Monthly form submissions with responses and completion tracking  
  - `Contact.js` - Advanced contact management with tags, status, and CSV import
  - `Handshake.js` - Contact relationship requests with accept/decline workflows
  - `Invitation.js` - Email invitations with tokens and tracking
  - `Notification.js` - In-app notification system with types and delivery tracking
  - `Response.js` - Legacy FAF v1 model (maintained for migration compatibility)
- `config/` - Enterprise configuration architecture:
  - `cloudinary.js` - Cloudinary upload service configuration
  - `cors.js` - Cross-Origin Resource Sharing configuration
  - `database.js` - MongoDB connection and configuration
  - `environment.js` - Environment variable validation and setup
  - `session.js` - Session store and cookie configuration
  - `enterpriseSecurity.js` - Advanced enterprise security configurations
  - `privacy.js` - Privacy and data protection configurations
- **Services** (`services/`) - Microservices architecture with service instances:
  - **Core Services**:
    - `authService.js` - Authentication business logic and bcrypt handling
    - `responseService.js` - Legacy response operations (FAF v1 compatibility)
    - `uploadService.js` - File upload processing and Cloudinary integration
    - `serviceFactory.js` - Service layer dependency injection and factory pattern
  - **Form-a-Friend v2 Services**:
    - `submissionService.js` + `submissionServiceInstance.js` - Monthly submission management
    - `contactService.js` + `contactServiceInstance.js` - Contact management with CSV import
    - `handshakeService.js` + `handshakeServiceInstance.js` - Relationship workflows
    - `invitationService.js` + `invitationServiceInstance.js` - Invitation and token management
    - `notificationService.js` + `notificationServiceInstance.js` - Notification system
    - `emailService.js` - Multi-provider email service (Resend/Postmark)
  - **Automation & Scheduling**:
    - `schedulerService.js` + `schedulerServiceInstance.js` - Monthly automation cycles
    - `schedulerMonitoringService.js` - Scheduler monitoring and alerting
    - `schedulerLogger.js` - Structured logging for scheduler operations
    - `schedulerAlerting.js` - Intelligent alerting for scheduler issues
    - `schedulerMonitoringFactory.js` - Factory for scheduler monitoring components
    - `schedulerMonitoringIntegration.js` - Integration layer for scheduler monitoring
    - `workers/batchProcessor.js` - Batch processing for large operations
  - **Performance & Security**:
    - `sessionCleanupService.js` - Automatic cleanup of expired sessions and inactive users
    - `sessionMonitoringService.js` - Real-time session activity monitoring and threat detection
    - `hybridIndexMonitor.js` - Database query monitoring for hybrid index performance
    - `dbPerformanceMonitor.js` - Comprehensive database performance monitoring
    - `realTimeMetrics.js` - Real-time performance metrics collection
    - `performanceAlerting.js` - Intelligent performance alerting system
    - `searchMonitoringService.js` - Search query monitoring and optimization
    - `emailMonitoringService.js` + `emailMonitoringServiceInstance.js` - Email delivery monitoring
- **Middleware** (`middleware/`) - Enterprise security middleware architecture:
  - **Authentication & Authorization**:
    - `auth.js` - Admin authentication with bcrypt and session management
    - `hybridAuth.js` - Hybrid authentication system supporting both legacy and new user-based authentication
    - `authRateLimit.js` - Authentication-specific rate limiting
  - **Security & Validation**:
    - `validation.js` - Smart XSS escaping with Cloudinary URL preservation + null/undefined edge case handling
      - `smartEscape()` - Intelligent escaping that preserves valid Cloudinary URLs while protecting against XSS
      - `isCloudinaryUrl()` - Validates Cloudinary URLs with security checks for malicious content
    - `security.js` - CSP nonce generation + environment-adaptive session cookies
    - `enhancedSecurity.js` - Advanced security features and threat protection
    - `csrf.js` - CSRF protection middleware
    - `paramValidation.js` - URL parameter validation and sanitization
    - `querySanitization.js` - Database query sanitization and injection prevention
  - **Performance & Monitoring**:
    - `bodyParser.js` - Optimized body limits per endpoint type (512KB/2MB/5MB)
    - `rateLimiting.js` - Basic rate limiting configurations per endpoint
    - `enhancedRateLimiting.js` - Advanced rate limiting with intelligent patterns
    - `sessionMonitoring.js` - Session security middleware with threat detection
    - `statisticsMonitoring.js` - Application statistics and metrics collection
    - `csvSecurityMonitoring.js` - CSV operations security monitoring
    - `searchBlockingMiddleware.js` - Search query blocking for suspicious patterns
    - `searchComplexityAnalyzer.js` - Analysis of search query complexity
    - `emailDomainValidation.js` - Email domain validation and security
    - `advancedThreatDetection.js` - AI-powered threat detection and prevention
  - **Error Handling**:
    - `errorHandler.js` - Centralized error handling and logging
- `tests/` - Comprehensive security test suites (100+ tests):
  - `validation.edge-cases.test.js` - Null/undefined/malformed input handling (30 tests)
  - `validation.boundary.test.js` - Exact boundary conditions + performance (32 tests)
  - `validation.security.test.js` - XSS protection + HTML escaping (22 tests)
  - `validation.smart-escape.test.js` - Smart escape function with Cloudinary URL handling (44 tests)
  - `security.enhanced.test.js` - CSP nonce generation + session configs (19 tests)
  - `bodyParser.limits.test.js` - Optimized body parser limits per endpoint (16 tests)
  - `constraint.unit.test.js` - Database constraint validation (14 tests)
  - `session.config.test.js` - Environment-adaptive cookie settings (12 tests)
  - `dynamic.option.integration.test.js` - Dynamic option validation and testing
  - `integration.full.test.js` - Full integration testing scenarios
  - `middleware.integration.test.js` - Middleware integration testing
  - `sessionMonitoring.test.js` - Session monitoring unit tests (25+ tests)
  - `sessionManagement.integration.test.js` - Session management integration tests
  - `dbPerformanceMonitor.test.js` - Database performance monitoring tests
  - `admin-login.dual-endpoint.test.js` - Dual endpoint consistency tests for POST /login and POST /admin-login
  - `admin-login.frontend-errors.test.js` - Frontend error message handling validation
- **Routes** (`routes/`) - Complete API architecture with layered security:
  - **Core API Routes**:
    - `responseRoutes.js` - Legacy FAF v1 form submissions (maintained for compatibility)
    - `adminRoutes.js` - Admin dashboard APIs with advanced permissions and audit logs
    - `formRoutes.js` - Form utilities with legacy compatibility and basic validation
    - `upload.js` - Image upload handling (5MB limit) with MIME validation and Cloudinary integration
  - **Form-a-Friend v2 API Routes**:
    - `authRoutes.js` - User authentication, registration, and session management
    - `submissionRoutes.js` - Monthly submission management with validation and security
    - `contactRoutes.js` - Contact management with CSV import, tagging, and search
    - `handshakeRoutes.js` - Contact relationship workflows and mutual connections
    - `invitationRoutes.js` - Email invitation system with token validation
    - `notificationRoutes.js` - In-app notification management and delivery
    - `dashboardRoutes.js` - Universal dashboard APIs for all user roles
    - `webhookRoutes.js` - Email service webhook handling (bounces, unsubscribes)
  - **Monitoring & Administration Routes**:
    - `securityRoutes.js` - Security monitoring and threat detection endpoints
    - `schedulerMonitoringRoutes.js` - Scheduler monitoring and control endpoints
    - `rateLimitMonitoringRoutes.js` - Rate limiting monitoring and management
    - `searchMonitoringRoutes.js` - Search query monitoring and optimization
    - `emailHealthRoutes.js` - Email service health monitoring and diagnostics
    - `emailDomainAdminRoutes.js` - Email domain administration and validation

### Frontend Structure (`frontend/`)
- **Public Pages** (`public/`) - Anonymous user interface:
  - `auth-choice.html` - Landing page for authentication choices (new entry point)
  - `register.html` - User registration with validation
  - `login.html` - User login interface
  - `admin-login.html` - Admin-specific login interface
  - `form.html` - Legacy FAF v1 form (maintained for compatibility)
  - `view.html` - Private response viewing with secure HTML entity decoding
  - **Styling**: `css/` directory with modular CSS architecture
    - `auth-choice.css`, `register.css`, `login.css` - Authentication styling
    - `form.css`, `view.css` - Form and viewing interfaces
    - `faf-base.css`, `shared-base.css` - Shared base styles
    - `mobile-responsive.css` - Mobile-first responsive design
    - `photo-*.css` - Photo optimization and lightbox features
  - **JavaScript**: `js/` directory with modular functionality
    - `form.js`, `view.js` - Core form functionality
    - `homepage.js` - Landing page interactions
    - `photo-compression.js`, `photo-lazy-loading.js`, `photo-lightbox.js` - Photo features
- **Admin Interface** (`admin/`) - Administrative dashboard:
  - `admin.html` - Main admin dashboard with Chart.js visualizations
  - `admin_gestion.html` - Response management with advanced filtering
  - `contacts.html` - Contact management interface
  - `compare.html` - 1-vs-1 comparison view for responses
  - `timeline.html` - Timeline view for user activity
  - `faf-admin.js` - Unified ES6 module with named exports (AdminAPI, Utils, UI, Charts)
  - `contacts.js` - Contact management JavaScript
  - `css/admin.css` - Admin-specific styling
  - `js/notificationCenter.js` - Notification system
- **Universal Dashboard** (`dashboard/`) - Role-based user interface:
  - `dashboard.html` - Main universal dashboard
  - `dashboard-contacts.html` - Contact management for all users
  - `dashboard-responses.html` - Response viewing and management
  - `dashboard-contact-view.html` - Individual contact view
  - `dashboard.js` - Universal dashboard JavaScript
  - `css/dashboard.css` - Dashboard-specific styling
- **Shared JavaScript** (`js/`) - Cross-component utilities:
  - `authStateManager.js` - Authentication state management
- **Testing Infrastructure** (`tests/`) - Comprehensive frontend testing:
  - **Core Testing**:
    - `dynamic-option.test.js` - Dynamic form option testing
    - `form-integration.test.js` - Form integration testing
    - `form-submission.test.js` - Form submission validation
    - `real-form-submission.test.js` - Real-world scenarios
    - `faf-admin.test.js` - Admin module testing
  - **Advanced Testing**:
    - `cross-browser-compatibility.test.js` - Browser compatibility validation
    - `css-architecture.test.js` - CSS architecture validation
    - `dashboard-interactions.test.js` - Dashboard interaction testing
    - `mobile-navigation.test.js` - Mobile interface testing
    - `modular-architecture.test.js` - Component architecture validation
    - `performance-security.test.js` - Performance and security testing
    - `photo-compression-advanced.test.js`, `photo-optimization.test.js` - Photo feature testing
    - `end-to-end-integration.test.js` - Complete user journey testing
  - **Configuration**: `jest.config.js`, `setup.js` - Test environment setup

### Authentication System Architecture

**Dual Endpoint System** - The application supports both legacy and modern authentication through parallel endpoints:

#### Admin Authentication Endpoints
- **`POST /login`** - Legacy admin authentication endpoint (original system)
- **`POST /admin-login`** - Dedicated admin login endpoint for consistency and clarity
- **Identical Behavior**: Both endpoints use the same middleware stack and authentication logic:
  ```javascript
  app.post('/login', sessionMonitoringMiddleware.blockSuspiciousSessions(), authenticateAdmin);
  app.post('/admin-login', sessionMonitoringMiddleware.blockSuspiciousSessions(), authenticateAdmin);
  ```

#### User Redirection Flow
- **Regular Users**: `/login` → `/form` (main application functionality)
- **Admin Users**: `/login` or `/admin-login` → `/admin` (dashboard)
- **Legacy Admin**: `/admin-login` with dedicated UI emphasizing legacy system

#### Error Message Handling
Enhanced error parameter support in admin-login.html:
- `?error=1` - Invalid credentials message
- `?timeout=1` - Session expiration message  
- `?security=1` - Security issue detected message

#### Hybrid Authentication Middleware
The `hybridAuth.js` middleware provides:
- **`detectAuthMethod`** - Automatically detects user session vs token-based authentication
- **`requireAdminAccess`** - Supports both new User.role='admin' and legacy session.isAdmin
- **`requireUserAuth`** - Ensures modern user account authentication
- **`enrichUserData`** - Maintains session data consistency with database

### Key Features
- **Nonce-based CSP Security** - Dynamic nonces per request, eliminates unsafe-inline completely
- **Smart XSS Prevention** - Intelligent escaping that preserves Cloudinary image URLs while protecting against XSS attacks
- **XSS Prevention Architecture** - Secure DOM element creation, whitelist-based HTML entity decoding, no innerHTML with user content
- **Comprehensive Input Validation** - 100+ tests covering null/undefined/boundary/XSS edge cases
- **UTF-8 Encoding Support** - Global UTF-8 middleware, proper character encoding for French accented characters
- **ES6 Module Architecture** - Unified faf-admin.js module with named exports, eliminating dual-file complexity
- **Service Layer Architecture** - Separation of concerns with dedicated service classes for business logic
- **Configuration Modularity** - Environment-specific configuration files for database, CORS, sessions
- **Optimized Body Parser Limits** - 512KB standard, 2MB forms, 5MB images (80% memory reduction)
- **Environment-adaptive Configuration** - Auto-detection dev/prod with appropriate security settings
- **Database Constraint Enforcement** - Unique index preventing admin duplicates per month at DB level
- **Advanced Session Management** - Secure cookies (sameSite/secure) adapting to HTTPS availability + real-time monitoring
- **Session Security Monitoring** - Real-time threat detection, IP blocking, and suspicious activity alerts
- **Automatic Session Cleanup** - Expired sessions and inactive user cleanup with 90-day retention
- **Database Performance Monitoring** - Hybrid index performance tracking with intelligent alerting
- **Multi-layer XSS Protection** - HTML escaping + CSP headers + input sanitization + secure rendering
- **Enhanced Error Handling** - Hierarchical fallback system + centralized error middleware
- **CSRF Protection** - Token-based CSRF protection middleware
- **Parameter Validation** - URL parameter validation and sanitization middleware
- **Dynamic Question Ordering** - Zero-maintenance algorithm using first submission's natural order (replaces hardcoded arrays)
- **Intelligent Caching System** - 10-minute TTL with memory leak prevention, pre-warming, and automatic cleanup
- **Structured Logging** - Context-aware debugging with performance metrics and error resilience
- **Frontend Testing Infrastructure** - Dedicated frontend test suite with Jest configuration
- **Dynamic Option Testing** - Integration testing for dynamic form options
- **Session-based admin authentication** with bcrypt password hashing and session store
- **Monthly response system** where each user can submit once per month with token-based private viewing
- **Admin responses** stored without tokens, accessible only through authenticated admin interface
- **Intelligent rate limiting** -3 submissions per 15 minutes with IP-based tracking
- **Advanced spam protection** - Honeypot fields + request validation + pattern detection
- **Performance optimized** - Indexes on createdAt, admin constraints, efficient memory usage, asset caching

### Environment Variables Required

**Core Application**:
- `NODE_ENV` - Environment mode (`production` for secure HTTPS cookies + sameSite='none', `development`/unset for HTTP compatibility + sameSite='lax')
- `MONGODB_URI` - MongoDB connection string
- `SESSION_SECRET` - Session encryption key for secure authentication (32+ chars recommended)
- `APP_BASE_URL` - Base URL for generating private links and CORS
- `FRONTEND_URL` - Frontend domain URL for CORS configuration (optional secondary origin)

**Authentication & Security**:
- `LOGIN_ADMIN_USER` - Admin username for web interface login
- `LOGIN_ADMIN_PASS` - Admin password for web interface (hashed with bcrypt)
- `FORM_ADMIN_NAME` - Name of the person who fills forms as admin (e.g., "riri")
- `HTTPS` - Optional override to enable secure cookies in development (set to 'true')
- `COOKIE_DOMAIN` - Optional domain scope for production cookies (e.g., '.example.com' for subdomains)

**Email Service (Multi-provider)**:
- `EMAIL_PROVIDER` - Primary email provider ('resend' or 'postmark', defaults to 'resend')
- `EMAIL_FALLBACK_PROVIDER` - Fallback email provider for redundancy
- **Resend Configuration**:
  - `RESEND_API_KEY` - Resend API key for email sending
  - `RESEND_WEBHOOK_SECRET` - Webhook signature verification secret
- **Postmark Configuration**:
  - `POSTMARK_API_TOKEN` - Postmark server API token
  - `POSTMARK_WEBHOOK_SECRET` - Webhook signature verification secret
- **Email Settings**:
  - `EMAIL_FROM_ADDRESS` - Default sender email address
  - `EMAIL_FROM_NAME` - Default sender name (e.g., "Form-a-Friend")
  - `EMAIL_REPLY_TO` - Optional reply-to email address

**File Upload**:
- `CLOUDINARY_CLOUD_NAME` - Cloudinary cloud name
- `CLOUDINARY_API_KEY` - Cloudinary API key
- `CLOUDINARY_API_SECRET` - Cloudinary API secret

**Scheduler Service**:
- `SCHEDULER_TIMEZONE` - Timezone for scheduled operations (e.g., 'Europe/Paris')
- `SCHEDULER_ENABLED` - Enable/disable scheduler service (true/false, defaults to true)
- `MONTHLY_SEND_TIME` - Time to send monthly invitations (e.g., '18:00')
- `MONTHLY_SEND_DAY` - Day of month to send invitations (e.g., '5')

**Performance & Monitoring**:
- `PERFORMANCE_MONITORING_ENABLED` - Enable performance monitoring (true/false)
- `SESSION_MONITORING_ENABLED` - Enable session security monitoring (true/false)
- `DATABASE_MONITORING_ENABLED` - Enable database performance monitoring (true/false)

**Rate Limiting & Security**:
- `RATE_LIMIT_WINDOW_MS` - Rate limit window in milliseconds (default: 900000 = 15 min)
- `RATE_LIMIT_MAX_REQUESTS` - Max requests per window (default: 3)
- `ENHANCED_RATE_LIMITING` - Enable advanced rate limiting features (true/false)

**Development & Testing**:
- `DEBUG_MODE` - Enable debug logging (true/false, development only)
- `DISABLE_RATE_LIMITING` - Disable rate limiting for testing (true/false, testing only)

### Database Schema - Form-a-Friend v2 Architecture

**User Model** - Complete user authentication and profile system:
- `username` - Unique identifier for login (3-30 chars, serves as display name)
- `email` - Unique email address for authentication with validation
- `password` - Hashed password with bcrypt (min 6 chars)
- `role` - User role ('user' or 'admin', defaults to 'user')
- `profile` - Optional profile data (firstName, lastName, dateOfBirth, profession, location)
- `preferences` - User preferences (emailNotifications, reminderFrequency, timezone, language, privacy settings)
- `metadata` - System metadata (isActive, emailVerified, lastActive, responseCount, registeredAt, lastLoginAt)
- `migrationData` - Legacy migration data (legacyName, migratedAt, source)

**Submission Model** - Monthly form submissions (replaces Response for v2):
- `userId` - Reference to User who submitted (indexed)
- `month` - YYYY-MM format for monthly grouping with validation
- `responses[]` - Array of question/answer pairs with type support (text, photo, radio)
- `freeText` - Optional free-text field (max 5000 chars)
- `completionRate` - Percentage of questions completed
- `metadata` - Submission metadata (submittedAt, timeSpent, deviceInfo, ipAddress)

**Contact Model** - Advanced contact management system:
- `userId` - Owner of the contact list (indexed)
- `contactInfo` - Contact details (name, email, phone, relationship, notes)
- `tags[]` - Flexible tagging system for contact organization
- `status` - Contact status (active, inactive, blocked, pending)
- `source` - How contact was added (manual, csv_import, handshake, invitation)
- `preferences` - Contact-specific preferences and settings
- `metadata` - Contact metadata (addedAt, lastInteraction, responseCount)

**Handshake Model** - Contact relationship workflows:
- `requesterId` - User who sent the handshake request
- `recipientId` - User who received the request (optional, can be null for external)
- `recipientEmail` - Email of recipient (for external contacts)
- `status` - Handshake status (pending, accepted, declined, expired)
- `message` - Optional personal message with the request
- `expiresAt` - Expiration date for the handshake request
- `metadata` - Request metadata (createdAt, respondedAt, ipAddress)

**Invitation Model** - Email invitation system:
- `senderId` - User who sent the invitation
- `recipientEmail` - Email address of the recipient
- `month` - Target month for the invitation (YYYY-MM)
- `token` - Unique secure token for accessing the invitation
- `status` - Invitation status (sent, opened, completed, expired)
- `remindersSent` - Count of reminder emails sent
- `metadata` - Invitation metadata (sentAt, openedAt, completedAt, expiresAt)

**Notification Model** - In-app notification system:
- `userId` - User who should receive the notification
- `type` - Notification type (handshake_request, invitation_received, form_reminder, etc.)
- `title` - Notification title
- `message` - Notification content
- `read` - Whether the notification has been read
- `actionUrl` - Optional URL for notification action
- `metadata` - Notification metadata (createdAt, readAt, deliveredAt)

**Response Model** (Legacy) - FAF v1 compatibility:
- `name` - User's name (admin detection via `FORM_ADMIN_NAME` env var)
- `responses[]` - Array of question/answer pairs
- `month` - YYYY-MM format for monthly grouping
- `isAdmin` - Boolean flag for admin responses
- `token` - Unique token for private viewing (null for admin)
- `createdAt` - Timestamp with index
- **Status**: Maintained for migration compatibility, will be gradually phased out

**API Response Format**:
User `toPublicJSON()` method returns:
```json
{
  "id": "user_id",
  "username": "john_doe",
  "email": "john@example.com",
  "displayName": "john_doe",  // ⚠️ Returns username value for backward compatibility
  "role": "user",
  "profile": { "firstName": "John", "lastName": "Doe", ... },
  "metadata": { "isActive": true, "responseCount": 5, ... }
}
```
**Note**: `displayName` field was removed from schema but returned in API responses as alias for `username` to maintain backward compatibility.

### Security Features
- **Helmet.js security headers** with Content Security Policy (CSP) protecting against XSS, clickjacking, and MIME sniffing
- **CORS configuration** supporting multiple origins (`APP_BASE_URL` and `FRONTEND_URL`) with credentials
- **Modular authentication middleware** (`middleware/auth.js`) with bcrypt comparison and session management
- **Multi-tier input validation** (`middleware/validation.js`):
  - **Strict validation** (`validateResponseStrict`) for main endpoints with XSS escaping
  - **Compatible validation** (`validateResponse`) for legacy endpoints
  - **Character limits**: Names (2-100), Questions (≤500), Answers (≤10k), Max 20 responses
- **Rate limiting** (3 submissions per 15 minutes) with memory-based tracking
- **Honeypot spam protection** with hidden 'website' field validation
- **Admin duplicate prevention** with case-insensitive detection and monthly constraints
- **Environment-aware session configuration**:
  - **Development**: `sameSite: 'lax'`, `secure: false` (HTTP compatible)
  - **Production**: `sameSite: 'none'`, `secure: true` (HTTPS required)
  - **MongoDB store** with 1-hour cookie expiry and 14-day session TTL
- **Request body size limits** (10MB) using Express native parsers (optimized from 50MB)
- **XSS Protection**: All HTML entities escaped (`<`, `>`, `&`, `"`, `'` → HTML entities)
- **Secure HTML Entity Handling**: Whitelist-based decoding with `SAFE_HTML_ENTITIES` constant
- **UTF-8 Encoding Middleware**: Global charset support for French characters (éàçùûîôêâ)

### Frontend Security Architecture
- **XSS Prevention**: Secure DOM element creation, no `innerHTML` with user content
- **HTML Entity Decoding**: Whitelist approach supporting only known-safe entities with `SAFE_HTML_ENTITIES`
- **ES6 Module Structure**: Clean imports with `AdminAPI`, `Utils`, `UI`, and `Charts` namespaces
- **Unified Error Handling**: Centralized alert system through `UI.showAlert()`
- **CSRF Integration**: Automatic token management through `AdminAPI.request()`
- **Content Security Policy**: Strict CSP with nonces preventing injection attacks

### Dynamic Question Ordering System
**Algorithm Overview**: Zero-maintenance question ordering that eliminates hardcoded arrays

**Problem Solved**: Previously used a 12-line hardcoded `QUESTION_ORDER` array that required manual updates whenever form questions changed, risking desync between form and backend.

**Solution**: Dynamic ordering based on natural form submission order with intelligent caching.

**Implementation Steps**:
1. **Cache Check** - 10-minute TTL with month-specific keys (`"YYYY-MM"` or `"all"`)
2. **First Response Discovery** - Find oldest response for the time period using `createdAt` index  
3. **Natural Order Extraction** - Use that response's question sequence as canonical ordering
4. **PIE_Q Prioritization** - Always place pie chart question first regardless of original position
5. **Question Normalization** - Group similar questions using `normalizeQuestion()` for French accents/spacing
6. **Fallback Strategy** - Use `textSummary` order if no valid first response found
7. **Cache Population** - Store result with metadata (source, performance metrics, response ID)

**Cache Optimizations**:
- **Memory Leak Prevention** - MAX_CACHE_SIZE (50 entries) with LRU eviction
- **Automatic Cleanup** - Removes expired entries every 5 minutes
- **Pre-warming** - Current month cached on startup and monthly refresh
- **Error Resilience** - Falls back to expired cache if DB errors occur

**Performance Benefits**:
- **Eliminates DB queries** for repeated requests (10-minute cache)
- **Pre-warmed cache** ensures fast initial response times
- **Structured logging** tracks hit/miss ratios and performance metrics

**Test Coverage**:
- **15 comprehensive tests** in `admin.question-order.test.js`
- **Edge cases**: corrupted data, empty datasets, normalization failures
- **Performance tests**: large datasets, consistency across concurrent requests
- **Fallback validation**: textSummary ordering when primary method fails

### Testing Infrastructure
- **Backend**: Jest + Supertest + MongoDB Memory Server for comprehensive testing
- **Security Test Coverage**:
  - **XSS injection attempts** - Script tags, HTML entities, JavaScript events, complex payloads (22 tests)
  - **Boundary testing** - Character limits (2-100 name, 500 question, 10k answer, 20 responses max)
  - **Admin duplicate scenarios** - Case-insensitive detection, monthly constraints, race conditions
  - **Session configuration** - Environment-aware cookie settings (development vs production)
  - **Body size limits** - 10MB Express parser configuration validation (reduced from 50MB)
  - **Honeypot protection** - Spam field detection and rejection
  - **Input sanitization** - Null/undefined handling, whitespace trimming, Unicode support
  - **Dynamic question ordering** - 15 tests covering natural order, caching, edge cases, performance
- **Test Commands**: `npm test`, `npm run test:watch`, `npm run test:coverage`
- **Test Results**: 257+ tests pass (January 2025), comprehensive security validation
- **Performance Testing**: Large payload handling, concurrent request processing, validation speed
- **Architecture Validation**: Middleware modularity, Express parser optimization, environment adaptation

### User Authentication Simplification (August 2025)
**displayName Field Removal**:
- **🎯 Simplified Authentication**: Removed separate `displayName` field from User model to eliminate user confusion
- **✅ Backward Compatibility**: `toPublicJSON()` method now returns `username` as `displayName` for API compatibility
- **📝 No Migration Required**: Existing users unaffected as displayName was computed field, not stored data
- **🔧 Frontend Simplified**: Registration form no longer requires separate display name input
- **🧪 Test Coverage Updated**: 100+ test cases updated to reflect new username-only approach
- **📋 Decision Rationale**: Users found separate username/displayName confusing; username serves both purposes effectively

### Recent Architecture Improvements (January 2025)
**Security & XSS Fixes**:
- **🚨 CRITICAL XSS Fix**: Replaced `innerHTML` with secure `textContent` in view.html:51
- **🔧 Session Cookie Fix**: Corrected cookie name from `connect.sid` to `faf-session` in logout
- **🛡️ Complete innerHTML Audit**: Replaced all unsafe `innerHTML` usage with `createElement()` and `textContent`
- **🔒 Production Debug Lock**: Debug endpoints now disabled in production environment

**UI/UX & Display Fixes**:
- **🔧 French Character Display**: Fixed apostrophe display in admin.html (&#x27; → ') by removing overly aggressive .escape() from express-validator
- **✨ Natural Language Support**: Questions now display with proper French apostrophes and accents without compromising XSS security
- **🎯 Smart Escaping Strategy**: Preserved `escapeQuestion()` function that protects against dangerous characters while allowing natural French text
- **🧪 Frontend HTML Entity Decoding**: Enhanced `Utils.unescapeHTML()` in faf-admin.js with better entity handling and secure DOM creation

**Code Quality & Architecture**:
- **🧹 Code Cleanup**: Removed 18 duplicate/obsolete files (*.refactored.js, *.v2.js, test files)
- **✅ Test Repairs**: Fixed session configuration tests and removed problematic upload mocks
- **🔧 Architecture Refactor**: Replaced admin-utils.js + core-utils.js with unified faf-admin.js ES6 module

**Dynamic Question Ordering Implementation**:
- **✨ Zero-Maintenance Algorithm**: Eliminated hardcoded QUESTION_ORDER array (12 lines removed)
- **🚀 Intelligent Caching**: 10-minute TTL with memory leak prevention and pre-warming
- **📊 Structured Logging**: Context-aware debugging with performance metrics and error resilience
- **🛡️ Robust Fallback**: Multiple fallback strategies for corrupted/missing data
- **⚡ Performance Optimized**: Pre-warmed cache, LRU eviction, automatic cleanup
- **✅ Comprehensive Testing**: 15 new tests covering edge cases, performance, and consistency

### Session Management & Security Improvements (August 2025)
**Advanced Session Monitoring**:
- **🔍 Real-time Threat Detection**: SessionMonitoringService tracks suspicious login patterns and IP behavior
- **🚫 Automatic IP Blocking**: 5 failed login attempts within 15 minutes triggers automatic IP blocking
- **📊 Session Statistics**: Real-time dashboard for administrators with security metrics
- **🤖 Bot Detection**: Identifies and blocks automated tools and suspicious user agents
- **⚡ Performance Impact**: Minimal overhead with intelligent sampling and memory management

**Session Lifecycle Management**:
- **🧹 Automatic Cleanup**: SessionCleanupService removes expired sessions and inactive users (90-day retention)
- **📋 Comprehensive Auditing**: Detailed logs of all session activities for security analysis
- **🔄 Graceful Shutdown**: Proper cleanup of all services during application shutdown
- **📈 Monitoring Integration**: Full integration with performance alerting system

**Database Performance Monitoring**:
- **📊 Hybrid Index Monitoring**: HybridIndexMonitor tracks dual authentication system performance
- **🚨 Intelligent Alerting**: Automatic alerts for performance degradation or security issues
- **📉 Query Analysis**: Real-time analysis of database query patterns and index efficiency
- **🔧 Optimization Recommendations**: Automated suggestions for index improvements

**Migration & Rollback Procedures**:
- **📚 Complete Documentation**: Comprehensive rollback procedures in `docs/MIGRATION_ROLLBACK_PROCEDURES.md`
- **🔄 Automated Rollback**: Interactive script for safe migration rollback with dry-run mode
- **🛡️ Data Integrity**: Multi-phase verification with backup creation and integrity checks
- **⚠️ Risk Assessment**: Detailed risk mitigation strategies and recovery procedures

**Test Coverage Expansion**:
- **✅ Session Monitoring Tests**: 25+ unit tests for session monitoring functionality
- **🔄 Integration Testing**: Complete session management integration test suite
- **🏗️ Performance Testing**: Database monitoring and hybrid index performance validation
- **📊 Comprehensive Coverage**: 100+ additional tests covering all new security features