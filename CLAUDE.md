# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FAF (Form-a-Friend) is a monthly form application that allows friends to submit responses and view each other's answers. The application consists of:

- **Backend**: Node.js/Express server with MongoDB database
- **Frontend**: Static HTML/CSS/JS files served by the backend

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
```


### No Frontend Build Process
The frontend consists of static files served directly by Express from `frontend/public/` and `frontend/admin/`.

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
- `app.js` - Main Express server with nonce-based CSP, optimized body parsers (512KB-5MB), environment-adaptive sessions, and database constraints
- `models/Response.js` - MongoDB schema with unique admin constraint per month and optimized indexes
- `config/` - Modular configuration architecture:
  - `cloudinary.js` - Cloudinary upload service configuration
  - `cors.js` - Cross-Origin Resource Sharing configuration
  - `database.js` - MongoDB connection and configuration
  - `environment.js` - Environment variable validation and setup
  - `session.js` - Session store and cookie configuration
- `services/` - Business logic service layer:
  - `authService.js` - Authentication business logic and bcrypt handling
  - `responseService.js` - Response CRUD operations and validation
  - `uploadService.js` - File upload processing and Cloudinary integration
  - `serviceFactory.js` - Service layer dependency injection and factory pattern
- `middleware/` - Modular security middleware architecture:
  - `auth.js` - Admin authentication with bcrypt and session management
  - `validation.js` - Strict XSS escaping + null/undefined edge case handling (dual validation levels)
  - `security.js` - CSP nonce generation + environment-adaptive session cookies
  - `bodyParser.js` - Optimized body limits per endpoint type (512KB/2MB/5MB)
  - `rateLimiting.js` - Rate limiting configurations per endpoint
  - `csrf.js` - CSRF protection middleware
  - `errorHandler.js` - Centralized error handling and logging
  - `paramValidation.js` - URL parameter validation and sanitization
- `tests/` - Comprehensive security test suites (100+ tests):
  - `validation.edge-cases.test.js` - Null/undefined/malformed input handling (30 tests)
  - `validation.boundary.test.js` - Exact boundary conditions + performance (32 tests)
  - `validation.security.test.js` - XSS protection + HTML escaping (22 tests)
  - `security.enhanced.test.js` - CSP nonce generation + session configs (19 tests)
  - `bodyParser.limits.test.js` - Optimized body parser limits per endpoint (16 tests)
  - `constraint.unit.test.js` - Database constraint validation (14 tests)
  - `session.config.test.js` - Environment-adaptive cookie settings (12 tests)
  - `dynamic.option.integration.test.js` - Dynamic option validation and testing
  - `integration.full.test.js` - Full integration testing scenarios
  - `middleware.integration.test.js` - Middleware integration testing
- `routes/` - API endpoints with layered security and optimized body parsing:
  - `responseRoutes.js` - Public form submission (2MB body limit) with strict validation, XSS escaping, admin duplicate prevention
  - `adminRoutes.js` - Admin dashboard APIs (1MB body limit) with pagination, summary, CRUD operations
  - `formRoutes.js` - Form utilities with legacy compatibility and basic validation
  - `upload.js` - Image upload handling (5MB limit) with MIME validation and Cloudinary integration

### Frontend Structure (`frontend/`)
- `public/` - Public-facing pages:
  - `index.html` - Main form page
  - `view.html` - Private response viewing page with secure HTML entity decoding
  - `login.html` - Admin login
- `admin/` - Admin dashboard:
  - `admin.html` - Main admin interface with refactored utility functions
  - `admin_gestion.html` - Response management with enhanced error handling
  - `core-utils.js` - Essential utilities loaded synchronously (unescapeHTML, coreAlert)
  - `admin-utils.js` - Extended functionality loaded asynchronously (CSRF, API calls, UI components)
- `tests/` - Frontend testing infrastructure:
  - `dynamic-option.test.js` - Dynamic form option testing
  - `form-integration.test.js` - Form integration testing
  - `form-submission.test.js` - Form submission validation testing
  - `real-form-submission.test.js` - Real-world form submission scenarios
  - `jest.config.js` - Frontend-specific Jest configuration
  - `setup.js` - Test environment setup and utilities

### Key Features
- **Nonce-based CSP Security** - Dynamic nonces per request, eliminates unsafe-inline completely
- **XSS Prevention Architecture** - Secure DOM element creation, whitelist-based HTML entity decoding, no innerHTML with user content
- **Comprehensive Input Validation** - 100+ tests covering null/undefined/boundary/XSS edge cases
- **UTF-8 Encoding Support** - Global UTF-8 middleware, proper character encoding for French accented characters
- **Modular Frontend Architecture** - DRY principle with shared constants, synchronous/asynchronous utility loading
- **Service Layer Architecture** - Separation of concerns with dedicated service classes for business logic
- **Configuration Modularity** - Environment-specific configuration files for database, CORS, sessions
- **Optimized Body Parser Limits** - 512KB standard, 2MB forms, 5MB images (80% memory reduction)
- **Environment-adaptive Configuration** - Auto-detection dev/prod with appropriate security settings
- **Database Constraint Enforcement** - Unique index preventing admin duplicates per month at DB level
- **Advanced Session Management** - Secure cookies (sameSite/secure) adapting to HTTPS availability
- **Multi-layer XSS Protection** - HTML escaping + CSP headers + input sanitization + secure rendering
- **Enhanced Error Handling** - Hierarchical fallback system + centralized error middleware
- **CSRF Protection** - Token-based CSRF protection middleware
- **Parameter Validation** - URL parameter validation and sanitization middleware
- **Frontend Testing Infrastructure** - Dedicated frontend test suite with Jest configuration
- **Dynamic Option Testing** - Integration testing for dynamic form options
- **Session-based admin authentication** with bcrypt password hashing and session store
- **Monthly response system** where each user can submit once per month with token-based private viewing
- **Admin responses** stored without tokens, accessible only through authenticated admin interface
- **Intelligent rate limiting** (3 submissions per 15 minutes) with IP-based tracking
- **Advanced spam protection** - Honeypot fields + request validation + pattern detection
- **Performance optimized** - Indexes on createdAt, admin constraints, efficient memory usage, asset caching

### Environment Variables Required
- `NODE_ENV` - Environment mode (`production` for secure HTTPS cookies + sameSite='none', `development`/unset for HTTP compatibility + sameSite='lax')
- `HTTPS` - Optional override to enable secure cookies in development (set to 'true')
- `COOKIE_DOMAIN` - Optional domain scope for production cookies (e.g., '.example.com' for subdomains)
- `MONGODB_URI` - MongoDB connection string
- `SESSION_SECRET` - Session encryption key for secure authentication
- `LOGIN_ADMIN_USER` - Admin username for web interface login
- `LOGIN_ADMIN_PASS` - Admin password for web interface (hashed with bcrypt)
- `FORM_ADMIN_NAME` - Name of the person who fills forms as admin (e.g., "riri")
- `APP_BASE_URL` - Base URL for generating private links and CORS
- `FRONTEND_URL` - Frontend domain URL for CORS configuration (optional secondary origin)
- `CLOUDINARY_*` - Cloudinary configuration for file uploads

### Database Schema
The `Response` model contains:
- `name` - User's name (admin detection via `FORM_ADMIN_NAME` env var)
- `responses[]` - Array of question/answer pairs
- `month` - YYYY-MM format for monthly grouping
- `isAdmin` - Boolean flag for admin responses
- `token` - Unique token for private viewing (null for admin)
- `createdAt` - Timestamp with index

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
- **HTML Entity Decoding**: Whitelist approach supporting only known-safe entities
- **Shared Constants**: `SAFE_HTML_ENTITIES` prevents code duplication and drift
- **Hierarchical Error Handling**: `safeAlert()` with multiple fallback levels
- **Modular Loading**: Synchronous loading for critical utilities, asynchronous for extended features
- **Content Security Policy**: Strict CSP with nonces preventing injection attacks

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
- **Test Commands**: `npm test`, `npm run test:watch`, `npm run test:coverage`
- **Test Results**: 38+ security tests pass, maintaining 100% backward compatibility
- **Performance Testing**: Large payload handling, concurrent request processing, validation speed
- **Architecture Validation**: Middleware modularity, Express parser optimization, environment adaptation