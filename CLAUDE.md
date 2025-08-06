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
npm test            # Run all tests
npm run test:watch  # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
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
- `app.js` - Main Express server with Helmet security headers, optimized Express parsers (10MB limit), CORS, sessions, and routing
- `models/Response.js` - MongoDB schema for form responses with admin/user distinction
- `middleware/` - Security-focused middleware functions:
  - `auth.js` - Admin authentication and session management
  - `validation.js` - Strict input validation with XSS escaping (dual validation levels)
  - `rateLimiting.js` - Rate limiting configurations
  - `errorHandler.js` - Centralized error handling
- `tests/` - Comprehensive security test suites:
  - `validation.security.test.js` - XSS protection and boundary testing (22 tests)
  - `session.config.test.js` - Environment-aware cookie configuration validation (12 tests)
  - `body.limit.test.js` - Request size limit validation (4 tests)
  - `admin.duplicate.test.js` - Admin duplicate prevention scenarios
  - `middleware.integration.test.js` - End-to-end security pipeline tests
- `routes/` - API endpoints with layered security:
  - `responseRoutes.js` - Public form submission with strict validation, XSS escaping, and admin duplicate prevention
  - `adminRoutes.js` - Admin dashboard APIs (pagination, summary, CRUD)
  - `formRoutes.js` - Form utilities (legacy compatibility, basic validation)
  - `upload.js` - File upload handling with Cloudinary
- `config/cloudinary.js` - Cloudinary configuration

### Frontend Structure (`frontend/`)
- `public/` - Public-facing pages:
  - `index.html` - Main form page
  - `view.html` - Private response viewing page
  - `login.html` - Admin login
- `admin/` - Admin dashboard:
  - `admin.html` - Main admin interface
  - `admin_gestion.html` - Response management

### Key Features
- **Session-based admin authentication** with bcrypt password hashing
- **Monthly response system** where each user can submit once per month
- **Private response viewing** via secure tokens for non-admin users
- **Admin responses** stored without tokens, accessible only through admin interface
- **Rate limiting** (3 submissions per 15 minutes) on form endpoints
- **Enhanced security** with Helmet.js security headers and CSP policies preventing script injection
- **Multi-layer input validation** with express-validator escaping and dual validation levels (strict/compatible)
- **Honeypot spam protection** with hidden 'website' field
- **MongoDB indexes** on createdAt and unique month/isAdmin combinations

### Environment Variables Required
- `NODE_ENV` - Environment mode (`production` for secure cookies, or `development`/unset for HTTP compatibility)
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