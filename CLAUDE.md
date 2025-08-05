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
npm install          # Install dependencies
npm start           # Start production server (node app.js)
npm run dev         # Start development server with nodemon
npm test            # Run all tests
npm run test:watch  # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
```


### No Frontend Build Process
The frontend consists of static files served directly by Express from `frontend/public/` and `frontend/admin/`.

## Architecture

### Backend Structure (`backend/`)
- `app.js` - Main Express server with authentication, CORS, sessions, and routing
- `models/Response.js` - MongoDB schema for form responses with admin/user distinction
- `routes/` - API endpoints:
  - `responseRoutes.js` - Public form submission endpoint
  - `adminRoutes.js` - Admin dashboard APIs (pagination, summary, CRUD)
  - `formRoutes.js` - Form-related utilities
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
- **Honeypot spam protection** with hidden 'website' field
- **MongoDB indexes** on createdAt and unique month/isAdmin combinations

### Environment Variables Required
- `MONGODB_URI` - MongoDB connection string
- `SESSION_SECRET` - Session encryption key
- `ADMIN_USER` - Admin username
- `ADMIN_PASS` - Admin password (hashed with bcrypt)
- `APP_BASE_URL` - Base URL for generating private links
- `FRONTEND_URL` - Frontend domain URL for CORS configuration
- `CLOUDINARY_*` - Cloudinary configuration for file uploads

### Database Schema
The `Response` model contains:
- `name` - User's name (admin detection via 'riri')
- `responses[]` - Array of question/answer pairs
- `month` - YYYY-MM format for monthly grouping
- `isAdmin` - Boolean flag for admin responses
- `token` - Unique token for private viewing (null for admin)
- `createdAt` - Timestamp with index

### Security Features
- CORS configuration supporting multiple origins (`APP_BASE_URL` and `FRONTEND_URL`)
- Admin middleware protecting all admin routes
- Input validation using express-validator
- Rate limiting on form submissions (3 per 15 minutes)
- Honeypot spam protection with hidden 'website' field
- Secure session configuration with MongoDB store

### Testing Infrastructure
- **Backend**: Jest + Supertest + MongoDB Memory Server for API and integration tests
- **Coverage**: Response validation, spam detection, admin logic, rate limiting, file uploads
- **Test Commands**: `npm test`, `npm run test:watch`, `npm run test:coverage`