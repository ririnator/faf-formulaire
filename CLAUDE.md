# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FAF (Form-a-Friend) is a **multi-tenant serverless application** that allows admins to create monthly forms and collect responses from friends. The application uses:

- **Architecture**: Vercel Serverless Functions (12 functions on Hobby plan limit)
- **Database**: Supabase PostgreSQL with Row Level Security (RLS)
- **Authentication**: JWT-based (stateless, 7-day expiry)
- **Payment**: Stripe subscription (€12/month with grandfathered accounts)
- **Frontend**: Static HTML/CSS/JS served by Vercel
- **Deployment**: Production at https://faf-multijoueur.vercel.app

## Development Commands

### Serverless Development
```bash
# Development server (Vercel local emulation)
vercel dev

# Run tests
npm test

# Deploy to production
vercel --prod

# View logs
vercel logs
```

### Testing
```bash
npm test                    # Run all tests
npm test -- tests/auth.test.js  # Run specific test file
```

**Note**: Legacy Express/MongoDB code is archived in `backend_mono_user_legacy/` and should NOT be used for development.

## Architecture

### Serverless Functions (`api/`)

The application uses **12 Vercel Serverless Functions** (Hobby plan limit):

```
api/
├── auth/
│   ├── login.js            # POST - JWT authentication (username + password)
│   └── register.js         # POST - New admin registration
├── form/
│   └── [username].js       # GET - Dynamic form by username (public)
├── response/
│   ├── submit.js           # POST - Submit form response (public)
│   └── view/
│       └── [token].js      # GET - View private comparison (token-based)
├── admin/
│   ├── dashboard.js        # GET - Admin dashboard data (JWT + Payment required)
│   ├── responses.js        # GET - Paginated responses (JWT + Payment required)
│   └── response/
│       └── [id].js         # GET/PATCH/DELETE - CRUD operations (JWT + Payment required)
├── payment/
│   ├── create-checkout.js  # POST - Create Stripe checkout (JWT required)
│   ├── status.js           # GET - Check payment status (JWT required)
│   └── webhook.js          # POST - Stripe webhook handler (public with signature verification)
└── upload.js               # POST - Cloudinary image upload (public with rate limiting)
```

### Database (Supabase PostgreSQL)

**Schema Location**: `sql/` directory

#### Main Tables

```sql
-- Admins table
admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  payment_status TEXT CHECK (payment_status IN ('active', 'trialing', 'past_due', 'canceled', 'unpaid')),
  subscription_end_date TIMESTAMPTZ,
  is_grandfathered BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
)

-- Responses table
responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES admins(id) NOT NULL,
  name TEXT NOT NULL,
  responses JSONB NOT NULL,
  month TEXT NOT NULL,
  is_owner BOOLEAN DEFAULT FALSE,
  token TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
)
```

#### Row Level Security (RLS)

All tables have RLS policies enforcing data isolation:
- Admins can only see/modify **their own** responses (`owner_id = auth.uid()`)
- Public routes use service role key with application-level validation
- Admin routes use authenticated user context

### Frontend Structure (`frontend/`)

```
frontend/
├── public/
│   ├── auth/
│   │   ├── landing.html        # Landing page (public)
│   │   ├── register.html       # Registration form (public)
│   │   └── login.html          # Login form (public)
│   ├── form/
│   │   └── index.html          # Dynamic form page (public)
│   ├── view/
│   │   └── index.html          # Private comparison view (token-based)
│   ├── css/
│   │   └── main.css            # Global styles
│   └── js/
│       ├── auth.js             # Authentication utilities (JWT)
│       └── form.js             # Form submission logic
└── admin/
    ├── admin.html              # Dashboard (JWT + Payment required)
    ├── admin_gestion.html      # Response management (JWT + Payment required)
    └── faf-admin.js            # ES6 module (AdminAPI, Utils, UI, Charts)
```

### Middleware (`middleware/`)

```
middleware/
├── auth.js           # JWT verification (verifyJWT, optionalAuth)
├── payment.js        # Payment status check (requirePayment)
└── rateLimit.js      # Rate limiting (IP-based, 3 submissions/15min)
```

### Utilities (`utils/`)

```
utils/
├── supabase.js       # Supabase client configuration
├── jwt.js            # JWT generation/verification (7-day expiry)
├── validation.js     # Input validation (XSS prevention, length checks)
├── questions.js      # Question normalization
└── tokens.js         # View token generation (UUIDs)
```

### SQL Migrations (`sql/`)

```
sql/
├── 001_initial_schema.sql      # Base tables (admins, responses)
├── 002_rls_policies.sql        # Row Level Security policies
├── 003_payment_columns.sql     # Stripe integration
├── 004_grandfathered.sql       # Grandfathered accounts feature
└── 005_cleanup_test_data.sql   # Production cleanup
```

### Tests (`tests/`)

```
tests/
├── auth.test.js                # JWT authentication tests
├── integration/
│   └── full-flow.test.js       # End-to-end integration tests
├── performance/
│   └── load.test.js            # Load testing
└── security/
    └── xss-csrf-ratelimit.test.js  # Security validation tests
```

**Note**: Legacy tests in `backend_mono_user_legacy/backend/tests/` are for the old Express/MongoDB architecture and are not used.

## Authentication & Security

### JWT Authentication Flow

```
1. Registration (POST /api/auth/register)
   → Create admin in Supabase (bcrypt password hash)
   → Generate JWT (7-day expiry, HS256)
   → Return JWT to client

2. Login (POST /api/auth/login)
   → Verify username + password (bcrypt compare)
   → Generate JWT
   → Return JWT to client

3. Protected Routes
   → Client sends: Authorization: Bearer <token>
   → middleware/auth.js verifies JWT signature
   → Extracts userId from token payload
   → Attaches userId to request

4. Payment-Protected Routes
   → middleware/payment.js checks payment_status
   → Allows: 'active', 'trialing', is_grandfathered=true
   → Blocks: 'past_due', 'canceled', 'unpaid', or missing payment info
```

### Payment System (Stripe)

**Features**:
- Monthly subscription: €12/month
- 7-day free trial for new admins
- Grandfathered accounts: Lifetime free access (is_grandfathered=true)
- Webhook-driven status updates (payment.succeeded, subscription.updated)

**Middleware Protection**:
```javascript
// api/admin/dashboard.js
export default verifyJWT(requirePayment(async (req, res) => {
  // Only accessible if JWT valid AND payment active/grandfathered
}))
```

**Stripe Webhook**:
- Endpoint: `/api/payment/webhook`
- Validates signature (STRIPE_WEBHOOK_SECRET)
- Updates admin payment_status and subscription_end_date

### Security Features

- **JWT Authentication** - Stateless, 7-day expiry, HS256 signing
- **Row Level Security (RLS)** - Database-level isolation by owner_id
- **XSS Prevention** - Input validation + HTML escaping in `utils/validation.js`
- **Rate Limiting** - 3 submissions per 15 minutes per IP (`middleware/rateLimit.js`)
- **CORS** - Configured in `vercel.json` for allowed origins
- **Payment Enforcement** - Admin routes require active subscription or grandfathered status
- **Cloudinary Signed Uploads** - Secure image uploads with signature verification

## Environment Variables

### Required Variables

```bash
# Supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGci...
SUPABASE_SERVICE_KEY=eyJhbGci...

# JWT
JWT_SECRET=your-super-secret-jwt-key-min-32-characters

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID=price_...

# Cloudinary (optional for image uploads)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=123456789012345
CLOUDINARY_API_SECRET=abcdefghijklmnopqrstuvwxyz

# Application
NODE_ENV=production
APP_BASE_URL=https://faf-multijoueur.vercel.app
```

### Configuration in Vercel

Add environment variables in Vercel Dashboard:
1. Project Settings → Environment Variables
2. Add each variable for Production, Preview, and Development
3. Redeploy after adding variables

## Database Queries

### Common Patterns

```javascript
// Get admin by username (public routes)
const { data: admin } = await supabase
  .from('admins')
  .select('*')
  .eq('username', username)
  .single()

// Get responses for authenticated admin (with RLS)
const { data: responses } = await supabase
  .from('responses')
  .select('*')
  .eq('owner_id', userId)
  .order('created_at', { ascending: false })

// Get response by token (public with token)
const { data: response } = await supabase
  .from('responses')
  .select('*')
  .eq('token', token)
  .single()
```

### RLS Context

- **Service Role Key** (`SUPABASE_SERVICE_KEY`): Bypasses RLS, used in public routes (`/api/response/submit`, `/api/form/[username]`)
- **Authenticated Context**: Uses `userId` from JWT, enforces RLS policies in admin routes

## Payment Integration

### Grandfathered Accounts

Admins with `is_grandfathered = true` have lifetime free access:

```sql
-- Grant grandfathered status
UPDATE admins
SET is_grandfathered = TRUE,
    payment_status = 'active'
WHERE username = 'riri';
```

### Payment Status Values

- `active` - Subscription active
- `trialing` - 7-day free trial
- `past_due` - Payment failed, grace period
- `canceled` - Subscription canceled
- `unpaid` - Trial ended, no payment
- `NULL` - New admin, no payment info yet

### Middleware Logic

```javascript
// middleware/payment.js
if (admin.is_grandfathered) {
  return next() // Bypass payment check
}

if (!['active', 'trialing'].includes(admin.payment_status)) {
  return res.status(402).json({ error: 'Payment required' })
}
```

## Deployment

### Production Deployment

```bash
# Deploy to production
vercel --prod

# View deployment status
vercel ls

# View logs
vercel logs faf-multijoueur --production
```

### Vercel Configuration (`vercel.json`)

- **Functions**: All files in `api/**/*.js` become serverless functions
- **Routes**: Defined for `/form/*`, `/view/*`, `/admin/*`, `/api/*`
- **Headers**: CORS headers for allowed origins
- **Regions**: Auto (Vercel edge network)

### Database Migrations

Run SQL migrations in Supabase SQL Editor:
1. Execute files in order: `001_initial_schema.sql` → `002_rls_policies.sql` → etc.
2. Verify tables and policies created
3. Test RLS with sample queries

## Legacy Code (DO NOT USE)

### Archived Express/MongoDB Architecture

**Location**: `backend_mono_user_legacy/`

This folder contains the **old mono-user architecture**:
- Express.js monolith with `app.js`
- MongoDB with Mongoose (`models/Response.js`)
- Session-based authentication (express-session)
- No payment system
- No multi-tenancy

**Status**: ⚠️ **ARCHIVED** - For reference only, do NOT use for development

**Why archived**:
- Migrated to Vercel serverless (scalability)
- Migrated to Supabase PostgreSQL (RLS, reliability)
- Migrated to JWT (stateless, multi-tenant)
- Added Stripe payment system

## Testing

### Running Tests

```bash
# All tests
npm test

# Specific test file
npm test -- tests/auth.test.js

# Watch mode
npm test -- --watch
```

### Test Structure

- **Unit tests**: Individual function testing
- **Integration tests**: Full API flow testing (`tests/integration/`)
- **Security tests**: XSS, CSRF, rate limiting (`tests/security/`)
- **Performance tests**: Load testing (`tests/performance/`)

**Legacy tests**: Tests in `backend_mono_user_legacy/backend/tests/` are for the old Express architecture and will fail (they test non-existent code).

## Common Tasks

### Adding a New Serverless Function

1. Create file in `api/` (e.g., `api/foo/bar.js`)
2. Export default async handler:
   ```javascript
   export default async function handler(req, res) {
     return res.status(200).json({ message: 'Hello' })
   }
   ```
3. Deploy: `vercel --prod`

**Note**: Hobby plan limited to 12 functions total.

### Protecting a Route with JWT + Payment

```javascript
import { verifyJWT } from '../../middleware/auth.js'
import { requirePayment } from '../../middleware/payment.js'

export default verifyJWT(requirePayment(async (req, res) => {
  const userId = req.userId // From verifyJWT
  const admin = req.admin   // From requirePayment

  // Your protected logic here
}))
```

### Adding a SQL Migration

1. Create file in `sql/` (e.g., `006_new_feature.sql`)
2. Write SQL with comments
3. Execute in Supabase SQL Editor
4. Update CLAUDE.md with migration details

## Documentation

- **[README.md](README.md)** - User-facing project overview
- **[CLAUDE.md](CLAUDE.md)** - Developer guidance (this file)
- **[docs/STRIPE_SETUP.md](docs/STRIPE_SETUP.md)** - Stripe integration guide
- **[docs/STRIPE_QUICKSTART.md](docs/STRIPE_QUICKSTART.md)** - Quick payment setup
- **[docs/SESSION_03_NOV_2025.md](docs/SESSION_03_NOV_2025.md)** - Session notes (Nov 3, 2025)
- **[docs/deployment/VERCEL_SETUP_GUIDE.md](docs/deployment/VERCEL_SETUP_GUIDE.md)** - Vercel deployment guide
- **[docs/architecture/MULTITENANT_SPEC.md](docs/architecture/MULTITENANT_SPEC.md)** - Multi-tenant specifications

## Important Reminders

1. **Architecture**: This is a **serverless application** (Vercel), NOT an Express server
2. **Database**: Uses **Supabase PostgreSQL**, NOT MongoDB
3. **Auth**: Uses **JWT tokens**, NOT sessions
4. **Payment**: **Stripe subscription** required for admin features (except grandfathered accounts)
5. **Function Limit**: **12 functions max** on Vercel Hobby plan - carefully manage new endpoints
6. **Legacy Code**: Files in `backend_mono_user_legacy/` are **ARCHIVED** - do NOT modify or reference
7. **RLS Policies**: Always consider Row Level Security when writing Supabase queries
8. **JWT Expiry**: Tokens expire after 7 days - users must re-login

## Development Workflow

1. **Local Development**: `vercel dev` (emulates serverless environment)
2. **Make Changes**: Edit files in `api/`, `frontend/`, `middleware/`, `utils/`
3. **Test**: `npm test` and manual testing at http://localhost:3000
4. **Commit**: Follow conventional commits (e.g., "feat:", "fix:", "docs:")
5. **Deploy**: `vercel --prod` (or push to GitHub for auto-deploy)
6. **Monitor**: Check Vercel logs and Supabase dashboard

## Support

For questions or issues:
- Check documentation in `docs/` folder
- Review session notes: `docs/SESSION_03_NOV_2025.md`
- Check Vercel logs: `vercel logs`
- Check Supabase dashboard: https://app.supabase.com

---

**Last Updated**: November 7, 2025
**Architecture Version**: Multi-Tenant v2.0 (Serverless)
**Production URL**: https://faf-multijoueur.vercel.app
