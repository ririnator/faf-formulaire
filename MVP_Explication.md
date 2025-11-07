# MVP_Explication.md

## Vue d'ensemble

Form-a-Friend (FAF) est une application SaaS multi-tenant permettant aux administrateurs de créer des formulaires mensuels et de collecter des réponses anonymes de leurs amis pour comparer les perceptions.

---

## PARTIE 1 : FONCTIONNALITÉS UTILISATEUR (Non-technique)

### Pour l'Administrateur

#### 1. **Inscription et Authentification**
- Créer un compte avec username, email et mot de passe
- Se connecter avec username et mot de passe
- Rester connecté pendant 7 jours (session automatique)
- Chaque admin a son propre espace isolé

#### 2. **Système d'Abonnement**
- **Essai gratuit de 7 jours** à l'inscription
- Abonnement mensuel à **12€/mois** via Stripe
- Accès au dashboard et aux données uniquement avec abonnement actif
- **Comptes grandfathered** : certains utilisateurs ont accès gratuit à vie

#### 3. **Partage du Formulaire**
- URL personnalisée : `https://faf-multijoueur.vercel.app/form/{votre-username}`
- Partager cette URL avec ses amis (WhatsApp, email, SMS, etc.)
- Le formulaire est public et accessible sans compte

#### 4. **Collecte de Réponses**
- Les amis remplissent le formulaire anonymement
- Questions sur des traits de personnalité, préférences, etc.
- Upload d'images possible via Cloudinary
- L'admin remplit aussi sa propre version (marquée comme "propriétaire")

#### 5. **Dashboard Administrateur**
- **Vue d'ensemble** :
  - Statistiques globales (nombre de réponses, mois actuel)
  - Statut de l'abonnement
  - Graphiques et visualisations

- **Gestion des réponses** :
  - Liste paginée de toutes les réponses reçues
  - Voir les détails de chaque réponse
  - Modifier ou supprimer des réponses
  - Tri et filtrage des données

#### 6. **Comparaison Privée**
- Chaque ami reçoit un **lien unique et privé** par email
- Via ce lien, il peut voir comment sa perception compare à :
  - La perception de l'admin sur lui-même
  - La moyenne des autres amis
- Visualisation sous forme de graphiques comparatifs

### Pour l'Ami (Répondant)

#### 1. **Remplir le Formulaire**
- Accéder via le lien partagé par l'admin
- Remplir un formulaire avec ~15 questions
- Ajouter son nom/prénom
- Uploader des images si nécessaire
- Soumettre anonymement

#### 2. **Recevoir son Lien Privé**
- Recevoir un email avec un token unique
- Accéder à une page de comparaison personnalisée
- Voir les écarts entre sa perception et celle de l'admin
- Visualisations graphiques des différences

#### 3. **Limitation**
- **Protection anti-spam** : maximum 3 soumissions par adresse IP toutes les 15 minutes

---

## PARTIE 2 : FONCTIONNALITÉS TECHNIQUES

### Architecture Globale

#### 1. **Infrastructure Serverless (Vercel)**
- **12 fonctions serverless** (limite Hobby plan)
- Déploiement automatique sur push GitHub
- Edge network pour latence minimale
- Auto-scaling selon la demande

#### 2. **Base de Données (Supabase PostgreSQL)**
- **Tables principales** :
  - `admins` : comptes utilisateurs avec infos Stripe
  - `responses` : réponses collectées avec JSONB
- **Row Level Security (RLS)** : isolation des données par admin
- Sauvegardes automatiques
- Indexes optimisés pour les requêtes fréquentes

#### 3. **Authentification JWT (Stateless)**
- Tokens signés avec HS256
- Expiration après 7 jours
- Payload : `{ userId, iat, exp }`
- Vérification dans middleware `verifyJWT`

### Fonctionnalités Backend (API)

#### API d'Authentification
```
POST /api/auth/register
- Crée un admin (bcrypt hash du mot de passe)
- Génère un JWT
- Retourne le token

POST /api/auth/login
- Vérifie username + password
- Génère un JWT
- Retourne le token
```

#### API Formulaire
```
GET /api/form/[username]
- Route dynamique publique
- Retourne les questions du formulaire
- Pas d'authentification requise

POST /api/response/submit
- Soumission publique avec rate limiting
- Validation XSS des inputs
- Génération d'un token unique pour visualisation
- Stockage en JSONB dans PostgreSQL

GET /api/response/view/[token]
- Accès public avec token UUID
- Retourne les données de comparaison
- Calculs de moyennes côté serveur
```

#### API Admin (Protégée JWT + Payment)
```
GET /api/admin/dashboard
- Middleware: verifyJWT + requirePayment
- Statistiques agrégées
- Graphiques de répartition
- Infos d'abonnement

GET /api/admin/responses
- Pagination (limit, offset)
- Tri et filtrage
- Métadonnées (total, page, etc.)

GET /api/admin/response/[id]
- Détails d'une réponse spécifique

PATCH /api/admin/response/[id]
- Mise à jour d'une réponse

DELETE /api/admin/response/[id]
- Suppression d'une réponse
```

#### API Paiement (Stripe)
```
POST /api/payment/create-checkout
- Middleware: verifyJWT
- Crée une session Stripe Checkout
- Mode subscription (12€/mois)
- Essai gratuit de 7 jours
- Retourne l'URL de paiement

GET /api/payment/status
- Middleware: verifyJWT
- Retourne le statut d'abonnement actuel
- Informations sur le customer Stripe

POST /api/payment/webhook
- Route publique avec vérification de signature
- Événements Stripe :
  - checkout.session.completed
  - invoice.payment_succeeded
  - customer.subscription.updated
  - customer.subscription.deleted
- Met à jour payment_status et subscription_end_date
```

#### API Upload
```
POST /api/upload
- Upload d'images vers Cloudinary
- Rate limiting (3 uploads/15min/IP)
- Signature de sécurité Cloudinary
- Retourne l'URL de l'image uploadée
```

### Middleware

#### 1. **auth.js**
```javascript
verifyJWT(handler)
- Extrait le token du header Authorization
- Vérifie la signature JWT
- Attache req.userId
- Retourne 401 si invalide

optionalAuth(handler)
- Vérifie le JWT s'il est présent
- Continue même si absent/invalide
```

#### 2. **payment.js**
```javascript
requirePayment(handler)
- Vérifie req.userId existe
- Fetch admin depuis Supabase
- Check is_grandfathered OU payment_status in ['active', 'trialing']
- Retourne 402 si paiement requis
- Attache req.admin
```

#### 3. **rateLimit.js**
```javascript
createRateLimiter({ maxRequests, windowMs })
- Basé sur l'IP du client (req.headers['x-forwarded-for'])
- Store en mémoire avec Map()
- Cleanup automatique des anciennes entrées
- Retourne 429 si limite dépassée
```

### Utilitaires

#### 1. **supabase.js**
```javascript
export const supabase
- Client Supabase avec ANON_KEY (RLS activé)

export const supabaseAdmin
- Client avec SERVICE_KEY (bypass RLS)
- Utilisé pour les routes publiques
```

#### 2. **jwt.js**
```javascript
generateToken(userId)
- Signe un JWT avec JWT_SECRET
- Expiration : 7 jours
- Algorithme : HS256

verifyToken(token)
- Vérifie la signature
- Retourne le payload ou null
```

#### 3. **validation.js**
```javascript
sanitizeInput(input)
- Échappe les caractères HTML (<, >, &, ", ')
- Prévention XSS

validateResponseData(data)
- Vérifie les longueurs (nom ≤ 100 chars, etc.)
- Vérifie la structure JSONB
- Retourne errors[] ou null
```

#### 4. **questions.js**
```javascript
normalizeQuestions()
- Retourne le set de questions standardisé
- Format : { id, question, type, options }
- Utilisé pour validation côté serveur
```

#### 5. **tokens.js**
```javascript
generateViewToken()
- Génère un UUID v4
- Utilisé pour les liens de visualisation privés
```

### Sécurité

#### 1. **Prévention XSS**
- Sanitization de tous les inputs utilisateur
- HTML escaping dans `validation.js`
- Content Security Policy headers (Vercel)

#### 2. **Rate Limiting**
- 3 soumissions max par IP toutes les 15 minutes
- 3 uploads max par IP toutes les 15 minutes
- Middleware `rateLimit.js` avec cleanup automatique

#### 3. **Row Level Security (RLS)**
- Politique SQL :
  ```sql
  CREATE POLICY admin_own_responses ON responses
  FOR ALL USING (owner_id = auth.uid())
  ```
- Isolation automatique des données par admin

#### 4. **CORS**
- Configuré dans `vercel.json`
- Origines autorisées :
  - `https://faf-multijoueur.vercel.app`
  - `http://localhost:3000` (dev)

#### 5. **Stripe Webhook Security**
- Vérification de signature avec `STRIPE_WEBHOOK_SECRET`
- Validation de l'événement avant traitement
- Prévention des replay attacks

### Frontend

#### 1. **Pages Publiques**
```
/auth/landing.html        - Page d'accueil
/auth/register.html       - Inscription
/auth/login.html          - Connexion
/form/index.html          - Formulaire dynamique (GET username via query)
/view/index.html          - Comparaison privée (GET token via query)
```

#### 2. **Pages Admin**
```
/admin/admin.html         - Dashboard principal
/admin/admin_gestion.html - Gestion des réponses
```

#### 3. **JavaScript Modules**
```javascript
// frontend/public/js/auth.js
- getAuthToken() : lit le JWT du localStorage
- isAuthenticated() : vérifie la présence du token
- logout() : supprime le token et redirige

// frontend/public/js/form.js
- Logique de soumission du formulaire
- Gestion de l'upload Cloudinary
- Validation côté client

// frontend/admin/faf-admin.js (ES6 module)
- AdminAPI : classe pour les appels API
- Utils : fonctions utilitaires (formatDate, etc.)
- UI : gestion du DOM et des événements
- Charts : visualisations avec Chart.js
```

#### 4. **Gestion du State**
- JWT stocké dans `localStorage`
- Vérification à chaque chargement de page admin
- Redirection automatique si non authentifié

### Base de Données

#### Schéma `admins`
```sql
CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  payment_status TEXT CHECK (payment_status IN
    ('active', 'trialing', 'past_due', 'canceled', 'unpaid')),
  subscription_end_date TIMESTAMPTZ,
  is_grandfathered BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_admins_username ON admins(username);
CREATE INDEX idx_admins_stripe_customer ON admins(stripe_customer_id);
```

#### Schéma `responses`
```sql
CREATE TABLE responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES admins(id) NOT NULL,
  name TEXT NOT NULL,
  responses JSONB NOT NULL,
  month TEXT NOT NULL,
  is_owner BOOLEAN DEFAULT FALSE,
  token TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_responses_owner ON responses(owner_id);
CREATE INDEX idx_responses_token ON responses(token);
CREATE INDEX idx_responses_month ON responses(month);
CREATE INDEX idx_responses_created ON responses(created_at DESC);
```

#### Structure JSONB `responses.responses`
```json
{
  "question_1": "answer_value",
  "question_2": "answer_value",
  "qualite_principale": "Honnête",
  "animal_totem": "Lion",
  "superpouvoir": "Vol",
  "image_url": "https://res.cloudinary.com/.../image.jpg"
}
```

### Déploiement

#### Configuration Vercel (`vercel.json`)
```json
{
  "functions": {
    "api/**/*.js": {
      "maxDuration": 10
    }
  },
  "routes": [
    { "src": "/form/(.*)", "dest": "/frontend/public/form/index.html" },
    { "src": "/view/(.*)", "dest": "/frontend/public/view/index.html" },
    { "src": "/admin/(.*)", "dest": "/frontend/admin/$1" },
    { "src": "/api/(.*)", "dest": "/api/$1" }
  ],
  "headers": [
    {
      "source": "/api/(.*)",
      "headers": [
        { "key": "Access-Control-Allow-Origin", "value": "*" },
        { "key": "Access-Control-Allow-Methods", "value": "GET,POST,PUT,DELETE,PATCH,OPTIONS" }
      ]
    }
  ]
}
```

#### Variables d'Environnement
```bash
# Supabase
SUPABASE_URL
SUPABASE_ANON_KEY
SUPABASE_SERVICE_KEY

# JWT
JWT_SECRET (min 32 caractères)

# Stripe
STRIPE_SECRET_KEY
STRIPE_WEBHOOK_SECRET
STRIPE_PRICE_ID

# Cloudinary
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET

# Application
NODE_ENV=production
APP_BASE_URL=https://faf-multijoueur.vercel.app
```

### Limites et Contraintes

#### Vercel Hobby Plan
- **12 fonctions max** (actuellement 12/12 utilisées)
- 100 GB-hours/mois de compute
- 100 GB de bande passante
- 10 secondes max par fonction

#### Supabase Free Tier
- 500 MB de stockage PostgreSQL
- 2 GB de bande passante
- 50 MB de stockage fichiers (non utilisé, on utilise Cloudinary)

#### Stripe
- Frais de transaction : 1.4% + 0.25€ par paiement réussi
- Essai gratuit de 7 jours automatique

#### Rate Limits
- 3 soumissions/15min/IP (`/api/response/submit`)
- 3 uploads/15min/IP (`/api/upload`)

### Monitoring et Logs

#### Vercel Logs
```bash
vercel logs faf-multijoueur --production
```
- Logs en temps réel des fonctions
- Erreurs et stack traces
- Requêtes HTTP (méthode, status, durée)

#### Supabase Dashboard
- Requêtes SQL exécutées
- Performance des indexes
- Utilisation du stockage
- Logs des politiques RLS

#### Stripe Dashboard
- Événements webhook
- Statut des abonnements
- Historique des paiements
- Clients et subscriptions

### Tests

#### Structure des Tests
```
tests/
├── auth.test.js                    # Tests JWT et authentification
├── integration/
│   └── full-flow.test.js           # Tests end-to-end
├── performance/
│   └── load.test.js                # Tests de charge
└── security/
    └── xss-csrf-ratelimit.test.js  # Tests de sécurité
```

#### Commandes
```bash
npm test                           # Tous les tests
npm test -- tests/auth.test.js     # Tests spécifiques
npm test -- --watch                # Mode watch
```

### Fonctionnalités Avancées

#### 1. **Comptes Grandfathered**
```sql
-- Accorder un accès gratuit à vie
UPDATE admins
SET is_grandfathered = TRUE,
    payment_status = 'active'
WHERE username = 'riri';
```
- Bypass complet du système de paiement
- Accès illimité sans abonnement Stripe

#### 2. **Pagination Côté Serveur**
```javascript
// GET /api/admin/responses?limit=20&offset=0
- Limite : 20 réponses par page
- Offset : calcul automatique (page * limit)
- Métadonnées : { total, page, totalPages, hasMore }
```

#### 3. **Calculs de Moyennes**
- Agrégation JSONB dans PostgreSQL
- Calculs côté serveur pour la page `/view/[token]`
- Comparaison en temps réel

#### 4. **Upload d'Images Sécurisé**
- Signature Cloudinary avec `api_secret`
- Transformation d'images automatique (resize, crop)
- URLs optimisées pour le web

---

## Flux Complet (End-to-End)

### 1. Inscription → Essai Gratuit
```
1. User visite /auth/register.html
2. Remplit username, email, password
3. POST /api/auth/register
   → Crée admin avec payment_status = 'trialing'
   → Génère JWT
   → Retourne token
4. Frontend stocke token dans localStorage
5. Redirection vers /admin/admin.html
```

### 2. Abonnement Stripe
```
1. Admin clique "S'abonner" dans le dashboard
2. POST /api/payment/create-checkout
   → Crée session Stripe
   → Retourne URL de paiement
3. Redirection vers Stripe Checkout
4. User entre infos bancaires
5. Stripe webhook → POST /api/payment/webhook
   → Met à jour payment_status = 'active'
   → Stocke stripe_customer_id et stripe_subscription_id
6. Redirection vers /admin/admin.html (succès)
```

### 3. Partage du Formulaire
```
1. Admin partage https://faf-multijoueur.vercel.app/form/{username}
2. Ami ouvre le lien
3. GET /api/form/[username]
   → Retourne les questions
4. Ami remplit le formulaire
5. POST /api/response/submit
   → Valide les données (XSS, longueur)
   → Génère un token UUID
   → Stocke dans responses table
   → Envoie email avec lien /view/{token}
6. Ami clique sur le lien privé
7. GET /api/response/view/[token]
   → Calcule les moyennes
   → Retourne les données de comparaison
8. Affichage des graphiques comparatifs
```

### 4. Gestion des Réponses (Admin)
```
1. Admin se connecte
2. JWT vérifié par middleware
3. Payment status vérifié par middleware
4. GET /api/admin/dashboard
   → Statistiques globales
5. GET /api/admin/responses?limit=20&offset=0
   → Liste paginée
6. Click sur une réponse
7. GET /api/admin/response/[id]
   → Détails complets
8. Modification
9. PATCH /api/admin/response/[id]
   → Mise à jour dans Supabase
10. Suppression
11. DELETE /api/admin/response/[id]
    → Suppression avec RLS check
```

---

## Points Clés du MVP

### ✅ Ce qui est implémenté
- Multi-tenant serverless complet
- Authentification JWT stateless
- Système de paiement Stripe avec essai gratuit
- Comptes grandfathered (accès gratuit à vie)
- Upload d'images sécurisé (Cloudinary)
- Rate limiting anti-spam
- Row Level Security (isolation des données)
- Dashboard admin avec graphiques
- Comparaisons privées par token
- Tests automatisés (auth, sécurité, performance)
- Déploiement production sur Vercel

### ❌ Ce qui n'est PAS implémenté
- Envoi d'emails automatiques (les liens sont générés mais pas envoyés)
- Notifications push
- Export de données (CSV, PDF)
- Multi-langues (français uniquement)
- Mode sombre
- Application mobile native
- Webhooks pour intégrations tierces
- Analytics avancées (Google Analytics, Mixpanel)

### 🔄 Évolutions Futures Possibles
- Formulaires personnalisables (admin définit ses propres questions)
- Thèmes personnalisables
- Invitations par email automatiques
- Rappels automatiques pour les amis qui n'ont pas répondu
- Export de rapports PDF
- Intégration avec Zapier/Make
- Mode hors-ligne (PWA)
- Historique des formulaires (archives par mois/année)

---

**Date de création** : 7 novembre 2025
**Version MVP** : 2.0 (Multi-Tenant Serverless)
**Production URL** : https://faf-multijoueur.vercel.app
