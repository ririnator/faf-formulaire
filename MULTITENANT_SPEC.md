# FAF Multi-Tenant - Spécifications complètes

## Vue d'ensemble

Transformer FAF d'une application mono-admin en une plateforme multi-tenant où chaque utilisateur peut créer un compte et gérer son propre formulaire mensuel avec ses propres amis.

---

## Architecture actuelle (mono-admin)

### Fonctionnement existant

**Rôle de Riri (admin unique)** :
- Possède un compte hardcodé dans `.env` (LOGIN_ADMIN_USER, LOGIN_ADMIN_PASS)
- Remplit le formulaire mensuel en premier
- Ses réponses servent de référence pour tous les utilisateurs
- Accède au dashboard admin via `/admin`
- Voit toutes les réponses de tous ses amis

**Rôle des amis (utilisateurs)** :
- Vont sur `/` (formulaire public)
- Remplissent le formulaire avec leur nom
- Reçoivent un lien privé unique : `/view/{token}`
- Sur ce lien, voient leurs réponses **vs** les réponses de Riri (format 1vs1)
- Ne peuvent voir que leurs propres réponses comparées à Riri

**Flux complet actuel** :

```
1. Riri remplit le formulaire
   └─> Stocké avec isAdmin: true, token: null

2. Riri envoie le lien / à Alice, Bob, Charlie

3. Alice remplit le formulaire
   └─> Stocké avec isAdmin: false, token: "abc123"
   └─> Reçoit le lien /view/abc123
   └─> Voit "Alice vs Riri" (comparaison côte-à-côte)

4. Bob remplit le formulaire
   └─> Stocké avec isAdmin: false, token: "def456"
   └─> Reçoit le lien /view/def456
   └─> Voit "Bob vs Riri"

5. Charlie remplit le formulaire
   └─> Stocké avec isAdmin: false, token: "ghi789"
   └─> Reçoit le lien /view/ghi789
   └─> Voit "Charlie vs Riri"

6. Riri se connecte à /admin
   └─> Voit toutes les réponses : Alice, Bob, Charlie
   └─> Peut filtrer par mois
   └─> Voit des statistiques et graphiques
   └─> Peut modifier/supprimer des réponses
```

**Limitation actuelle** :
- Alice ne peut PAS voir les réponses de Bob ou Charlie
- Bob ne peut PAS voir les réponses d'Alice ou Charlie
- Seul Riri voit tout
- Un seul admin possible dans toute l'application

---

## Architecture cible (multi-tenant)

### Concept fondamental

Chaque personne qui crée un compte devient un "admin" de son propre espace isolé, avec :
- Son propre formulaire unique
- Son propre dashboard personnel
- Ses propres réponses (de ses amis uniquement)
- Isolation complète : ne voit jamais les données des autres admins

### Exemple concret avec 3 admins

#### **Admin 1 : Riri**

**Setup** :
- Crée un compte : username = "riri", password = "***"
- Obtient un formulaire unique : `https://faf.app/form/riri`
- Envoie ce lien à son groupe d'amis : Alice, Bob, Charlie

**Utilisation mensuelle** :
1. Riri remplit son formulaire `/form/riri`
   - Stocké avec : `owner_id = riri_uuid`, `is_owner = true`

2. Alice va sur `/form/riri` et remplit
   - Stocké avec : `owner_id = riri_uuid`, `is_owner = false`, `token = "abc123"`
   - Reçoit le lien `/view/abc123`
   - Voit "Alice vs Riri"

3. Bob va sur `/form/riri` et remplit
   - Stocké avec : `owner_id = riri_uuid`, `is_owner = false`, `token = "def456"`
   - Reçoit le lien `/view/def456`
   - Voit "Bob vs Riri"

4. Charlie va sur `/form/riri` et remplit
   - Stocké avec : `owner_id = riri_uuid`, `is_owner = false`, `token = "ghi789"`
   - Reçoit le lien `/view/ghi789`
   - Voit "Charlie vs Riri"

**Dashboard de Riri** :
- Login à `/admin` avec username/password
- Voit **uniquement** les réponses de Alice, Bob, Charlie (son groupe)
- Statistiques pour son groupe uniquement
- Graphiques basés sur ses données

---

#### **Admin 2 : Sophie**

**Setup** :
- Crée un compte : username = "sophie", password = "***"
- Obtient un formulaire unique : `https://faf.app/form/sophie`
- Envoie ce lien à son groupe d'amis : David, Emma, Fiona

**Utilisation mensuelle** :
1. Sophie remplit son formulaire `/form/sophie`
   - Stocké avec : `owner_id = sophie_uuid`, `is_owner = true`

2. David va sur `/form/sophie` et remplit
   - Stocké avec : `owner_id = sophie_uuid`, `is_owner = false`, `token = "xyz123"`
   - Reçoit le lien `/view/xyz123`
   - Voit "David vs Sophie"

3. Emma va sur `/form/sophie` et remplit
   - Stocké avec : `owner_id = sophie_uuid`, `is_owner = false`, `token = "uvw456"`
   - Reçoit le lien `/view/uvw456`
   - Voit "Emma vs Sophie"

4. Fiona va sur `/form/sophie` et remplit
   - Stocké avec : `owner_id = sophie_uuid`, `is_owner = false`, `token = "rst789"`
   - Reçoit le lien `/view/rst789`
   - Voit "Fiona vs Sophie"

**Dashboard de Sophie** :
- Login à `/admin` avec username/password
- Voit **uniquement** les réponses de David, Emma, Fiona (son groupe)
- Ne voit JAMAIS Alice, Bob, Charlie (qui appartiennent à Riri)
- Statistiques indépendantes de celles de Riri

---

#### **Admin 3 : Alice (double rôle)**

Alice était d'abord une amie de Riri, mais décide de créer son propre compte.

**Setup** :
- Crée un compte : username = "alice", password = "***"
- Obtient un formulaire unique : `https://faf.app/form/alice`
- Envoie ce lien à son groupe d'amis : George, Hannah, Iris

**Double rôle d'Alice** :

**En tant qu'utilisatrice (répond au formulaire de Riri)** :
- Continue de remplir `/form/riri` chaque mois
- Reçoit son lien privé `/view/abc123`
- Voit "Alice vs Riri"

**En tant qu'admin (son propre groupe)** :
- George remplit `/form/alice`
  - Stocké avec : `owner_id = alice_uuid`, `token = "pqr123"`
  - Voit "George vs Alice"

- Hannah remplit `/form/alice`
  - Stocké avec : `owner_id = alice_uuid`, `token = "mno456"`
  - Voit "Hannah vs Alice"

- Iris remplit `/form/alice`
  - Stocké avec : `owner_id = alice_uuid`, `token = "jkl789"`
  - Voit "Iris vs Alice"

**Dashboard d'Alice** :
- Login à `/admin` avec username/password
- Voit **uniquement** George, Hannah, Iris (son groupe)
- Ne voit PAS les réponses qu'elle-même a envoyées à Riri
- Ne voit PAS les données de Riri, Sophie, ou leurs groupes

---

### Isolation des données (critique)

```
Base de données Supabase

┌─────────────────────────────────────────────┐
│ Table: admins                               │
├─────────────────────────────────────────────┤
│ id (UUID)          │ username │ email       │
├────────────────────┼──────────┼─────────────┤
│ riri-uuid          │ riri     │ r@email.com │
│ sophie-uuid        │ sophie   │ s@email.com │
│ alice-uuid         │ alice    │ a@email.com │
└─────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│ Table: responses                                              │
├──────────┬───────────┬──────┬────────┬──────────┬────────────┤
│ owner_id │ name      │ month│is_owner│ token    │ responses  │
├──────────┼───────────┼──────┼────────┼──────────┼────────────┤
│ riri-uuid│ riri      │01-25 │ true   │ null     │ [...]      │ ← Réponse de Riri
│ riri-uuid│ Alice     │01-25 │ false  │ abc123   │ [...]      │ ← Alice répond à Riri
│ riri-uuid│ Bob       │01-25 │ false  │ def456   │ [...]      │ ← Bob répond à Riri
│ riri-uuid│ Charlie   │01-25 │ false  │ ghi789   │ [...]      │ ← Charlie répond à Riri
├──────────┼───────────┼──────┼────────┼──────────┼────────────┤
│sophie-uuid│ sophie   │01-25 │ true   │ null     │ [...]      │ ← Réponse de Sophie
│sophie-uuid│ David    │01-25 │ false  │ xyz123   │ [...]      │ ← David répond à Sophie
│sophie-uuid│ Emma     │01-25 │ false  │ uvw456   │ [...]      │ ← Emma répond à Sophie
│sophie-uuid│ Fiona    │01-25 │ false  │ rst789   │ [...]      │ ← Fiona répond à Sophie
├──────────┼───────────┼──────┼────────┼──────────┼────────────┤
│alice-uuid│ alice    │01-25 │ true   │ null     │ [...]      │ ← Réponse d'Alice (admin)
│alice-uuid│ George   │01-25 │ false  │ pqr123   │ [...]      │ ← George répond à Alice
│alice-uuid│ Hannah   │01-25 │ false  │ mno456   │ [...]      │ ← Hannah répond à Alice
│alice-uuid│ Iris     │01-25 │ false  │ jkl789   │ [...]      │ ← Iris répond à Alice
└──────────┴───────────┴──────┴────────┴──────────┴────────────┘

Row Level Security (RLS) :
- Riri voit uniquement les lignes où owner_id = riri-uuid (4 lignes)
- Sophie voit uniquement les lignes où owner_id = sophie-uuid (4 lignes)
- Alice voit uniquement les lignes où owner_id = alice-uuid (4 lignes)
```

**Règle absolue** :
- `owner_id` détermine à quel admin appartiennent les données
- RLS de Supabase filtre automatiquement par `owner_id`
- Impossible de voir les données d'un autre admin, même avec une requête malicieuse

---

## Parcours utilisateur complet

### Parcours 1 : Nouvel admin créant son compte

**Étape 1 : Landing page (`/`)**
- Visite `https://faf.app`
- Voit une landing page expliquant le concept
- Sections :
  - Hero : "Créez votre formulaire mensuel personnalisé"
  - "Comment ça marche" (3 étapes illustrées)
  - "Créer un compte" (bouton CTA)
  - "Se connecter" (lien)

**Étape 2 : Inscription (`/register`)**
- Clique sur "Créer un compte"
- Formulaire :
  - Username (unique, 3-20 caractères, alphanumériques + tirets)
  - Email (validation format)
  - Mot de passe (min 8 caractères, 1 majuscule, 1 chiffre)
  - Confirmation mot de passe
- Validation côté client + serveur
- Submit → `POST /api/auth/register`
- Si succès :
  - Compte créé dans Supabase
  - Redirection vers `/onboarding`

**Étape 3 : Onboarding (`/onboarding`)**
- Message de bienvenue : "Félicitations, {username} !"
- Affichage du lien unique : `https://faf.app/form/{username}`
- Bouton "Copier le lien"
- Instructions :
  1. "Envoyez ce lien à vos amis"
  2. "Remplissez d'abord le formulaire vous-même"
  3. "Consultez les réponses dans votre dashboard"
- Bouton "Remplir mon formulaire"
- Bouton "Aller au dashboard"

**Étape 4 : Remplir son propre formulaire**
- Va sur `/form/{username}` (son formulaire)
- Remplit toutes les questions
- Submit → `POST /api/response/submit`
  - Backend détecte que `name === admin.username`
  - Stocke avec `is_owner = true`, `token = null`
- Message de confirmation (pas de lien privé pour l'admin)

**Étape 5 : Consulter le dashboard**
- Va sur `/admin`
- Login avec username/password
- Dashboard vide (aucun ami n'a encore répondu)
- Message : "Aucune réponse pour le moment. Partagez votre lien !"
- Affiche son lien de formulaire avec bouton de copie
- Section "Mes réponses" visible

---

### Parcours 2 : Ami remplissant le formulaire

**Étape 1 : Réception du lien**
- Reçoit un message WhatsApp/Email : "Salut ! Remplis mon formulaire mensuel 😊 https://faf.app/form/sophie"

**Étape 2 : Accès au formulaire**
- Clique sur le lien → `/form/sophie`
- Voit le formulaire avec en-tête : "Formulaire mensuel de Sophie"
- Toutes les questions habituelles (11 questions)
- Pas besoin de compte pour répondre

**Étape 3 : Remplissage**
- Remplit son nom : "Emma"
- Répond aux 11 questions (textes + uploads d'images)
- Submit → `POST /api/response/submit`
  - Backend détecte que `name !== admin.username`
  - Génère un token unique : `"uvw456"`
  - Stocke avec `owner_id = sophie_uuid`, `is_owner = false`, `token = "uvw456"`

**Étape 4 : Réception du lien privé**
- Modal de succès avec le lien : `https://faf.app/view/uvw456`
- Message : "Voici votre lien privé pour voir la comparaison Emma vs Sophie"
- Bouton "Voir ma comparaison"

**Étape 5 : Consultation de la comparaison**
- Clique sur le lien → `/view/uvw456`
- Voit la page de comparaison format 1vs1 :
  - En-tête : "Emma vs Sophie - Janvier 2025"
  - Questions au centre
  - Réponses d'Emma à gauche
  - Réponses de Sophie à droite
  - Images cliquables (modal)
- Peut sauvegarder ce lien pour le consulter plus tard

---

### Parcours 3 : Admin consultant son dashboard

**Étape 1 : Login**
- Va sur `/admin`
- Si pas connecté, redirection vers `/login`
- Entre username + password
- Submit → `POST /api/auth/login`
- JWT token généré et stocké (cookie httpOnly)
- Redirection vers `/admin`

**Étape 2 : Dashboard principal**

**Vue d'ensemble** :
- Header :
  - Logo FAF
  - "Bienvenue, {username}"
  - Bouton "Mon formulaire" (copie le lien)
  - Bouton "Déconnexion"

- Section "Stats rapides" :
  - Nombre de réponses ce mois-ci
  - Nombre total de participants
  - Taux de réponse (vs mois dernier)

- Section "Filtres" :
  - Dropdown "Mois" (liste des mois avec réponses)
  - Bouton "Voir tout"

- Section "Réponses" :
  - Liste des réponses (cartes)
  - Chaque carte affiche :
    - Nom de la personne
    - Date de soumission
    - Aperçu de la première réponse
    - Bouton "Voir détails"
    - Bouton "Supprimer" (avec confirmation)

- Section "Graphiques" :
  - Graphique camembert de la question 1 (Comment ça va ?)
  - Graphique d'évolution (nombre de réponses par mois)

**Étape 3 : Détail d'une réponse**
- Clique sur "Voir détails" pour Emma
- Modal ou page dédiée :
  - Toutes les réponses d'Emma
  - Format lisible (questions + réponses)
  - Images affichées
  - Bouton "Modifier" (édition inline)
  - Bouton "Supprimer"
  - Bouton "Voir comparaison" → génère un lien temporaire `/compare/{admin}/{respondent}/{month}`

**Étape 4 : Gestion des réponses**
- Peut modifier une réponse (typo, correction)
- Peut supprimer une réponse (avec confirmation)
- Peut exporter les données (JSON/CSV)

---

## Structure des données Supabase

### Table `admins`

```sql
CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9_-]{3,20}$'),
  email TEXT UNIQUE NOT NULL CHECK (email ~ '^[^@]+@[^@]+\.[^@]+$'),
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX idx_admins_username ON admins(username);
CREATE INDEX idx_admins_email ON admins(email);

-- Fonction de mise à jour du timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger pour updated_at
CREATE TRIGGER trigger_admins_updated_at
BEFORE UPDATE ON admins
FOR EACH ROW
EXECUTE FUNCTION update_updated_at();
```

**Champs** :
- `id` : UUID unique (clé primaire)
- `username` : Identifiant unique (utilisé dans l'URL du formulaire)
- `email` : Email unique (pour récupération de mot de passe futur)
- `password_hash` : Hash bcrypt du mot de passe (10 rounds)
- `created_at` : Date de création du compte
- `updated_at` : Date de dernière modification

**Contraintes** :
- Username : 3-20 caractères, lowercase, alphanumériques + tirets/underscores
- Email : Format valide
- Username et email uniques

---

### Table `responses`

```sql
CREATE TABLE responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 100),
  responses JSONB NOT NULL,
  month TEXT NOT NULL CHECK (month ~ '^\d{4}-\d{2}$'),
  is_owner BOOLEAN DEFAULT false,
  token TEXT UNIQUE CHECK (token IS NULL OR char_length(token) = 64),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes pour performance
CREATE INDEX idx_responses_owner ON responses(owner_id);
CREATE INDEX idx_responses_token ON responses(token) WHERE token IS NOT NULL;
CREATE INDEX idx_responses_month ON responses(month);
CREATE INDEX idx_responses_owner_month ON responses(owner_id, month);
CREATE INDEX idx_responses_created ON responses(created_at DESC);

-- Contrainte unique : un admin ne peut avoir qu'une réponse par mois
CREATE UNIQUE INDEX idx_owner_month_unique
ON responses(owner_id, month)
WHERE is_owner = true;

-- Validation du format JSONB responses
CREATE OR REPLACE FUNCTION validate_responses_format()
RETURNS TRIGGER AS $$
BEGIN
  -- Vérifier que responses est un array
  IF jsonb_typeof(NEW.responses) != 'array' THEN
    RAISE EXCEPTION 'responses must be a JSON array';
  END IF;

  -- Vérifier que chaque élément a question et answer
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(NEW.responses) AS elem
    WHERE NOT (elem ? 'question' AND elem ? 'answer')
  ) THEN
    RAISE EXCEPTION 'Each response must have question and answer fields';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_validate_responses
BEFORE INSERT OR UPDATE ON responses
FOR EACH ROW
EXECUTE FUNCTION validate_responses_format();
```

**Champs** :
- `id` : UUID unique
- `owner_id` : Référence vers l'admin propriétaire (avec CASCADE DELETE)
- `name` : Nom de la personne qui a rempli (2-100 caractères)
- `responses` : Array JSON des réponses au format :
  ```json
  [
    {
      "question": "En rapide, comment ça va ?",
      "answer": "ça va"
    },
    {
      "question": "Photo de toi ce mois-ci",
      "answer": "https://res.cloudinary.com/xxx/image.jpg"
    }
  ]
  ```
- `month` : Format YYYY-MM (ex: "2025-01")
- `is_owner` : `true` si c'est la réponse de l'admin lui-même, `false` pour les amis
- `token` : Token unique de 64 caractères (null pour l'admin)
- `created_at` : Timestamp de création

**Contraintes** :
- `owner_id` doit exister dans `admins`
- Un admin ne peut avoir qu'une seule réponse par mois (avec `is_owner = true`)
- Token unique de 64 caractères ou null
- Format `responses` validé par trigger

---

### Row Level Security (RLS)

```sql
-- Activer RLS sur la table responses
ALTER TABLE responses ENABLE ROW LEVEL SECURITY;

-- Policy SELECT : Les admins voient uniquement leurs réponses
CREATE POLICY "select_own_responses"
ON responses FOR SELECT
USING (
  owner_id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy INSERT : Les admins peuvent créer des réponses pour eux
CREATE POLICY "insert_own_responses"
ON responses FOR INSERT
WITH CHECK (
  owner_id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy UPDATE : Les admins peuvent modifier leurs réponses
CREATE POLICY "update_own_responses"
ON responses FOR UPDATE
USING (owner_id = auth.uid())
WITH CHECK (owner_id = auth.uid());

-- Policy DELETE : Les admins peuvent supprimer leurs réponses
CREATE POLICY "delete_own_responses"
ON responses FOR DELETE
USING (owner_id = auth.uid());

-- Policy spéciale pour les consultations publiques via token
CREATE POLICY "select_by_token"
ON responses FOR SELECT
USING (
  token IS NOT NULL AND
  EXISTS (
    SELECT 1 FROM responses r2
    WHERE r2.token = responses.token
  )
);
```

**Fonctionnement** :
- Chaque requête est automatiquement filtrée par `owner_id = auth.uid()`
- `auth.uid()` est l'UUID de l'admin connecté (depuis le JWT)
- Les consultations publiques via token sont autorisées (pour `/view/{token}`)
- Le rôle `service_role` peut tout voir (pour les opérations admin système)

---

## Routes API (Vercel Serverless)

### Structure des dossiers

```
/api/
├── auth/
│   ├── register.js         # POST - Créer un compte
│   ├── login.js            # POST - Se connecter
│   ├── logout.js           # POST - Se déconnecter
│   └── verify.js           # GET - Vérifier le JWT
├── form/
│   └── [username].js       # GET - Récupérer le formulaire d'un admin
├── response/
│   ├── submit.js           # POST - Soumettre un formulaire
│   └── view/
│       └── [token].js      # GET - Consulter une comparaison privée
├── admin/
│   ├── dashboard.js        # GET - Récupérer les stats du dashboard
│   ├── responses.js        # GET - Liste des réponses (avec pagination)
│   ├── response/
│   │   ├── [id].js         # GET/PATCH/DELETE - Détail/Modifier/Supprimer
│   │   └── compare.js      # GET - Comparaison admin vs respondent
│   └── export.js           # GET - Exporter les données (JSON/CSV)
└── upload/
    └── image.js            # POST - Upload d'image vers Cloudinary
```

---

### `/api/auth/register.js`

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "email": "sophie@example.com",
  "password": "Password123!"
}
```

**Validation** :
- Username : 3-20 caractères, alphanumériques + tirets/underscores, lowercase uniquement
- Email : format valide
- Password : min 8 caractères, au moins 1 majuscule, 1 chiffre, 1 caractère spécial

**Traitement** :
1. Vérifier que username et email sont uniques (requête Supabase)
2. Hasher le password avec bcrypt (10 rounds)
3. Insérer dans la table `admins`
4. Générer un JWT token (expiration : 7 jours)
5. Retourner le token + infos admin

**Réponse succès** (201) :
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "admin": {
    "id": "uuid-xxx",
    "username": "sophie",
    "email": "sophie@example.com"
  }
}
```

**Réponses erreur** :
- 400 : Validation échouée (champs manquants, format invalide)
- 409 : Username ou email déjà utilisé
- 500 : Erreur serveur

**Sécurité** :
- Rate limiting : 5 tentatives / 15 minutes par IP
- Honeypot field (champ caché anti-bot)
- Validation stricte des formats

---

### `/api/auth/login.js`

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "password": "Password123!"
}
```

**Traitement** :
1. Chercher l'admin par username (case-insensitive)
2. Vérifier le password avec bcrypt.compare()
3. Générer un JWT token (expiration : 7 jours)
4. Retourner le token

**Réponse succès** (200) :
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "admin": {
    "id": "uuid-xxx",
    "username": "sophie"
  }
}
```

**Réponses erreur** :
- 400 : Champs manquants
- 401 : Credentials invalides
- 429 : Trop de tentatives (rate limiting)
- 500 : Erreur serveur

**Sécurité** :
- Rate limiting : 5 tentatives / 15 minutes par IP
- Pas de distinction entre "username inconnu" et "password incorrect" (évite l'énumération)
- Délai constant de réponse (évite le timing attack)

---

### `/api/form/[username].js`

**Méthode** : `GET`

**Paramètres** :
- `username` : Nom d'utilisateur de l'admin (dans l'URL)

**Traitement** :
1. Vérifier que l'admin existe dans la table `admins`
2. Récupérer les informations de l'admin
3. Retourner les données nécessaires au formulaire

**Réponse succès** (200) :
```json
{
  "success": true,
  "admin": {
    "username": "sophie",
    "formUrl": "/form/sophie"
  },
  "questions": [
    {
      "id": "q1",
      "type": "radio",
      "question": "En rapide, comment ça va ?",
      "options": ["ça va", "a connu meilleur mois", "ITS JOEVER", "WE'RE BARACK"]
    },
    {
      "id": "q2",
      "type": "text",
      "question": "Possibilité d'ajouter un peu plus de détails...",
      "maxLength": 10000
    }
    // ... autres questions
  ]
}
```

**Réponses erreur** :
- 404 : Admin introuvable
- 500 : Erreur serveur

**Note** : Cette route est publique (pas d'auth requise)

---

### `/api/response/submit.js`

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "name": "Emma",
  "responses": [
    {
      "question": "En rapide, comment ça va ?",
      "answer": "ça va"
    },
    {
      "question": "Photo de toi ce mois-ci",
      "answer": "https://res.cloudinary.com/xxx/image.jpg"
    }
    // ... autres réponses
  ],
  "website": ""
}
```

**Traitement** :
1. **Validation honeypot** : Si `website` n'est pas vide → rejeter (spam bot)
2. **Validation rate limiting** : Max 3 soumissions / 15 minutes par IP
3. **Trouver l'admin** par username
4. **Déterminer is_owner** : `name.toLowerCase() === admin.username.toLowerCase()`
5. **Validation stricte** :
   - Name : 2-100 caractères
   - Responses : Array de 10-11 éléments (Q11 optionnelle)
   - Chaque réponse : question (max 500 chars), answer (max 10k chars ou URL Cloudinary)
   - XSS escaping sur tous les champs texte
6. **Générer token** : Si `is_owner = false` → `crypto.randomBytes(32).toString('hex')`
7. **Insérer dans Supabase** :
   ```javascript
   {
     owner_id: admin.id,
     name: escapedName,
     responses: escapedResponses,
     month: new Date().toISOString().slice(0, 7), // "2025-01"
     is_owner: isOwner,
     token: token || null
   }
   ```
8. **Retourner le lien** (si token existe)

**Réponse succès** (201) :
```json
{
  "success": true,
  "message": "Réponse enregistrée avec succès !",
  "link": "https://faf.app/view/uvw456",
  "userName": "Emma",
  "adminName": "Sophie"
}
```

**Réponses erreur** :
- 400 : Validation échouée
- 404 : Admin introuvable
- 409 : Admin a déjà répondu ce mois-ci (si is_owner = true)
- 429 : Rate limit dépassé
- 500 : Erreur serveur

**Sécurité** :
- XSS escaping : `<`, `>`, `&`, `"`, `'` → HTML entities
- Preservation des URLs Cloudinary (whitelist)
- Validation MIME type des images
- Rate limiting par IP
- Honeypot anti-spam

---

### `/api/response/view/[token].js`

**Méthode** : `GET`

**Paramètres** :
- `token` : Token unique de 64 caractères (dans l'URL)

**Traitement** :
1. **Trouver la réponse utilisateur** par token
2. **Récupérer le owner_id** et le mois
3. **Trouver la réponse de l'admin** : `owner_id + is_owner=true + même mois`
4. **Récupérer le username de l'admin**
5. **Retourner les deux réponses**

**Réponse succès** (200) :
```json
{
  "success": true,
  "user": {
    "name": "Emma",
    "responses": [
      { "question": "Comment ça va ?", "answer": "ça va" },
      { "question": "Photo", "answer": "https://..." }
    ],
    "month": "2025-01",
    "createdAt": "2025-01-15T10:30:00Z"
  },
  "admin": {
    "name": "sophie",
    "responses": [
      { "question": "Comment ça va ?", "answer": "WE'RE BARACK" },
      { "question": "Photo", "answer": "https://..." }
    ],
    "month": "2025-01"
  },
  "adminName": "Sophie"
}
```

**Réponses erreur** :
- 404 : Token invalide ou expiré
- 500 : Erreur serveur

**Note** : Cette route est publique (pas d'auth requise, token suffit)

**Sécurité** :
- Pas d'énumération possible (token de 64 chars = 2^256 possibilités)
- Rate limiting : 100 requêtes / minute par IP

---

### `/api/admin/dashboard.js`

**Méthode** : `GET`

**Headers** :
- `Authorization: Bearer {jwt_token}`

**Query params** :
- `month` (optionnel) : Format YYYY-MM (défaut : mois actuel)

**Traitement** :
1. **Vérifier le JWT** : Extraire `admin.id`
2. **Filtrer les réponses** : `owner_id = admin.id` + mois spécifié
3. **Calculer les stats** :
   - Nombre total de réponses (exclude is_owner)
   - Répartition question 1 (camembert)
   - Évolution par mois (graphique ligne)
4. **Retourner les données**

**Réponse succès** (200) :
```json
{
  "success": true,
  "stats": {
    "totalResponses": 12,
    "currentMonth": "2025-01",
    "responseRate": "+25%",
    "question1Distribution": {
      "ça va": 5,
      "a connu meilleur mois": 4,
      "ITS JOEVER": 2,
      "WE'RE BARACK": 1
    }
  },
  "responses": [
    {
      "id": "uuid-xxx",
      "name": "Emma",
      "createdAt": "2025-01-15T10:30:00Z",
      "preview": "ça va"
    },
    {
      "id": "uuid-yyy",
      "name": "David",
      "createdAt": "2025-01-14T15:20:00Z",
      "preview": "WE'RE BARACK"
    }
  ],
  "months": ["2025-01", "2024-12", "2024-11"]
}
```

**Réponses erreur** :
- 401 : JWT invalide ou expiré
- 403 : Token valide mais pas admin
- 500 : Erreur serveur

---

### `/api/admin/responses.js`

**Méthode** : `GET`

**Headers** :
- `Authorization: Bearer {jwt_token}`

**Query params** :
- `month` (optionnel) : Filtrer par mois
- `page` (optionnel, défaut: 1) : Numéro de page
- `limit` (optionnel, défaut: 50) : Résultats par page

**Traitement** :
1. **Vérifier le JWT**
2. **Filtrer par owner_id** et mois (si spécifié)
3. **Pagination** : OFFSET/LIMIT
4. **Retourner les réponses complètes**

**Réponse succès** (200) :
```json
{
  "success": true,
  "responses": [
    {
      "id": "uuid-xxx",
      "name": "Emma",
      "responses": [
        { "question": "Comment ça va ?", "answer": "ça va" }
      ],
      "month": "2025-01",
      "createdAt": "2025-01-15T10:30:00Z",
      "token": "uvw456"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 12,
    "totalPages": 1
  }
}
```

---

### `/api/admin/response/[id].js`

**Méthodes** : `GET`, `PATCH`, `DELETE`

**Headers** :
- `Authorization: Bearer {jwt_token}`

#### GET - Récupérer une réponse

**Réponse** (200) :
```json
{
  "success": true,
  "response": {
    "id": "uuid-xxx",
    "name": "Emma",
    "responses": [...],
    "month": "2025-01",
    "createdAt": "2025-01-15T10:30:00Z"
  }
}
```

#### PATCH - Modifier une réponse

**Body** :
```json
{
  "name": "Emma (corrigé)",
  "responses": [...]
}
```

**Réponse** (200) :
```json
{
  "success": true,
  "response": { ... }
}
```

#### DELETE - Supprimer une réponse

**Réponse** (204) : No content

**Sécurité** :
- RLS vérifie automatiquement que `owner_id = admin.id`
- Impossible de modifier/supprimer les réponses d'un autre admin

---

### `/api/upload/image.js`

**Méthode** : `POST`

**Body** : `multipart/form-data` avec champ `image`

**Traitement** :
1. **Validation** :
   - MIME type : `image/jpeg`, `image/png`, `image/gif`, `image/webp`
   - Taille max : 5 MB
2. **Upload vers Cloudinary** :
   - Transformation : max 1920px, qualité 85%
   - Format : auto (WebP si supporté)
3. **Retourner l'URL**

**Réponse succès** (200) :
```json
{
  "success": true,
  "url": "https://res.cloudinary.com/xxx/image/upload/v1234/abc.jpg"
}
```

**Réponses erreur** :
- 400 : Format invalide ou taille dépassée
- 500 : Erreur Cloudinary

**Sécurité** :
- Validation MIME type stricte
- Scan anti-malware (via Cloudinary)
- Rate limiting : 20 uploads / minute par IP

---

## Frontend

### Structure des pages

```
/frontend/
├── public/
│   ├── index.html              # Landing page
│   ├── register.html           # Inscription
│   ├── login.html              # Connexion
│   ├── onboarding.html         # Guide après inscription
│   ├── form/
│   │   └── [username].html     # Formulaire dynamique
│   ├── view/
│   │   └── [token].html        # Comparaison 1vs1
│   ├── css/
│   │   ├── main.css            # Styles globaux
│   │   ├── form.css            # Styles formulaire
│   │   ├── view.css            # Styles comparaison
│   │   └── admin.css           # Styles dashboard
│   └── js/
│       ├── auth.js             # Gestion auth (login/register)
│       ├── form.js             # Logique formulaire
│       ├── view.js             # Logique comparaison
│       └── utils.js            # Fonctions utilitaires
├── admin/
│   ├── dashboard.html          # Dashboard principal
│   ├── responses.html          # Liste détaillée
│   ├── faf-admin.js            # Module ES6 admin (existant)
│   └── mobile-responsive.css   # Styles responsive (existant)
└── components/
    ├── navbar.html             # Barre de navigation
    └── modal.html              # Modal réutilisable
```

---

### Landing page (`/index.html`)

**Sections** :

1. **Hero** :
   - Titre : "Créez votre formulaire mensuel personnalisé"
   - Sous-titre : "Partagez vos réponses avec vos amis et comparez vos vies de manière amusante"
   - CTA : "Créer un compte gratuitement"
   - Image/illustration

2. **Comment ça marche** (3 étapes) :
   - Étape 1 : "Créez votre compte" + icône
   - Étape 2 : "Partagez votre formulaire" + icône
   - Étape 3 : "Consultez les comparaisons" + icône

3. **Fonctionnalités** :
   - "Formulaire mensuel automatique"
   - "Comparaisons 1vs1 privées"
   - "Dashboard avec statistiques"
   - "Upload d'images illimité"
   - "100% gratuit"

4. **Footer** :
   - "Déjà un compte ? Se connecter"
   - Liens : CGU, Confidentialité, Contact

**Design** :
- Responsive (mobile-first)
- Couleurs : Reprendre le thème actuel (bleu/rose)
- Animations subtiles (scroll reveal)

---

### Page d'inscription (`/register.html`)

**Formulaire** :
```html
<form id="registerForm">
  <h1>Créer un compte</h1>

  <div class="form-group">
    <label for="username">Nom d'utilisateur</label>
    <input
      type="text"
      id="username"
      required
      pattern="[a-z0-9_-]{3,20}"
      placeholder="ex: sophie"
    >
    <small>3-20 caractères, lettres minuscules, chiffres, tirets</small>
  </div>

  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" required>
  </div>

  <div class="form-group">
    <label for="password">Mot de passe</label>
    <input type="password" id="password" required minlength="8">
    <small>Min 8 caractères, 1 majuscule, 1 chiffre</small>
  </div>

  <div class="form-group">
    <label for="confirmPassword">Confirmer le mot de passe</label>
    <input type="password" id="confirmPassword" required>
  </div>

  <!-- Honeypot -->
  <input type="text" name="website" style="display:none" tabindex="-1">

  <button type="submit">Créer mon compte</button>

  <p>Déjà un compte ? <a href="/login.html">Se connecter</a></p>
</form>

<div id="feedback"></div>
```

**JavaScript (`/js/auth.js`)** :
```javascript
document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('username').value.trim().toLowerCase();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  // Validation côté client
  if (password !== confirmPassword) {
    showError('Les mots de passe ne correspondent pas');
    return;
  }

  if (!validatePassword(password)) {
    showError('Mot de passe trop faible');
    return;
  }

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    const data = await res.json();

    if (res.ok) {
      // Stocker le JWT token
      localStorage.setItem('faf_token', data.token);
      localStorage.setItem('faf_username', data.admin.username);

      // Redirection vers onboarding
      window.location.href = '/onboarding.html';
    } else {
      showError(data.error || 'Erreur lors de l\'inscription');
    }
  } catch (err) {
    showError('Erreur réseau. Réessayez.');
  }
});

function validatePassword(password) {
  // Min 8 chars, 1 uppercase, 1 digit
  const regex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
  return regex.test(password);
}
```

---

### Page onboarding (`/onboarding.html`)

**Contenu** :
```html
<div class="onboarding-container">
  <div class="success-icon">✅</div>

  <h1>Félicitations, <span id="username"></span> !</h1>
  <p>Votre compte a été créé avec succès.</p>

  <div class="form-link-box">
    <h2>Votre formulaire unique</h2>
    <div class="link-display">
      <input
        type="text"
        id="formLink"
        readonly
        value="https://faf.app/form/sophie"
      >
      <button id="copyBtn">Copier</button>
    </div>
    <p class="success-message" id="copyFeedback" style="display:none">
      ✓ Lien copié !
    </p>
  </div>

  <div class="instructions">
    <h2>Prochaines étapes</h2>
    <ol>
      <li>
        <strong>Remplissez votre formulaire</strong>
        <p>Soyez le premier à répondre pour que vos amis puissent se comparer à vous.</p>
        <a href="#" id="fillFormBtn" class="btn-primary">Remplir mon formulaire</a>
      </li>
      <li>
        <strong>Partagez votre lien</strong>
        <p>Envoyez le lien ci-dessus à vos amis via WhatsApp, email, etc.</p>
      </li>
      <li>
        <strong>Consultez les réponses</strong>
        <p>Dès que vos amis répondent, consultez leur réponses dans votre dashboard.</p>
        <a href="/admin/dashboard.html" class="btn-secondary">Aller au dashboard</a>
      </li>
    </ol>
  </div>
</div>

<script>
  const username = localStorage.getItem('faf_username');
  document.getElementById('username').textContent = username;
  document.getElementById('formLink').value = `https://faf.app/form/${username}`;
  document.getElementById('fillFormBtn').href = `/form/${username}.html`;

  // Copy to clipboard
  document.getElementById('copyBtn').addEventListener('click', () => {
    const input = document.getElementById('formLink');
    input.select();
    document.execCommand('copy');
    document.getElementById('copyFeedback').style.display = 'block';
    setTimeout(() => {
      document.getElementById('copyFeedback').style.display = 'none';
    }, 2000);
  });
</script>
```

---

### Formulaire dynamique (`/form/[username].html`)

**Différences avec la version actuelle** :

1. **Récupération du username depuis l'URL** :
```javascript
// Extraire username de l'URL : /form/sophie
const pathParts = window.location.pathname.split('/');
const username = pathParts[pathParts.length - 1].replace('.html', '');

// Vérifier que l'admin existe
const res = await fetch(`/api/form/${username}`);
if (!res.ok) {
  document.body.innerHTML = '<h1>Formulaire introuvable</h1>';
  return;
}

const data = await res.json();
document.getElementById('admin-name').textContent = data.admin.username;
```

2. **Ajout d'un champ caché avec le username** :
```html
<form id="friendForm">
  <input type="hidden" name="username" id="adminUsername" value="">

  <!-- Reste du formulaire identique -->
</form>
```

3. **Modification de la soumission** :
```javascript
const data = {
  username: document.getElementById('adminUsername').value,
  name: name,
  responses: responses
};

const resp = await fetch('/api/response/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data)
});
```

**Reste identique** :
- Toutes les 11 questions
- Validation côté client
- Upload d'images
- Modal de succès
- Affichage du lien privé

---

### Dashboard admin (`/admin/dashboard.html`)

**Modifications par rapport à la version actuelle** :

1. **Vérification JWT au chargement** :
```javascript
async function checkAuth() {
  const token = localStorage.getItem('faf_token');
  if (!token) {
    window.location.href = '/login.html';
    return false;
  }

  try {
    const res = await fetch('/api/auth/verify', {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) {
      localStorage.removeItem('faf_token');
      window.location.href = '/login.html';
      return false;
    }

    return true;
  } catch (err) {
    window.location.href = '/login.html';
    return false;
  }
}

// Appeler au chargement
if (await checkAuth()) {
  loadDashboard();
}
```

2. **Header avec info admin** :
```html
<header class="admin-header">
  <div class="logo">FAF</div>
  <div class="admin-info">
    <span>Bienvenue, <strong id="adminUsername"></strong></span>
    <button id="myFormBtn">Mon formulaire</button>
    <button id="logoutBtn">Déconnexion</button>
  </div>
</header>

<script>
  // Afficher le username
  document.getElementById('adminUsername').textContent =
    localStorage.getItem('faf_username');

  // Bouton "Mon formulaire" → copie le lien
  document.getElementById('myFormBtn').addEventListener('click', () => {
    const username = localStorage.getItem('faf_username');
    const link = `https://faf.app/form/${username}`;
    navigator.clipboard.writeText(link);
    alert('Lien copié !');
  });

  // Bouton déconnexion
  document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('faf_token');
    localStorage.removeItem('faf_username');
    window.location.href = '/login.html';
  });
</script>
```

3. **Chargement des données avec JWT** :
```javascript
async function loadDashboard(month = null) {
  const token = localStorage.getItem('faf_token');
  const url = month
    ? `/api/admin/dashboard?month=${month}`
    : '/api/admin/dashboard';

  const res = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  const data = await res.json();

  // Afficher les stats
  document.getElementById('totalResponses').textContent = data.stats.totalResponses;

  // Afficher les réponses
  renderResponses(data.responses);

  // Afficher les graphiques
  renderCharts(data.stats);
}
```

**Reste identique** :
- Layout du dashboard
- Graphiques (Chart.js)
- Liste des réponses
- Filtrage par mois
- Actions (modifier/supprimer)

---

## Migration des données existantes

### Script de migration (`/scripts/migrate-to-supabase.js`)

**Objectif** : Transférer toutes les données MongoDB vers Supabase sans perte.

**Étapes** :

1. **Backup MongoDB** :
```javascript
const { MongoClient } = require('mongodb');
const fs = require('fs');

async function backupMongoDB() {
  const client = await MongoClient.connect(process.env.MONGODB_URI);
  const db = client.db();

  const responses = await db.collection('responses').find({}).toArray();

  fs.writeFileSync(
    'backup-mongodb.json',
    JSON.stringify(responses, null, 2)
  );

  console.log(`✅ Backup MongoDB : ${responses.length} réponses sauvegardées`);

  await client.close();
  return responses;
}
```

2. **Créer l'admin Riri dans Supabase** :
```javascript
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

async function createRiriAdmin(supabase) {
  const passwordHash = await bcrypt.hash(process.env.RIRI_PASSWORD, 10);

  const { data, error } = await supabase
    .from('admins')
    .insert({
      username: 'riri',
      email: process.env.RIRI_EMAIL,
      password_hash: passwordHash
    })
    .select()
    .single();

  if (error) {
    console.error('❌ Erreur création admin:', error);
    throw error;
  }

  console.log('✅ Admin Riri créé avec ID:', data.id);
  return data.id;
}
```

3. **Migrer les réponses** :
```javascript
async function migrateResponses(supabase, mongoResponses, ririAdminId) {
  let successCount = 0;
  let errorCount = 0;

  for (const mongoResp of mongoResponses) {
    try {
      const supabaseResp = {
        owner_id: ririAdminId,
        name: mongoResp.name,
        responses: mongoResp.responses, // JSONB
        month: mongoResp.month,
        is_owner: mongoResp.isAdmin || false,
        token: mongoResp.token || null,
        created_at: mongoResp.createdAt
      };

      const { error } = await supabase
        .from('responses')
        .insert(supabaseResp);

      if (error) {
        console.error(`❌ Erreur pour ${mongoResp.name}:`, error);
        errorCount++;
      } else {
        successCount++;
      }
    } catch (err) {
      console.error(`❌ Exception pour ${mongoResp.name}:`, err);
      errorCount++;
    }
  }

  console.log(`✅ Migration terminée : ${successCount} succès, ${errorCount} erreurs`);
}
```

4. **Script complet** :
```javascript
async function migrate() {
  console.log('🚀 Début de la migration MongoDB → Supabase');

  // 1. Backup MongoDB
  const mongoResponses = await backupMongoDB();

  // 2. Connexion Supabase
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
  );

  // 3. Créer admin Riri
  const ririAdminId = await createRiriAdmin(supabase);

  // 4. Migrer les réponses
  await migrateResponses(supabase, mongoResponses, ririAdminId);

  // 5. Vérification
  const { count } = await supabase
    .from('responses')
    .select('*', { count: 'exact', head: true })
    .eq('owner_id', ririAdminId);

  console.log(`✅ Vérification : ${count} réponses dans Supabase`);
  console.log(`📊 MongoDB avait : ${mongoResponses.length} réponses`);

  if (count === mongoResponses.length) {
    console.log('✅ Migration réussie à 100% !');
  } else {
    console.log('⚠️ Différence détectée, vérifier les erreurs');
  }
}

migrate();
```

**Utilisation** :
```bash
# Définir les variables d'environnement
export MONGODB_URI="mongodb+srv://..."
export SUPABASE_URL="https://xxx.supabase.co"
export SUPABASE_SERVICE_KEY="eyJhbGc..."
export RIRI_EMAIL="riri@email.com"
export RIRI_PASSWORD="Password123!"

# Lancer la migration
node scripts/migrate-to-supabase.js
```

---

## Configuration Vercel

### Structure finale pour Vercel

```
FAF/
├── api/                    # Serverless functions
│   ├── auth/
│   ├── form/
│   ├── response/
│   ├── admin/
│   └── upload/
├── frontend/               # Static files
│   ├── public/
│   └── admin/
├── vercel.json            # Configuration Vercel
├── package.json
└── .env.example
```

### `vercel.json`

```json
{
  "version": 2,
  "builds": [
    {
      "src": "api/**/*.js",
      "use": "@vercel/node"
    },
    {
      "src": "frontend/**",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    },
    {
      "src": "/form/(.*)",
      "dest": "/frontend/public/form/index.html"
    },
    {
      "src": "/view/(.*)",
      "dest": "/frontend/public/view/index.html"
    },
    {
      "src": "/admin/(.*)",
      "dest": "/frontend/admin/$1"
    },
    {
      "src": "/(.*\\.(css|js|png|jpg|jpeg|gif|svg|ico))",
      "dest": "/frontend/public/$1"
    },
    {
      "src": "/(.*)",
      "dest": "/frontend/public/$1"
    }
  ],
  "env": {
    "SUPABASE_URL": "@supabase-url",
    "SUPABASE_ANON_KEY": "@supabase-anon-key",
    "SUPABASE_SERVICE_KEY": "@supabase-service-key",
    "JWT_SECRET": "@jwt-secret",
    "CLOUDINARY_CLOUD_NAME": "@cloudinary-cloud-name",
    "CLOUDINARY_API_KEY": "@cloudinary-api-key",
    "CLOUDINARY_API_SECRET": "@cloudinary-api-secret"
  },
  "headers": [
    {
      "source": "/api/(.*)",
      "headers": [
        {
          "key": "Access-Control-Allow-Credentials",
          "value": "true"
        },
        {
          "key": "Access-Control-Allow-Origin",
          "value": "*"
        },
        {
          "key": "Access-Control-Allow-Methods",
          "value": "GET,OPTIONS,PATCH,DELETE,POST,PUT"
        },
        {
          "key": "Access-Control-Allow-Headers",
          "value": "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization"
        }
      ]
    }
  ]
}
```

### Variables d'environnement Vercel

**À configurer dans le dashboard Vercel** :
```bash
# Supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# JWT
JWT_SECRET=une-cle-secrete-tres-longue-et-complexe-192837465

# Cloudinary
CLOUDINARY_CLOUD_NAME=votre-cloud-name
CLOUDINARY_API_KEY=123456789012345
CLOUDINARY_API_SECRET=abcdefghijklmnopqrstuvwxyz

# App
APP_BASE_URL=https://faf.vercel.app
NODE_ENV=production
```

### Déploiement

**Étapes** :

1. **Créer un projet Vercel** :
```bash
npm install -g vercel
vercel login
vercel
```

2. **Lier le repo Git** :
```bash
vercel --prod
```

3. **Configurer les variables d'environnement** :
- Aller dans le dashboard Vercel
- Settings → Environment Variables
- Ajouter toutes les variables ci-dessus

4. **Déploiement automatique** :
- Chaque push sur `main` → déploiement automatique
- Chaque push sur `multijoueurs` → preview deployment

---

## Tests

### Tests unitaires (`/tests/unit/`)

**1. Validation des inputs** (`validation.test.js`) :
```javascript
describe('Input Validation', () => {
  test('Username validation', () => {
    expect(validateUsername('sophie')).toBe(true);
    expect(validateUsername('So')).toBe(false); // trop court
    expect(validateUsername('SOPHIE')).toBe(false); // majuscules
    expect(validateUsername('sophie@123')).toBe(false); // caractères invalides
  });

  test('Password validation', () => {
    expect(validatePassword('Password123!')).toBe(true);
    expect(validatePassword('password')).toBe(false); // pas de majuscule
    expect(validatePassword('Pass1')).toBe(false); // trop court
  });

  test('XSS escaping', () => {
    const input = '<script>alert("XSS")</script>';
    const escaped = escapeHtml(input);
    expect(escaped).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
  });
});
```

**2. Génération de tokens** (`tokens.test.js`) :
```javascript
describe('Token Generation', () => {
  test('Generate unique 64-char token', () => {
    const token1 = generateToken();
    const token2 = generateToken();

    expect(token1).toHaveLength(64);
    expect(token2).toHaveLength(64);
    expect(token1).not.toBe(token2);
  });
});
```

**3. Hash de passwords** (`bcrypt.test.js`) :
```javascript
describe('Password Hashing', () => {
  test('Hash and compare password', async () => {
    const password = 'Password123!';
    const hash = await bcrypt.hash(password, 10);

    expect(await bcrypt.compare(password, hash)).toBe(true);
    expect(await bcrypt.compare('wrongpass', hash)).toBe(false);
  });
});
```

---

### Tests d'intégration (`/tests/integration/`)

**1. Cycle complet d'inscription/login** (`auth.test.js`) :
```javascript
describe('Auth Flow', () => {
  test('Register → Login → Access dashboard', async () => {
    // 1. Inscription
    const registerRes = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123!'
      })
    });

    expect(registerRes.status).toBe(201);
    const registerData = await registerRes.json();
    expect(registerData.token).toBeDefined();

    // 2. Login
    const loginRes = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser',
        password: 'Password123!'
      })
    });

    expect(loginRes.status).toBe(200);
    const loginData = await loginRes.json();
    const token = loginData.token;

    // 3. Accès dashboard
    const dashboardRes = await fetch('/api/admin/dashboard', {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    expect(dashboardRes.status).toBe(200);
  });
});
```

**2. Soumission de formulaire** (`form.test.js`) :
```javascript
describe('Form Submission', () => {
  test('Submit form → Receive token → View comparison', async () => {
    // 1. Soumettre le formulaire
    const submitRes = await fetch('/api/response/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser',
        name: 'Emma',
        responses: [
          { question: 'Q1', answer: 'A1' },
          { question: 'Q2', answer: 'A2' }
        ]
      })
    });

    expect(submitRes.status).toBe(201);
    const submitData = await submitRes.json();
    expect(submitData.link).toBeDefined();

    // Extraire le token du lien
    const token = submitData.link.split('/').pop();

    // 2. Consulter la comparaison
    const viewRes = await fetch(`/api/response/view/${token}`);
    expect(viewRes.status).toBe(200);

    const viewData = await viewRes.json();
    expect(viewData.user.name).toBe('Emma');
    expect(viewData.admin).toBeDefined();
  });
});
```

**3. Isolation des données** (`isolation.test.js`) :
```javascript
describe('Data Isolation', () => {
  test('Admin A cannot see Admin B data', async () => {
    // Créer deux admins
    const adminA = await createTestAdmin('adminA');
    const adminB = await createTestAdmin('adminB');

    // Admin B crée des réponses
    await createTestResponse(adminB.id, 'User1');
    await createTestResponse(adminB.id, 'User2');

    // Admin A tente d'accéder au dashboard
    const dashboardRes = await fetch('/api/admin/dashboard', {
      headers: { 'Authorization': `Bearer ${adminA.token}` }
    });

    const data = await dashboardRes.json();

    // Admin A ne doit voir AUCUNE réponse (car il n'en a pas)
    expect(data.responses).toHaveLength(0);
  });
});
```

---

### Tests de migration (`/tests/migration/`)

**Script de validation post-migration** (`validate-migration.js`) :
```javascript
async function validateMigration() {
  console.log('🔍 Validation de la migration...');

  // 1. Compter les réponses MongoDB (backup)
  const mongoBackup = JSON.parse(fs.readFileSync('backup-mongodb.json'));
  const mongoCount = mongoBackup.length;
  console.log(`MongoDB : ${mongoCount} réponses`);

  // 2. Compter les réponses Supabase
  const { count: supabaseCount } = await supabase
    .from('responses')
    .select('*', { count: 'exact', head: true })
    .eq('owner_id', ririAdminId);
  console.log(`Supabase : ${supabaseCount} réponses`);

  // 3. Vérifier l'égalité
  if (mongoCount !== supabaseCount) {
    console.error('❌ ERREUR : Nombre de réponses différent !');
    process.exit(1);
  }

  // 4. Vérifier un échantillon de tokens
  const sampleTokens = mongoBackup
    .filter(r => r.token)
    .slice(0, 10)
    .map(r => r.token);

  for (const token of sampleTokens) {
    const { data } = await supabase
      .from('responses')
      .select('*')
      .eq('token', token)
      .single();

    if (!data) {
      console.error(`❌ Token ${token} introuvable dans Supabase`);
      process.exit(1);
    }
  }

  console.log('✅ Migration validée : toutes les données sont intactes');
}
```

---

## Checklist de déploiement

### Phase 1 : Setup Supabase
- [ ] Créer un projet Supabase
- [ ] Exécuter les scripts SQL (tables + indexes + RLS)
- [ ] Tester la connexion depuis Node.js
- [ ] Configurer les variables d'environnement

### Phase 2 : Développement backend
- [ ] Créer la structure `/api` pour Vercel
- [ ] Implémenter `/api/auth/register`
- [ ] Implémenter `/api/auth/login`
- [ ] Implémenter `/api/form/[username]`
- [ ] Implémenter `/api/response/submit`
- [ ] Implémenter `/api/response/view/[token]`
- [ ] Implémenter `/api/admin/dashboard`
- [ ] Implémenter `/api/upload/image`
- [ ] Tester chaque endpoint (Postman/Insomnia)

### Phase 3 : Développement frontend
- [ ] Créer la landing page
- [ ] Créer la page d'inscription
- [ ] Créer la page de login
- [ ] Créer la page onboarding
- [ ] Adapter le formulaire (dynamique par admin)
- [ ] Adapter la page de comparaison
- [ ] Adapter le dashboard admin (avec JWT)
- [ ] Tester l'UX complète

### Phase 4 : Migration des données
- [ ] Créer le script de backup MongoDB
- [ ] Créer le script de migration
- [ ] Tester sur une base de test
- [ ] Exécuter sur la base de production
- [ ] Valider l'intégrité des données
- [ ] Tester les liens privés existants

### Phase 5 : Tests
- [ ] Écrire les tests unitaires
- [ ] Écrire les tests d'intégration
- [ ] Tester l'isolation des données
- [ ] Tester la sécurité (XSS, CSRF, etc.)
- [ ] Tester les performances (Lighthouse)

### Phase 6 : Déploiement Vercel
- [ ] Créer le projet Vercel
- [ ] Configurer `vercel.json`
- [ ] Définir les variables d'environnement
- [ ] Déployer en preview (branche multijoueurs)
- [ ] Tester en staging
- [ ] Déployer en production (merge vers main)

### Phase 7 : Post-déploiement
- [ ] Configurer le DNS (domaine custom)
- [ ] Activer HTTPS (automatique Vercel)
- [ ] Configurer les analytics (Vercel Analytics)
- [ ] Monitorer les erreurs (Sentry/LogRocket)
- [ ] Documenter l'API (Swagger/OpenAPI)

---

## Différences clés avec la version actuelle

| Aspect | Version mono-admin | Version multi-tenant |
|--------|-------------------|---------------------|
| **Admins** | 1 seul (hardcodé) | Illimité (inscription) |
| **URL formulaire** | `/` (unique) | `/form/{username}` (dynamique) |
| **Auth** | Session + .env | JWT + Supabase |
| **Base de données** | MongoDB | PostgreSQL (Supabase) |
| **Isolation données** | Logique applicative | RLS natif |
| **Dashboard** | Global (voit tout) | Personnel (owner_id) |
| **Déploiement** | Serveur traditionnel | Vercel Serverless |
| **Scalabilité** | Limitée (1 serveur) | Automatique (edge) |
| **Coût** | Serveur dédié | Gratuit (tier Vercel/Supabase) |

---

## Roadmap future (post-MVP)

**Phase 1 - Multi-tenant de base** (ce document) :
- Inscription/login
- Formulaire dynamique
- Dashboard isolé
- Migration des données

**Phase 2 - Améliorations UX** :
- Récupération de mot de passe (email)
- Personnalisation du formulaire (questions custom)
- Thèmes de couleurs personnalisables
- Notifications email (nouvel ami a répondu)

**Phase 3 - Fonctionnalités sociales** :
- Partage public des comparaisons (opt-in)
- Commentaires sur les réponses
- Système de "likes"
- Galerie publique des meilleures réponses

**Phase 4 - Monétisation** :
- Plan gratuit : 10 amis max
- Plan premium : illimité + analytics avancés
- Export CSV/PDF des réponses
- API publique pour intégrations

---

## Ressources et documentation

### Supabase
- Docs : https://supabase.com/docs
- Row Level Security : https://supabase.com/docs/guides/auth/row-level-security
- JavaScript Client : https://supabase.com/docs/reference/javascript

### Vercel
- Docs : https://vercel.com/docs
- Serverless Functions : https://vercel.com/docs/functions
- Environment Variables : https://vercel.com/docs/environment-variables

### Sécurité
- OWASP Top 10 : https://owasp.org/www-project-top-ten/
- JWT Best Practices : https://datatracker.ietf.org/doc/html/rfc8725
- bcrypt : https://github.com/kelektiv/node.bcrypt.js

---

## Conclusion

Cette spécification décrit en détail la transformation de FAF en plateforme multi-tenant avec :
- Architecture backend serverless (Vercel)
- Base de données PostgreSQL avec RLS (Supabase)
- Isolation complète des données par admin
- Système d'authentification JWT
- Migration sans perte des données existantes
- Interface responsive et moderne
- Sécurité renforcée (XSS, CSRF, rate limiting)

Le développement sera progressif, permettant de tester chaque composant indépendamment avant l'intégration finale.
