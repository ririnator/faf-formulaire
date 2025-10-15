# Guide de déploiement Vercel - FAF Multi-Tenant

Ce guide décrit comment déployer FAF Multi-Tenant sur Vercel en mode serverless.

---

## Vue d'ensemble

**Architecture déployée** :
- **Backend** : Serverless functions (Node.js) dans `/api/`
- **Frontend** : Static files dans `/frontend/`
- **Base de données** : Supabase (PostgreSQL avec RLS)
- **Hébergement** : Vercel (edge network mondial)

---

## Prérequis

- ✅ Compte Vercel ([vercel.com](https://vercel.com))
- ✅ Compte GitHub (repository FAF)
- ✅ Projet Supabase configuré (tables + RLS)
- ✅ Compte Cloudinary (upload images)
- ✅ Migration MongoDB → Supabase terminée

---

## Étape 1 : Installation Vercel CLI

### macOS / Linux
```bash
npm install -g vercel
```

### Vérification
```bash
vercel --version
```

### Login
```bash
vercel login
```

Choisir la méthode d'authentification (GitHub recommandé).

---

## Étape 2 : Configuration du projet

### Structure vérifiée

Le projet est déjà structuré pour Vercel :

```
FAF/
├── api/                    # ✅ Serverless functions
│   ├── auth/
│   │   ├── register.js
│   │   ├── login.js
│   │   └── verify.js
│   ├── form/
│   │   └── [username].js
│   ├── response/
│   │   ├── submit.js
│   │   └── view/
│   │       └── [token].js
│   ├── admin/
│   │   ├── dashboard.js
│   │   ├── responses.js
│   │   └── response/
│   │       └── [id].js
│   └── upload/
│       └── image.js
├── frontend/               # ✅ Static files
│   ├── public/
│   │   ├── auth/
│   │   ├── form/
│   │   ├── view/
│   │   ├── css/
│   │   └── js/
│   └── admin/
│       ├── dashboard.html
│       ├── gestion.html
│       └── faf-admin.js
├── vercel.json            # ✅ Configuration Vercel
├── .vercelignore          # ✅ Fichiers exclus
└── package.json           # ✅ Dépendances
```

### Fichier `vercel.json`

Le fichier est déjà créé avec :
- ✅ Builds configurés (Node.js + static)
- ✅ Routes définies (`/api/*`, `/form/*`, `/view/*`, `/admin/*`)
- ✅ Headers CORS
- ✅ Variables d'environnement (références)

---

## Étape 3 : Variables d'environnement

### 3.1. Variables requises

Les variables suivantes doivent être configurées dans le **Vercel Dashboard** :

#### Supabase
```bash
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Où les trouver** :
1. [Supabase Dashboard](https://app.supabase.com)
2. Projet FAF → Settings → API
3. Copier URL + anon key + service_role key

#### JWT
```bash
JWT_SECRET=your-super-secret-jwt-key-min-32-characters
```

**Génération** :
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### Cloudinary
```bash
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=123456789012345
CLOUDINARY_API_SECRET=abcdefghijklmnopqrstuvwxyz
```

**Où les trouver** :
1. [Cloudinary Dashboard](https://cloudinary.com/console)
2. Dashboard → Settings → Access Keys

#### Application
```bash
APP_BASE_URL=https://faf-xxxxx.vercel.app
NODE_ENV=production
```

**Note** : `APP_BASE_URL` sera l'URL Vercel après déploiement.

---

### 3.2. Ajouter les variables dans Vercel

#### Via Dashboard (recommandé)

1. Aller sur [vercel.com/dashboard](https://vercel.com/dashboard)
2. Sélectionner le projet FAF
3. Settings → Environment Variables
4. Ajouter chaque variable :
   - **Key** : Nom de la variable (ex: `SUPABASE_URL`)
   - **Value** : Valeur de la variable
   - **Environments** : Production, Preview, Development (cocher tous)
5. Cliquer "Save"

#### Via CLI

```bash
vercel env add SUPABASE_URL production
# Coller la valeur
vercel env add SUPABASE_URL preview
vercel env add SUPABASE_URL development
```

Répéter pour toutes les variables.

---

## Étape 4 : Test local avec Vercel Dev

### 4.1. Installation des dépendances
```bash
npm install
```

### 4.2. Créer `.env` local
```bash
cp .env.example .env
# Éditer .env avec les vraies valeurs
```

### 4.3. Lancer Vercel Dev
```bash
vercel dev
```

**Sortie attendue** :
```
Vercel CLI 33.0.0
> Ready! Available at http://localhost:3000
```

### 4.4. Tester les routes

#### Frontend
- http://localhost:3000/ → Landing page (login)
- http://localhost:3000/auth/register.html → Inscription
- http://localhost:3000/form/riri → Formulaire dynamique
- http://localhost:3000/admin/dashboard.html → Dashboard admin

#### API
- http://localhost:3000/api/auth/verify (GET avec Bearer token)
- http://localhost:3000/api/form/riri (GET)
- http://localhost:3000/api/admin/dashboard (GET avec Bearer token)

### 4.5. Vérifier les logs

Les logs s'affichent en temps réel dans le terminal. Vérifier :
- ✅ Routes API répondent (200)
- ✅ Static files chargés
- ✅ Pas d'erreurs 500

---

## Étape 5 : Déploiement

### 5.1. Push vers GitHub

```bash
# Vérifier le statut
git status

# Ajouter les fichiers
git add vercel.json .vercelignore docs/DEPLOYMENT.md

# Commit
git commit -m "🚀 FEAT: Étape 11 - Configuration Vercel

- vercel.json avec builds + routes + headers CORS
- .vercelignore pour exclure fichiers inutiles
- docs/DEPLOYMENT.md (guide complet)
"

# Push vers GitHub
git push origin multijoueurs
```

### 5.2. Lier le repository à Vercel

#### Via Dashboard

1. [Vercel Dashboard](https://vercel.com/new)
2. "Import Project"
3. Sélectionner le repository GitHub `FAF`
4. Branche : `multijoueurs`
5. Framework Preset : **Other** (pas Next.js, pas Vue, etc.)
6. Root Directory : `.` (racine)
7. Build Command : Laisser vide (serverless, pas de build)
8. Output Directory : Laisser vide
9. Cliquer "Deploy"

#### Via CLI

```bash
# À la racine du projet
vercel

# Répondre aux questions :
# - Set up and deploy? Yes
# - Which scope? [Votre compte]
# - Link to existing project? No
# - What's your project's name? faf-multitenant
# - In which directory is your code located? ./
```

### 5.3. Configuration automatique

Vercel détecte automatiquement `vercel.json` et configure :
- ✅ Builds pour `/api/**/*.js` (Node.js functions)
- ✅ Routes définies dans `vercel.json`
- ✅ Headers CORS

---

## Étape 6 : Vérification du déploiement

### 6.1. URL de déploiement

Une fois le déploiement terminé, Vercel affiche l'URL :
```
https://faf-multitenant-xxxxx.vercel.app
```

### 6.2. Tests manuels

#### Test 1 : Page de connexion
```
https://faf-multitenant-xxxxx.vercel.app/
```
→ Doit afficher la page de login

#### Test 2 : API publique
```
https://faf-multitenant-xxxxx.vercel.app/api/form/riri
```
→ Doit retourner JSON avec les questions

#### Test 3 : Inscription
1. Aller sur `/auth/register.html`
2. Créer un compte test
3. Vérifier JWT retourné

#### Test 4 : Dashboard admin
1. Se connecter avec le compte créé
2. Vérifier dashboard s'affiche
3. Vérifier stats/graphiques

#### Test 5 : Soumission formulaire
1. Aller sur `/form/{username}`
2. Remplir et soumettre
3. Vérifier lien privé généré
4. Tester le lien `/view/{token}`

---

## Étape 7 : Mise à jour de APP_BASE_URL

### 7.1. Mettre à jour la variable

Une fois l'URL Vercel connue, mettre à jour `APP_BASE_URL` :

1. Vercel Dashboard → Settings → Environment Variables
2. Trouver `APP_BASE_URL`
3. Modifier : `https://faf-multitenant-xxxxx.vercel.app`
4. Sauvegarder

### 7.2. Redéployer

```bash
vercel --prod
```

Ou via GitHub :
```bash
git commit --allow-empty -m "chore: trigger redeploy"
git push origin multijoueurs
```

---

## Étape 8 : Domaine custom (optionnel)

### 8.1. Ajouter un domaine

1. Vercel Dashboard → Settings → Domains
2. Cliquer "Add"
3. Entrer votre domaine (ex: `faf.votredomaine.com`)
4. Suivre les instructions DNS

### 8.2. Configurer DNS

Chez votre registrar (Namecheap, OVH, etc.), ajouter :

**CNAME Record** :
```
Type: CNAME
Name: faf (ou @ pour root)
Value: cname.vercel-dns.com
TTL: 3600
```

### 8.3. Vérification

Attendre la propagation DNS (5-30 min), puis :
```bash
curl https://faf.votredomaine.com
```

### 8.4. HTTPS automatique

Vercel configure automatiquement un certificat SSL (Let's Encrypt).

---

## Monitoring et logs

### Logs en temps réel

1. Vercel Dashboard → Deployments
2. Cliquer sur le déploiement actif
3. Onglet "Functions"
4. Voir les logs de chaque fonction serverless

### Analytics

Vercel fournit gratuitement :
- **Requests** : Nombre de requêtes par fonction
- **Errors** : Taux d'erreur 4xx/5xx
- **Duration** : Temps d'exécution moyen
- **Bandwidth** : Consommation de bande passante

Activer : Settings → Analytics → Enable

---

## Troubleshooting

### Erreur : "Function Timeout"

**Cause** : Fonction serverless dépasse 10s (limite gratuite)

**Solution** :
- Optimiser les requêtes SQL
- Ajouter des indexes Supabase
- Utiliser la pagination

### Erreur : "Environment Variable Missing"

**Cause** : Variable non définie dans Vercel

**Solution** :
```bash
vercel env ls
# Vérifier que toutes les variables sont présentes
```

### Erreur : "CORS blocked"

**Cause** : Headers CORS mal configurés

**Solution** : Vérifier `vercel.json` section `headers`

### Erreur : "Module not found"

**Cause** : Dépendance npm manquante

**Solution** :
```bash
npm install [package-name]
git add package.json package-lock.json
git commit -m "chore: add missing dependency"
git push
```

---

## Déploiement continu (CI/CD)

### Configuration

Vercel déploie automatiquement :
- **Push sur `main`** → Production
- **Push sur autre branche** → Preview deployment
- **Pull Request** → Preview deployment

### Workflow

```
1. Développement local
   └─> vercel dev

2. Commit + Push branche
   └─> Preview deployment (https://faf-xxxxx-git-branch.vercel.app)

3. Merge vers main
   └─> Production deployment (https://faf-multitenant.vercel.app)
```

---

## Checklist de déploiement

- [ ] ✅ `vercel.json` créé et validé
- [ ] ✅ `.vercelignore` configuré
- [ ] ✅ Variables d'environnement ajoutées dans Vercel Dashboard
- [ ] ✅ `vercel dev` fonctionne localement
- [ ] ✅ Repository GitHub lié à Vercel
- [ ] ✅ Premier déploiement réussi
- [ ] ✅ URL Vercel fonctionnelle
- [ ] ✅ `APP_BASE_URL` mise à jour
- [ ] ✅ Tests manuels passés (login, form, dashboard)
- [ ] ✅ Domaine custom configuré (optionnel)
- [ ] ✅ Analytics activées
- [ ] ✅ Monitoring en place

---

## Ressources

- **Vercel Docs** : https://vercel.com/docs
- **Serverless Functions** : https://vercel.com/docs/functions
- **Environment Variables** : https://vercel.com/docs/environment-variables
- **Custom Domains** : https://vercel.com/docs/custom-domains

---

## Prochaines étapes

Après le déploiement, passer à l'**Étape 12 : Tests & Déploiement** pour :
- Tests d'intégration complets
- Tests de performance (Lighthouse)
- Tests de charge
- Monitoring production

---

**Déploiement Vercel terminé ! 🚀**
