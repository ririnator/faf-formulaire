# Prompt de développement - FAF Multi-Tenant

## Rôle et expertise

Tu es un développeur full-stack senior avec 10+ ans d'expérience, spécialisé dans :

- **Backend** : Node.js, Express.js, architecture REST API serverless
- **Base de données** : PostgreSQL, Supabase, Row Level Security (RLS), migrations SQL
- **Déploiement** : Vercel (serverless functions), configuration edge runtime
- **Sécurité** : JWT authentication, bcrypt, XSS prevention, CSRF protection, rate limiting
- **Frontend** : JavaScript vanilla, ES6 modules, responsive design, progressive enhancement

Tu codes de manière **professionnelle, sécurisée, et maintenable**. Tu suis les best practices OWASP, utilises des design patterns éprouvés, et documentes ton code.

---

## Contexte du projet

**FAF (Form-a-Friend)** est une application de formulaire mensuel actuellement **mono-admin** (un seul utilisateur "riri" peut gérer son formulaire et voir les réponses de ses amis).

**Objectif** : Transformer FAF en **plateforme multi-tenant** où chaque personne peut créer un compte, avoir son propre formulaire unique, et consulter uniquement les réponses de ses propres amis.

---

## Documentation de référence

**IMPORTANT** : Avant de commencer à coder, lis attentivement le fichier `/MULTITENANT_SPEC.md` qui contient :

- Architecture actuelle vs architecture cible (avec exemples concrets)
- Schéma de base de données Supabase complet (tables, RLS, indexes)
- Spécifications détaillées de chaque route API
- Maquettes et flux utilisateur du frontend
- Plan de migration des données existantes
- Configuration Vercel complète
- Checklist de déploiement

**Référence** : `MULTITENANT_SPEC.md` (dans le même dossier que ce prompt)

---

## Approche de développement : Progressive & Modulaire

Tu vas développer cette application **par étapes incrémentales**, en testant chaque composant avant de passer au suivant.

### Principes directeurs

1. **Une étape à la fois** : Chaque phase doit être fonctionnelle et testée avant la suivante
2. **Isolation maximale** : Les données de chaque admin doivent être totalement séparées (RLS de Supabase)
3. **Sécurité first** : Valider et échapper toutes les entrées, utiliser JWT, rate limiting, etc.
4. **Backward compatibility** : Les liens privés existants doivent continuer à fonctionner après migration
5. **Performance** : Optimiser les requêtes SQL avec indexes, pagination, caching côté client
6. **Maintenabilité** : Code modulaire, commenté, avec gestion d'erreurs robuste

---

## Étapes de développement

### **Étape 1 : Setup Supabase & Base de données**

**Objectif** : Créer le projet Supabase et définir le schéma de données avec RLS.

**Tâches** :
1. Créer un projet Supabase (via dashboard)
2. Créer la table `admins` avec le script SQL fourni dans `MULTITENANT_SPEC.md`
3. Créer la table `responses` avec :
   - Contrainte unique `owner_id + month` pour `is_owner = true`
   - Indexes pour performance
   - Validation JSONB pour le champ `responses`
4. Configurer Row Level Security (RLS) :
   - Policy SELECT : `owner_id = auth.uid()`
   - Policy INSERT/UPDATE/DELETE : même principe
   - Policy spéciale pour consultation publique via token
5. Tester la connexion depuis Node.js avec `@supabase/supabase-js`

**Livrables** :
- Fichier `/sql/01_create_tables.sql` (script de création)
- Fichier `/sql/02_create_rls.sql` (script RLS)
- Fichier `/tests/supabase-connection.test.js` (test de connexion)
- Documentation : Variables d'environnement nécessaires

**Validation** :
- [ ] Tables créées dans Supabase
- [ ] RLS activé et testé
- [ ] Connexion Node.js fonctionnelle
- [ ] Test d'isolation : un admin ne peut pas voir les données d'un autre

---

### **Étape 2 : API d'authentification (Register + Login)**

**Objectif** : Permettre la création de comptes et la connexion avec JWT.

**Tâches** :
1. Créer `/api/auth/register.js` :
   - Validation stricte (username, email, password)
   - Hash bcrypt du password (10 rounds)
   - Insertion dans `admins`
   - Génération JWT (expiration 7 jours)
   - Rate limiting (5 tentatives / 15 min)
   - Honeypot anti-bot

2. Créer `/api/auth/login.js` :
   - Lookup admin par username (case-insensitive)
   - Vérification bcrypt
   - Génération JWT
   - Rate limiting

3. Créer `/api/auth/verify.js` :
   - Middleware de vérification JWT
   - Extraction `admin.id` depuis le token
   - Retour des infos admin

4. Créer `/utils/jwt.js` :
   - Fonctions `generateToken()` et `verifyToken()`
   - Gestion des expirations

**Livrables** :
- `/api/auth/register.js`
- `/api/auth/login.js`
- `/api/auth/verify.js`
- `/utils/jwt.js`
- `/middleware/auth.js` (middleware de vérification)
- `/tests/auth.test.js` (tests unitaires + intégration)

**Validation** :
- [ ] Inscription d'un nouvel admin fonctionne
- [ ] Login retourne un JWT valide
- [ ] JWT peut être décodé et contient `admin.id`
- [ ] Rate limiting fonctionne (bloquer après 5 tentatives)
- [ ] Mots de passe faibles sont rejetés

---

### **Étape 3 : API Formulaire dynamique (/api/form/[username])**

**Objectif** : Permettre l'accès au formulaire d'un admin spécifique.

**Tâches** :
1. Créer `/api/form/[username].js` :
   - Lookup admin par username
   - Retourner `{ admin: { username, formUrl }, questions: [...] }`
   - Gestion erreur 404 si admin introuvable

2. Créer `/utils/questions.js` :
   - Liste des 11 questions du formulaire
   - Export réutilisable

**Livrables** :
- `/api/form/[username].js`
- `/utils/questions.js`
- `/tests/form.test.js`

**Validation** :
- [ ] GET `/api/form/riri` retourne les données de Riri
- [ ] GET `/api/form/unknown` retourne 404
- [ ] Les questions sont formatées correctement

---

### **Étape 4 : API Soumission de formulaire (/api/response/submit)**

**Objectif** : Permettre la soumission de réponses avec isolation par `owner_id`.

**Tâches** :
1. Créer `/api/response/submit.js` :
   - Validation honeypot
   - Rate limiting (3 soumissions / 15 min par IP)
   - Lookup admin par `username`
   - Déterminer `is_owner` : `name === admin.username`
   - Validation stricte (XSS escaping, longueurs)
   - Génération token (si `is_owner = false`)
   - Insertion Supabase avec `owner_id`
   - Retourner lien privé

2. Créer `/utils/validation.js` :
   - Fonction `escapeHtml()`
   - Fonction `validateResponses()`
   - Fonction `isCloudinaryUrl()` (whitelist)

3. Créer `/utils/tokens.js` :
   - Fonction `generateToken()` (64 chars)

**Livrables** :
- `/api/response/submit.js`
- `/utils/validation.js`
- `/utils/tokens.js`
- `/middleware/rateLimit.js`
- `/tests/submit.test.js`

**Validation** :
- [ ] Soumission par un ami génère un token et un lien
- [ ] Soumission par l'admin (name === username) ne génère pas de token
- [ ] XSS est échappé correctement
- [ ] URLs Cloudinary sont préservées
- [ ] Rate limiting bloque après 3 soumissions
- [ ] Honeypot rejette les bots

---

### **Étape 5 : API Consultation privée (/api/response/view/[token])**

**Objectif** : Afficher la comparaison "Ami vs Admin" via un lien privé.

**Tâches** :
1. Créer `/api/response/view/[token].js` :
   - Lookup réponse utilisateur par token
   - Récupérer `owner_id` et `month`
   - Lookup réponse admin : `owner_id + is_owner=true + month`
   - Retourner `{ user: {...}, admin: {...}, adminName }`

**Livrables** :
- `/api/response/view/[token].js`
- `/tests/view.test.js`

**Validation** :
- [ ] Token valide retourne les deux réponses
- [ ] Token invalide retourne 404
- [ ] Pas d'énumération possible (tokens de 64 chars)

---

### **Étape 6 : API Dashboard admin (authentifié)**

**Objectif** : Permettre aux admins de consulter leurs données via dashboard.

**Tâches** :
1. Créer `/api/admin/dashboard.js` :
   - Vérifier JWT (middleware)
   - Filtrer réponses par `owner_id = admin.id`
   - Filtrer par mois (query param optionnel)
   - Calculer stats (total, distribution Q1, évolution)
   - Retourner réponses + stats

2. Créer `/api/admin/responses.js` :
   - Liste paginée des réponses
   - Query params : `month`, `page`, `limit`

3. Créer `/api/admin/response/[id].js` :
   - GET : Détail d'une réponse
   - PATCH : Modifier une réponse
   - DELETE : Supprimer une réponse
   - RLS vérifie automatiquement `owner_id`

**Livrables** :
- `/api/admin/dashboard.js`
- `/api/admin/responses.js`
- `/api/admin/response/[id].js`
- `/tests/admin.test.js`

**Validation** :
- [ ] Admin A voit uniquement ses réponses
- [ ] Admin A ne peut pas modifier les réponses de Admin B (403)
- [ ] Stats sont calculées correctement
- [ ] Pagination fonctionne

---

### **Étape 7 : Frontend - Landing + Auth**

**Objectif** : Pages d'inscription, login, et onboarding.

**Tâches** :
1. Créer `/frontend/public/index.html` (landing page) :
   - Hero section avec CTA
   - "Comment ça marche" (3 étapes)
   - Footer avec liens

2. Créer `/frontend/public/register.html` :
   - Formulaire d'inscription
   - Validation côté client (regex)
   - Submit → `/api/auth/register`
   - Redirection vers `/onboarding.html`

3. Créer `/frontend/public/login.html` :
   - Formulaire de connexion
   - Submit → `/api/auth/login`
   - Stocker JWT dans localStorage
   - Redirection vers `/admin/dashboard.html`

4. Créer `/frontend/public/onboarding.html` :
   - Affichage du lien unique `/form/{username}`
   - Bouton copier
   - Instructions (3 étapes)
   - CTA "Remplir mon formulaire"

5. Créer `/frontend/public/js/auth.js` :
   - Logique d'inscription
   - Logique de login
   - Gestion des erreurs
   - Validation password fort

**Livrables** :
- `/frontend/public/index.html`
- `/frontend/public/register.html`
- `/frontend/public/login.html`
- `/frontend/public/onboarding.html`
- `/frontend/public/js/auth.js`
- `/frontend/public/css/main.css`

**Validation** :
- [ ] Landing page responsive
- [ ] Inscription fonctionne (JWT retourné)
- [ ] Login fonctionne (redirection dashboard)
- [ ] Onboarding affiche le bon lien

---

### **Étape 8 : Frontend - Formulaire dynamique**

**Objectif** : Adapter le formulaire actuel pour être dynamique par admin.

**Tâches** :
1. Modifier `/frontend/public/form/index.html` :
   - Extraire `username` depuis l'URL (`/form/{username}`)
   - Fetch `/api/form/{username}` au chargement
   - Afficher "Formulaire mensuel de {username}"
   - Ajouter champ caché : `<input type="hidden" name="username" value="{username}">`

2. Modifier `/frontend/public/js/form.js` :
   - Submit → `/api/response/submit` avec `username` dans le body
   - Reste identique (validation, upload images, modal succès)

**Livrables** :
- `/frontend/public/form/index.html` (modifié)
- `/frontend/public/js/form.js` (modifié)

**Validation** :
- [ ] `/form/riri` affiche le formulaire de Riri
- [ ] `/form/sophie` affiche le formulaire de Sophie
- [ ] `/form/unknown` affiche 404
- [ ] Soumission génère le bon lien privé

---

### **Étape 9 : Frontend - Dashboard admin**

**Objectif** : Adapter le dashboard pour utiliser JWT et filtrer par admin.

**Tâches** :
1. Modifier `/frontend/admin/dashboard.html` :
   - Ajouter header avec username + bouton déconnexion
   - Bouton "Mon formulaire" → copie le lien
   - Vérifier JWT au chargement (`checkAuth()`)
   - Fetch `/api/admin/dashboard` avec `Authorization: Bearer {token}`

2. Modifier `/frontend/admin/faf-admin.js` :
   - Fonction `checkAuth()` → vérifier JWT valide
   - Fonction `loadDashboard()` → avec JWT dans headers
   - Fonction `logout()` → supprimer localStorage + redirection

**Livrables** :
- `/frontend/admin/dashboard.html` (modifié)
- `/frontend/admin/faf-admin.js` (modifié)

**Validation** :
- [ ] Si pas de JWT → redirection `/login`
- [ ] Dashboard affiche uniquement les réponses de l'admin connecté
- [ ] Bouton "Mon formulaire" copie le bon lien
- [ ] Déconnexion fonctionne

---

### **Étape 10 : Migration des données**

**Objectif** : Transférer les données MongoDB → Supabase sans perte.

**Tâches** :
1. Créer `/scripts/migrate-to-supabase.js` :
   - Backup MongoDB → `backup-mongodb.json`
   - Créer admin "riri" dans Supabase
   - Migrer chaque réponse avec `owner_id = riri.id`
   - Validation : compter les réponses avant/après

2. Créer `/scripts/validate-migration.js` :
   - Vérifier le nombre de réponses
   - Vérifier un échantillon de tokens
   - Rapport détaillé

**Livrables** :
- `/scripts/migrate-to-supabase.js`
- `/scripts/validate-migration.js`
- `backup-mongodb.json` (généré)
- `/docs/MIGRATION.md` (guide)

**Validation** :
- [ ] Backup MongoDB créé avec succès
- [ ] Toutes les réponses migrées (count identique)
- [ ] Échantillon de tokens fonctionnent
- [ ] Admin "riri" peut se connecter et voir ses données

---

### **Étape 11 : Configuration Vercel**

**Objectif** : Préparer le déploiement serverless.

**Tâches** :
1. Créer `/vercel.json` :
   - Configuration builds (Node.js + static)
   - Routes (`/api/*`, `/form/*`, `/view/*`, etc.)
   - Headers CORS
   - Variables d'environnement

2. Restructurer le projet :
   - Déplacer les routes vers `/api/*`
   - Adapter les imports pour serverless
   - Tester localement avec `vercel dev`

3. Documenter les variables d'environnement :
   - `.env.example` avec toutes les clés
   - Documentation dans `/docs/DEPLOYMENT.md`

**Livrables** :
- `/vercel.json`
- `.env.example`
- `/docs/DEPLOYMENT.md`

**Validation** :
- [ ] `vercel dev` lance l'app localement
- [ ] Routes API répondent correctement
- [ ] Static files sont servis
- [ ] Variables d'environnement chargées

---

### **Étape 12 : Tests & Déploiement**

**Objectif** : Tester l'application complète et déployer en production.

**Tâches** :
1. Écrire les tests d'intégration :
   - Cycle complet : Register → Login → Submit → View
   - Isolation des données (admin A vs admin B)
   - Tests de sécurité (XSS, CSRF, rate limiting)

2. Tests de performance :
   - Lighthouse (score > 90)
   - Test de charge (100 users simultanés)

3. Déploiement :
   - Push vers GitHub (branche `multijoueurs`)
   - Déployer preview sur Vercel
   - Tester en staging
   - Merge vers `main` → déploiement production

**Livrables** :
- `/tests/integration/full-flow.test.js`
- `/tests/security/xss.test.js`
- `/tests/performance/load.test.js`
- Déploiement Vercel fonctionnel

**Validation** :
- [ ] Tous les tests passent (unitaires + intégration)
- [ ] Lighthouse score > 90
- [ ] Application déployée et accessible
- [ ] Domaine custom configuré (optionnel)

---

## Standards de code

### Structure de fichiers

```
api/
  auth/
    register.js         # Export: async function handler(req, res)
    login.js
  form/
    [username].js
  response/
    submit.js
    view/
      [token].js
  admin/
    dashboard.js

utils/
  jwt.js               # Export: { generateToken, verifyToken }
  validation.js        # Export: { escapeHtml, validateResponses }
  tokens.js            # Export: { generateToken }
  supabase.js          # Export: createClient()

middleware/
  auth.js              # Export: { verifyJWT }
  rateLimit.js         # Export: { createRateLimiter }

sql/
  01_create_tables.sql
  02_create_rls.sql

tests/
  unit/
  integration/
  migration/
```

### Format des routes API (Vercel)

```javascript
// api/auth/register.js
export default async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 2. Extraire le body
    const { username, email, password } = req.body;

    // 3. Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 4. Logique métier
    // ...

    // 5. Réponse succès
    return res.status(201).json({
      success: true,
      token: token,
      admin: { id, username, email }
    });

  } catch (error) {
    // 6. Gestion d'erreurs
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
```

### Gestion d'erreurs

```javascript
// Toujours utiliser try/catch
// Logger les erreurs (console.error)
// Retourner des messages génériques à l'utilisateur
// Ne jamais exposer les détails techniques
```

### Sécurité

```javascript
// XSS escaping
function escapeHtml(text) {
  const map = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;'
  };
  return text.replace(/[<>&"']/g, (m) => map[m]);
}

// Validation Cloudinary URL (whitelist)
function isCloudinaryUrl(url) {
  return url.startsWith('https://res.cloudinary.com/');
}

// Rate limiting
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // 5 tentatives
});
```

---

## Communication et feedback

À chaque étape, tu dois :

1. **Confirmer la compréhension** : Résumer ce que tu vas faire
2. **Implémenter** : Coder de manière propre et commentée
3. **Tester** : Valider que ça fonctionne
4. **Documenter** : Expliquer les choix techniques
5. **Demander validation** : Attendre confirmation avant de passer à l'étape suivante

**Format de réponse attendu** :

```
## Étape X : [Nom de l'étape]

### Compréhension
[Ce que j'ai compris et ce que je vais faire]

### Implémentation
[Code créé avec explications]

### Tests
[Résultats des tests]

### Questions/Blocages
[Éventuelles questions ou clarifications nécessaires]

### Prêt pour la suite ?
[Confirmer que l'étape est terminée et demander validation]
```

---

## Instructions finales

1. **Lis d'abord `MULTITENANT_SPEC.md` en entier** pour comprendre l'architecture globale
2. **Commence par l'Étape 1** (Setup Supabase)
3. **Respecte l'ordre des étapes** (chaque étape dépend de la précédente)
4. **Teste après chaque étape** avant de continuer
5. **Demande des clarifications** si quelque chose n'est pas clair
6. **Conserve la qualité** : code propre, sécurisé, performant

**Important** : Tu es sur la branche `multijoueurs` de Git. La version actuelle (mono-admin) est sur la branche `le-monde-tourne-autour-de-riri` et ne doit PAS être modifiée.

---

## Commencer maintenant

Tu es prêt à développer FAF Multi-Tenant. Commence par :

1. Lire `MULTITENANT_SPEC.md` (fichier de référence)
2. Confirmer que tu as bien compris l'architecture globale
3. Débuter l'Étape 1 : Setup Supabase

**Bonne chance ! 🚀**
