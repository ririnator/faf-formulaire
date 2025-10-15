# Étape 4 : API Soumission de formulaire - TERMINÉE ✅

**Date** : 14 octobre 2025

## Résumé

L'Étape 4 est complète. L'API `/api/response/submit` permet maintenant de soumettre des réponses au formulaire d'un admin avec isolation complète par `owner_id`, rate limiting, et validation stricte.

---

## Fichiers créés

### 1. `/utils/tokens.js`
**Description** : Génération de tokens sécurisés pour les liens privés

**Fonctions exportées** :
- `generateToken()` - Génère un token de 64 caractères hexadécimaux
- `generateShortToken(length)` - Génère un token court
- `isValidToken(token)` - Valide le format d'un token

**Caractéristiques** :
- Utilise `crypto.randomBytes()` pour sécurité cryptographique
- Tokens de 64 caractères (32 bytes → hex)
- Format validé par regex

---

### 2. `/utils/validation.js` (enrichi)
**Description** : Validation et sécurité des entrées utilisateur

**Nouvelles fonctions ajoutées** :
- `isCloudinaryUrl(url)` - Valide les URLs Cloudinary (whitelist)
- `cleanResponse(text)` - Échappe HTML sauf URLs Cloudinary
- `validateResponses(responses)` - Valide et nettoie un tableau de réponses
- `validateName(name)` - Valide un nom (2-100 caractères)
- `validateHoneypot(honeypot)` - Valide le champ anti-spam

**Sécurité** :
- Échappe `<`, `>`, `&`, `"`, `'` → HTML entities
- Whitelist stricte pour Cloudinary : `https://res.cloudinary.com/{cloud}/image/upload/...`
- Détection patterns XSS : `<script>`, `javascript:`, `on\w+=`, `<iframe>`, etc.
- Validation longueurs : Questions ≤500 chars, Réponses ≤10k chars, 10-11 réponses

---

### 3. `/middleware/rateLimit.js`
**Description** : Middleware de rate limiting par IP

**Configuration** :
- **Fenêtre** : 15 minutes par défaut
- **Max requêtes** : 3 par défaut
- **Stockage** : En mémoire (Map)
- **Nettoyage** : Automatique toutes les 5 minutes

**Headers ajoutés** :
- `X-RateLimit-Limit` - Nombre max de requêtes
- `X-RateLimit-Remaining` - Requêtes restantes
- `X-RateLimit-Reset` - Timestamp de reset
- `Retry-After` - Secondes avant retry (si limite dépassée)

**Extraction IP** :
- Supporte `x-forwarded-for` (Vercel)
- Supporte `x-real-ip`
- Fallback `remoteAddress`

**Réponse 429** :
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "message": "Vous avez soumis trop de formulaires. Réessayez dans 15 minutes.",
  "retryAfter": 897
}
```

---

### 4. `/api/response/submit.js`
**Description** : Route principale de soumission de formulaire

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "name": "Emma",
  "responses": [
    { "question": "Q1", "answer": "A1" },
    { "question": "Q2", "answer": "A2" }
    // ... 10-11 réponses
  ],
  "website": ""
}
```

**Traitement** :
1. Vérifier méthode HTTP (POST uniquement)
2. Appliquer rate limiting (3 / 15 min)
3. Validation honeypot (champ `website` doit être vide)
4. Validation champs requis (username, name, responses)
5. Validation nom (2-100 chars)
6. Validation réponses (10-11, longueurs, structure)
7. Lookup admin par username (case-insensitive)
8. Déterminer `is_owner` : `name.toLowerCase() === admin.username.toLowerCase()`
9. Générer mois actuel (YYYY-MM)
10. Si is_owner, vérifier qu'il n'a pas déjà répondu ce mois
11. Générer token (64 chars) seulement si `is_owner = false`
12. Insérer dans Supabase avec `owner_id`
13. Retourner lien privé (si token généré)

**Réponse succès (201)** :

**Pour un ami** :
```json
{
  "success": true,
  "message": "Réponse enregistrée avec succès !",
  "userName": "Emma",
  "adminName": "Sophie",
  "link": "https://faf.app/view/abc123..."
}
```

**Pour l'admin** :
```json
{
  "success": true,
  "message": "Réponse enregistrée avec succès !",
  "userName": "Sophie",
  "adminName": "Sophie"
}
```

**Codes d'erreur** :
- `405` - Méthode HTTP non autorisée
- `400` - Validation échouée (honeypot, champs manquants, format invalide)
- `404` - Admin introuvable
- `409` - Admin a déjà soumis ce mois-ci
- `429` - Rate limit dépassé
- `500` - Erreur serveur

**Isolation des données** :
- Chaque réponse est liée à `owner_id` (UUID de l'admin)
- RLS Supabase filtre automatiquement
- Impossible de voir les réponses d'un autre admin

---

### 5. `/tests/api/submit.test.js`
**Description** : Tests complets de l'API de soumission

**Tests (13 au total)** :

#### Tests de validation basique
1. ✅ Retourne 405 pour méthodes non-POST
2. ✅ Rejette spam (honeypot rempli)
3. ✅ Retourne 400 si champs requis manquants
4. ✅ Retourne 400 pour nom invalide (<2 ou >100 chars)
5. ✅ Retourne 400 pour nombre de réponses invalide (<10 ou >11)
6. ✅ Retourne 404 si admin introuvable

#### Tests de soumission
7. ✅ Accepte soumission ami et génère token + lien
8. ✅ Accepte soumission admin sans token
9. ✅ Échappe XSS dans les réponses
10. ✅ Préserve URLs Cloudinary

#### Tests de sécurité
11. ✅ Rate limiting fonctionne (3 max, 4ème = 429)
12. ✅ Empêche admin de soumettre 2x dans même mois
13. ✅ Ajoute headers de rate limiting

**Résultat** : **13/13 tests ✅**

---

## Structure finale

```
FAF/
├── api/
│   ├── form/
│   │   └── [username].js       # Étape 3
│   ├── auth/
│   │   ├── register.js         # Étape 2
│   │   ├── login.js            # Étape 2
│   │   └── verify.js           # Étape 2
│   └── response/
│       └── submit.js           # ✅ Étape 4
│
├── config/
│   └── supabase.js             # Étape 3
│
├── middleware/
│   └── rateLimit.js            # ✅ Étape 4
│
├── utils/
│   ├── jwt.js                  # Étape 2
│   ├── questions.js            # Étape 3
│   ├── tokens.js               # ✅ Étape 4
│   └── validation.js           # Étape 2 + ✅ Étape 4
│
└── tests/
    ├── supabase-connection.test.js  # Étape 1
    ├── auth.test.js                 # Étape 2
    └── api/
        ├── form.test.js             # Étape 3
        └── submit.test.js           # ✅ Étape 4
```

---

## Validation

### ✅ Checklist de l'étape 4

- [x] Route `/api/response/submit` créée et fonctionnelle
- [x] Module `utils/tokens.js` avec génération sécurisée
- [x] Module `utils/validation.js` enrichi (XSS, Cloudinary, honeypot)
- [x] Middleware `middleware/rateLimit.js` avec tracking IP
- [x] Tests complets (13 tests passent)
- [x] Soumission ami génère token + lien ✅
- [x] Soumission admin ne génère pas de token ✅
- [x] XSS échappé correctement ✅
- [x] URLs Cloudinary préservées ✅
- [x] Rate limiting bloque après 3 soumissions ✅
- [x] Honeypot rejette les bots ✅
- [x] Admin ne peut pas soumettre 2x/mois ✅

### Tests de scénarios

**Scénario 1 : Ami soumet le formulaire**
```
POST /api/response/submit
{
  "username": "sophie",
  "name": "Emma",
  "responses": [10 réponses],
  "website": ""
}

→ 201 Created
→ Token généré (64 chars)
→ Lien : https://faf.app/view/{token}
→ Données stockées avec owner_id = sophie_uuid, is_owner = false
```

**Scénario 2 : Admin soumet son propre formulaire**
```
POST /api/response/submit
{
  "username": "sophie",
  "name": "Sophie",
  "responses": [10 réponses],
  "website": ""
}

→ 201 Created
→ Pas de token
→ Pas de lien
→ Données stockées avec owner_id = sophie_uuid, is_owner = true
```

**Scénario 3 : Tentative XSS**
```
POST /api/response/submit
{
  "username": "sophie",
  "name": "Hacker",
  "responses": [
    { "question": "Q1", "answer": "<script>alert('XSS')</script>" }
  ],
  "website": ""
}

→ 201 Created (accepté mais échappé)
→ Stocké : "&lt;script&gt;alert('XSS')&lt;/script&gt;"
→ Sécurisé contre XSS ✅
```

**Scénario 4 : URL Cloudinary**
```
POST /api/response/submit
{
  "username": "sophie",
  "name": "Emma",
  "responses": [
    { "question": "Photo", "answer": "https://res.cloudinary.com/.../photo.jpg" }
  ],
  "website": ""
}

→ 201 Created
→ URL préservée intacte (pas échappée)
→ URL valide dans la DB ✅
```

**Scénario 5 : Rate limiting**
```
IP: 127.0.0.1

Requête 1 → 201 Created (X-RateLimit-Remaining: 2)
Requête 2 → 201 Created (X-RateLimit-Remaining: 1)
Requête 3 → 201 Created (X-RateLimit-Remaining: 0)
Requête 4 → 429 Too Many Requests (Retry-After: 897s)
```

**Scénario 6 : Bot spam (honeypot)**
```
POST /api/response/submit
{
  "username": "sophie",
  "name": "Bot",
  "responses": [10 réponses],
  "website": "http://spam.com"  ← Honeypot rempli
}

→ 400 Bad Request
→ Message : "Votre soumission a été détectée comme spam"
```

**Scénario 7 : Admin soumet 2x dans le mois**
```
Soumission 1 (1er octobre) → 201 Created
Soumission 2 (15 octobre, même mois) → 409 Conflict
Message : "Vous avez déjà rempli votre formulaire ce mois-ci"
```

---

## Sécurité

### Protection XSS multi-couches
1. **Validation input** - Rejection patterns suspects
2. **Escaping HTML** - Conversion `<>&"'` → entities
3. **Whitelist Cloudinary** - Préservation URLs valides uniquement
4. **Content Security Policy** - Headers CSP (étapes futures)

### Protection spam/abus
1. **Honeypot** - Champ caché `website` doit rester vide
2. **Rate limiting** - 3 soumissions max / 15 min par IP
3. **Validation stricte** - Longueurs, formats, structure

### Isolation des données
1. **owner_id** - Chaque réponse liée à un admin spécifique
2. **RLS Supabase** - Filtrage automatique au niveau DB
3. **Token unique** - 64 chars cryptographiques (2^256 possibilités)

---

## Performance

### Temps d'exécution des tests
- **Total** : ~4 secondes
- **Tests API** : ~3.8s (avec insertions Supabase)
- **Tests rapides** : <5ms (validation pure)

### Optimisations
- Rate limiter en mémoire (pas de DB lookup)
- Nettoyage automatique du cache rate limiting
- Validation early-return (fail fast)

---

## Intégration avec l'architecture existante

### Étapes précédentes
- ✅ **Étape 1** : Setup Supabase & Base de données (13 tests ✅)
- ✅ **Étape 2** : API d'authentification (18 tests ✅)
- ✅ **Étape 3** : API Formulaire dynamique (15 tests ✅)
- ✅ **Étape 4** : API Soumission de formulaire (13 tests ✅)

### Total cumulé

```
╔════════════════════════════════════════════════╗
║  ÉTAPE 1:  13 tests ✅                         ║
║  ÉTAPE 2:  18 tests ✅                         ║
║  ÉTAPE 3:  15 tests ✅                         ║
║  ÉTAPE 4:  13 tests ✅                         ║
║  ─────────────────────────────────────────     ║
║  TOTAL:    59 tests ✅                         ║
╚════════════════════════════════════════════════╝
```

### Prochaine étape
- 🔄 **Étape 5** : API Consultation privée (`/api/response/view/[token]`)

---

## Flux complet d'utilisation

### 1. Admin crée son compte
```
POST /api/auth/register
→ JWT token généré
```

### 2. Admin remplit son formulaire
```
GET /api/form/sophie  → Questions du formulaire
POST /api/response/submit
  - username: "sophie"
  - name: "Sophie"
  - responses: [10 réponses]
→ is_owner: true, token: null
```

### 3. Admin partage son lien
```
Envoie "https://faf.app/form/sophie" à ses amis
```

### 4. Ami remplit le formulaire
```
GET /api/form/sophie  → Questions du formulaire
POST /api/response/submit
  - username: "sophie"
  - name: "Emma"
  - responses: [10 réponses]
→ is_owner: false, token: "abc123..."
→ Lien privé: https://faf.app/view/abc123...
```

### 5. Ami consulte sa comparaison (Étape 5, à venir)
```
GET /api/response/view/abc123...
→ Comparaison "Emma vs Sophie" (côte à côte)
```

### 6. Admin consulte toutes les réponses (Étape 6, à venir)
```
GET /api/admin/dashboard (avec JWT)
→ Liste de toutes les réponses de ses amis
→ Stats, graphiques, filtres par mois
```

---

## Points techniques importants

### 1. Détermination is_owner
```javascript
const isOwner = cleanName.toLowerCase() === admin.username.toLowerCase();
```
- Comparaison case-insensitive
- L'admin peut écrire "Sophie", "sophie", "SOPHIE" → détecté comme owner

### 2. Génération du token
```javascript
const token = isOwner ? null : generateToken();
```
- Admin : `token = null` (pas de lien privé)
- Ami : `token = "abc123..."` (64 chars)

### 3. Mois actuel
```javascript
const month = new Date().toISOString().slice(0, 7); // "2025-10"
```
- Format : YYYY-MM
- Utilisé pour contrainte unique admin/mois

### 4. Contrainte unique admin/mois
```sql
CREATE UNIQUE INDEX idx_owner_month_unique
ON responses(owner_id, month)
WHERE is_owner = true;
```
- Empêche l'admin de soumettre 2x dans le même mois
- Contrainte au niveau DB (sécurisé)

### 5. Rate limiting par IP
- Stockage en mémoire (Map)
- Clé : IP (x-forwarded-for ou x-real-ip)
- Valeur : { count, resetTime }
- Nettoyage automatique toutes les 5 minutes

---

## Conclusion

✅ **L'Étape 4 est complète et validée**

Tous les tests passent (13/13), la route API est sécurisée, et l'isolation des données fonctionne parfaitement.

La route `/api/response/submit` :
- ✅ Valide et nettoie toutes les entrées
- ✅ Protège contre XSS, spam, rate limiting
- ✅ Détecte automatiquement si c'est l'admin
- ✅ Génère des tokens sécurisés
- ✅ Isole les données par owner_id
- ✅ Empêche les doublons admin/mois
- ✅ Est testée exhaustivement

**Total tests cumulés** : 59/59 tests ✅
- Étape 1 : 13 tests
- Étape 2 : 18 tests
- Étape 3 : 15 tests
- Étape 4 : 13 tests

**Prêt pour l'Étape 5 : API Consultation privée ! 🚀**
