# Configuration Session - Environnements Dev vs Production

## Vue d'ensemble

FAF implémente une configuration de session adaptative qui s'ajuste automatiquement selon l'environnement, garantissant la sécurité en production tout en maintenant la compatibilité en développement.

## Configuration Automatique par Environnement

### 🔧 **Développement** (`NODE_ENV=development` ou non défini)

```javascript
cookie: {
  maxAge: 1000 * 60 * 60,    // 1 heure
  httpOnly: true,            // ✅ Protection XSS
  sameSite: 'lax',          // ✅ Compatible HTTP localhost
  secure: false,            // ✅ Fonctionne sans HTTPS
  name: 'faf-session'       // ✅ Nom personnalisé
}
```

**Avantages développement :**
- ✅ **HTTP compatible** - Fonctionne sur `http://localhost:3000`
- ✅ **Cross-tab sharing** - Sessions partagées entre onglets
- ✅ **Hot reload friendly** - Survit aux redémarrages du serveur
- ✅ **Debugging facilité** - Cookies visibles dans DevTools

### 🚀 **Production** (`NODE_ENV=production`)

```javascript
cookie: {
  maxAge: 1000 * 60 * 60,    // 1 heure  
  httpOnly: true,            // ✅ Protection XSS
  sameSite: 'none',         // ✅ Cross-origin HTTPS
  secure: true,             // ✅ HTTPS obligatoire
  domain: '.example.com',   // ✅ Multi-domaine (si configuré)
  path: '/',               // ✅ Application-wide
  name: 'faf-session'      // ✅ Nom personnalisé
}
```

**Avantages production :**
- 🔒 **HTTPS obligatoire** - Cookies uniquement sur connexions sécurisées
- 🌐 **Cross-origin support** - Compatible avec CDN/proxies
- 🛡️ **XSS Protection** - HttpOnly empêche l'accès JavaScript
- 🔐 **Domain scoping** - Limitation aux domaines autorisés

## Variables d'Environnement

### **Variables Principales**
```bash
# Environnement principal (détermine le comportement général)
NODE_ENV=production              # ou development

# Override HTTPS en développement (optionnel)
HTTPS=true                      # Force cookies secure même en dev

# Configuration domaine production (optionnel)
COOKIE_DOMAIN=.votre-domaine.com # Scope multi-sous-domaines
```

### **Variables MongoDB Session Store**
```bash
MONGODB_URI=mongodb://localhost:27017/faf  # Dev
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/faf  # Prod

SESSION_SECRET=your-super-secret-key-here
```

## Logique de Détection Avancée

### **Algorithme de Configuration**
```javascript
function getSessionConfig() {
  const isProduction = process.env.NODE_ENV === 'production';
  const isHttpsExplicit = process.env.HTTPS === 'true';
  
  return {
    sameSite: isProduction ? 'none' : 'lax',
    secure: isHttpsExplicit || isProduction,
    httpOnly: true,  // Toujours activé pour la sécurité
    maxAge: 1000 * 60 * 60  // 1 heure dans tous les cas
  };
}
```

### **Cas d'Usage Spéciaux**

#### **HTTPS en Développement**
```bash
# Pour tester les cookies production en local
NODE_ENV=development
HTTPS=true
# Résultat: sameSite='lax' + secure=true
```

#### **Staging Environment**
```bash
# Environnement de test avec production settings
NODE_ENV=production
COOKIE_DOMAIN=.staging.example.com
# Résultat: Comportement production avec domaine staging
```

## Comportements par Plateforme

### **🏠 Développement Local**
| Aspect | Configuration | Justification |
|--------|---------------|---------------|
| **Protocol** | HTTP accepté | `secure: false` permet localhost |
| **CORS** | Same-origin OK | `sameSite: 'lax'` autorise navigation |
| **Domain** | localhost/127.0.0.1 | Pas de restriction domain |
| **DevTools** | Cookies visibles | Debugging facilité |

### **☁️ Render/Heroku Production**
| Aspect | Configuration | Justification |
|--------|---------------|---------------|
| **Protocol** | HTTPS obligatoire | `secure: true` + reverse proxy |
| **CORS** | Cross-origin strict | `sameSite: 'none'` pour CDN |
| **Domain** | `.render.com` scope | `domain` configuré si multi-apps |
| **Security** | Headers maximum | Helmet + CSP renforcés |

### **🔧 Docker/Kubernetes**
```bash
# docker-compose.yml
environment:
  NODE_ENV: production
  HTTPS: "true"
  COOKIE_DOMAIN: ".k8s.cluster.local"
  SESSION_SECRET: "${SESSION_SECRET}"
```

## Debugging et Troubleshooting

### **🐛 Problèmes Courants**

#### **1. Session perdue après refresh (Dev)**
```bash
# Symptôme: Déconnexion automatique après F5
# Cause: secure=true en HTTP
# Solution:
NODE_ENV=development  # Assure secure=false
# OU
unset HTTPS          # Retire override HTTPS
```

#### **2. Cookies rejetés en production**
```bash
# Symptôme: Login ne fonctionne pas sur HTTPS
# Cause: sameSite='lax' + cross-origin
# Solution:
NODE_ENV=production  # Assure sameSite='none' + secure=true
```

#### **3. Session non partagée entre sous-domaines**
```bash
# Symptôme: Login sur app.example.com ne marche pas sur api.example.com
# Solution:
COOKIE_DOMAIN=.example.com  # Scope élargi
```

### **🔍 Tests de Configuration**

#### **Vérification Environnement**
```javascript
// Test unitaire pour vérifier config
const { getEnvironmentInfo } = require('./middleware/security');

console.log('Environment Info:', {
  ...getEnvironmentInfo(),
  sessionConfig: createSessionOptions().cookie
});
```

#### **Test Production Simulé**
```bash
# Tester comportement production en local
NODE_ENV=production HTTPS=true npm run dev
```

### **📊 Monitoring des Sessions**

#### **Métriques MongoDB Store**
```javascript
// Vérifier sessions actives
db.sessions.find().count()           // Nombre total
db.sessions.find({expires: {$gt: new Date()}}).count()  // Sessions valides
```

#### **Logs de Debugging**
```javascript
// En mode développement seulement
if (process.env.NODE_ENV !== 'production') {
  console.log('Session Config:', {
    sameSite: cookie.sameSite,
    secure: cookie.secure,
    domain: cookie.domain || 'not-set'
  });
}
```

## Sécurité et Bonnes Pratiques

### **✅ Recommandations**

#### **Développement**
- ✅ Utiliser `NODE_ENV=development` explicitement
- ✅ Tester occasionnellement avec `HTTPS=true`
- ✅ Monitorer la durée des sessions (1h max)
- ✅ Vérifier que `httpOnly` est toujours activé

#### **Production**
- ✅ Toujours définir `NODE_ENV=production`
- ✅ Configurer `COOKIE_DOMAIN` si multi-domaines
- ✅ Utiliser des secrets de session robustes (32+ chars)
- ✅ Monitorer les expirations de sessions MongoDB

### **❌ À Éviter**

#### **Configuration Dangereuse**
```bash
# ❌ DANGEREUX: Session sans protection
httpOnly: false     # Vulnérable XSS
secure: false       # En production HTTPS
sameSite: 'none'    # En HTTP (sera rejeté)
```

#### **Secrets Faibles**
```bash
# ❌ DANGEREUX: Secrets prévisibles
SESSION_SECRET=secret123
SESSION_SECRET=password
# ✅ SÉCURISÉ: Entropie élevée
SESSION_SECRET=7x9$kL2p9NqR8zF3vB6mC4sE1wQ5yT0aG
```

## Migration et Mise à Jour

### **Passage Dev → Production**
1. **Variables d'environnement**
   ```bash
   NODE_ENV=production
   SESSION_SECRET=<nouveau-secret-robuste>
   MONGODB_URI=<mongodb-production>
   ```

2. **Vérification cookies**
   - DevTools → Application → Cookies
   - Vérifier `secure: true`, `sameSite: none`

3. **Tests fonctionnels**
   - Login/logout fonctionne
   - Sessions persistent entre pages
   - Expiration après 1 heure

### **Rollback d'Urgence**
```bash
# Retour rapide aux paramètres dev
NODE_ENV=development
unset HTTPS
unset COOKIE_DOMAIN
# Redémarrer application
```

Cette configuration garantit **sécurité maximale en production** et **expérience développeur optimale** ! 🔒✨