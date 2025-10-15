# Frontend Legacy (Mono-User)

**⚠️ FICHIERS ARCHIVÉS - NE PAS UTILISER ⚠️**

Ce dossier contient les fichiers frontend de l'ancienne version mono-utilisateur qui ont été retirés du code multi-tenant.

## Fichiers archivés

### HTML
- `index.html` - Ancien formulaire principal (remplacé par `/frontend/public/form/index.html`)
- `login.html` - Ancien login avec sessions (remplacé par `/frontend/public/auth/login.html`)

### CSS
- `styles.css` - Styles basiques du formulaire mono-user
- `admin.css` - Styles admin pour l'ancien dashboard

## Pourquoi archivés ?

Ces fichiers utilisaient l'architecture mono-user :
- Sessions backend (cookies `connect.sid`)
- Route `/login` avec authentification serveur
- Un seul formulaire à la racine `/`
- Pas de système multi-tenant

## Remplacements dans la version multi-tenant

| Ancien (legacy) | Nouveau (multi-tenant) | Changement |
|----------------|------------------------|------------|
| `/index.html` | `/form/{username}` | Formulaire dynamique par admin |
| `/login` (POST) | `/api/auth/login` (JWT) | Authentification JWT |
| Session cookies | JWT localStorage | Auth stateless |
| 1 formulaire | N formulaires | Multi-tenant |

---

**Date d'archivage** : 14 octobre 2025
**Raison** : Migration vers architecture multi-tenant serverless
