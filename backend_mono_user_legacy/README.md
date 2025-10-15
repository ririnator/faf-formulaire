# Backend Mono-User Legacy (Archive)

**⚠️ CETTE VERSION N'EST PLUS UTILISÉE ⚠️**

Ce dossier contient l'ancien code du système mono-utilisateur (version initiale de FAF avant la migration multi-tenant).

## Contexte

- **Période** : Développement initial jusqu'au 13 octobre 2025
- **Architecture** : Express.js + MongoDB + Sessions
- **Limitations** : Un seul admin (configuré via variables d'environnement)

## Structure

```
backend/
├── app.js              # Serveur Express principal
├── routes/
│   ├── adminRoutes.js  # Routes admin (sessions)
│   ├── responseRoutes.js
│   └── upload.js
├── middleware/         # Middleware Express (auth sessions, validation)
├── models/            # Modèles MongoDB/Mongoose
├── config/            # Configuration (DB, CORS, sessions)
└── tests/             # Tests de la version mono-user
```

## Différences avec la version multi-tenant actuelle

| Aspect | Mono-User (legacy) | Multi-Tenant (actuel) |
|--------|-------------------|----------------------|
| **Architecture** | Express.js monolithe | Vercel Serverless Functions |
| **Base de données** | MongoDB | Supabase (PostgreSQL) |
| **Authentification** | Sessions (cookies) | JWT (localStorage) |
| **Admins** | 1 seul (hardcodé .env) | Illimité (table `admins`) |
| **Routes** | `/admin/...` | `/api/admin/...` |
| **Déploiement** | Serveur Node.js | Vercel Edge Functions |

## Pourquoi archivé ?

Le système a été migré vers une architecture multi-tenant pour permettre :
- ✅ Plusieurs administrateurs indépendants
- ✅ Isolation des données par admin (RLS)
- ✅ Architecture serverless scalable
- ✅ Authentification JWT moderne
- ✅ Base de données PostgreSQL avec Supabase

## Utilité de cette archive

Cette archive est conservée pour :
1. **Référence** : Comprendre les décisions de design initiales
2. **Migration** : Comparer l'ancien et le nouveau code
3. **Récupération** : Accès au code de l'ancien dashboard (`frontend/admin/admin.html` utilisait certaines routes ici)
4. **Historique** : Documentation de l'évolution du projet

## ⚠️ NE PAS UTILISER EN PRODUCTION

Ce code n'est **plus maintenu** et ne doit **PAS** être déployé. Utilisez uniquement le code multi-tenant dans le dossier racine du projet.

---

**Date d'archivage** : 14 octobre 2025
**Version archivée** : Mono-User v1.0 (pré-migration)
**Version actuelle** : Multi-Tenant v2.0 (Étapes 1-9)
