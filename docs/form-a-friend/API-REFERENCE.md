# Form-a-Friend - Référence API

## 📋 Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Authentification](#authentification)
3. [Contacts](#contacts)
4. [Soumissions](#soumissions)
5. [Invitations](#invitations)
6. [Handshakes](#handshakes)
7. [Utilisateurs](#utilisateurs)
8. [Admin](#admin)
9. [Codes d'erreur](#codes-derreur)

---

## 🌐 Vue d'ensemble

### Base URL
- **Développement** : `http://localhost:3000`
- **Production** : `https://form-a-friend.com`

### Format des Réponses
Toutes les réponses suivent le format JSON standard :

```json
{
  "success": true,
  "data": { ... },
  "message": "Opération réussie",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Codes de Statut HTTP
- **200** : Succès
- **201** : Créé avec succès
- **400** : Requête invalide
- **401** : Non authentifié
- **403** : Accès refusé
- **404** : Non trouvé
- **409** : Conflit (duplicate)
- **429** : Trop de requêtes
- **500** : Erreur serveur

---

## 🔐 Authentification

### POST /api/auth/login
Connexion utilisateur

**Body :**
```json
{
  "email": "user@example.com",
  "password": "motdepasse123"
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "60f7b1234567890abcdef123",
      "username": "johndoe",
      "email": "user@example.com",
      "role": "user"
    },
    "sessionId": "sess_abc123"
  }
}
```

### POST /api/auth/register
Inscription nouvel utilisateur

**Body :**
```json
{
  "username": "johndoe",
  "email": "user@example.com",
  "password": "motdepasse123",
  "firstName": "John",
  "lastName": "Doe"
}
```

### POST /api/auth/logout
Déconnexion

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "message": "Déconnexion réussie"
}
```

### GET /api/auth/me
Profil utilisateur connecté

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "60f7b1234567890abcdef123",
    "username": "johndoe",
    "email": "user@example.com",
    "displayName": "johndoe",
    "role": "user",
    "preferences": {
      "sendTime": "18:00",
      "timezone": "Europe/Paris"
    }
  }
}
```

---

## 👥 Contacts

### GET /api/contacts
Liste des contacts de l'utilisateur

**Headers :** `Cookie: faf.session=...`

**Query Parameters :**
- `status` (optionnel) : `active|pending|opted_out|bounced|blocked`
- `tag` (optionnel) : Filtrer par tag
- `limit` (optionnel) : Nombre max de résultats (défaut: 50)
- `offset` (optionnel) : Pagination (défaut: 0)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "contacts": [
      {
        "id": "60f7b1234567890abcdef456",
        "email": "alice@example.com",
        "firstName": "Alice",
        "lastName": "Martin",
        "status": "active",
        "contactUserId": "60f7b1234567890abcdef789",
        "handshakeId": "60f7b1234567890abcdef101",
        "tags": ["amis", "paris"],
        "tracking": {
          "addedAt": "2025-01-01T10:00:00Z",
          "lastSentAt": "2025-01-05T18:00:00Z",
          "lastSubmittedAt": "2025-01-07T14:30:00Z",
          "responseRate": 85,
          "responseCount": 3
        }
      }
    ],
    "stats": {
      "total": 25,
      "active": 20,
      "responseRate": 76
    },
    "pagination": {
      "limit": 50,
      "offset": 0,
      "total": 25
    }
  }
}
```

### POST /api/contacts
Ajouter un nouveau contact

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "email": "bob@example.com",
  "firstName": "Bob",
  "lastName": "Dupont",
  "tags": ["travail", "collègue"]
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "contact": { ... },
    "isNew": true,
    "handshakeSent": false,
    "message": "Contact ajouté avec succès"
  }
}
```

### POST /api/contacts/import
Import CSV de contacts

**Headers :** `Cookie: faf.session=...`

**Body :** `multipart/form-data`
- `csv` : Fichier CSV (colonnes : email, firstName, lastName, tags)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "imported": [
      { "email": "user1@example.com", "firstName": "User1" }
    ],
    "duplicates": [
      { "email": "existing@example.com", "reason": "Déjà existant" }
    ],
    "errors": [
      { "row": 3, "error": "Email invalide" }
    ],
    "stats": {
      "total": 100,
      "imported": 85,
      "duplicates": 10,
      "errors": 5
    }
  }
}
```

### PUT /api/contacts/:id
Modifier un contact

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "firstName": "Robert",
  "tags": ["famille", "frère"],
  "notes": "Mon frère aîné"
}
```

### DELETE /api/contacts/:id
Supprimer un contact

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "message": "Contact supprimé"
}
```

---

## 📝 Soumissions

### GET /api/submissions/current
Ma soumission du mois en cours

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "submission": {
      "id": "60f7b1234567890abcdef999",
      "userId": "60f7b1234567890abcdef123",
      "month": "2025-01",
      "responses": [
        {
          "questionId": "q1",
          "type": "radio",
          "answer": "ça va"
        },
        {
          "questionId": "q3",
          "type": "photo",
          "photoUrl": "https://res.cloudinary.com/faf/image/upload/v1/photo.jpg",
          "photoCaption": "Ma photo du mois"
        }
      ],
      "freeText": "Ce mois-ci j'ai découvert...",
      "completionRate": 90,
      "isComplete": true,
      "submittedAt": "2025-01-07T14:30:00Z"
    },
    "formVersion": "v1"
  }
}
```

### POST /api/submissions
Créer/modifier ma soumission

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "responses": [
    {
      "questionId": "q1",
      "type": "radio",
      "answer": "ça va"
    },
    {
      "questionId": "q2",
      "type": "text",
      "answer": "Ce mois-ci j'ai bien travaillé sur mes projets"
    }
  ],
  "freeText": "Vivement les vacances !",
  "isDraft": false
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "submission": { ... },
    "isNew": false,
    "completionRate": 85
  }
}
```

### GET /api/submissions/timeline/:contactId
Timeline des soumissions avec un contact

**Headers :** `Cookie: faf.session=...`

**Query Parameters :**
- `limit` (optionnel) : Nombre de mois (défaut: 12)
- `before` (optionnel) : Avant ce mois (YYYY-MM)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "timeline": [
      {
        "month": "2025-01",
        "mySubmission": { ... },
        "contactSubmission": { ... },
        "bothSubmitted": true
      },
      {
        "month": "2024-12",
        "mySubmission": { ... },
        "contactSubmission": null,
        "bothSubmitted": false
      }
    ],
    "contact": {
      "id": "60f7b1234567890abcdef456",
      "firstName": "Alice",
      "email": "alice@example.com"
    },
    "stats": {
      "totalMonths": 6,
      "responseRate": 83
    }
  }
}
```

### GET /api/submissions/comparison/:contactId/:month
Vue 1-vs-1 pour un mois

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "month": "2025-01",
    "viewer": {
      "submission": { ... },
      "user": {
        "id": "60f7b1234567890abcdef123",
        "firstName": "John"
      }
    },
    "contact": {
      "submission": { ... },
      "user": {
        "id": "60f7b1234567890abcdef456",
        "firstName": "Alice"
      }
    },
    "canView": true,
    "handshakeStatus": "accepted"
  }
}
```

### GET /api/submissions/received/:month
Toutes les soumissions reçues ce mois

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "month": "2025-01",
    "submissions": [
      {
        "contact": {
          "id": "60f7b1234567890abcdef456",
          "firstName": "Alice",
          "email": "alice@example.com"
        },
        "submission": { ... },
        "submittedAt": "2025-01-07T14:30:00Z"
      }
    ],
    "stats": {
      "total": 15,
      "responseRate": 75
    }
  }
}
```

---

## 📧 Invitations

### GET /api/invitations
Mes invitations envoyées

**Headers :** `Cookie: faf.session=...`

**Query Parameters :**
- `month` (optionnel) : Mois spécifique (YYYY-MM)
- `status` (optionnel) : `queued|sent|opened|submitted|expired`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "invitations": [
      {
        "id": "60f7b1234567890abcdef200",
        "toEmail": "alice@example.com",
        "toUserId": "60f7b1234567890abcdef456",
        "month": "2025-01",
        "token": "abc123def456",
        "type": "user",
        "status": "submitted",
        "tracking": {
          "sentAt": "2025-01-05T18:00:00Z",
          "openedAt": "2025-01-06T09:15:00Z",
          "submittedAt": "2025-01-07T14:30:00Z"
        },
        "reminders": []
      }
    ],
    "stats": {
      "total": 25,
      "sent": 25,
      "opened": 20,
      "submitted": 15,
      "responseRate": 60
    }
  }
}
```

### POST /api/invitations/manual
Envoyer invitation manuelle

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "contactId": "60f7b1234567890abcdef456",
  "customMessage": "Salut ! J'aimerais avoir tes nouvelles ce mois-ci"
}
```

### POST /api/invitations/remind/:id
Envoyer rappel manuel

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "message": "Rappel envoyé"
}
```

### GET /api/invitations/public/:token
Accès public via token (sans auth)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "invitation": {
      "fromUser": {
        "firstName": "John",
        "email": "john@example.com"
      },
      "month": "2025-01",
      "status": "opened",
      "expiresAt": "2025-03-07T18:00:00Z"
    },
    "formQuestions": [ ... ],
    "comparison": {
      "fromSubmission": { ... },
      "allowSubmission": true
    }
  }
}
```

### POST /api/invitations/public/:token/submit
Soumettre via token public

**Body :**
```json
{
  "responses": [ ... ],
  "freeText": "Merci pour l'invitation !"
}
```

---

## 🤝 Handshakes

### GET /api/handshakes/received
Demandes de handshake reçues

**Headers :** `Cookie: faf.session=...`

**Réponse :**
```json
{
  "success": true,
  "data": {
    "handshakes": [
      {
        "id": "60f7b1234567890abcdef300",
        "requester": {
          "id": "60f7b1234567890abcdef789",
          "username": "alice_m",
          "firstName": "Alice",
          "email": "alice@example.com"
        },
        "status": "pending",
        "requestedAt": "2025-01-10T15:30:00Z",
        "message": "Salut ! On pourrait échanger nos réponses ?",
        "expiresAt": "2025-02-09T15:30:00Z"
      }
    ]
  }
}
```

### GET /api/handshakes/sent
Demandes de handshake envoyées

**Headers :** `Cookie: faf.session=...`

### POST /api/handshakes/request
Demander un handshake

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "targetUserId": "60f7b1234567890abcdef789",
  "message": "Salut Alice ! Ça te dit d'échanger nos réponses mensuelles ?"
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "handshake": {
      "id": "60f7b1234567890abcdef300",
      "status": "pending",
      "requestedAt": "2025-01-15T10:30:00Z"
    }
  }
}
```

### POST /api/handshakes/:id/accept
Accepter un handshake

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "responseMessage": "Avec plaisir ! Hâte de voir tes réponses"
}
```

### POST /api/handshakes/:id/decline
Refuser un handshake

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "responseMessage": "Merci mais je préfère garder mes réponses privées"
}
```

---

## 👤 Utilisateurs

### GET /api/users/search
Rechercher des utilisateurs

**Headers :** `Cookie: faf.session=...`

**Query Parameters :**
- `q` : Terme de recherche (email ou username)
- `limit` (optionnel) : Max résultats (défaut: 10)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "60f7b1234567890abcdef789",
        "username": "alice_m",
        "email": "alice@example.com",
        "displayName": "alice_m",
        "role": "user",
        "isContact": true,
        "handshakeStatus": "accepted"
      }
    ]
  }
}
```

### PUT /api/users/preferences
Modifier mes préférences

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "sendTime": "19:00",
  "timezone": "Europe/London",
  "sendDay": 1,
  "reminderSettings": {
    "firstReminder": true,
    "secondReminder": false
  },
  "emailTemplate": "fun"
}
```

### PUT /api/users/profile
Modifier mon profil

**Headers :** `Cookie: faf.session=...`

**Body :**
```json
{
  "firstName": "Jean",
  "lastName": "Dupont",
  "profession": "Développeur",
  "location": "Paris, France"
}
```

---

## 👑 Admin

### GET /api/admin/stats
Statistiques générales (admin seulement)

**Headers :** `Cookie: faf.session=...` (role: admin)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "users": {
      "total": 1250,
      "active": 1100,
      "newThisMonth": 45
    },
    "submissions": {
      "thisMonth": 850,
      "lastMonth": 920,
      "averageCompletionRate": 87
    },
    "invitations": {
      "sent": 25000,
      "opened": 18500,
      "submitted": 15300,
      "responseRate": 61
    },
    "handshakes": {
      "pending": 120,
      "accepted": 2300,
      "acceptanceRate": 78
    }
  }
}
```

### GET /api/admin/users
Liste des utilisateurs (admin)

**Headers :** `Cookie: faf.session=...` (role: admin)

**Query Parameters :**
- `role` : `user|admin`
- `status` : `active|inactive`
- `limit`, `offset` : Pagination

### GET /api/admin/sessions
Sessions actives (admin)

**Headers :** `Cookie: faf.session=...` (role: admin)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "sess_abc123",
        "userId": "60f7b1234567890abcdef123",
        "ipAddress": "192.168.xxx.xxx",
        "userAgent": "Mozilla/5.0...",
        "lastActive": "2025-01-15T10:25:00Z",
        "isActive": true
      }
    ],
    "stats": {
      "total": 245,
      "active": 89,
      "suspicious": 0,
      "blocked": 3
    }
  }
}
```

### POST /api/admin/sessions/cleanup
Nettoyage manuel des sessions

**Headers :** `Cookie: faf.session=...` (role: admin)

### GET /api/admin/monitoring
Métriques de performance

**Headers :** `Cookie: faf.session=...` (role: admin)

---

## ❌ Codes d'erreur

### Erreurs d'Authentification (401)
```json
{
  "success": false,
  "error": "UNAUTHORIZED",
  "message": "Session expirée ou invalide",
  "code": 401
}
```

### Erreurs de Validation (400)
```json
{
  "success": false,
  "error": "VALIDATION_ERROR",
  "message": "Données invalides",
  "details": [
    {
      "field": "email",
      "message": "Format d'email invalide"
    },
    {
      "field": "password",
      "message": "Le mot de passe doit contenir au moins 6 caractères"
    }
  ],
  "code": 400
}
```

### Erreurs de Conflit (409)
```json
{
  "success": false,
  "error": "DUPLICATE_ERROR",
  "message": "Ce contact existe déjà",
  "code": 409
}
```

### Erreurs de Permission (403)
```json
{
  "success": false,
  "error": "FORBIDDEN",
  "message": "Handshake requis pour accéder à cette ressource",
  "code": 403
}
```

### Erreurs de Rate Limiting (429)
```json
{
  "success": false,
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Trop de requêtes. Réessayez dans 15 minutes.",
  "retryAfter": 900,
  "code": 429
}
```

### Erreurs Serveur (500)
```json
{
  "success": false,
  "error": "INTERNAL_ERROR",
  "message": "Une erreur interne s'est produite",
  "requestId": "req_abc123def456",
  "code": 500
}
```

---

## 📚 Exemples d'Usage

### Flux complet d'ajout de contact
```javascript
// 1. Connexion
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'john@example.com',
    password: 'password123'
  })
});

// 2. Ajout contact
const contactResponse = await fetch('/api/contacts', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'alice@example.com',
    firstName: 'Alice',
    tags: ['amis']
  })
});

// 3. Si handshake proposé, l'autre user peut l'accepter
const handshakeResponse = await fetch('/api/handshakes/123/accept', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    responseMessage: 'Avec plaisir !'
  })
});
```

### Soumission de formulaire
```javascript
const submission = await fetch('/api/submissions', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    responses: [
      { questionId: 'q1', type: 'radio', answer: 'ça va' },
      { questionId: 'q2', type: 'text', answer: 'Ce mois-ci...' }
    ],
    freeText: 'Hâte de voir vos réponses !',
    isDraft: false
  })
});
```

---

*API Reference Form-a-Friend v1.0 - Documentation complète des endpoints*