# Configuration Centralisée des Services

Ce document décrit la configuration centralisée pour les nouveaux services de Form-a-Friend et leurs variables d'environnement.

## Vue d'ensemble

La configuration centralisée permet de gérer tous les paramètres des services depuis un seul endroit, avec des valeurs par défaut appropriées et la possibilité de personnaliser via des variables d'environnement.

## Variables d'environnement

### Services Configuration

#### ContactService
Variables pour la gestion des contacts et l'import CSV :

- `CONTACT_MAX_CSV_SIZE` (optionnel, défaut: 5242880 - 5MB)
  - Taille maximale des fichiers CSV d'import en octets
  
- `CONTACT_MAX_BATCH_SIZE` (optionnel, défaut: 100)
  - Nombre de contacts traités simultanément lors de l'import
  
- `CONTACT_MAX_TAGS` (optionnel, défaut: 10)
  - Nombre maximum de tags par contact

**Valeurs fixes dans la configuration :**
- `maxNameLength`: 100 caractères
- `maxEmailLength`: 320 caractères  
- `maxNotesLength`: 1000 caractères
- `maxTagLength`: 50 caractères

#### InvitationService
Variables pour la sécurité des invitations et tokens :

- `INVITATION_TOKEN_LENGTH` (optionnel, défaut: 32)
  - Longueur des tokens d'invitation en octets (256 bits de sécurité)
  
- `INVITATION_EXPIRATION_DAYS` (optionnel, défaut: 60)
  - Durée de validité des invitations en jours
  
- `INVITATION_MAX_IP_CHANGES` (optionnel, défaut: 3)
  - Nombre maximum de changements d'IP autorisés par invitation

**Valeurs fixes dans la configuration :**
- `shortCodeLength`: 8 caractères
- `antiTransferWindowHours`: 24 heures
- `rateLimitAttempts`: 5 tentatives par heure

#### SubmissionService
Variables pour la validation des soumissions :

- `SUBMISSION_MAX_TEXT_RESPONSES` (optionnel, défaut: 8)
  - Nombre maximum de réponses textuelles par soumission
  
- `SUBMISSION_MAX_PHOTO_RESPONSES` (optionnel, défaut: 5)
  - Nombre maximum de réponses photos par soumission
  
- `SUBMISSION_MIN_COMPLETION_RATE` (optionnel, défaut: 50)
  - Taux de complétion minimum requis en pourcentage

**Valeurs fixes dans la configuration :**
- `maxQuestionTextLength`: 500 caractères
- `maxAnswerTextLength`: 10000 caractères
- `maxPhotoCaptionLength`: 500 caractères
- `maxFreeTextLength`: 5000 caractères

#### HandshakeService
Variables pour la gestion des handshakes entre utilisateurs :

- `HANDSHAKE_EXPIRATION_DAYS` (optionnel, défaut: 30)
  - Durée de validité des handshakes en jours
  
- `HANDSHAKE_MAX_PENDING` (optionnel, défaut: 50)
  - Nombre maximum de handshakes en attente par utilisateur
  
- `HANDSHAKE_CLEANUP_INTERVAL_HOURS` (optionnel, défaut: 6)
  - Intervalle de nettoyage automatique des handshakes expirés

**Valeurs fixes dans la configuration :**
- `maxMessageLength`: 500 caractères
- `notificationBeforeExpiryDays`: 3 jours

## Structure de la configuration

### Environment.js
Le fichier `/backend/config/environment.js` centralise toute la configuration :

```javascript
services: {
  contact: {
    maxCsvSize: parseInt(process.env.CONTACT_MAX_CSV_SIZE) || (5 * 1024 * 1024),
    maxBatchSize: parseInt(process.env.CONTACT_MAX_BATCH_SIZE) || 100,
    maxTags: parseInt(process.env.CONTACT_MAX_TAGS) || 10,
    // ... autres valeurs fixes
  },
  invitation: {
    tokenLength: parseInt(process.env.INVITATION_TOKEN_LENGTH) || 32,
    expirationDays: parseInt(process.env.INVITATION_EXPIRATION_DAYS) || 60,
    // ... autres valeurs
  },
  // ... autres services
}
```

### ServiceFactory
Le `ServiceFactory` injecte la configuration dans chaque service :

```javascript
getContactService() {
  if (!this._services.has('contact')) {
    const service = new ContactService(this.config.services.contact);
    this._services.set('contact', service);
  }
  return this._services.get('contact');
}
```

### Services
Chaque service reçoit sa configuration via le constructeur :

```javascript
class ContactService {
  constructor(config = {}) {
    this.config = {
      maxCsvSize: config.maxCsvSize || (5 * 1024 * 1024),
      maxBatchSize: config.maxBatchSize || 100,
      // ... autres paramètres avec valeurs par défaut
    };
  }
}
```

## Avantages

1. **Centralisation** : Toute la configuration dans un seul endroit
2. **Flexibilité** : Variables d'environnement pour personnalisation
3. **Valeurs par défaut** : Fonctionnement out-of-the-box
4. **Type safety** : Conversion automatique des types (parseInt)
5. **Maintenabilité** : Modification facile des limites et paramètres

## Exemple de fichier .env

```bash
# Configuration des services (optionnel)
CONTACT_MAX_CSV_SIZE=10485760
CONTACT_MAX_BATCH_SIZE=50
CONTACT_MAX_TAGS=15

INVITATION_TOKEN_LENGTH=64
INVITATION_EXPIRATION_DAYS=90
INVITATION_MAX_IP_CHANGES=5

SUBMISSION_MAX_TEXT_RESPONSES=10
SUBMISSION_MAX_PHOTO_RESPONSES=8
SUBMISSION_MIN_COMPLETION_RATE=60

HANDSHAKE_EXPIRATION_DAYS=45
HANDSHAKE_MAX_PENDING=75
HANDSHAKE_CLEANUP_INTERVAL_HOURS=12
```

## Migration

Cette configuration centralisée remplace les constantes hardcodées qui étaient présentes dans chaque service. Les valeurs par défaut restent identiques pour assurer la compatibilité.

## Tests

Les tests doivent être mis à jour pour utiliser des configurations de test appropriées :

```javascript
const testConfig = {
  maxCsvSize: 1024, // Plus petit pour les tests
  maxBatchSize: 10,
  // ...
};

const contactService = new ContactService(testConfig);
```