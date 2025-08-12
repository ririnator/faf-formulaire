# 📋 Guide Administrateur - FAF (Form-a-Friend)

## 🚀 Vue d'ensemble

FAF est une application de formulaires mensuels permettant aux amis de soumettre des réponses et de consulter celles des autres. En tant qu'administrateur, vous gérez l'ensemble du système et avez accès à des fonctionnalités avancées.

## 🔑 Accès Administrateur

### Connexion
1. Rendez-vous sur `/admin-login`
2. Utilisez vos identifiants administrateur configurés dans les variables d'environnement
3. Vous serez redirigé vers le tableau de bord admin

### Variables d'environnement requises
```bash
LOGIN_ADMIN_USER=votre_nom_admin
LOGIN_ADMIN_PASS=votre_mot_de_passe_admin
FORM_ADMIN_NAME=riri  # Nom utilisé pour les réponses admin
SESSION_SECRET=clé_secrète_session
```

## 🎛️ Fonctionnalités Administrateur

### 1. Tableau de Bord Principal (`/admin`)
- **Vue d'ensemble mensuelle** : Statistiques des réponses du mois en cours
- **Graphiques interactifs** : Visualisation des données sous forme de camemberts et graphiques
- **Gestion rapide** : Accès aux fonctions principales

### 2. Gestion des Réponses (`/admin/gestion`)
- **Liste complète** : Toutes les réponses avec pagination
- **Filtrage par mois** : Navigation entre les différents mois
- **Actions en lot** :
  - Suppression multiple de réponses
  - Export des données
  - Modération du contenu

### 3. Soumission Privilégiée
- Les réponses admin sont **sans token** et accessibles uniquement via l'interface admin
- Contrainte unique : **1 seule réponse admin par mois** (appliquée au niveau base de données)
- Détection automatique basée sur la variable `FORM_ADMIN_NAME`

## 🔒 Sécurité et Sessions

### Système de Sessions Avancé
- **Monitoring en temps réel** : Détection des activités suspectes
- **Blocage automatique** : 5 tentatives de connexion échouées = blocage IP 15 minutes
- **Nettoyage automatique** : Sessions expirées supprimées automatiquement
- **Rétention** : Données utilisateur conservées 90 jours

### Surveillance des Performances
- **Monitoring base de données** : Surveillance des requêtes lentes
- **Alertes intelligentes** : Notifications automatiques en cas de problème
- **Métriques en temps réel** : Performance du système hybride d'authentification

## 📊 Gestion des Données

### Structure des Réponses
```javascript
{
  name: "nom_utilisateur",           // Pour les réponses legacy
  userId: ObjectId,                  // Pour les utilisateurs connectés
  responses: [{
    question: "Question posée",
    answer: "Réponse donnée"
  }],
  month: "YYYY-MM",                  // Format mensuel
  isAdmin: true/false,               // Flag administrateur
  token: "token_unique",             // Null pour admin
  authMethod: "admin"|"user"|"legacy", // Méthode d'authentification
  createdAt: Date
}
```

### Migration des Données Legacy
- **Migration automatique** : Lors de l'inscription utilisateur avec token
- **Association sécurisée** : Linking des anciennes réponses aux nouveaux comptes
- **Logs sécurisés** : Pas d'exposition de données sensibles dans les logs

## 🛠️ Administration Technique

### Commandes de Développement
```bash
# Backend
npm start           # Serveur production
npm run dev         # Serveur développement avec nodemon
npm test            # Tests complets
npm run test:watch  # Tests en mode watch

# Tests spécialisés
npm run test:frontend        # Tests frontend
npm run test:coverage       # Tests avec couverture
npm run test:dynamic        # Tests d'options dynamiques
```

### Monitoring et Logs
- **Logs structurés** : Horodatage et niveaux de criticité
- **Protection données** : Sanitisation automatique des informations sensibles
- **Audit trail** : Traçabilité des actions administrateur
- **Métriques performance** : Monitoring continu de la base de données

### Variables de Configuration Avancées
```bash
# Sécurité
NODE_ENV=production              # Mode production
HTTPS=true                      # Force HTTPS en dev
COOKIE_DOMAIN=.example.com      # Domaine des cookies

# Base de données
MONGODB_URI=mongodb://...       # Connexion MongoDB

# CORS et Frontend
APP_BASE_URL=https://...        # URL base application
FRONTEND_URL=https://...        # URL frontend (optionnel)

# Upload d'images
CLOUDINARY_CLOUD_NAME=...       # Configuration Cloudinary
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...

# Debug et monitoring
DEBUG_STACK_TRACES=true         # Stack traces en dev
ENABLE_DEBUG_LOGS=true          # Logs debug étendus
PERFORMANCE_LOGGING=true        # Logs performance
```

## 🔧 Dépannage Courant

### Problèmes de Session
1. **Sessions expirées** : Vérifier `SESSION_SECRET` et redémarrer le serveur
2. **Cookies non définis** : Contrôler la configuration HTTPS/HTTP
3. **Blocage IP** : Attendre 15 minutes ou redémarrer le service de monitoring

### Problèmes de Base de Données
1. **Contraintes violées** : Une seule réponse admin par mois autorisée
2. **Migration échouée** : Vérifier les logs de migration dans la console
3. **Performance dégradée** : Consulter les métriques de monitoring

### Problèmes d'Upload
1. **Images non affichées** : Vérifier la configuration Cloudinary
2. **Limite de taille** : Maximum 5MB par image
3. **Formats supportés** : JPG, PNG, GIF, WebP

## 📈 Bonnes Pratiques

### Gestion Mensuelle
1. **Début de mois** : Vérifier les statistiques du mois précédent
2. **Modération** : Surveiller le contenu inapproprié
3. **Backup** : S'assurer de la sauvegarde des données importantes

### Sécurité
1. **Mots de passe** : Utiliser des mots de passe forts (bcrypt hashé)
2. **Sessions** : Déconnexion après utilisation
3. **Monitoring** : Surveiller les alertes de sécurité
4. **Logs** : Consulter régulièrement les logs d'audit

### Performance
1. **Cache** : Le système utilise un cache intelligent de 10 minutes
2. **Indexes** : Optimisation automatique des index base de données
3. **Monitoring** : Alertes automatiques si performance dégradée

## 🆘 Support et Contact

En cas de problème technique majeur :
1. Consulter les logs serveur (`console.log` avec horodatage)
2. Vérifier les métriques de monitoring
3. Redémarrer les services si nécessaire
4. Consulter la documentation technique dans `/backend/README.md`

---

*Guide mis à jour pour la version système hybride avec authentification avancée et monitoring en temps réel.*