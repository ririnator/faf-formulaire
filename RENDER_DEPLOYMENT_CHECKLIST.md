# Checklist de Déploiement FAF sur Render.com

## Préparation (Avant le déploiement)

### Configuration des Prérequis
- [ ] Compte GitHub avec accès au repository FAF
- [ ] Compte Render.com créé et vérifié
- [ ] Compte MongoDB Atlas créé
- [ ] Compte Cloudinary créé (pour uploads d'images)

### Génération des Secrets
- [ ] Exécuter `node scripts/render-deploy-setup.js` pour générer les secrets
- [ ] Noter le SESSION_SECRET généré (64 caractères)
- [ ] Préparer un mot de passe admin sécurisé
- [ ] Valider tous les prérequis système

### Configuration MongoDB Atlas
- [ ] Créer un cluster MongoDB Atlas
  - [ ] Nom : `faf-production`
  - [ ] Région : Même que Render (Frankfurt pour Europe)
  - [ ] Tier : M0 (gratuit) ou supérieur selon besoins
- [ ] Configurer l'accès réseau
  - [ ] IP Whitelist : `0.0.0.0/0` (Render utilise des IPs dynamiques)
- [ ] Créer un utilisateur de base de données
  - [ ] Username : `fafuser` (ou autre)
  - [ ] Mot de passe fort généré
  - [ ] Rôles : `readWrite` sur `faf-production`
- [ ] Récupérer la string de connexion MongoDB
- [ ] Tester la connexion depuis votre machine locale

### Configuration Cloudinary
- [ ] Créer un compte Cloudinary
- [ ] Noter les informations de configuration :
  - [ ] `CLOUDINARY_CLOUD_NAME`
  - [ ] `CLOUDINARY_API_KEY`
  - [ ] `CLOUDINARY_API_SECRET`
- [ ] Tester l'upload depuis l'interface Cloudinary

## Déploiement sur Render

### Création du Service Web
- [ ] Se connecter à Render.com
- [ ] Cliquer "New +" → "Web Service"
- [ ] Connecter le repository GitHub FAF
- [ ] Configuration du service :
  - [ ] **Name**: `faf-production`
  - [ ] **Runtime**: `Node`
  - [ ] **Region**: `Frankfurt` (Europe) ou `Oregon` (US)
  - [ ] **Branch**: `main`
  - [ ] **Root Directory**: `backend`
  - [ ] **Build Command**: `npm ci --only=production`
  - [ ] **Start Command**: `npm start`

### Configuration des Variables d'Environnement
Copier les variables du fichier `render-env-template.txt` généré :

#### Variables Obligatoires
- [ ] `NODE_ENV` = `production`
- [ ] `PORT` = `10000`
- [ ] `HTTPS` = `true`
- [ ] `MONGODB_URI` = (string de connexion MongoDB Atlas)
- [ ] `SESSION_SECRET` = (clé de 64 caractères générée)
- [ ] `LOGIN_ADMIN_USER` = `admin`
- [ ] `LOGIN_ADMIN_PASS` = (mot de passe admin sécurisé)
- [ ] `FORM_ADMIN_NAME` = `riri`
- [ ] `APP_BASE_URL` = `https://votre-app.onrender.com`
- [ ] `FRONTEND_URL` = `https://votre-app.onrender.com`
- [ ] `CLOUDINARY_CLOUD_NAME` = (depuis Cloudinary)
- [ ] `CLOUDINARY_API_KEY` = (depuis Cloudinary)
- [ ] `CLOUDINARY_API_SECRET` = (depuis Cloudinary)

#### Variables Optionnelles Recommandées
- [ ] `COOKIE_DOMAIN` = `.votre-domaine.com` (si domaine personnalisé)
- [ ] `RESEND_API_KEY` = (si service email configuré)
- [ ] `EMAIL_FROM_ADDRESS` = `noreply@votre-domaine.com`
- [ ] `ENABLE_EMAIL_MONITORING` = `true`
- [ ] `SCHEDULER_TIMEZONE` = `Europe/Paris`

### Lancement du Déploiement
- [ ] Cliquer "Create Web Service"
- [ ] Attendre la completion du build (5-10 minutes)
- [ ] Vérifier les logs de build pour les erreurs
- [ ] Vérifier que le service démarre sans erreurs

## Validation Post-Déploiement

### Tests Automatiques
- [ ] Exécuter le script de validation :
  ```bash
  node scripts/render-post-deploy-validation.js https://votre-app.onrender.com
  ```
- [ ] Tous les tests doivent passer (taux de réussite 100%)

### Tests Manuels Critiques

#### Test 1: Health Check
- [ ] Ouvrir `https://votre-app.onrender.com/health`
- [ ] Vérifier la réponse JSON : `{"status":"healthy",...}`

#### Test 2: Page d'Accueil
- [ ] Ouvrir `https://votre-app.onrender.com/`
- [ ] Page se charge correctement
- [ ] Design et contenu présents

#### Test 3: Formulaire Public
- [ ] Ouvrir `https://votre-app.onrender.com/form`
- [ ] Formulaire s'affiche correctement
- [ ] Champs de saisie présents et fonctionnels

#### Test 4: Authentification Admin
- [ ] Aller sur `https://votre-app.onrender.com/admin-login`
- [ ] Se connecter avec `LOGIN_ADMIN_USER` / `LOGIN_ADMIN_PASS`
- [ ] Redirection vers dashboard admin réussie

#### Test 5: Dashboard Admin
- [ ] Dashboard admin s'affiche
- [ ] Navigation fonctionnelle
- [ ] Données se chargent (réponses, statistiques)

#### Test 6: Upload d'Images
- [ ] Dans le dashboard admin, tester l'upload d'une image
- [ ] Image s'upload sur Cloudinary
- [ ] Image s'affiche correctement dans l'interface

### Vérification de la Sécurité

#### Headers de Sécurité
- [ ] Utiliser les DevTools pour vérifier les headers :
  - [ ] `X-Frame-Options`
  - [ ] `X-Content-Type-Options`
  - [ ] `Content-Security-Policy`
  - [ ] `Strict-Transport-Security` (pour HTTPS)

#### Cookies Sécurisés
- [ ] Dans DevTools > Application > Cookies
- [ ] Vérifier que les cookies ont :
  - [ ] `Secure` = true
  - [ ] `SameSite` = None
  - [ ] `HttpOnly` = true

#### Endpoints de Debug
- [ ] Vérifier que `/api/debug/health` retourne 404 (désactivé en production)
- [ ] Vérifier que les endpoints de développement ne sont pas accessibles

### Tests de Performance

#### Temps de Réponse
- [ ] Page d'accueil < 2 secondes
- [ ] Formulaire < 2 secondes
- [ ] Dashboard admin < 3 secondes
- [ ] Health check < 500ms

#### Fonctionnalité Base de Données
- [ ] Connexion MongoDB établie (vérifier logs)
- [ ] Index créés automatiquement
- [ ] Soumission de formulaire fonctionne
- [ ] Récupération des données fonctionne

## Configuration Post-Déploiement

### Domaine Personnalisé (Optionnel)
- [ ] Dans Render Dashboard > Settings > Custom Domains
- [ ] Ajouter votre domaine
- [ ] Configurer les enregistrements DNS
- [ ] Vérifier le certificat SSL automatique
- [ ] Mettre à jour `APP_BASE_URL` avec le nouveau domaine

### Monitoring et Alertes
- [ ] Configurer les notifications Render :
  - [ ] Deploy success/failure notifications
  - [ ] Service health notifications
- [ ] Configurer les alertes par email
- [ ] Tester les notifications

### Backup et Sécurité
- [ ] Vérifier les backups automatiques MongoDB Atlas
- [ ] Configurer la rétention des backups
- [ ] Documenter les procédures de restauration

## Tests Utilisateurs Finaux

### Scénario Utilisateur Standard
- [ ] Utilisateur visite la page d'accueil
- [ ] Utilisateur accède au formulaire
- [ ] Utilisateur remplit et soumet le formulaire
- [ ] Soumission réussie avec message de confirmation
- [ ] Token de consultation privée généré

### Scénario Admin
- [ ] Admin se connecte au dashboard
- [ ] Admin consulte les réponses soumises
- [ ] Admin peut voir les statistiques
- [ ] Admin peut gérer les réponses
- [ ] Admin peut uploader des images

### Test de Charge Léger
- [ ] Plusieurs utilisateurs simultanés (5-10)
- [ ] Performance reste acceptable
- [ ] Pas d'erreurs de base de données
- [ ] Sessions gérées correctement

## Procédures d'Urgence

### Rollback Rapide
- [ ] Documentation de la procédure de rollback Render
- [ ] Accès aux versions précédentes dans le dashboard
- [ ] Procédure de rollback base de données documentée

### Contacts d'Urgence
- [ ] Support Render.com contacté si nécessaire
- [ ] Documentation d'escalade préparée
- [ ] Procédures de maintenance d'urgence définies

## Documentation Finale

### Documentation Technique
- [ ] Variables d'environnement documentées
- [ ] Procédures de déploiement enregistrées
- [ ] Architecture de production documentée
- [ ] Contacts et accès documentés

### Formation Équipe
- [ ] Équipe formée sur l'accès Render
- [ ] Procédures de monitoring enseignées
- [ ] Procédures d'urgence communiquées

---

## Validation Finale

- [ ] **Tous les tests automatiques passent (100%)**
- [ ] **Tous les tests manuels validés**
- [ ] **Performance dans les seuils acceptables**
- [ ] **Sécurité validée et conforme**
- [ ] **Monitoring opérationnel**
- [ ] **Documentation complète**

**Date de déploiement validé :** _______________

**Responsable validation :** _______________

**Signature :** _______________

---

*Cette checklist garantit un déploiement sécurisé et robuste de l'application FAF sur Render.com. Chaque point doit être validé avant la mise en production.*