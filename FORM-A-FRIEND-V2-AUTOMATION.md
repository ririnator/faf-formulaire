# 🚀 Form-a-Friend v2 - Automatisation Complète

## 📋 Instructions d'Utilisation

1. **Copiez-collez** chaque commande une par une dans Claude Code
2. **Attendez** que l'agent termine sa tâche
3. **Validez** le résultat (✅ OK ou ❌ À corriger)
4. **Passez** à la commande suivante seulement après validation
5. **Checkpoints** : Arrêtez-vous aux 🔍 pour vérifier l'état général

---

# 🏗️ PHASE 1 : FONDATIONS DATABASE & ARCHITECTURE (Jours 1-3)

## Jour 1 - Matin : Modèles de Données

### Commande 1 : Création des Modèles
```bash
@faf-database-specialist "Crée les 4 nouveaux modèles MongoDB (Contact, Submission, Invitation, Handshake) avec leurs contraintes unique, indexes optimisés et relations. Utilise les spécifications exactes du DATA-MODELS.md"
```
**✅ Validation** : Vérifiez que 4 fichiers sont créés dans `/backend/models/`

### Commande 2 : Validation Architecture
```bash
@faf-project-supervisor "Valide l'architecture des nouveaux modèles créés, vérifie leur cohérence avec l'existant User et Response, et confirme que les contraintes métier sont bien implémentées"
```
**✅ Validation** : Pas d'erreurs d'architecture signalées

### Commande 3 : Tests Unitaires Modèles
```bash
@faf-test-specialist "Crée tests unitaires complets pour les 4 nouveaux modèles : validation contraintes, relations, méthodes d'instance et indexes"
```
**✅ Validation** : Tests passent avec `npm test`

## 🔍 CHECKPOINT 1 : Modèles Validés
- [ ] 4 modèles créés et fonctionnels
- [ ] Tests passent
- [ ] Architecture validée

---

## Jour 1 - Après-midi : Services Métier (Parallèle)

### Commande 4 : Service Contact Management
```bash
@faf-contact-management-specialist "Implémente ContactService complet avec méthodes addContact, importCSV, getContactsWithStats, updateTracking et gestion handshakes automatiques"
```

### Commande 5 : Service Invitation & Tokens
```bash
@faf-invitation-token-specialist "Crée InvitationService avec génération tokens sécurisés, gestion expiration, codes anti-transfert et méthodes de validation"
```

### Commande 6 : Service Submission
```bash
@faf-backend-architect "Crée SubmissionService qui remplace ResponseService avec contrainte 1-soumission-par-user-par-mois et méthodes de comparaison 1-vs-1"
```

### Commande 7 : Service Handshake
```bash
@faf-contact-management-specialist "Implémente HandshakeService avec méthodes createMutual, accept, decline, checkPermission et gestion expiration"
```

**✅ Validation** : 4 services créés dans `/backend/services/`

## Jour 2 : Intégration Services

### Commande 8 : Validation Services
```bash
@faf-project-supervisor "Valide l'intégration des 4 nouveaux services avec l'architecture existante et vérifie la séparation des responsabilités"
```

### Commande 9 : Tests Services
```bash
@faf-test-specialist "Crée tests d'intégration pour tous les nouveaux services avec scénarios complets et mocks appropriés"
```

### Commande 10 : Enrichissement User Model
```bash
@faf-database-specialist "Enrichit le modèle User existant avec les champs preferences, statistics et migrationData selon DATA-MODELS.md"
```

**✅ Validation** : Tests services passent

## 🔍 CHECKPOINT 2 : Services Opérationnels
- [ ] 4 services créés et testés
- [ ] User model enrichi
- [ ] Intégration validée

---

# 🌐 PHASE 2 : APIs REST & BACKEND (Jours 4-5)

## Jour 4 - Matin : Routes API Principales

### Commande 11 : Routes Contact
```bash
@faf-contact-management-specialist "Crée toutes les routes /api/contacts/* : GET (liste), POST (ajout), POST /import (CSV), PUT /:id (modification), DELETE /:id avec validation et sécurité"
```

### Commande 12 : Routes Invitation
```bash
@faf-invitation-token-specialist "Implémente routes /api/invitations/* et /api/invitations/public/:token pour accès externe avec gestion tokens et validation"
```

### Commande 13 : Routes Submission
```bash
@faf-backend-architect "Crée routes /api/submissions/* : GET /current, POST (création/modification), GET /timeline/:contactId, GET /comparison/:contactId/:month"
```

### Commande 14 : Routes Handshake
```bash
@faf-contact-management-specialist "Implémente routes /api/handshakes/* : GET /received, GET /sent, POST /request, POST /:id/accept, POST /:id/decline"
```

## Jour 4 - Après-midi : Sécurité & Intégration

### Commande 15 : Audit Sécurité APIs
```bash
@faf-security-expert "Audite toutes les nouvelles routes API pour XSS, CSRF, validation input, rate limiting et permissions"
```

### Commande 16 : Intégration Routes
```bash
@faf-backend-architect "Intègre toutes les nouvelles routes dans app.js avec middleware approprié et gestion d'erreurs"
```

### Commande 17 : Tests API Complets
```bash
@faf-test-specialist "Crée tests d'intégration API complets pour tous les endpoints avec cas nominaux, erreurs et sécurité"
```

## 🔍 CHECKPOINT 3 : Backend API Complète
- [ ] Toutes les routes API créées
- [ ] Sécurité validée
- [ ] Tests API passent

---

# 📧 PHASE 3 : EMAIL & AUTOMATISATION (Jours 6-7)

## Jour 6 : Service Email

### Commande 18 : Configuration Email
```bash
@faf-email-service-expert "Configure EmailService avec Resend/Postmark, crée les templates d'invitation responsive et implémente méthodes sendInvitation et sendReminder"
```

### Commande 19 : Templates Email
```bash
@faf-email-service-expert "Crée templates HTML responsive pour : invitation initiale, reminder J+3, reminder J+7, notification handshake avec variables dynamiques"
```

### Commande 20 : Webhooks Email
```bash
@faf-email-service-expert "Implémente gestion webhooks pour bounces, unsubscribes avec mise à jour automatique des statuts Contact"
```

## Jour 7 : Automatisation Scheduler

### Commande 21 : Jobs Cron
```bash
@faf-scheduler-automation "Implémente SchedulerService avec job mensuel (5e jour 18h Paris), jobs reminders J+3/J+7, et cleanup automatique"
```

### Commande 22 : Intégration Email+Scheduler
```bash
@faf-scheduler-automation "Intègre SchedulerService avec EmailService et ContactService pour cycle mensuel complet automatisé"
```

### Commande 23 : Monitoring Automation
```bash
@faf-scheduler-automation "Ajoute monitoring temps réel, logs détaillés et alertes pour tous les jobs automatisés"
```

## 🔍 CHECKPOINT 4 : Automatisation Opérationnelle
- [ ] Service email configuré et testé
- [ ] Jobs cron opérationnels
- [ ] Cycle mensuel automatisé

---

# 🎨 PHASE 4 : FRONTEND MOBILE-FIRST (Jours 8-10)

## Jour 8 : Dashboard Universel

### Commande 24 : Dashboard Base
```bash
@faf-user-dashboard-specialist "Transforme admin.html en dashboard universel accessible à tous les users avec adaptation contenu par rôle (user/admin)"
```

### Commande 25 : Interface Contact Management
```bash
@faf-user-dashboard-specialist "Crée interface gestion contacts avec grid responsive, filtres par statut/tags, stats visuelles et actions touch-optimisées"
```

### Commande 26 : Centre Notifications
```bash
@faf-user-dashboard-specialist "Implémente centre notifications handshake temps réel avec actions accept/decline et badges de comptage"
```

## Jour 9 : Vues Comparaison & Timeline

### Commande 27 : Vue 1-vs-1
```bash
@faf-user-dashboard-specialist "Crée compare.html avec vue côte-à-côte, navigation mensuelle, et intégration permissions handshake"
```

### Commande 28 : Timeline Contact
```bash
@faf-user-dashboard-specialist "Implémente timeline chronologique par contact avec indicateurs visuels soumissions et stats engagement"
```

### Commande 29 : Mobile & Photo Features
```bash
@faf-frontend-dev "Ajoute compression photos client, lightbox responsive avec zoom/pan, et optimisations mobile-first"
```

## Jour 10 : Intégration Frontend

### Commande 30 : Tests Frontend
```bash
@faf-test-specialist "Crée tests frontend complets : interactions dashboard, compression photos, lightbox, navigation mobile"
```

### Commande 31 : Validation UX
```bash
@faf-project-supervisor "Valide expérience utilisateur complète, cohérence interface et performance mobile"
```

## 🔍 CHECKPOINT 5 : Interface Fonctionnelle
- [ ] Dashboard universel opérationnel
- [ ] Vues 1-vs-1 et timeline fonctionnelles
- [ ] Mobile-first validé

---

# 🔄 PHASE 5 : MIGRATION & DÉPLOIEMENT (Jours 11-15)

## Jour 11-12 : Préparation Migration

### Commande 32 : Scripts Migration
```bash
@faf-migration-specialist "Crée script migration complète Response→Submission avec génération Users automatique, préservation tokens legacy et validation intégrité"
```

### Commande 33 : Rollback Procedures
```bash
@faf-migration-specialist "Implémente rollback automatique complet avec backup/restore et vérifications état système"
```

### Commande 34 : Optimisation Migration
```bash
@faf-database-specialist "Optimise performances migration pour gros volumes avec batch processing et monitoring progrès"
```

## Jour 13 : Tests Migration

### Commande 35 : Tests Migration Staging
```bash
@faf-test-specialist "Tests complets migration en environnement staging avec validation données et fonctionnalités"
```

### Commande 36 : Validation Migration
```bash
@faf-migration-specialist "Valide intégrité post-migration : comptages, relations, tokens legacy et fonctionnalités"
```

## Jour 14-15 : Déploiement Production

### Commande 37 : Configuration Production
```bash
@faf-deployment-specialist "Configure environnement production : variables, SSL, monitoring, backup et sécurité"
```

### Commande 38 : Migration Production
```bash
@faf-migration-specialist "Exécute migration production avec supervision temps réel et procédures rollback prêtes"
```

### Commande 39 : Tests Production
```bash
@faf-test-specialist "Tests post-déploiement complets : fonctionnalités, performances, sécurité et intégrations"
```

### Commande 40 : Validation Finale
```bash
@faf-project-supervisor "Validation finale système complet : architecture, sécurité, performances et expérience utilisateur"
```

## 🔍 CHECKPOINT FINAL : Production Ready
- [ ] Migration réussie sans perte de données
- [ ] Toutes les fonctionnalités opérationnelles
- [ ] Performances et sécurité validées
- [ ] Form-a-Friend v2 en production ! 🚀

---

# 📊 Résumé de l'Automatisation

**Total** : 40 commandes chronologiques
**Durée estimée** : 10-12 jours avec validation
**Parallélisation** : Optimisée par phase
**Sécurité** : Validation continue intégrée

## 🎯 Utilisation Optimale

1. **Une commande à la fois** - Ne pas précipiter
2. **Validation systématique** - Chaque étape confirmée
3. **Checkpoints obligatoires** - Points d'arrêt pour bilan
4. **Rollback préparé** - Sécurité maximale

**Votre travail** : Copier-coller et valider ✅
**Travail des agents** : Implémentation experte 🤖

---

*Automatisation Form-a-Friend v2 - Prêt pour l'exécution !*