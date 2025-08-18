# FAF Production Deployment Guide

Ce guide vous accompagne dans le déploiement et la configuration d'un environnement de production robuste pour l'application FAF (Form-a-Friend).

## 📋 Vue d'ensemble

Cette configuration de production comprend :

- ✅ **Variables d'environnement** sécurisées et validées
- 🔒 **SSL/HTTPS** automatisé avec Let's Encrypt
- 📊 **Monitoring** en temps réel avec dashboard
- 💾 **Backup automatisé** avec chiffrement et stockage cloud
- 🛡️ **Sécurité avancée** avec pare-feu et détection d'intrusion
- 🐳 **Infrastructure Docker** optimisée pour la production
- 🚀 **Scripts de déploiement** automatisés avec rollback

## 🚀 Déploiement rapide

### 1. Préparation de l'environnement

```bash
# Cloner le projet
git clone <repository-url>
cd FAF

# Copier la configuration de production
cp deployment/production/config/.env.production .env

# Éditer les variables d'environnement
nano .env
```

### 2. Configuration des variables d'environnement

Éditez le fichier `.env` avec vos valeurs spécifiques :

```bash
# Domaine et SSL
APP_BASE_URL=https://yourdomain.com
COOKIE_DOMAIN=yourdomain.com
LETSENCRYPT_EMAIL=admin@yourdomain.com

# Base de données MongoDB
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/faf_production

# Sécurité
SESSION_SECRET=$(openssl rand -hex 32)
LOGIN_ADMIN_PASS=$(node -e "console.log(require('bcrypt').hashSync('votre-mot-de-passe', 10))")

# Cloudinary (pour les images)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

### 3. Validation et déploiement

```bash
# Valider la configuration
node deployment/production/config/production-validation.js

# Déployer
sudo deployment/production/scripts/deploy.sh
```

## 📁 Structure des fichiers

```
deployment/production/
├── config/
│   ├── .env.production              # Variables d'environnement
│   ├── production-validation.js     # Validation de configuration
│   ├── ssl-setup.js                # Configuration SSL automatisée
│   └── nginx-production.conf        # Configuration Nginx optimisée
├── monitoring/
│   ├── health-monitor.js            # Monitoring système
│   └── monitoring-dashboard.js      # Dashboard de monitoring
├── backup/
│   ├── backup-system.js             # Système de backup
│   └── backup-cli.js                # Interface en ligne de commande
├── security/
│   ├── firewall-setup.sh            # Configuration pare-feu
│   └── intrusion-detection.js       # Détection d'intrusion
├── docker/
│   ├── docker-compose.production.yml # Configuration Docker Compose
│   └── Dockerfile.production        # Dockerfile optimisé production
└── scripts/
    └── deploy.sh                    # Script de déploiement automatisé
```

## 🔧 Configuration détaillée

### 1. Variables d'environnement

Les variables d'environnement sont organisées en catégories :

#### **Application Core**
- `NODE_ENV=production` : Mode production
- `PORT=3000` : Port d'écoute
- `HTTPS=true` : Force HTTPS
- `APP_BASE_URL` : URL de base de l'application
- `COOKIE_DOMAIN` : Domaine pour les cookies

#### **Base de données**
- `MONGODB_URI` : URI de connexion MongoDB
- Configuration des index et contraintes automatique

#### **Sécurité**
- `SESSION_SECRET` : Clé de chiffrement des sessions (min 32 caractères)
- `LOGIN_ADMIN_USER/PASS` : Identifiants administrateur
- Headers de sécurité automatiques via Helmet.js

#### **Services externes**
- `CLOUDINARY_*` : Configuration service d'images
- `RESEND_API_KEY` : Service d'email (optionnel)
- `AWS_*` : Backup cloud S3 (optionnel)

### 2. Configuration SSL/HTTPS

#### **Let's Encrypt automatique**

```bash
# Configurer Let's Encrypt
export LETSENCRYPT_EMAIL=admin@yourdomain.com
export LETSENCRYPT_DOMAINS=yourdomain.com,www.yourdomain.com

# Lancer la configuration SSL
sudo node deployment/production/config/ssl-setup.js
```

#### **Certificats manuels**

```bash
# Pour des certificats existants
export SSL_CERT_PATH=/etc/ssl/certs/yourdomain.com.crt
export SSL_KEY_PATH=/etc/ssl/private/yourdomain.com.key

sudo node deployment/production/config/ssl-setup.js
```

#### **Fonctionnalités SSL**
- ✅ Configuration moderne TLS 1.2/1.3
- ✅ Headers de sécurité HSTS
- ✅ Redirection HTTP → HTTPS automatique
- ✅ Renouvellement automatique Let's Encrypt
- ✅ Validation et monitoring des certificats

### 3. Monitoring et alertes

#### **Dashboard de monitoring**

```bash
# Démarrer le dashboard de monitoring
node deployment/production/monitoring/monitoring-dashboard.js

# Accès: http://localhost:3001/dashboard
# Identifiants: admin / changeme (à modifier)
```

#### **Métriques surveillées**
- 📊 **Système** : CPU, mémoire, disque, uptime
- 🚀 **Application** : Temps de réponse, taux d'erreur, requêtes
- 🗄️ **Base de données** : Connectivité, temps de réponse
- 🔒 **SSL** : Validité, expiration des certificats
- 🛡️ **Sécurité** : Tentatives d'intrusion, IPs bloquées

#### **Alertes automatiques**
- ⚠️ Utilisation mémoire > 80%
- ⚠️ Temps de réponse > 2s
- 🚨 Taux d'erreur > 5%
- 🚨 Certificat SSL expire < 30 jours
- 🚨 Base de données indisponible

### 4. Système de backup

#### **Configuration backup**

```bash
# Variables d'environnement backup
BACKUP_ENABLED=true
BACKUP_SCHEDULE="0 2 * * *"          # Quotidien à 2h du matin
BACKUP_RETENTION_DAYS=30             # Retention 30 jours
BACKUP_ENCRYPTION_KEY=your-key       # Chiffrement (optionnel)

# Backup cloud S3 (optionnel)
AWS_S3_BUCKET=faf-backups
AWS_REGION=eu-west-1
```

#### **Utilisation du backup**

```bash
# Backup manuel
node deployment/production/backup/backup-cli.js backup

# Lister les backups
node deployment/production/backup/backup-cli.js list

# Restaurer un backup
node deployment/production/backup/backup-cli.js restore backup-2023-12-15T10-30-00

# Statut du système
node deployment/production/backup/backup-cli.js status
```

#### **Contenu des backups**
- ✅ Base de données MongoDB complète
- ✅ Fichiers application et configurations
- ✅ Logs système et application
- ✅ Certificats SSL et configurations Nginx
- ✅ Métadonnées et scripts de restauration

### 5. Sécurité production

#### **Configuration pare-feu**

```bash
# Variables d'environnement sécurité
SSH_PORT=22
TRUSTED_IPS=1.2.3.4,5.6.7.8         # IPs de confiance
ADMIN_IPS=9.10.11.12                 # IPs administrateur

# Configuration pare-feu
sudo deployment/production/security/firewall-setup.sh
```

#### **Règles de sécurité appliquées**
- 🔓 SSH (port 22) avec rate limiting
- 🌐 HTTP/HTTPS (ports 80/443) avec rate limiting
- 🚀 Application (port 3000) selon configuration
- 📊 Monitoring (port 3001) : IPs admin uniquement
- 🚫 MongoDB (port 27017) : bloqué depuis l'extérieur
- 🛡️ Scan ports communs bloqués

#### **Détection d'intrusion**

```bash
# Activer la détection d'intrusion
ENABLE_SECURITY_MONITORING=true
FAILED_LOGIN_THRESHOLD=5
IP_BLOCK_DURATION=3600000            # 1 heure

# Démarrer le système
node deployment/production/security/intrusion-detection.js
```

#### **Patterns détectés**
- 🚨 Injection SQL
- 🚨 Tentatives XSS
- 🚨 Path traversal
- 🚨 Brute force
- 🚨 Outils de scan
- 🚨 Rate limiting

### 6. Déploiement Docker

#### **Configuration Docker Compose**

```bash
# Déploiement avec Docker
cd deployment/production
docker-compose -f docker/docker-compose.production.yml up -d
```

#### **Services inclus**
- 🚀 **faf-app** : Application principale
- 🗄️ **mongodb** : Base de données avec réplication
- 🔗 **redis** : Cache et sessions
- 🌐 **nginx** : Reverse proxy avec SSL
- 🔒 **certbot** : Gestion automatique SSL
- 📊 **monitoring** : Dashboard de monitoring
- 💾 **backup** : Service de backup automatisé
- 📝 **fluentd** : Agrégation de logs (optionnel)

#### **Optimisations production**
- ✅ Images multi-stage optimisées
- ✅ Utilisateur non-root pour sécurité
- ✅ Health checks automatiques
- ✅ Limites de ressources configurées
- ✅ Volumes persistants pour données
- ✅ Réseau isolé entre services
- ✅ Restart automatique des services

## 🚀 Scripts de déploiement

### Déploiement automatisé

```bash
# Déploiement complet avec tous les checks
sudo deployment/production/scripts/deploy.sh

# Options disponibles
sudo deployment/production/scripts/deploy.sh --help

# Déploiement rapide sans tests
sudo deployment/production/scripts/deploy.sh --skip-tests --force

# Rollback vers un déploiement précédent
sudo deployment/production/scripts/deploy.sh --rollback deploy-20231215-143022
```

### Fonctionnalités du script

#### **Pré-déploiement**
- ✅ Validation de l'environnement
- ✅ Backup automatique avant déploiement
- ✅ Exécution des tests (optionnel)
- ✅ Vérification des ressources système

#### **Déploiement**
- ✅ Arrêt gracieux des services actuels
- ✅ Build et démarrage de la nouvelle version
- ✅ Health checks complets
- ✅ Vérification de connectivité base de données

#### **Post-déploiement**
- ✅ Nettoyage des caches application
- ✅ Redémarrage des services de monitoring
- ✅ Notification de déploiement
- ✅ Sauvegarde des métadonnées de déploiement

#### **Rollback automatique**
- ✅ Détection d'échec de déploiement
- ✅ Rollback automatique vers version précédente
- ✅ Restauration depuis backup si disponible
- ✅ Validation post-rollback

## 📊 Monitoring et maintenance

### Dashboard de monitoring

Accédez au dashboard de monitoring à l'adresse :
- **URL** : `https://yourdomain.com:3001/dashboard`
- **Identifiants** : Configurés via `MONITOR_USERNAME/PASSWORD`

### Métriques clés

1. **Santé système**
   - Utilisation CPU et mémoire
   - Espace disque disponible
   - Uptime système

2. **Performance application**
   - Temps de réponse moyen
   - Taux d'erreur
   - Nombre de requêtes

3. **Base de données**
   - Statut de connexion
   - Temps de réponse
   - Connexions actives

4. **Sécurité**
   - Tentatives d'intrusion
   - IPs bloquées
   - Alertes sécurité

### Logs et diagnostics

```bash
# Logs application
tail -f /var/log/faf/app.log

# Logs Nginx
tail -f /var/log/nginx/faf_access.log
tail -f /var/log/nginx/faf_error.log

# Logs système
journalctl -u faf-app -f

# Logs Docker
docker-compose -f deployment/production/docker/docker-compose.production.yml logs -f
```

## 🔧 Maintenance et dépannage

### Commandes utiles

```bash
# Statut des services
systemctl status faf-app
docker-compose -f deployment/production/docker/docker-compose.production.yml ps

# Redémarrage des services
systemctl restart faf-app
docker-compose -f deployment/production/docker/docker-compose.production.yml restart

# Vérification de la configuration
node deployment/production/config/production-validation.js

# Test des backups
node deployment/production/backup/backup-cli.js test

# Statut du pare-feu
sudo ufw status verbose

# Vérification SSL
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com
```

### Problèmes courants

#### **Application ne démarre pas**
1. Vérifier les variables d'environnement
2. Vérifier la connectivité MongoDB
3. Vérifier les permissions de fichiers
4. Consulter les logs d'erreur

#### **Erreurs SSL**
1. Vérifier la validité du certificat
2. Vérifier la configuration Nginx
3. Vérifier les permissions des fichiers SSL
4. Renouveler le certificat si expiré

#### **Performance dégradée**
1. Vérifier l'utilisation des ressources
2. Analyser les logs de performance
3. Vérifier la connectivité base de données
4. Optimiser les requêtes lentes

#### **Problèmes de sécurité**
1. Vérifier les logs d'intrusion
2. Analyser les IPs bloquées
3. Mettre à jour les règles de pare-feu
4. Vérifier les tentatives d'authentification

## 🔄 Procédures de maintenance

### Mise à jour de l'application

```bash
# 1. Backup avant mise à jour
node deployment/production/backup/backup-cli.js backup

# 2. Récupérer la nouvelle version
git pull origin main

# 3. Déployer la nouvelle version
sudo deployment/production/scripts/deploy.sh

# 4. Vérifier le bon fonctionnement
curl -f https://yourdomain.com/health
```

### Mise à jour des certificats SSL

```bash
# Renouvellement automatique Let's Encrypt
sudo certbot renew

# Ou redémarrer la configuration SSL
sudo node deployment/production/config/ssl-setup.js
```

### Nettoyage de maintenance

```bash
# Nettoyage des anciens backups
node deployment/production/backup/backup-cli.js cleanup

# Nettoyage des logs anciens
sudo logrotate -f /etc/logrotate.d/faf

# Nettoyage des images Docker inutilisées
docker system prune -a
```

## 🛡️ Sécurité et conformité

### Bonnes pratiques appliquées

1. **Chiffrement**
   - HTTPS obligatoire avec TLS 1.2+
   - Sessions chiffrées
   - Backups chiffrés

2. **Authentification**
   - Mots de passe hachés avec bcrypt
   - Sessions sécurisées
   - Rate limiting sur les connexions

3. **Autorisation**
   - Accès administrateur protégé
   - Principe du moindre privilège
   - Isolation des services

4. **Monitoring**
   - Logs sécurisés et auditables
   - Détection d'intrusion en temps réel
   - Alertes automatiques

5. **Infrastructure**
   - Pare-feu configuré
   - Services isolés
   - Mise à jour de sécurité automatiques

### Conformité

Cette configuration respecte les standards de sécurité suivants :
- 🔒 **OWASP Top 10** : Protection contre les vulnérabilités web
- 🛡️ **RGPD** : Protection des données utilisateur
- 📋 **ISO 27001** : Bonnes pratiques de sécurité IT
- 🔐 **PCI DSS** : Sécurité des données (si applicable)

## 📞 Support et ressources

### Documentation technique
- [Architecture FAF](../docs/ARCHITECTURE.md)
- [Guide de sécurité](../backend/SECURITY.md)
- [API Reference](../docs/API.md)

### Monitoring et alertes
- Dashboard de monitoring : `https://yourdomain.com:3001/dashboard`
- Logs centralisés : `/var/log/faf/`
- Métriques Prometheus : `http://localhost:9090` (si configuré)

### Support technique
- Issues GitHub : [Repository Issues](https://github.com/your-repo/issues)
- Documentation : [Wiki du projet](https://github.com/your-repo/wiki)
- Communauté : [Discord/Slack channel]

---

## 🎉 Conclusion

Votre environnement de production FAF est maintenant configuré avec :

✅ **Sécurité de niveau entreprise**  
✅ **Monitoring et alertes en temps réel**  
✅ **Backup automatisé et chiffré**  
✅ **SSL/HTTPS avec renouvellement automatique**  
✅ **Infrastructure Docker optimisée**  
✅ **Scripts de déploiement avec rollback**  
✅ **Documentation complète et procédures**  

L'application est prête pour un usage en production avec une haute disponibilité, une sécurité renforcée et un monitoring complet.

Pour toute question ou support technique, consultez la documentation ou ouvrez une issue sur le repository du projet.