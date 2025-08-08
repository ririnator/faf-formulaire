# 🐳 Guide Docker pour FAF (Form-a-Friend)

Ce guide explique comment utiliser Docker pour développer, tester et déployer l'application FAF.

## 📋 Prérequis

- Docker >= 20.10
- Docker Compose >= 2.0
- 4GB RAM disponible minimum
- 5GB espace disque libre

## 🚀 Démarrage Rapide

### 1. Configuration Initiale

```bash
# Cloner le projet
git clone <votre-repo>
cd FAF

# Copier et configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos valeurs

# Construire et démarrer
docker-compose up -d
```

### 2. Vérification

```bash
# Vérifier que les services sont démarrés
docker-compose ps

# Consulter les logs
docker-compose logs -f faf-app

# Tester l'application
curl http://localhost:3000/health
```

## 🛠️ Développement

### Mode Développement

```bash
# Démarrer en mode développement (avec hot-reload)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Rebuild après changement de dépendances
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Exécuter les tests
docker-compose exec faf-app npm test
```

### Commandes Utiles

```bash
# Shell dans le conteneur
docker-compose exec faf-app sh

# Voir les logs en temps réel
docker-compose logs -f

# Restart un service
docker-compose restart faf-app

# Rebuild un service
docker-compose up --build faf-app
```

## 🧪 Tests

### Exécution des Tests

```bash
# Tests backend
docker-compose exec faf-app npm test

# Tests avec couverture
docker-compose exec faf-app npm run test:coverage

# Tests frontend
docker-compose exec faf-app npm run test:frontend

# Tous les tests
docker-compose exec faf-app npm run test:all
```

### Service de Test Automatique

```bash
# Démarrer le service de test en mode watch
docker-compose --profile testing up faf-tests
```

## 🗃️ Base de Données

### Accès MongoDB

```bash
# Shell MongoDB
docker-compose exec mongodb mongosh

# Backup
docker-compose exec mongodb mongodump --out /data/backup

# Import de données
docker-compose exec -T mongodb mongorestore < backup.archive
```

### Gestion des Données

```bash
# Vider la base (développement uniquement)
docker-compose exec mongodb mongosh --eval "db.dropDatabase()"

# Voir les volumes
docker volume ls | grep faf

# Supprimer les volumes (ATTENTION: perte de données)
docker-compose down -v
```

## 🚀 Production

### Déploiement Simple

```bash
# Variables d'environnement production
cp .env.example .env.production
# Configurer .env.production

# Démarrer en production
docker-compose --env-file .env.production up -d
```

### Déploiement avec Nginx

```bash
# Avec reverse proxy Nginx
docker-compose --profile production up -d

# Certificats SSL (remplacer par vos certificats)
mkdir -p docker/ssl
cp your-fullchain.pem docker/ssl/fullchain.pem
cp your-private-key.pem docker/ssl/privkey.pem
```

### Surveillance

```bash
# Statut des services
docker-compose ps

# Utilisation des ressources
docker stats

# Healthcheck
docker-compose exec faf-app wget -qO- http://localhost:3000/health
```

## 📊 Monitoring et Logs

### Consultation des Logs

```bash
# Logs de l'application
docker-compose logs faf-app

# Logs MongoDB
docker-compose logs mongodb

# Logs en temps réel
docker-compose logs -f --tail=100

# Logs dans un fichier
docker-compose logs > faf-logs.txt
```

### Métriques de Performance

```bash
# Utilisation des ressources
docker stats faf-application faf-mongodb

# Espace disque des volumes
docker system df

# Nettoyage (prudence)
docker system prune
```

## 🔧 Maintenance

### Mises à Jour

```bash
# Rebuild après changements
docker-compose up --build

# Mise à jour des images de base
docker-compose pull
docker-compose up -d

# Mise à jour complète
docker-compose down
docker-compose pull
docker-compose up --build -d
```

### Backup

```bash
# Backup MongoDB
docker-compose exec mongodb mongodump --archive=/data/backup/faf-$(date +%Y%m%d).archive

# Backup des volumes
docker run --rm -v faf-mongodb-data:/data -v $(pwd):/backup alpine tar czf /backup/mongodb-data-$(date +%Y%m%d).tar.gz /data
```

### Nettoyage

```bash
# Arrêter tous les services
docker-compose down

# Supprimer les images inutilisées
docker image prune

# Nettoyage complet (ATTENTION)
docker system prune -a --volumes
```

## 🐛 Dépannage

### Problèmes Fréquents

#### Port déjà utilisé
```bash
# Trouver le processus qui utilise le port 3000
lsof -i :3000

# Changer le port dans docker-compose.yml
ports:
  - "3001:3000"  # Port externe différent
```

#### Problème de permissions
```bash
# Reconstruire avec permissions correctes
docker-compose build --no-cache faf-app
```

#### MongoDB ne démarre pas
```bash
# Vérifier les logs
docker-compose logs mongodb

# Réinitialiser MongoDB (perte de données)
docker-compose down
docker volume rm faf-mongodb-data faf-mongodb-config
docker-compose up -d
```

#### Application ne répond pas
```bash
# Vérifier le healthcheck
docker-compose ps

# Redémarrer l'application
docker-compose restart faf-app

# Reconstruire si nécessaire
docker-compose up --build -d faf-app
```

### Logs de Debug

```bash
# Logs détaillés
docker-compose logs --details faf-app

# Entrer dans le conteneur pour debug
docker-compose exec faf-app sh
ps aux
netstat -tlnp
```

## 📁 Structure des Fichiers Docker

```
FAF/
├── Dockerfile              # Image principale
├── docker-compose.yml      # Services production
├── docker-compose.dev.yml  # Override développement  
├── .dockerignore           # Fichiers à ignorer
├── .env.example           # Variables d'environnement
└── docker/
    ├── nginx.conf         # Configuration Nginx
    └── mongo-init.js      # Script d'init MongoDB
```

## 🔒 Sécurité

### Bonnes Pratiques

- ✅ Utilisateur non-root dans les conteneurs
- ✅ Variables d'environnement pour les secrets
- ✅ Healthchecks configurés
- ✅ Volumes séparés pour les données
- ✅ Network isolé pour les services
- ✅ Images Alpine (légères et sécurisées)

### Configuration Production

```bash
# Variables sensibles
export SESSION_SECRET="$(openssl rand -base64 64)"
export MONGODB_ROOT_PASSWORD="$(openssl rand -base64 32)"

# Fichier .env sécurisé
chmod 600 .env
```

## 🚀 Optimisations

### Performance

- Multi-stage builds pour images plus légères
- Layer caching optimisé avec .dockerignore
- Healthchecks pour auto-healing
- Resource limits configurables
- Network overlay pour scaling

### Scaling Horizontal

```bash
# Scaler l'application
docker-compose up -d --scale faf-app=3

# Load balancer avec Nginx
# Configuré automatiquement dans nginx.conf
```

## 📞 Support

Pour des problèmes spécifiques à Docker avec FAF :

1. Consulter les logs : `docker-compose logs`
2. Vérifier la configuration : `docker-compose config`
3. Tester la connectivité : `docker-compose exec faf-app ping mongodb`
4. Vérifier les ressources : `docker stats`

---

*Guide créé pour FAF v1.0.0 - Mise à jour : $(date)*