# Dockerfile pour FAF (Form-a-Friend) Backend
# Image Node.js LTS avec Alpine pour plus de sécurité et moins de taille
FROM node:18-alpine

# Métadonnées
LABEL maintainer="FAF Team"
LABEL description="Form-a-Friend Application - Secure monthly form system"
LABEL version="1.0.0"

# Variables d'environnement par défaut
ENV NODE_ENV=production
ENV PORT=3000

# Créer un utilisateur non-root pour la sécurité
RUN addgroup -g 1001 -S nodejs
RUN adduser -S fafuser -u 1001

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers package pour optimiser les layers Docker
COPY backend/package*.json ./

# Installer les dépendances
# Utiliser npm ci pour les installations reproductibles en production
RUN npm ci --only=production && npm cache clean --force

# Copier le code source
COPY backend/ ./
COPY frontend/ ./frontend/

# Copier les fichiers de test et utilitaires depuis la racine
COPY run-frontend-tests.js ./
COPY test-form-locally.js ./

# Créer les répertoires nécessaires avec les bonnes permissions
RUN mkdir -p logs uploads temp && \
    chown -R fafuser:nodejs /app

# Exposer le port
EXPOSE 3000

# Passer à l'utilisateur non-root
USER fafuser

# Vérifications de santé
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) })" || exit 1

# Commande de démarrage
CMD ["npm", "start"]