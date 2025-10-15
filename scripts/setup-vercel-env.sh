#!/bin/bash

###############################################################################
# Script de configuration des variables d'environnement Vercel
# FAF Multi-Tenant
#
# Ce script lit le fichier .env et configure automatiquement les variables
# d'environnement Vercel pour les environnements preview et production
###############################################################################

set -e  # Exit on error

echo "🔧 Configuration des variables d'environnement Vercel..."
echo ""

# Vérifier que .env existe
if [ ! -f .env ]; then
  echo "❌ Erreur: fichier .env introuvable"
  echo "Créez un fichier .env à partir de .env.example"
  exit 1
fi

# Charger les variables depuis .env
source .env

# Vérifier que les variables critiques existent
if [ -z "$SUPABASE_URL" ]; then
  echo "❌ Erreur: SUPABASE_URL manquante dans .env"
  exit 1
fi

if [ -z "$SUPABASE_SERVICE_KEY" ]; then
  echo "❌ Erreur: SUPABASE_SERVICE_KEY manquante dans .env"
  exit 1
fi

if [ -z "$JWT_SECRET" ]; then
  echo "❌ Erreur: JWT_SECRET manquante dans .env"
  exit 1
fi

echo "📦 Variables détectées:"
echo "  - SUPABASE_URL: ${SUPABASE_URL:0:30}..."
echo "  - JWT_SECRET: ${JWT_SECRET:0:10}..."
echo "  - APP_BASE_URL: ${APP_BASE_URL:-non défini}"
echo ""

# Fonction pour ajouter une variable d'environnement Vercel
add_env_var() {
  local key=$1
  local value=$2
  local envs=$3  # preview, production, ou les deux

  echo "  Ajout de $key..."

  # Vérifier si la variable existe déjà
  if vercel env ls | grep -q "$key"; then
    echo "    ⚠️  $key existe déjà, suppression..."
    echo "$value" | vercel env rm "$key" "$envs" --yes 2>/dev/null || true
  fi

  # Ajouter la nouvelle valeur
  echo "$value" | vercel env add "$key" "$envs" --yes >/dev/null 2>&1

  if [ $? -eq 0 ]; then
    echo "    ✅ $key ajoutée"
  else
    echo "    ❌ Échec ajout de $key"
  fi
}

echo "🚀 Configuration des variables Vercel (preview + production)..."
echo ""

# Ajouter toutes les variables d'environnement
add_env_var "SUPABASE_URL" "$SUPABASE_URL" "preview,production"
add_env_var "SUPABASE_ANON_KEY" "$SUPABASE_ANON_KEY" "preview,production"
add_env_var "SUPABASE_SERVICE_KEY" "$SUPABASE_SERVICE_KEY" "preview,production"
add_env_var "JWT_SECRET" "$JWT_SECRET" "preview,production"
add_env_var "NODE_ENV" "production" "preview,production"

# Cloudinary (optionnel)
if [ -n "$CLOUDINARY_CLOUD_NAME" ]; then
  add_env_var "CLOUDINARY_CLOUD_NAME" "$CLOUDINARY_CLOUD_NAME" "preview,production"
  add_env_var "CLOUDINARY_API_KEY" "$CLOUDINARY_API_KEY" "preview,production"
  add_env_var "CLOUDINARY_API_SECRET" "$CLOUDINARY_API_SECRET" "preview,production"
fi

# APP_BASE_URL (sera défini après déploiement)
if [ -n "$APP_BASE_URL" ]; then
  add_env_var "APP_BASE_URL" "$APP_BASE_URL" "preview,production"
else
  echo "⚠️  APP_BASE_URL non défini - à configurer manuellement après déploiement"
fi

echo ""
echo "✅ Configuration terminée!"
echo ""
echo "📋 Variables configurées:"
vercel env ls

echo ""
echo "🎯 Prochaines étapes:"
echo "  1. Déployer preview: npm run deploy:preview"
echo "  2. Tester l'URL preview"
echo "  3. Déployer production: npm run deploy:prod"
echo ""
