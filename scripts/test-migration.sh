#!/bin/bash

# Script de test de la migration (environnement local)
# Usage: ./scripts/test-migration.sh

echo "🧪 Test de la migration MongoDB → Supabase"
echo "==========================================="
echo ""

# Vérifier que Node.js est installé
if ! command -v node &> /dev/null; then
    echo "❌ Node.js n'est pas installé"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"
echo ""

# Vérifier que le fichier .env existe
if [ ! -f .env ]; then
    echo "❌ Fichier .env introuvable"
    echo "   Créer un fichier .env à partir de .env.example"
    exit 1
fi

echo "✅ Fichier .env trouvé"
echo ""

# Vérifier les dépendances npm
if [ ! -d "node_modules" ]; then
    echo "⚠️  node_modules introuvable"
    echo "   Installation des dépendances..."
    npm install
    echo ""
fi

echo "✅ Dépendances npm installées"
echo ""

# Vérifier les variables d'environnement
echo "🔍 Vérification des variables d'environnement:"
echo ""

check_env_var() {
    if grep -q "^$1=" .env && ! grep -q "^$1=your-" .env && ! grep -q "^$1=https://xxxxx" .env; then
        echo "   ✅ $1"
    else
        echo "   ❌ $1 (non configuré)"
        return 1
    fi
}

ENV_OK=true

# Variables MongoDB
if check_env_var "MONGODB_URI"; then
    :
else
    ENV_OK=false
fi

# Variables Supabase
if check_env_var "SUPABASE_URL"; then
    :
else
    ENV_OK=false
fi

if check_env_var "SUPABASE_SERVICE_KEY"; then
    :
else
    ENV_OK=false
fi

# Variables admin
if check_env_var "RIRI_EMAIL"; then
    :
else
    ENV_OK=false
fi

if check_env_var "RIRI_PASSWORD"; then
    :
else
    ENV_OK=false
fi

echo ""

if [ "$ENV_OK" = false ]; then
    echo "❌ Certaines variables d'environnement ne sont pas configurées"
    echo "   Éditer le fichier .env avec les bonnes valeurs"
    exit 1
fi

echo "✅ Toutes les variables d'environnement sont configurées"
echo ""

# Menu interactif
echo "Choisir une action:"
echo "  1) Backup MongoDB uniquement"
echo "  2) Migration complète (backup + migration + validation)"
echo "  3) Validation uniquement (post-migration)"
echo "  4) Quitter"
echo ""
read -p "Choix [1-4]: " choice

case $choice in
    1)
        echo ""
        echo "📋 Exécution du backup MongoDB..."
        node scripts/backup-mongodb.js
        ;;
    2)
        echo ""
        echo "🚀 Exécution de la migration complète..."
        echo ""
        node scripts/migrate-to-supabase.js

        if [ $? -eq 0 ]; then
            echo ""
            read -p "Exécuter la validation maintenant ? [o/N]: " validate
            if [ "$validate" = "o" ] || [ "$validate" = "O" ]; then
                echo ""
                node scripts/validate-migration.js
            fi
        fi
        ;;
    3)
        echo ""
        echo "🔍 Exécution de la validation..."
        node scripts/validate-migration.js
        ;;
    4)
        echo "👋 Au revoir!"
        exit 0
        ;;
    *)
        echo "❌ Choix invalide"
        exit 1
        ;;
esac

echo ""
echo "✨ Terminé!"
