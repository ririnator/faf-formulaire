# Guide de configuration Vercel pour FAF Multi-Joueurs

## 🎯 Configuration souhaitée
- **Nom du projet** : `faf-multijoueurs`
- **Branche de production** : `multijoueurs`
- **Repository** : `ririnator/faf-formulaire`

## 📋 Étapes à suivre (via le dashboard Vercel)

### 1. Créer le projet via Vercel Dashboard

#### 1.1 Aller sur Vercel
👉 https://vercel.com/new

#### 1.2 Import Git Repository
- Clique sur **"Add New..."** → **"Project"**
- Dans la section **"Import Git Repository"**
- Cherche et sélectionne : **`ririnator/faf-formulaire`**
- Clique sur **"Import"**

### 2. Configurer le projet

Tu vas voir un écran de configuration avec plusieurs sections :

#### 2.1 Project Name
```
Project Name: faf-multijoueurs
```
**Action** : Change le nom en `faf-multijoueurs`

#### 2.2 Framework Preset
```
Framework Preset: Other
```
**Action** : Laisse sur "Other" (Vercel détectera automatiquement)

#### 2.3 Root Directory
```
Root Directory: ./
```
**Action** : Laisse `./` (racine du projet)

#### 2.4 Build and Output Settings
```
Build Command: [laisser vide ou "npm install"]
Output Directory: [laisser vide]
Install Command: npm install
```
**Action** : Laisse les valeurs par défaut

#### 2.5 **IMPORTANT : Production Branch**

Cherche cette section (peut-être repliée, clique pour déplier si nécessaire) :

```
┌──────────────────────────────┐
│ Production Branch            │
│ ┌──────────────────────────┐ │
│ │ main                   ▼ │ │  ← CLIQUE ICI
│ └──────────────────────────┘ │
└──────────────────────────────┘
```

**Action** :
1. Clique sur le menu déroulant
2. Sélectionne **`multijoueurs`**

#### 2.6 Environment Variables

**Action** : Clique sur **"Add Environment Variable"** et ajoute :

| Name | Value | Environment |
|------|-------|-------------|
| `SUPABASE_URL` | (copie depuis ton .env) | Production |
| `SUPABASE_SERVICE_KEY` | (copie depuis ton .env) | Production |
| `JWT_SECRET` | (copie depuis ton .env) | Production |
| `NODE_ENV` | `production` | Production |
| `CLOUDINARY_CLOUD_NAME` | (copie depuis ton .env) | Production |
| `CLOUDINARY_API_KEY` | (copie depuis ton .env) | Production |
| `CLOUDINARY_API_SECRET` | (copie depuis ton .env) | Production |

💡 **Astuce** : Tu peux copier-coller depuis ton fichier `.env`

### 3. Déployer

Clique sur le gros bouton bleu **"Deploy"** en bas

Vercel va :
1. ✅ Cloner la branche `multijoueurs` depuis GitHub
2. ✅ Installer les dépendances (`npm install`)
3. ✅ Builder le projet
4. ✅ Déployer sur une URL de production

### 4. Vérifier le déploiement

Une fois le build terminé (2-3 minutes), tu verras :

```
🎉 Congratulations!

Your project is now live:
https://faf-multijoueurs.vercel.app
```

### 5. Activer les déploiements automatiques

Une fois le projet créé :

1. Va sur **Settings** → **Git**
2. Vérifie que **Production Branch** est bien `multijoueurs`
3. Active **"Automatically deploy new commits"** (normalement activé par défaut)

Maintenant, à chaque fois que tu fais :
```bash
git push origin multijoueurs
```

Vercel va automatiquement redéployer ! 🚀

---

## 🔧 Alternative : Via CLI (plus rapide mais moins de contrôle)

Si tu préfères tout faire en ligne de commande (mais tu ne pourras pas choisir la branche) :

```bash
# 1. Lier le projet local à un nouveau projet Vercel
vercel link --yes

# Quand demandé :
# - Set up and deploy? Y
# - Which scope? ririnators-projects
# - Link to existing project? N
# - What's your project's name? faf-multijoueurs
# - In which directory is your code located? ./

# 2. Configurer les variables d'environnement
vercel env add SUPABASE_URL production
vercel env add SUPABASE_SERVICE_KEY production
vercel env add JWT_SECRET production
vercel env add CLOUDINARY_CLOUD_NAME production
vercel env add CLOUDINARY_API_KEY production
vercel env add CLOUDINARY_API_SECRET production
vercel env add NODE_ENV production

# 3. Déployer
vercel --prod

# 4. PUIS aller sur le dashboard pour changer la branche
# https://vercel.com/ririnators-projects/faf-multijoueurs/settings/git
# Changer Production Branch: main → multijoueurs
```

---

## 📝 Checklist finale

Une fois tout configuré, vérifie :

- [ ] Nom du projet : `faf-multijoueurs`
- [ ] Branche de production : `multijoueurs`
- [ ] 7 variables d'environnement configurées
- [ ] Déploiement réussi
- [ ] URL accessible : `https://faf-multijoueurs.vercel.app`
- [ ] Déploiements automatiques activés

---

## 🎯 Prochaine étape

Une fois le projet déployé :

1. Teste l'URL : https://faf-multijoueurs.vercel.app
2. Vérifie les pages statiques (login, register, dashboard)
3. Teste les API routes (pour voir si elles fonctionnent)
4. Si elles ne fonctionnent pas, consulte les logs Vercel pour débugger

---

## ❓ Questions fréquentes

**Q : Je ne vois pas "Production Branch" dans la configuration**
**R** : Déplie toutes les sections "Advanced" ou "Git Configuration". C'est parfois caché.

**Q : Vercel déploie depuis `main` au lieu de `multijoueurs`**
**R** : Va dans Settings → Git et change manuellement la branche après le premier déploiement.

**Q : Les API routes ne marchent toujours pas**
**R** : C'est normal, on débuggera après. Le problème vient des imports de modules dans les fonctions serverless.

---

**Bonne chance ! 🚀**
