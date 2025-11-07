# OFFER - Form-a-Friend

## Vue d'ensemble de l'Offre

Form-a-Friend est un **système de continuité relationnelle** basé sur des formulaires mensuels personnalisés. L'offre se concentre sur la simplicité d'usage et l'efficacité préventive pour maintenir des relations authentiques à distance.

**Core Offering :** Un formulaire mensuel que tu partages avec tes amis pour rester connecté sans effort.

**Modèle économique :** Paid-only, subscription €12/mois, 7 jours d'essai gratuit

**Positionnement prix :** Premium accessible - comparable à Notion Pro (€10), Headspace (€13), YNAB (€15)

---

## Structure de l'Offre

### Philosophie : Paid-Only, No Freemium

**Décision stratégique : Pas de version gratuite.**

#### Pourquoi Pas de Freemium ?

**1. Filtrage de la cible**
- Seuls les utilisateurs vraiment engagés paient
- Élimine les tire-kickers qui ne valorisent pas leurs relations
- Focus sur Emma (intentionnelle, prête à investir)

**2. Signal de valeur**
- "Si c'est gratuit, ça ne vaut rien" (perception qualité)
- €12/mois = sérieux du produit
- Comparable aux autres outils d'amélioration personnelle

**3. Simplicité opérationnelle**
- Pas de gestion de deux tiers (free vs paid)
- Pas de features limitées artificiellement
- Pas de conversion funnel à optimiser
- Focus 100% sur la rétention

**4. Viabilité économique rapide**
- 10 utilisateurs = €120 MRR = coûts serveur couverts
- 100 utilisateurs = €1,200 MRR = salaire part-time viable
- Pas besoin de millions d'utilisateurs pour être rentable

#### L'Exception : Comptes Grandfathered

**Qu'est-ce que c'est :**
Accès gratuit à vie pour un nombre limité d'utilisateurs (early supporters, beta testers, famille/amis proches).

**Justification :**
- Reconnaissance des premiers supporters
- Testimonials authentiques sans biais financier
- Goodwill et word-of-mouth
- Cas d'usage réels pour améliorer le produit

**Limite stricte :** Maximum 10-15 comptes grandfathered. Au-delà, le modèle économique ne tient pas.

---

## Pricing Structure

### Plan Unique : Form-a-Friend Pro

**€12/mois** (ou €120/an avec 2 mois offerts)

#### Ce qui est inclus

✅ **Formulaire mensuel personnalisé illimité**
- Partage avec autant d'amis que tu veux
- Aucune limite sur le nombre de réponses collectées
- URL personnalisée : `faf.app/form/{ton-username}`

✅ **Dashboard complet**
- Statistiques globales (nombre de réponses, mois actuel)
- Graphiques de visualisation
- Gestion de toutes tes réponses

✅ **Comparaisons privées automatiques**
- Chaque ami reçoit un lien unique pour voir sa comparaison
- Visualisation graphique des écarts de perception
- Confidentialité totale (chaque lien est individuel)

✅ **Upload d'images**
- Intégration Cloudinary sécurisée
- Pas de limite de stockage raisonnable

✅ **Support prioritaire**
- Réponse sous 24-48h
- Demandes de features priorisées

✅ **Données sécurisées**
- Row Level Security (isolation totale de tes données)
- Sauvegardes automatiques quotidiennes
- RGPD compliant

#### Essai Gratuit : 7-14 Jours (À Valider)

**Stratégie actuelle : 7 jours**

**Fonctionnement :**
1. Inscription sans carte bancaire
2. Accès complet pendant 7 jours
3. À J+7, redirection vers page de paiement Stripe
4. Si paiement → abonnement actif
5. Si pas de paiement → accès bloqué (données conservées 30 jours)

**Philosophie de l'essai 7 jours :**
- 7 jours suffisent pour créer un formulaire et collecter quelques réponses
- Pas assez long pour "profiter" sans payer
- Assez long pour voir la valeur concrète

**Justification du no credit card upfront :**
- Réduit la friction à l'inscription
- Emma veut tester avant de sortir sa CB
- Taux de conversion essai→payant attendu : 30-40%

---

**Considération Q1 2026 : Extended Trial à 14 jours**

**Rationale pour 14 jours durant phase validation :**

**Avantages :**
- ✅ **Plus de temps pour voir la valeur** : Créer form + partager + attendre réponses prend du temps
- ✅ **2 weekends vs 1** : Emma peut tester un weekend, puis relancer le suivant
- ✅ **Réduit friction psychologique** : "14 jours gratuits" sonne plus généreux
- ✅ **Conversion potentiellement meilleure** : Plus de temps = plus d'engagement

**Inconvénients :**
- ❌ **Rallonge le cycle de validation** : 14 jours trial = feedback plus lent
- ❌ **Risque de "forget"** : Certains s'inscrivent, oublient, ne testent jamais
- ❌ **Peut attirer des gens pas sérieux** : "Je testerai quand j'aurai le temps" (jamais)

**Timeline réelle Emma :**
- Jour 1 : Inscription, création form (1h)
- Jour 2-3 : Partage link à 5 amis
- Jour 4-7 : Attente réponses (2-3 amis répondent)
- Jour 8 : Check dashboard, voit comparaisons
- Jour 9-14 : Décision de payer ou non

**Avec 7 jours :** Emma doit décider avant d'avoir assez de réponses (risque)
**Avec 14 jours :** Emma a le temps de voir la valeur complète

---

**Décision recommandée :**

**Q1 2026 (Jan-Mar) : 14 jours trial**
- Phase validation, friction minimale prioritaire
- Track : combien utilisent vraiment le produit avant J+7 vs J+14

**Q2 2026+ : Revenir à 7 jours**
- Une fois PMF validé
- Standard SaaS (Letterloop = 2 issues gratuites ~2 semaines aussi)

**Metric clé à tracker :**
- % users qui testent activement durant jours 1-7 vs jours 8-14
- Si 80% de l'engagement est J1-J7 → 7 jours suffisent
- Si engagement significatif J8-J14 → 14 jours nécessaire

**Test en live, ajuste selon data.**

---

#### Exit Survey : Comprendre les Non-Conversions

**Critique pour validation pricing :**

Chaque utilisateur qui ne convertit pas après le trial doit recevoir un **survey de sortie automatique**.

**Questions obligatoires (max 3 pour taux de réponse) :**

**Q1 : "Pourquoi n'avez-vous pas souscrit à FAF ?"**
- [ ] Le prix est trop élevé
- [ ] Je ne vois pas assez de valeur
- [ ] J'ai besoin de plus de temps pour tester
- [ ] Mes amis n'ont pas répondu au formulaire
- [ ] Autre : ___________

**Q2 : "À quel prix mensuel auriez-vous souscrit ?"**
- [ ] €6/mois
- [ ] €9/mois
- [ ] €12/mois (mais pas maintenant)
- [ ] Aucun prix (le produit ne me convient pas)

**Q3 (optionnelle) : "Qu'est-ce qui aurait pu vous convaincre ?"**
[Texte libre]

---

**Analyse des patterns :**

**Si >50% disent "Prix trop élevé" :**
→ Problème pricing. Consider test €9/mois Q2.

**Si >50% disent "Pas de valeur vue" :**
→ Problème messaging/value prop. Garder €12, améliorer communication.

**Si >50% disent "Amis n'ont pas répondu" :**
→ Problème produit/onboarding. Garder €12, fix activation friends.

**Dashboard tracking :**
- Survey response rate target : >40%
- Pattern analysis hebdomadaire
- Ajustements messaging en temps réel

**Cette data est CRITIQUE pour décision pricing fin Q1.**

---

#### Pourquoi €12/mois ? (Analyse Critique)

**Positioning intentionnel :**
€12/mois n'est pas choisi au hasard. C'est un prix **premium assumé** qui filtre pour les utilisateurs intentionnels.

**Comparaison avec alternatives :**
- Letterloop (concurrent #1) : $5/mois (~€4.60) ← **2.4x moins cher**
- Notion Pro : €10/mois
- Headspace : €13/mois
- Duolingo Plus : €7/mois
- YNAB : €15/mois
- Spotify Premium : €10/mois
- Netflix Basic : €14/mois

**La vraie question : Pourquoi 2.4x plus cher que Letterloop ?**

| Ce que Letterloop donne ($5) | Ce que FAF donne (€12) |
|------------------------------|------------------------|
| Newsletter groupe passive | Coaching 1-on-1 actif personnalisé |
| Questions génériques | Questions ciblées par relation |
| Partage de vie broadcast | Approfondissement intentionnel |
| Pas de suivi temporel | Suivi évolution + suggestions |
| Email uniquement | Dashboard complet + analytics |
| Format groupe seulement | 1-on-1 + option groupe |

**Value delivered = 2.4x supérieure → Prix justifié**

---

**Calcul de valeur perçue :**
- €12/mois = **€0,40/jour**
- Moins qu'un café (€1,50)
- Moins qu'un brunch avec une amie (€20-30)
- **Value prop : "Investis €0,40/jour pour ne jamais perdre tes amies"**

**La bataille de prioritisation :**

**Budget mensuel réaliste d'Emma (25-30 ans, cadre urbaine) :**

**Revenus & Dépenses :**
- Salaire net : €2,000-2,500/mois
- Loyer : €800-1,200 (35-50% du revenu)
- Budget "apps/abonnements" : **€20-40/mois** total

**€12/mois FAF = 30-60% de son budget apps**

**Concurrence directe pour ces €20-40 :**

| App | Prix/mois | Statut | Substituable ? |
|-----|-----------|--------|----------------|
| **Spotify** | €10 | Quasi non-négociable | ❌ (quotidien) |
| **Netflix** | €14 | Divertissement établi | ⚠️ (peut résilier) |
| **Salle de sport** | €40 | Santé prioritaire | ❌ (important) |
| **Notion Pro** | €10 | Productivité (si utilisé) | ⚠️ (peut downgrade) |
| **FAF** | €12 | Nouveau | ❓ (doit prouver valeur) |

**Pour que FAF gagne sa place :**

FAF doit convaincre Emma qu'il vaut plus que Netflix dans sa hiérarchie mentale.

**La vraie question n'est PAS :**
> "Emma peut-elle se permettre €12/mois ?"
> (Oui. €12 = 0.6% de son salaire)

**La vraie question EST :**
> "Est-ce que ne pas perdre ses amis vaut plus que Netflix dans la vie d'Emma ?"

**Pour y répondre, le pain "catchup friends" doit être 7-8/10 :**
- Frustration récurrente (elle y pense 1x/semaine minimum)
- A déjà essayé des solutions qui ont échoué (calendar, WhatsApp)
- Culpabilité réelle de perdre contact
- Prête à investir maintenant pour éviter regrets plus tard

**Validation ICP :**
D'après le profil Emma détaillé, le pain EST 7-8/10.

**Donc : €12/mois est justifiable pour Emma SI on articule parfaitement la value prop.**

**Le défi : Prouver que FAF > Netflix dans sa vie.**

---

**Pour que FAF gagne :**
Le pain "catchup friends" doit être une frustration récurrente (7-8/10), pas juste un "nice to have".

**C'est le cas pour Emma** → €12/mois est justifiable.

---

**Price Anchoring Strategy : Améliorer la Perception**

Pour rendre €12/mois plus acceptable psychologiquement, plusieurs techniques d'ancrage :

**Anchor #1 : Plan Annuel (Q2+ seulement)**
- Mensuel : €12/mois (€144/an)
- Annuel : €120/an (€10/mois effectif, 2 mois offerts = 17% discount)

**Effet psychologique :**
€12 mensuel semble raisonnable comparé à €144 upfront.

**Note :** Ne lancer le plan annuel qu'en Q2 après validation PMF. Au début, focus sur mensuel pour tester retention réelle.

---

**Anchor #2 : "Cost Per Friendship"**

**Reframe le coût :**
- Si 5 amis proches : €12 ÷ 5 = **€2.40/mois par amitié**
- Si 10 amis : €12 ÷ 10 = **€1.20/mois par amitié**

**Messaging :**
> "€1-2/mois pour chaque amitié que tu refuses de perdre."

**Utilisation :** Landing page, social media, objection handling.

---

**Anchor #3 : Alternative Cost Comparison**

**Le coût d'un brunch raté :**
- 1 brunch "catchup" avec amie = €25 + 2h perdues à se raconter les 6 derniers mois
- FAF pendant 2 mois = €24, mais conversations profondes continues toute l'année

**ROI messaging :**
> "Meilleur usage du temps ET de l'argent."

---

**Anchor #4 : Status Quo Cost**

**Le vrai coût de ne rien faire :**
- Option A : Ne rien faire (€0/mois)
  - Dans 5 ans : réaliser que tu es seule
  - Cost émotionnel : inestimable (in the bad way)

- Option B : FAF (€12/mois)
  - Dans 5 ans : tes amis proches sont toujours là
  - Cost : €720 total (€144/an × 5)

**Question finale :**
> "Quel est le prix de perdre ta meilleure amie ? Plus ou moins de €720 sur 5 ans ?"

**Cette approche reframe €12/mois comme un investissement préventif, pas une dépense.**

---

**Les risques du pricing €12/mois :**

**Risk #1 : Friction vs Letterloop**
- 2.4x plus cher = objection prévisible
- **Mitigation :** Messaging béton sur différenciation value
- **Tracking :** Conversion trial→paid doit être >30%

**Risk #2 : Pas de social proof au lancement**
- €12 AVEC testimonials = facile
- €12 SANS preuves = harder sell
- **Mitigation :** Warm network pour 10-15 premiers, build social proof rapidement

**Risk #3 : Budget serré Emma**
- €12 = 30-60% de son budget apps total
- **Mitigation :** Prouver que FAF > Netflix dans sa vie

---

**Stratégie de validation pricing Q1 2026 :**

**Hypothèse :**
€12/mois est le bon prix SI messaging value prop est parfait.

**Test durant Q1 :**
1. Lance à €12/mois
2. Track religieusement trial → paid conversion
3. Collecte objections pricing

**Seuils de décision (fin mars 2026) :**

| Conversion Rate | Verdict | Action |
|----------------|---------|--------|
| **>30%** | ✅ €12 validé | Continue, scale |
| **20-30%** | ⚠️ Limite | Améliore messaging, observe Q2 |
| **<20%** | ❌ Problème | Investigate : prix ou value prop ? |

**Si <20% ET feedback = "trop cher" :**
- Option A : Drop à €9/mois (test 3 mois)
- Option B : Early bird €9/mois pour 50 premiers users
- Option C : Pivot segment (Expatriés = WTP plus élevée)

**Si <20% ET feedback = "je ne vois pas la valeur" :**
- Problème de messaging, PAS de prix
- Fix value prop communication
- Garde €12/mois

---

**Considération : Extended Trial**

**Current :** 7 jours gratuits sans CB

**Alternative pour Q1 (phase validation) :**
**14 jours gratuits** sans CB

**Rationale :**
- Donne plus de temps pour voir la valeur (créer form + collecter réponses prend du temps)
- Réduit friction psychologique initiale
- Emma a 2 weekends pour tester (vs 1 seul weekend avec 7 jours)

**Après PMF validé (Q2+) :**
Revenir à 7 jours (standard SaaS)

**Décision finale :** À tester en live. Commencer avec 14 jours pour Q1, évaluer.

---

**Point d'ancrage psychologique :**

Emma paie déjà pour :
- Salle de sport : €40/mois (santé physique)
- Apps productivité : €10-20/mois (efficacité)
- Streaming : €20-30/mois (divertissement)

**FAF = santé relationnelle**

Si elle investit €40/mois pour son corps, pourquoi pas €12/mois pour ses amitiés ?

**Message clé :**
> "Tu paies €40/mois pour ne pas perdre ta forme physique. Pourquoi pas €12/mois pour ne pas perdre tes amies ?"

---

**Conclusion pricing :**

€12/mois est le **bon prix** si :
✅ Messaging value prop est béton
✅ PMF via warm network d'abord (confiance établie)
✅ Social proof construit rapidement (testimonials M2-M3)
✅ Tu assumes le premium (pas d'excuses)

€12/mois est **trop cher** si :
❌ Value prop pas claire
❌ Scale trop vite sans PMF
❌ Tu ne peux pas articuler le 2.4x vs Letterloop

**Approche recommandée :**
Lance à €12, track obsessivement, ajuste après 3 mois de data si nécessaire.

**Ne baisse pas le prix par peur. Baisse-le SEULEMENT si les données le prouvent nécessaire.**

#### Options de Paiement

**Mensuel : €12/mois**
- Engagement minimal
- Parfait pour tester la rétention long-terme
- Annulable à tout moment

**Annuel : €120/an** (€10/mois effectif)
- 2 mois offerts (€144 → €120)
- Engagement long-terme = meilleure rétention
- Cash flow upfront pour croissance

**Stratégie de lancement :**
Phase 1 (Q1 2026) : Mensuel uniquement (focus validation)
Phase 2 (Q2 2026) : Ajout de l'option annuelle (optimisation LTV)

#### Considération : Early Bird Discount (Optionnel)

**Stratégie alternative pour réduire friction initiale :**

**Option : "Launch Pricing"**
- Premiers 50 users : **€9/mois à vie** (grandfathered)
- Après 50 users : €12/mois pour tous les nouveaux

**Avantages :**
- ✅ Réduit friction pour early adopters
- ✅ Crée urgency ("seulement 50 places à €9")
- ✅ Reward les premiers supporters
- ✅ Facilite conversion 10-15 premiers admins

**Inconvénients :**
- ❌ Revenue long-term réduit (€150/mois vs €600 si 50 users à €12)
- ❌ Peut signaler faiblesse pricing
- ❌ Complique messaging ("pourquoi augmenter après ?")

**Recommandation :**
- **NE PAS utiliser** si warm network suffit pour 10-15 premiers
- **UTILISER** si après 2 mois, <5 admins payants à €12

**Décision :** Garder en backup, pas en stratégie primaire.

---

## Features du MVP (Janvier 2026)

### Ce Qui Existe dans le MVP

#### 1. Système de Compte Admin

**Inscription et Authentification**
- Création de compte avec username, email, mot de passe
- Authentification JWT stateless (session 7 jours)
- Protection bcrypt pour les mots de passe
- Isolation complète des données par admin (Row Level Security)

**Dashboard Administrateur**
- Vue d'ensemble : statistiques globales, statut abonnement
- Graphiques de visualisation des réponses
- Liste paginée de toutes les réponses reçues
- Détail, modification, suppression de réponses individuelles
- Tri et filtrage des données

#### 2. Création et Partage de Formulaire

**Formulaire Standardisé**
- 11 questions prédéfinies couvrant :
  - Traits de personnalité perçus
  - Préférences et goûts
  - Perceptions relationnelles
  - Moments mémorables
- Upload d'images possible (Cloudinary)
- Format responsive (mobile, tablet, desktop)

**Partage Simplifié**
- URL personnalisée : `faf.app/form/{ton-username}`
- Accessible sans compte (tes amis n'ont pas besoin de créer un compte)
- Partageable via WhatsApp, email, SMS, réseaux sociaux

#### 3. Collecte de Réponses

**Soumission Publique**
- Formulaire remplissable anonymement par tes amis
- Protection anti-spam : maximum 3 soumissions/15min par IP
- Validation des inputs (longueur, format, XSS prevention)
- Stockage sécurisé en base de données PostgreSQL

**Réponse de l'Admin**
- L'admin remplit aussi sa propre version du formulaire
- Marquée comme "propriétaire" dans la base
- Sert de référence pour les comparaisons

#### 4. Comparaisons Privées

**Génération de Liens Uniques**
- Chaque ami reçoit un token UUID unique
- Lien privé : `faf.app/view/{token}`
- Accessible sans authentification mais protégé par token

**Visualisation Comparative**
- Graphiques montrant :
  - Perception de l'ami vs perception de l'admin
  - Moyenne des autres amis
  - Écarts et similitudes
- Format visuel clair et engageant

**Confidentialité Totale**
- Chaque ami voit UNIQUEMENT sa propre comparaison
- Pas d'accès aux réponses des autres
- Pas de classement ni de gamification sociale

#### 5. Système de Paiement

**Intégration Stripe**
- Checkout hébergé Stripe (sécurité maximale, pas de PCI compliance nécessaire)
- Abonnement mensuel à €12/mois
- Essai gratuit de 7 jours automatique
- Gestion des webhooks pour mise à jour du statut

**Gestion d'Abonnement**
- Statuts : trialing, active, past_due, canceled, unpaid
- Blocage d'accès si paiement en échec (avec période de grâce)
- Informations d'abonnement visibles dans le dashboard

#### 6. Upload d'Images

**Intégration Cloudinary**
- Upload sécurisé avec signature API
- Transformation automatique (resize, crop, optimisation)
- URLs optimisées pour le web
- Rate limiting : 3 uploads/15min par IP

#### 7. Sécurité et Performance

**Mesures de Sécurité**
- Row Level Security (RLS) PostgreSQL : isolation totale des données
- Protection XSS : sanitization de tous les inputs
- Rate limiting sur endpoints sensibles
- JWT avec expiration (7 jours)
- Vérification de signature Stripe pour webhooks

**Performance**
- Architecture serverless (Vercel) : auto-scaling
- Edge network : latence minimale
- Indexes PostgreSQL optimisés
- Pagination côté serveur

---

### Ce Qui N'Est PAS dans le MVP

Ces features sont **volontairement exclues** du MVP pour maintenir la simplicité et accélérer le lancement.

#### ❌ Envoi d'Emails Automatiques
**Status :** Liens générés mais pas envoyés automatiquement

**Workaround MVP :**
Admin copie le lien privé et l'envoie manuellement par WhatsApp/email

**Pourquoi pas dans MVP :**
- Nécessite service d'emailing (SendGrid, Postmark) = coût + complexité
- Risque de spam flags
- Pas bloquant pour validation product-market fit

**Quand ajouter :** Q2 2026, après validation des 10-15 premiers admins

---

#### ❌ Formulaires Personnalisables
**Status :** Questions standardisées pour tous les admins

**MVP actuel :**
11 questions fixes que tout le monde utilise

**Pourquoi pas dans MVP :**
- Complexité technique majeure (UI de création de questions, validation, stockage flexible)
- Paradox of choice : plus de flexibilité = plus de friction
- Besoin de valider d'abord que les questions standard marchent

**Quand ajouter :** 2027, si validation que le besoin existe vraiment

---

#### ❌ Rappels Automatiques
**Status :** Pas de notifications push ou emails de rappel

**Workaround MVP :**
Admin relance manuellement ses amis si besoin

**Pourquoi pas dans MVP :**
- Nécessite système de notifications (email + logique de timing)
- Risque d'être perçu comme spam
- Pas critique pour valider le core value

**Quand ajouter :** Q3 2026, si feedback utilisateurs le demande

---

#### ❌ Historique Multi-Mois
**Status :** Pas de comparaison mois-sur-mois ou archives

**MVP actuel :**
Un seul "mois actuel" à la fois

**Pourquoi pas dans MVP :**
- Complexité UX (navigation temporelle, graphiques évolution)
- Besoin de valider d'abord l'usage mois 1
- Les utilisateurs n'auront pas d'historique avant plusieurs mois d'usage

**Quand ajouter :** Q4 2026, une fois que les early users ont 6+ mois de données

---

#### ❌ Export de Données
**Status :** Pas de CSV, PDF, ou exports

**Workaround MVP :**
Les données sont visibles dans le dashboard, screenshots possibles

**Pourquoi pas dans MVP :**
- Feature "nice to have" pas "must have"
- Complexité technique (génération PDF, formatage CSV)
- Besoin de valider d'abord la rétention

**Quand ajouter :** 2027, si demandé par plusieurs utilisateurs

---

#### ❌ Application Mobile Native
**Status :** Web app responsive uniquement

**MVP actuel :**
Site web optimisé mobile, pas d'app iOS/Android

**Pourquoi pas dans MVP :**
- Coût de développement énorme (2-3 mois minimum)
- Maintenance double (iOS + Android)
- Web app suffit pour validation

**Quand ajouter :** 2027+, si traction significative (500+ admins)

---

#### ❌ Analytics Avancées
**Status :** Pas de Google Analytics, Mixpanel, etc.

**MVP actuel :**
Données basiques visibles dans dashboard admin

**Pourquoi pas dans MVP :**
- Pas prioritaire pour validation PMF
- Complexité de setup et privacy compliance
- Vercel logs suffisent pour debugging

**Quand ajouter :** Q2-Q3 2026, pour optimiser funnel conversion

---

#### ❌ Multi-Langues
**Status :** Français uniquement

**Pourquoi pas dans MVP :**
- Emma est francophone (cible primaire)
- Complexité technique (i18n, gestion traductions)
- Besoin de valider France d'abord

**Quand ajouter :** 2027, si opportunité expansion internationale

---

#### ❌ Intégrations Tierces
**Status :** Pas de Zapier, Make, webhooks

**Pourquoi pas dans MVP :**
- Use case pas clair pour le produit actuel
- Complexité technique significative
- Pas demandé par early users

**Quand ajouter :** 2027+, si demande utilisateurs

---

#### ❌ Thèmes/Personnalisation Visuelle
**Status :** Design unique pour tous

**Pourquoi pas dans MVP :**
- Pas différenciateur pour validation PMF
- Risque de diluer l'identité de marque
- Temps de dev mieux investi ailleurs

**Quand ajouter :** 2027, si feedback utilisateurs

---

### Roadmap Features Post-MVP

**Q2 2026 (Après validation PMF)**
- Envoi d'emails automatiques pour les liens privés
- Rappels doux pour les amis qui n'ont pas répondu
- Option paiement annuel (€120/an)
- Analytics basiques (GA4)

**Q3 2026 (Optimisation rétention)**
- Historique multi-mois (comparaison temporelle)
- Export basique (CSV des réponses)
- Notifications in-app

**Q4 2026 (Scale)**
- Questions personnalisables (admin définit ses propres questions)
- Thèmes visuels basiques
- API publique (webhooks)

**2027 (Expansion)**
- Application mobile native (si traction prouvée)
- Multi-langues (anglais)
- Intégrations tierces (Zapier)

---

## Proposition de Valeur Unique (USP)

### Ce Qui Rend FAF Unique

#### 1. **Prévention, Pas Intervention**

**FAF n'est pas :**
- Une app de chat mort ressuscitée
- Une solution d'urgence pour amitiés en crise
- Un pansement émotionnel

**FAF est :**
- Un système proactif qui empêche la dérive
- Comme la salle de sport pour tes relations : tu y vas quand tout va bien
- Une architecture préventive

**Comparaison avec alternatives :**
| Produit | Approche | Moment d'usage |
|---------|----------|----------------|
| WhatsApp Group | Réactive | Quand quelqu'un poste (rare) |
| Calendar Reminders | Réactive | Quand tu te souviens (oubli fréquent) |
| Instagram | Passive | Consommation de contenu (illusion proximité) |
| **FAF** | **Proactive** | **Système mensuel automatique** |

---

#### 2. **Structure Sans Pression**

**Le paradoxe des amitiés adultes :**
- On veut rester proche MAIS
- "Appeler juste pour parler" se sent artificiel
- Relancer le group chat mort = trop de pression sociale
- "Qu'est-ce que je dis ?" = paralysie

**FAF résout ça avec :**
- **Questions guidées** : Pas besoin de trouver quoi dire
- **Cadre mensuel** : Permission de prendre contact sans gêne
- **Format asynchrone** : Chacun répond quand il veut
- **Pas de conversation forcée** : Remplis le formulaire, c'est tout

**Ce que disent les utilisateurs :**
> "Avant, j'hésitais à envoyer un message random après 3 mois. Avec FAF, j'ai une raison légitime de recontacter."

---

#### 3. **Profondeur > Volume**

**FAF ne t'aide PAS à :**
- Avoir plus d'amis
- Optimiser ton réseau
- Faire du networking
- Créer de nouvelles amitiés

**FAF t'aide à :**
- Garder tes amis existants proches
- Maintenir la qualité de tes relations importantes
- Éviter que les gens qui comptent deviennent des étrangers

**Anti-feature volontaires :**
- ❌ Pas de feed social
- ❌ Pas de découverte d'amis
- ❌ Pas de gamification (points, badges, streaks)
- ❌ Pas de classement public
- ❌ Pas de "combien d'amis tu as"

**Pourquoi :**
FAF est pour Emma, pas pour les networkers. Emma valorise la profondeur, pas la quantité.

---

#### 4. **Intimité Préservée**

**Le problème des solutions existantes :**
- WhatsApp Group : Tout le monde voit tout = pas d'intimité
- Instagram : Public = highlight reel, pas vraie vie
- Calendar : Données locales = pas de partage structuré

**FAF garantit :**
- **Comparaisons privées** : Chaque ami voit UNIQUEMENT sa propre comparaison
- **Pas de feed public** : Pas de pression de poster pour les autres
- **Pas de like/commentaires** : Pas de validation sociale
- **Row Level Security** : Isolation totale des données par admin

**Ce que ça signifie :**
Tes amis peuvent partager authentiquement sans peur du jugement ou de l'exposition publique.

---

#### 5. **Simplicité Radicale**

**Le problème des produits complexes :**
Emma est busy. 50h de boulot/semaine. Pas le temps d'apprendre un outil compliqué.

**FAF = 3 étapes, 10 minutes/mois :**
1. Crée ton compte (1 min)
2. Partage ton lien avec tes amis (1 min)
3. Remplis ton formulaire mensuel (8 min)

**C'est tout.**

Pas de :
- ❌ Configuration complexe
- ❌ Courbe d'apprentissage
- ❌ Features cachées à découvrir
- ❌ Tutorials de 20 minutes

**Philosophy :**
> "La meilleure feature est celle que tu n'as pas besoin d'expliquer."

---

## Positionnement vs Alternatives

### Paysage Concurrentiel

#### Alternative 1 : WhatsApp/Messenger Group Chats

**Leur approche :**
- Chat de groupe pour rester en contact
- Communication spontanée et informelle
- Gratuit

**Pourquoi ils ne résolvent pas le problème :**
- **Le group chat meurt** : Personne n'ose relancer après 3 mois de silence
- **Flood ou désert** : Soit 247 messages en 2h, soit silence total
- **Superficialité** : Échanges légers (memes, lol), pas de profondeur
- **Asymétrie** : 2 personnes postent 90%, les autres lurk et culpabilisent

**Avantage FAF :**
✅ Structure mensuelle = pas de pression à poster constamment
✅ Questions guidées = profondeur naturelle
✅ Format asynchrone = chacun répond quand il veut
✅ Pas de FOMO si tu ne lis pas 100 messages

**Positioning statement :**
> "WhatsApp te donne un canal de communication. FAF te donne un système de continuité."

---

#### Alternative 2 : Calendar Reminders

**Leur approche :**
- Rappel périodique "Appeler Sarah"
- Auto-gestion des contacts
- Gratuit (intégré iOS/Google Calendar)

**Pourquoi ils ne résolvent pas le problème :**
- **Vide de contenu** : "Qu'est-ce que je dis ?" = paralysie
- **Artificiel** : Appeler "parce que le calendrier le dit" se sent forcé
- **Pas de réciprocité** : Emma fait l'effort, mais Sarah ?
- **Pas de suivi** : Oubli de 70% de ce qui a été dit après 1 semaine

**Avantage FAF :**
✅ Questions guidées = contenu structuré
✅ Réciprocité visible = les deux font l'effort
✅ Suivi temporel automatique = continuité
✅ Permission de recontact sans gêne

**Positioning statement :**
> "Les rappels te disent QUAND contacter. FAF te dit QUOI dire et COMMENT suivre."

---

#### Alternative 3 : Instagram/Social Media

**Leur approche :**
- Partage de moments de vie via posts/stories
- Like/commentaires pour maintenir le lien
- Gratuit

**Pourquoi ils ne résolvent pas le problème :**
- **Illusion de proximité** : Tu vois les posts mais tu ne sais PAS ce qui se passe vraiment
- **Highlight reel** : Version filtrée, pas vraie vie
- **Communication à sens unique** : Tu consommes, tu ne partages pas vraiment
- **Moments importants deviennent publics** : 500 followers apprennent en même temps

**Avantage FAF :**
✅ Vraies questions, vraies réponses = profondeur
✅ Partage privé avant annonce publique
✅ Bidirectionnel = conversation, pas monologue
✅ Intimité préservée = cercle restreint

**Positioning statement :**
> "Instagram te montre ce que tes amis veulent que tu voies. FAF te montre ce qui se passe vraiment."

---

#### Alternative 4 : Notion/Spreadsheets DIY

**Leur approche :**
- Créer son propre système de suivi relationnel
- Templates, bases de données, tracking manuel
- Gratuit ou €10/mois (Notion Pro)

**Pourquoi ils ne résolvent pas le problème :**
- **Setup complexe** : 2-3h pour créer le système
- **Maintenance constante** : Faut mettre à jour manuellement
- **Pas de réciprocité** : Système solo, amis pas impliqués
- **Abandonné après 2 mois** : Trop d'efforts pour maintenir

**Avantage FAF :**
✅ Zéro setup = créé en 1 minute
✅ Maintenance automatique = système fait le boulot
✅ Réciprocité native = amis participent activement
✅ Constance garantie = structure mensuelle

**Positioning statement :**
> "Notion te donne les briques. FAF te donne la maison déjà construite."

---

#### Alternative 5 : Apps de Networking (Lunchclub, Meetup)

**Leur approche :**
- Rencontrer de nouvelles personnes
- Optimiser son réseau professionnel/social
- Gratuit ou freemium

**Pourquoi ce n'est PAS la même chose :**
- **Objectif différent** : Créer de nouveaux liens vs maintenir les existants
- **Philosophie opposée** : Volume (plus d'amis) vs profondeur (garder les proches)
- **Use case incompatible** : Networking pro vs amitiés intimes

**FAF n'est PAS un concurrent :**
FAF ne t'aide pas à faire de nouveaux amis. FAF t'aide à ne pas perdre ceux que tu as.

**Positioning statement :**
> "Les apps de networking t'aident à gagner des amis. FAF t'aide à ne pas les perdre."

---

### Tableau Comparatif : FAF vs Alternatives

| Feature | WhatsApp Group | Calendar | Instagram | Notion DIY | **FAF** |
|---------|----------------|----------|-----------|------------|---------|
| **Structure mensuelle** | ❌ | ⚠️ (manuel) | ❌ | ⚠️ (manuel) | ✅ |
| **Questions guidées** | ❌ | ❌ | ❌ | ⚠️ (custom) | ✅ |
| **Réciprocité visible** | ⚠️ | ❌ | ⚠️ | ❌ | ✅ |
| **Suivi temporel** | ❌ | ❌ | ❌ | ⚠️ (manuel) | ✅ |
| **Intimité préservée** | ⚠️ | ✅ | ❌ | ✅ | ✅ |
| **Format asynchrone** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Profondeur native** | ❌ | ❌ | ❌ | ⚠️ | ✅ |
| **Zéro maintenance** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Prix** | Gratuit | Gratuit | Gratuit | €10/mois | **€12/mois** |

**Légende :**
- ✅ Excellent
- ⚠️ Partiel/Manuel
- ❌ Absent/Mauvais

---

### Unique Selling Proposition (USP) - Version Finale

**One-liner :**
> "FAF est le système mensuel qui empêche tes amis de devenir des étrangers."

**Value Proposition complète :**
> "Form-a-Friend transforme l'intention de rester proche en système de continuité relationnelle. Un formulaire mensuel avec questions guidées, réponses privées, et suivi automatique. Pour les gens intentionnels qui refusent de laisser leurs relations importantes au hasard. €12/mois."

**Pourquoi FAF gagne :**
1. **Seul produit proactif** : Prévention, pas intervention
2. **Structure sans pression** : Questions guidées, format asynchrone
3. **Profondeur garantie** : Conçu pour la qualité, pas la quantité
4. **Intimité préservée** : Comparaisons privées, pas de feed social
5. **Simplicité radicale** : 3 étapes, 10 min/mois

**Target segment ultra-clair :**
FAF n'est pas pour tout le monde. FAF est pour Emma : l'architecte intentionnelle de ses relations qui comprend que les grandes amitiés ne se maintiennent pas par accident, mais par design.

---

## Messaging et Communication de l'Offre

### Landing Page Structure

#### Hero Section
**Headline :**
"Your best friend got engaged. You found out on Instagram."

**Subheader :**
"Stay actually close with the people who matter. One monthly check-in at a time."

**CTA :**
"Start Your Free Trial - €12/month after 7 days"

---

#### Problem Section
**Header :**
"The worst part of adulting"

**Body :**
"Your friends become 'catchup friends.' You spend the entire hangout updating each other instead of just... hanging out. The group chat is dead. Nobody wants to be the one to revive it. You see their Instagram posts but you don't know what's really happening in their lives."

---

#### Solution Section
**Header :**
"Be intentional. Build the system now."

**Body :**
"Form-a-Friend gives you the structure to stay close without the awkwardness. One monthly form with guided questions. Private comparisons. Automatic follow-up. That's it."

**Features Grid :**
- ✅ Monthly guided questions
- ✅ Private comparisons for each friend
- ✅ No group chat pressure
- ✅ Automatic continuity tracking

---

#### Social Proof Section
**Testimonial 1 :**
> "I actually know what's happening in my friends' lives now. Best €12 I spend every month."
> — Emma, 28, Marketing Manager, Paris

**Testimonial 2 :**
> "FAF gave me permission to reach out without feeling like I'm bothering them. The questions guide the conversation naturally."
> — Sophie, 26, Software Engineer, Lyon

**Testimonial 3 :**
> "We went from catching up once a year to actually staying in each other's lives. It's the system I didn't know I needed."
> — Marine, 29, Consultant, Bordeaux

---

#### Pricing Section
**Header :**
"Simple pricing. No hidden fees."

**Plan :**
**Form-a-Friend Pro**
€12/month

✅ Unlimited forms and responses
✅ Private comparison links
✅ Full dashboard access
✅ Image uploads
✅ Priority support
✅ 7-day free trial

**CTA :**
"Start Free Trial - No credit card required"

**Subtext :**
"Cancel anytime. Your data stays safe for 30 days."

---

#### Philosophy Section (About Page)
**Header :**
"Most people wait for the crisis."

**Body :**
"They wait until they feel lonely. Until they see that Instagram post. Until they realize they don't know what's happening in their friends' lives anymore.

But what if you didn't have to wait?

Form-a-Friend is for people who want to be intentional about their relationships. Who understand that staying close doesn't happen by accident—it happens by design.

One monthly check-in. One simple system. That's all it takes."

**Quote :**
> "You could be the master of your fate, you could be the captain of your soul. But you have to realize that life is coming from you and not at you."

---

#### Who Is This For Section
**Header :**
"Form-a-Friend is for people who:"

✓ Understand that great friendships don't happen by accident
✓ Would rather prevent drift than fix it later
✓ Are willing to invest 10 minutes a month to stay truly close
✓ Believe that being intentional > hoping things work out

**Closing line :**
"If that's you, welcome. You're in the right place."

---

#### FAQ Section

**Q: Do my friends need to create an account?**
A: No. They just fill out your form via a link you share. No signup required.

**Q: How long does it take?**
A: ~10 minutes per month. That's it.

**Q: Can I cancel anytime?**
A: Yes. Cancel in one click from your dashboard. Your data stays safe for 30 days.

**Q: Is my data private?**
A: Absolutely. Row Level Security ensures complete isolation. Your friends can only see their own comparison, not others'.

**Q: Do you send emails automatically?**
A: Not yet (MVP). You share the links manually for now. Auto-emails coming in Q2 2026.

**Q: Can I customize the questions?**
A: Not in the MVP. Everyone uses the same 11 questions for now. Custom questions coming in 2027.

**Q: What if my friends don't respond?**
A: You can send gentle reminders manually. Automatic reminders coming Q3 2026.

**Q: €12/month seems expensive for a form.**
A: You're not paying for a form. You're paying to never lose sight of the people who matter. What's the price of a lost friendship?

---

### Email Sequences

#### Welcome Email (Post-Signup)
**Subject:** Welcome to Form-a-Friend 🎉

**Body:**
Hey [Name],

Welcome to Form-a-Friend! You've just taken the first step to never losing sight of your friends again.

Here's what to do next:

1. **Create your form** (1 min)
   Dashboard → Create Form → Done

2. **Share your link** (1 min)
   Copy this: faf.app/form/[username]
   Send it to 3-5 close friends via WhatsApp/email

3. **Fill your own form** (8 min)
   Your perception of yourself will be compared to theirs

That's it. You're set up.

**Remember:** You have 7 days to try everything for free. No credit card required yet.

Questions? Just reply to this email.

Riri
Form-a-Friend

---

#### Day 3 Email (Nudge)
**Subject:** Have you shared your form yet?

**Body:**
Hey [Name],

Quick check-in! You created your Form-a-Friend account 3 days ago. Have you shared your form with your friends yet?

If not, here's your unique link:
**faf.app/form/[username]**

Copy-paste this into your group chat or send it individually. Your friends don't need to create an account—they just fill it out.

**Pro tip:** Start with 3-5 close friends. Quality > quantity.

You have 4 days left in your free trial. Make the most of it!

Riri

---

#### Day 6 Email (Pre-Payment)
**Subject:** Your trial ends tomorrow. Here's what you've accomplished.

**Body:**
Hey [Name],

Your 7-day free trial ends tomorrow.

Here's what happened:
- [X] responses collected
- [X] private comparison links generated
- You stayed close with [X] friends this month

**Tomorrow, you'll be asked to subscribe for €12/month to keep access.**

Why subscribe?
- €12/month = €0.40/day to never lose your friends
- Less than 1 coffee
- Infinitely cheaper than regret

Ready to commit?
[Subscribe Now - €12/month]

Not ready? Your data will be saved for 30 days if you want to come back.

Questions? Reply to this email.

Riri

---

#### Post-Payment Email (Thank You)
**Subject:** Thank you for believing in intentional friendships ❤️

**Body:**
Hey [Name],

Thank you for subscribing to Form-a-Friend.

You just invested €12/month in something most people take for granted: your friendships.

That makes you rare. That makes you intentional.

**What's next:**
- Keep sharing your form every month
- Watch your dashboard grow
- See your friendships stay alive

You're now part of a small community of people who refuse to let their relationships drift.

Welcome to the club.

Riri
Form-a-Friend

P.S. - Questions, feedback, ideas? Just reply. I read every email.

---

## Objection Handling

### Objection 1 : "€12/mois c'est cher pour un formulaire"

**Réponse courte :**
"Tu ne paies pas pour un formulaire. Tu paies pour ne jamais perdre de vue les gens qui comptent."

**Réponse longue :**
"€12/mois = €0,40/jour. C'est :
- Moins qu'un café (€1,50)
- Moins qu'un brunch avec une amie (€25)
- Moins que Netflix (€14)

**La vraie question :** Quel est le prix de perdre une amitié importante ?

FAF n'est pas un formulaire. C'est un système qui empêche tes amis de devenir des étrangers. C'est la différence entre 'j'aurais dû donner des nouvelles' et 'on est restés proches malgré la distance.'

Si tu valorises tes amitiés, €12/mois est une évidence."

---

### Objection 2 : "Je peux faire ça gratuitement avec Google Forms"

**Réponse courte :**
"Tu peux. Comme tu peux faire ton budget sur Excel au lieu d'utiliser YNAB. Mais tu ne le feras pas."

**Réponse longue :**
"Oui, techniquement tu peux :
1. Créer un Google Form (30 min setup)
2. Partager le lien manuellement (5 min)
3. Collecter les réponses (ok, automatique)
4. Calculer les comparaisons manuellement (1h de spreadsheet hell)
5. Générer les graphiques (30 min dans Excel)
6. Envoyer les liens privés un par un (15 min)
7. Tout refaire le mois prochain (2h+)

**Total : 4-5h/mois de travail manuel.**

Ou tu paies €12/mois et FAF fait tout ça en 10 minutes.

**La question n'est pas 'peux-tu le faire gratuitement.' La question est 'vas-tu vraiment le faire tous les mois pendant un an ?'**

La réponse est non. C'est pour ça que FAF existe."

---

### Objection 3 : "Mes amis ne vont jamais remplir un formulaire"

**Réponse courte :**
"S'ils ne veulent pas investir 10 minutes pour rester proches, c'est peut-être un signal."

**Réponse longue :**
"Deux scénarios :

**Scénario 1 : Ils remplissent (90% des cas)**
Tes amis investissent 10 minutes parce qu'ils tiennent à toi. Le formulaire leur donne **permission et structure** pour partager. Beaucoup trouvent ça libérateur : 'Enfin un moyen facile de donner des nouvelles.'

**Scénario 2 : Ils ne remplissent pas**
Soit ils sont vraiment débordés (relance dans 2 semaines), soit... ils ne priorisent pas votre amitié.

Et dans ce cas, **FAF t'a rendu service.** Tu sais maintenant où investir ton énergie.

**Rappel :** FAF n'est pas pour forcer des gens à être tes amis. FAF est pour maintenir les amitiés qui comptent vraiment."

---

### Objection 4 : "J'attendrai qu'il y ait une version gratuite"

**Réponse courte :**
"FAF n'aura jamais de version gratuite. C'est un choix."

**Réponse longue :**
"Form-a-Friend est paid-only. Volontairement.

**Pourquoi ?**
Parce que les gens qui ne sont pas prêts à investir €12/mois dans leurs amitiés ne sont pas notre cible.

FAF est pour Emma : intentionnelle, proactive, qui comprend que les systèmes > la motivation.

Si €12/mois te semble cher pour ne jamais perdre tes amis, FAF n'est probablement pas pour toi. Et c'est ok.

On préfère 100 utilisateurs engagés à 10,000 utilisateurs gratuits qui churent après 2 semaines."

---

### Objection 5 : "Pourquoi pas juste relancer le WhatsApp group ?"

**Réponse courte :**
"Parce que personne ne le fera. Et tu le sais."

**Réponse longue :**
"Le WhatsApp group est mort depuis 4 mois. Pourquoi ?

1. **Personne n'ose briser le silence** : Trop de pression sociale
2. **Flood ou désert** : Soit 247 messages en 2h, soit rien
3. **Superficialité** : Memes et lol, pas de vraie profondeur
4. **Asymétrie** : 2 personnes postent tout, les autres lurk

**FAF résout chacun de ces problèmes :**
✅ Structure mensuelle = pas de pression constante
✅ Questions guidées = profondeur naturelle
✅ Format asynchrone = chacun répond quand il veut
✅ Réciprocité visible = tout le monde participe

Tu peux relancer le group chat. Ou tu peux mettre un système en place qui marche vraiment."

---

## Garanties et Politiques

### Période d'Essai de 7 Jours

**Engagement :**
Essai gratuit complet sans carte bancaire requise.

**Accès pendant l'essai :**
- Toutes les features du produit
- Aucune limitation artificielle
- Support complet

**Fin de l'essai :**
- Redirection vers page Stripe Checkout
- Si paiement → abonnement actif
- Si pas de paiement → accès bloqué, données conservées 30 jours

---

### Politique d'Annulation

**Annulation à tout moment :**
- 1 clic depuis le dashboard
- Aucun frais d'annulation
- Aucune pénalité

**Après annulation :**
- Accès maintenu jusqu'à la fin du mois payé
- Données conservées 30 jours
- Possibilité de réactiver sans perte de données

**Pas de remboursement :**
Abonnement mensuel = pas de remboursement pro-rata. Si tu annules le 15, tu as accès jusqu'au 30.

---

### Politique de Données

**Conservation :**
- Données conservées tant que compte actif
- 30 jours après annulation avant suppression définitive
- Possibilité d'export manuel avant suppression (sur demande)

**Propriété :**
- Tu es propriétaire de tes données
- Tes amis sont propriétaires de leurs réponses
- FAF ne vend jamais les données à des tiers

**Sécurité :**
- Row Level Security (RLS) PostgreSQL
- Isolation totale par admin
- Sauvegardes automatiques quotidiennes
- Encryption en transit (HTTPS)

**RGPD Compliance :**
- Droit à l'export
- Droit à la suppression
- Droit à la portabilité
- Privacy by design

---

## Métriques de Succès de l'Offre

### Métriques d'Acquisition

**Trial Sign-Up Rate :**
- Target : 5-10% des visiteurs uniques
- Benchmark : Apps SaaS similaires = 3-8%

**Trial → Paid Conversion Rate :**
- Target : 30-40%
- Benchmark : SaaS B2C = 20-30%

**Time to First Value (TTFV) :**
- Target : <24h (user crée form + reçoit 1ère réponse)
- Benchmark : Apps productivité = 24-48h

---

### Métriques d'Engagement

**Form Completion Rate :**
- Target : >70% des admins remplissent leur propre form
- Red flag : <50%

**Response Collection Rate :**
- Target : 3-5 réponses reçues par admin en mois 1
- Good : >5 réponses

**Monthly Active Rate :**
- Target : >60% des admins remplissent le form chaque mois
- Benchmark : Habit apps = 40-60%

---

### Métriques de Rétention

**Month 2 Retention :**
- Target : >60%
- Benchmark : SaaS B2C = 40-60%

**Month 3 Retention :**
- Target : >50%
- Benchmark : SaaS B2C = 30-50%

**Month 6 Retention :**
- Target : >40%
- Good : >50%

**Churn Rate :**
- Target : <10% monthly churn
- Acceptable : <15%

---

### Métriques Économiques

**CAC (Customer Acquisition Cost) :**
- Target : <€10 (phase early, word-of-mouth)
- Acceptable : <€20

**LTV (Lifetime Value) :**
- Target : €144 (12 mois retention)
- Good : €216 (18 mois)
- Excellent : €288+ (24 mois)

**LTV/CAC Ratio :**
- Target : >10x (€144 LTV / €10 CAC)
- Minimum viable : >3x

**MRR (Monthly Recurring Revenue) :**
- Q1 2026 : €120-180 (10-15 admins)
- Q2 2026 : €300-500 (25-40 admins)
- Q4 2026 : €1,200+ (100 admins)

**Payback Period :**
- Target : <1 mois (1 paiement couvre CAC)
- Acceptable : <3 mois

---

## Conclusion : L'Offre FAF en Une Page

**Produit :** Système de continuité relationnelle via formulaires mensuels guidés

**Cible :** Emma, 25-30 ans, cadre urbaine, intentionnelle sur ses relations

**Problème résolu :** Empêcher les amis proches de devenir des "catchup friends"

**Prix :** €12/mois (ou €120/an), essai gratuit 7 jours

**Features MVP :**
- Formulaire mensuel standardisé (11 questions)
- Partage via lien unique
- Comparaisons privées automatiques
- Dashboard admin complet
- Paiement Stripe intégré
- Upload d'images
- Sécurité maximale (RLS, rate limiting)

**USP :**
- Seul système proactif de prévention de dérive relationnelle
- Structure sans pression (questions guidées, format asynchrone)
- Profondeur > Volume (pas de networking, focus intimité)
- Intimité préservée (comparaisons privées, pas de feed social)
- Simplicité radicale (3 étapes, 10 min/mois)

**Positionnement vs alternatives :**
WhatsApp → Communication vs Système
Calendar → Rappel vs Contenu guidé
Instagram → Illusion vs Profondeur
Notion DIY → Setup complexe vs Clé-en-main

**Garanties :**
- 7 jours gratuits sans CB
- Annulation à tout moment
- Données conservées 30 jours

**Objectif 2026 :**
100 admins payants, €1,200 MRR, produit mature en maintenance

---

*Document créé pour Form-a-Friend | Novembre 2025*
