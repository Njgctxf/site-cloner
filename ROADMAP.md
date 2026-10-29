# Roadmap SiteCloner SaaS

## Vision — un studio pour codeurs et vibe codeurs

Cloner un site sert de point de départ : on explore ses pages, on récupère des pages ou des sections, on extrait
son design system, puis on transforme le tout en **son propre** site. Le cloneur est un outil d'inspiration et
d'analyse, pas de copie à revendre : on ne vend sur la plateforme que des créations originales.

### Studio (en cours)
- [x] Miniatures de toutes les pages clonées
- [x] Tableau visuel des pages façon Framer (déplacement, zoom, sélection)
- [x] Export des pages choisies en archive autonome
- [x] Extraction du design system (couleurs, typographies, tailles, rayons, ombres) en tokens CSS / Tailwind / JSON
- [x] Détection des sections d'une page (en-tête, hero, grilles, pied de page) et export d'une section
- [x] Export en code propre d'une page ou d'une section : HTML indenté, CSS réduit aux règles utilisées, composant React (JSX), tokens Tailwind
- [ ] Code propre : conversion des styles en classes utilitaires Tailwind, projet Next.js prêt à lancer, découpage en composants
- [x] Inspecteur de composants : arbre de la page (en-tête, hero, sections, titres, textes, images, vidéos, 3D, liens,
      boutons, formulaires), sélection dans l'arbre ou dans la page, modification en direct (textes, liens, images, vidéos,
      intégrations), masquer / dupliquer, remplacement d'un modèle 3D ou d'un élément 3D, enregistrement avec historique
- [ ] Inspecteur : couleurs et typographies par élément, déplacement de blocs, bibliothèque de sections à insérer
- [ ] Personnalisation par IA (textes, palette, images) pour transformer la base en création
- [ ] Éditeur visuel et code (voir V3)
- [ ] Déploiement en un clic (Hostinger, Vercel, Netlify, sous-domaine de la plateforme)
- [ ] Historique des versions et retour en arrière

### Communauté et marketplace (quand il y aura des utilisateurs)
- [ ] Templates et composants originaux à vendre, licences claires (perso, commerciale, revente interdite)
- [ ] Profils créateurs, portfolio, avis
- [ ] Vente de compétences (adaptation de template, création de site sur devis)
- [ ] Paiements Stripe Connect avec commission de la plateforme
- [ ] Détection de plagiat des templates mis en vente (comparaison avec des sites existants)
- [ ] Conditions d'utilisation et procédure de retrait des contenus signalés

### Modèle économique
- Gratuit (quelques clonages, consultation), Pro (export du code, IA, déploiement), Équipe, commission marketplace

## V2 — à faire maintenant

### Demandes du propriétaire
- [x] **Tableau de bord admin** (`/admin`) : connexion, vue d'ensemble, sites clonés, jobs, changement de mot de passe
- [ ] Admin : utilisateurs, projets en vente, commandes, paramètres (viendront avec la boutique et les comptes)
- [x] **Boutique de projets** (`/shop/`) : ajouter ses propres projets (applications, sites, etc.) et les vendre directement sur le site
  - [x] Fiche projet : titre, description, couverture, prix, fichier livrable, démo en ligne
  - [x] Gestion depuis l'admin : créer, modifier, publier/dépublier, supprimer
  - [x] Page publique : catalogue + page détail + achat sans compte
  - [x] Paiement Stripe Checkout + lien de téléchargement sécurisé (7 jours, 5 téléchargements)
  - [x] Suivi des commandes et du chiffre d'affaires dans l'admin
  - [x] Marketplace : designs, templates, prompts, skills, logiciels, assets 3D ; produits gratuits ou payants,
        plusieurs images et vidéos, aperçu texte copiable, tags, mise en avant, recherche, filtres, favoris, aperçu rapide, démo
  - [x] Admin : vue d'ensemble (sites, pages, ventes, vues, téléchargements), éditeur de produit avec médias (glisser-déposer, ordre)
  - [x] Design system animé commun (cloneur, Studio, inspecteur, marketplace, admin) et miniatures des sites
  - [ ] Tester un vrai paiement Stripe (mode test) une fois les clés configurées
  - [ ] Configurer l'envoi d'e-mails (SMTP) pour envoyer le lien à l'acheteur

### Fiabilité du clonage
- [ ] Profiler et accélérer le clonage (74 s pour example.com, anormal)
- [ ] Anti-bot : aligner Playwright sur `curl_cffi` (`impersonate="chrome124"`) + repli sur 403 / défi Cloudflare
- [ ] Sites de référence + `verify_clone.py` comme test de non-régression

### Produit SaaS
- [ ] Comptes utilisateurs + quotas de clones
- [ ] File d'attente de jobs persistante (remplacer les threads en mémoire)
- [ ] Sortir `cloned_sites/` de git, stockage objet en production

### Export et qualité
- [ ] Déploiement en un clic (Netlify, Vercel, Hostinger) en plus du ZIP
- [ ] Rapport de fidélité clone/original
- [ ] Découper `cloner.py` en modules, ajouter des tests, mettre le README à jour

## V3 — en dernier
- [ ] **Éditeur visuel / de code** (édition dans l'aperçu, export) — repoussé volontairement en V3
- [ ] Export vers React / Next.js
