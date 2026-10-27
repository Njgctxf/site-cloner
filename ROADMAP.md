# Roadmap SiteCloner SaaS

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
