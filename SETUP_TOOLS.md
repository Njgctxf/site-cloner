# Outils externes (non versionnés) - à lire après avoir cloné ce dépôt

Ce dossier contient des **binaires** (plusieurs centaines de Mo) volontairement
exclus du dépôt Git (voir `.gitignore`). Si tu clones ce projet pour la
première fois, ce dossier sera vide - c'est normal, pas une erreur.

## Installation en une commande

Depuis la racine du projet :

```bash
python scripts/install_tools.py
```

Ça télécharge et installe automatiquement :

| Outil | Rôle | Dossier attendu |
|---|---|---|
| Nuclei | Scanner CVE / mauvaises configs | `tools_bin/nuclei/nuclei.exe` |
| OWASP ZAP | Scan OWASP Top 10 | `tools_bin/zap/ZAP_2.17.0/zap.bat` |
| Trivy | Dépendances & secrets | `tools_bin/trivy/trivy.exe` |
| Gitleaks | Secrets exposés dans le code | `tools_bin/gitleaks/gitleaks.exe` |
| JRE (Temurin 17) | Requis par ZAP | `tools_bin/jre/jdk-17.0.21+9-jre/bin/java.exe` |
| Redis (Windows) | File de tâches (RQ) | `tools_bin/redis/redis-server.exe` |

Semgrep n'est pas ici : il s'installe via `pip install semgrep` (voir
`requirements.txt`), pas de binaire à télécharger.

Le script n'installe pas OWASP ZAP ni le JRE (installs multi-fichiers plus
lourds) - l'essentiel de la couverture (Nuclei, Trivy, Gitleaks, Semgrep)
fonctionne sans eux. Pour les ajouter manuellement :
- ZAP : https://www.zaproxy.org/download/ (version crossplatform/zip) → extraire dans `tools_bin/zap/`
- JRE : https://adoptium.net/temurin/releases/ (17, zip Windows x64) → extraire dans `tools_bin/jre/`

## Sans le script

Si le script échoue sur ta machine, chaque outil peut être téléchargé
manuellement depuis sa page de releases officielle - voir les URLs dans
`scripts/install_tools.py`, section par section.

## Après l'installation

Lance Redis une fois avant d'utiliser la file de tâches (RQ) :

```bash
tools_bin/redis/redis-server.exe tools_bin/redis/redis.windows.conf
```
