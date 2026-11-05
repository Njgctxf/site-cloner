#!/usr/bin/env bash
# ==============================================================================
# Script de déploiement PentAGI pour ULTON AI (Serveur Linux / Cloud)
# ==============================================================================
set -e

echo "=== Démarrage PentAGI Stack pour ULTON AI ==="

if ! command -v docker &> /dev/null; then
    echo "[ERREUR] Docker n'est pas installé sur ce serveur."
    exit 1
fi

if [ ! -f .env ]; then
    echo "[INFO] Création du fichier .env..."
    cp .env.example .env
fi

echo "[INFO] Lancement des conteneurs PentAGI..."
docker compose up -d

echo "=== PentAGI est prêt et connecté à ULTON AI sur http://127.0.0.1:8443 ==="
