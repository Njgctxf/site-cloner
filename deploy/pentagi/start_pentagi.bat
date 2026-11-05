@echo off
title Demarrage PentAGI Stack pour ULTON AI
echo ===================================================
echo   LANCEMENT DU STACK PENTAGI POUR ULTON AI (SENTINEL)
echo ===================================================

where docker >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERREUR] Docker n'est pas installe ou pas dans le PATH.
    echo Installez Docker Desktop ou lancez ce script sur votre serveur en ligne.
    pause
    exit /b 1
)

if not exist .env (
    echo [INFO] Creation du fichier .env depuis .env.example...
    copy .env.example .env
)

echo [INFO] Demarrage des conteneurs PentAGI (API Go, Workers Sandbox, PostgreSQL pgvector)...
docker compose up -d

echo.
echo ===================================================
echo [SUCCES] Stack PentAGI demarre avec succes !
echo - API REST/GraphQL : http://127.0.0.1:8443
echo - Web Dashboard    : http://127.0.0.1:3030
echo.
echo Ulton AI se connecte automatiquement sur http://127.0.0.1:8443
echo ===================================================
pause
