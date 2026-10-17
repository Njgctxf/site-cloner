@echo off
title SiteCloner SaaS Engine
echo ========================================================
echo          SiteCloner SaaS - Cloneur de Sites Web
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Verification des dependances Python...
python -m pip install -r requirements.txt --quiet

echo.
echo [2/2] Demarrage de l'application SaaS sur http://localhost:5000 ...
echo.
start "" http://localhost:5000
python app.py
pause
