@echo off
title SiteCloner SaaS v2 Engine
echo ========================================================
echo         SiteCloner SaaS v2 - Cloneur de Sites Web
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/3] Verification des dependances Python...
python -m pip install -r requirements.txt --quiet

echo.
echo [2/3] Verification des navigateurs Playwright...
python -m playwright install chromium

echo.
echo [3/3] Demarrage de l'application SaaS sur http://localhost:5050 ...
echo.
set PORT=5050
start "" http://localhost:5050
python app.py
pause
