@echo off
echo ==============================================
echo   Lancement du site 3D Igloo Inc. en local...
echo   Ouvrez: http://localhost:3001
echo ==============================================
start http://localhost:3001
python -m http.server 3001
pause
