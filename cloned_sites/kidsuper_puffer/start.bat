@echo off
cd /d "%~dp0"
start "" http://localhost:3014/
node ..\_outils\server.mjs . 3014

