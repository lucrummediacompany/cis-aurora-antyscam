@echo off
chcp 65001 >nul
title CIS Server (Aurora AntyScam)

echo ================== CIS SERVER STARTER ==================
set "ANALYZER_CMD=python -u analyzer_core.py --address {address}"
echo ANALYZER_CMD=%ANALYZER_CMD%
echo.

echo Starting CIS Flask server (serwer.py) ...
python serwer.py

pause
