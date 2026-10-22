@echo off
cd /d "%~dp0"
title JARVIS Reverse Engineering Workbench
echo ===============================================================
echo          JARVIS Reverse Engineering Workbench v0.1
echo ===============================================================
echo Starting local FastAPI server on http://127.0.0.1:8000 ...
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause
