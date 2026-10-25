@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -m venv .venv
    echo Installing requirements...
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)
rem Install any newly added dependency (e.g. watchdog for the ransomware module)
.venv\Scripts\python.exe -c "import watchdog" 2>nul || .venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
pause
