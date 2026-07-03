@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0\..\.."

if not exist .venv (
    python -m venv .venv
)

call .venv\Scripts\activate.bat

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --noconfirm --clean build.spec

echo.
echo Build finished.
echo Run: dist\AndroidKeystoreDecoder\AndroidKeystoreDecoder.exe
echo Zip dist\AndroidKeystoreDecoder and send the folder to colleagues.

endlocal
