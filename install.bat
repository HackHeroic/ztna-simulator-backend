@echo off
REM ZTNA Simulator Installation Script for Windows
REM This script sets up the environment and generates all required certificates

echo ==========================================
echo ZTNA Simulator Installation (Windows)
echo ==========================================
echo.

REM Check if Python is installed
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed. Please install Python 3.8+ first.
    exit /b 1
)
echo ✓ Python found
echo.

REM Check if OpenSSL is installed
echo Checking OpenSSL installation...
where openssl >nul 2>&1
if errorlevel 1 (
    echo Error: OpenSSL is not installed.
    echo Install from: https://slproweb.com/products/Win32OpenSSL.html
    echo Or use: choco install openssl
    exit /b 1
)
echo ✓ OpenSSL found
echo.

REM Get script directory
cd /d "%~dp0"

REM Step 1: Create virtual environment
echo Step 1: Creating virtual environment...
if exist venv (
    echo Virtual environment already exists. Skipping...
) else (
    python -m venv venv
    echo ✓ Virtual environment created
)
echo.

REM Step 2: Activate virtual environment
echo Step 2: Activating virtual environment...
call venv\Scripts\activate.bat
echo ✓ Virtual environment activated
echo.

REM Step 3: Upgrade pip
echo Step 3: Upgrading pip...
python -m pip install --upgrade pip --quiet
echo ✓ pip upgraded
echo.

REM Step 4: Install dependencies
echo Step 4: Installing dependencies...
pip install -r requirements.txt --quiet
echo ✓ Dependencies installed
echo.

REM Step 5: Generate OpenVPN certificates
echo Step 5: Generating OpenVPN certificates...

REM Check if certificates already exist
if exist ca.crt if exist server.crt if exist client.crt (
    set /p REGEN="Certificates already exist. Regenerate? (y/n): "
    if /i not "%REGEN%"=="y" (
        echo ✓ Using existing certificates
        goto :end
    )
    echo Removing old certificates...
    del /f ca.crt ca.key server.crt server.key client.crt client.key dh2048.pem ca.srl 2>nul
)

REM Generate CA
echo Generating Certificate Authority...
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=IT/CN=ZTNA-CA" >nul 2>&1
echo ✓ CA certificate generated

REM Generate server certificate
echo Generating server certificate...
openssl genrsa -out server.key 2048 >nul 2>&1
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Server/CN=server" >nul 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 >nul 2>&1
del server.csr 2>nul
echo ✓ Server certificate generated

REM Generate client certificate
echo Generating client certificate...
openssl genrsa -out client.key 2048 >nul 2>&1
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Client/CN=client" >nul 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650 >nul 2>&1
del client.csr 2>nul
echo ✓ Client certificate generated

REM Generate DH parameters
echo Generating Diffie-Hellman parameters (this may take a minute)...
openssl dhparam -out dh2048.pem 2048 >nul 2>&1
echo ✓ DH parameters generated
echo.

REM Step 6: Create necessary directories
echo Step 6: Creating necessary directories...
if not exist temp_ovpn mkdir temp_ovpn
if not exist ipp.txt type nul > ipp.txt
if not exist openvpn-status.log type nul > openvpn-status.log
echo ✓ Directories created
echo.

:end
echo ==========================================
echo Installation Complete!
echo ==========================================
echo.
echo Next steps:
echo 1. Activate virtual environment:
echo    venv\Scripts\activate
echo.
echo 2. Start the servers (in separate command prompts):
echo    python auth_server.py      # Port 5000
echo    python vpn_gateway.py      # Port 5001
echo    python policy_engine.py    # Port 5002
echo.
echo 3. Run verification:
echo    python test_openvpn_setup.py
echo.
pause

