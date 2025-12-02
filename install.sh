#!/bin/bash

# ZTNA Simulator Installation Script
# This script sets up the environment and generates all required certificates

set -e  # Exit on error

echo "=========================================="
echo "ZTNA Simulator Installation"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Python 3 is installed
echo -e "\n${YELLOW}Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed. Please install Python 3.8+ first.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}✓ Python ${PYTHON_VERSION} found${NC}"

# Check if OpenSSL is installed (needed for certificate generation)
echo -e "\n${YELLOW}Checking OpenSSL installation...${NC}"
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: OpenSSL is not installed.${NC}"
    echo "Install with:"
    echo "  macOS: brew install openssl"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  CentOS/RHEL: sudo yum install openssl"
    exit 1
fi
echo -e "${GREEN}✓ OpenSSL found${NC}"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Step 1: Create virtual environment
echo -e "\n${YELLOW}Step 1: Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists. Skipping...${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi

# Step 2: Activate virtual environment
echo -e "\n${YELLOW}Step 2: Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Step 3: Upgrade pip
echo -e "\n${YELLOW}Step 3: Upgrading pip...${NC}"
pip install --upgrade pip --quiet
echo -e "${GREEN}✓ pip upgraded${NC}"

# Step 4: Install dependencies
echo -e "\n${YELLOW}Step 4: Installing dependencies...${NC}"
pip install -r requirements.txt --quiet
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 5: Generate OpenVPN certificates
echo -e "\n${YELLOW}Step 5: Generating OpenVPN certificates...${NC}"

CERT_DIR="$SCRIPT_DIR"
cd "$CERT_DIR"

# Check if certificates already exist
if [ -f "ca.crt" ] && [ -f "server.crt" ] && [ -f "client.crt" ]; then
    echo -e "${YELLOW}Certificates already exist. Regenerate? (y/n)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✓ Using existing certificates${NC}"
        exit 0
    fi
    echo -e "${YELLOW}Removing old certificates...${NC}"
    rm -f ca.crt ca.key server.crt server.key client.crt client.key dh2048.pem ca.srl
fi

# Generate CA (Certificate Authority)
echo -e "${YELLOW}Generating Certificate Authority...${NC}"
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=IT/CN=ZTNA-CA" 2>/dev/null
chmod 600 ca.key
chmod 644 ca.crt
echo -e "${GREEN}✓ CA certificate generated${NC}"

# Generate server certificate
echo -e "${YELLOW}Generating server certificate...${NC}"
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Server/CN=server" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 3650 -extensions v3_req 2>/dev/null
chmod 600 server.key
chmod 644 server.crt
rm server.csr
echo -e "${GREEN}✓ Server certificate generated${NC}"

# Generate client certificate
echo -e "${YELLOW}Generating client certificate...${NC}"
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Client/CN=client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 3650 -extensions v3_req 2>/dev/null
chmod 600 client.key
chmod 644 client.crt
rm client.csr
echo -e "${GREEN}✓ Client certificate generated${NC}"

# Generate Diffie-Hellman parameters
echo -e "${YELLOW}Generating Diffie-Hellman parameters (this may take a minute)...${NC}"
openssl dhparam -out dh2048.pem 2048 2>/dev/null
chmod 600 dh2048.pem
echo -e "${GREEN}✓ DH parameters generated${NC}"

# Step 6: Verify certificates
echo -e "\n${YELLOW}Step 6: Verifying certificates...${NC}"
if [ -f "ca.crt" ] && [ -f "server.crt" ] && [ -f "client.crt" ] && [ -f "dh2048.pem" ]; then
    echo -e "${GREEN}✓ All certificates generated successfully${NC}"
    echo ""
    echo "Certificate files:"
    ls -lh ca.crt server.crt client.crt dh2048.pem 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
else
    echo -e "${RED}Error: Some certificates are missing${NC}"
    exit 1
fi

# Step 7: Check OpenVPN installation (optional)
echo -e "\n${YELLOW}Step 7: Checking OpenVPN installation (optional)...${NC}"
if command -v openvpn &> /dev/null; then
    OPENVPN_VERSION=$(openvpn --version | head -n 1)
    echo -e "${GREEN}✓ OpenVPN found: ${OPENVPN_VERSION}${NC}"
    echo -e "${YELLOW}  Note: OpenVPN is optional. System works in mock mode if not available.${NC}"
else
    echo -e "${YELLOW}⚠ OpenVPN not installed (optional)${NC}"
    echo "  Install with:"
    echo "    macOS: brew install openvpn"
    echo "    Ubuntu/Debian: sudo apt-get install openvpn"
    echo "    CentOS/RHEL: sudo yum install openvpn"
    echo -e "${YELLOW}  System will work in mock mode without OpenVPN.${NC}"
fi

# Step 8: Create necessary directories
echo -e "\n${YELLOW}Step 8: Creating necessary directories...${NC}"
mkdir -p temp_ovpn
touch ipp.txt
touch openvpn-status.log
echo -e "${GREEN}✓ Directories created${NC}"

# Summary
echo -e "\n${GREEN}=========================================="
echo "Installation Complete!"
echo "==========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Start the servers (in separate terminals):"
echo "   python auth_server.py      # Port 5000"
echo "   python vpn_gateway.py      # Port 5001"
echo "   python policy_engine.py    # Port 5002"
echo ""
echo "3. Run verification:"
echo "   python test_openvpn_setup.py"
echo ""
echo "4. Test the system:"
echo "   python ztna_client.py login alice@company.com:password123"
echo ""
echo -e "${YELLOW}Note: Certificates are valid for 10 years.${NC}"
echo -e "${YELLOW}Note: Keep ca.key, server.key, and client.key secure!${NC}"
echo ""

