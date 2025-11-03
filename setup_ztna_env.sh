set -e

PROJECT_DIR="$(pwd)"
VENV_DIR="$PROJECT_DIR/ztna-env"

echo "Setting up Python virtual environment!!!"
python3 -m venv "$VENV_DIR"

echo "Activating virtual environment!!!"
source "$VENV_DIR/bin/activate"

echo "Upgrading pip!!!"
pip install --upgrade pip setuptools wheel

echo "Installing Python dependencies!!!"
pip install flask pyjwt requests cryptography

echo "🔐 Installing system-level dependencies!!!"
# macOS or Linux detection
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🧰 Detected macOS — installing OpenVPN using Homebrew!!!"
    brew update
    brew install openvpn || echo "⚠️ If already installed, skipping."
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🧰 Detected Linux — installing OpenVPN via apt/yum!!!"
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y openvpn
    elif command -v yum &>/dev/null; then
        sudo yum install -y openvpn
    else
        echo "⚠️ Please install OpenVPN manually for your distro."
    fi
else
    echo "⚠️ Unsupported OS: please install OpenVPN manually."
fi

echo "Creating default .env file (if missing)!!!"
ENV_FILE="$PROJECT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
cat <<EOF > "$ENV_FILE"

JWT_SECRET=your-super-secret-key
ZTNA_OVPN=$PROJECT_DIR/openvpn-client.ovpn
OPENVPN_BIN=$(which openvpn)
OVPN_CONNECT_TIMEOUT=45
EOF
echo ".env created at $ENV_FILE"
else
    echo ".env already exists, skipping."
fi

echo "🔗 Ensuring your OVPN profile exists..."
if [[ ! -f "$PROJECT_DIR/openvpn-client.ovpn" ]]; then
    echo "❌ Missing openvpn-client.ovpn — please place it in:"
    echo "   $PROJECT_DIR/openvpn-client.ovpn"
else
    echo "Found openvpn-client.ovpn"
fi

echo ""
echo "Setup complete!"
echo "Next steps:"
echo "----------------------------------------"
echo "source $VENV_DIR/bin/activate"
echo "python auth_server.py       # Port 5000"
echo "sudo python vpn_gateway.py  # Port 5001"
echo "python policy_engine.py     # Port 5002"
echo ""
echo "💡 After servers are running, use:"
echo "curl -X POST http://127.0.0.1:5000/api/auth/login -d '{\"email\":\"alice@company.com\",\"password\":\"password123\"}' -H 'Content-Type: application/json'"
echo "----------------------------------------"
