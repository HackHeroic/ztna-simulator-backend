# ZTNA VPN Simulator - Backend

A comprehensive Zero Trust Network Access (ZTNA) VPN simulator backend system with authentication, VPN gateway, and policy engine services.

## Architecture

The system consists of three main services:

1. **Auth Server** (Port 5000): User authentication and JWT token management
2. **VPN Gateway** (Port 5001): VPN connection management and routing
3. **Policy Engine** (Port 5002): Risk assessment, anomaly detection, and access policies

## Features

- **JWT-based Authentication**: Secure token-based authentication
- **VPN Connection Management**: OpenVPN integration with secure tunnel fallback
- **Continuous Authentication**: Periodic risk assessment for active connections
- **Anomaly Detection**: Real-time threat detection and logging
- **Threat Intelligence**: Threat user tracking and management
- **Role-Based Access Control**: Clearance level-based permissions
- **Persistent Logging**: All events logged to JSON files

## Prerequisites

- Python 3.8+
- OpenVPN (optional - system works with secure tunnel mode)
- Virtual environment (recommended)

## Installation

1. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install OpenVPN:
```bash
# macOS
brew install openvpn

# Ubuntu/Debian
sudo apt-get install openvpn

# CentOS/RHEL
sudo yum install openvpn
```

## Running the Services

### Start All Services

Run each service in a separate terminal:

**Terminal 1 - Auth Server:**
```bash
cd ztna-simulator-backend
source venv/bin/activate
python auth_server.py
```

**Terminal 2 - VPN Gateway:**
```bash
cd ztna-simulator-backend
source venv/bin/activate
python vpn_gateway.py
```

**Terminal 3 - Policy Engine:**
```bash
cd ztna-simulator-backend
source venv/bin/activate
python policy_engine.py
```

### Using Installation Scripts

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```bash
install.bat
```

## API Endpoints

### Auth Server (Port 5000)

- `POST /api/auth/login` - User login
- `GET /api/auth/verify` - Verify token
- `POST /api/access/check` - Check resource access
- `POST /api/access/request-vpn` - Request VPN token
- `GET /health` - Health check

### VPN Gateway (Port 5001)

- `POST /api/vpn/connect` - Connect to VPN
- `POST /api/vpn/disconnect` - Disconnect VPN
- `POST /api/vpn/status` - Get VPN status
- `GET /api/vpn/connections` - List all connections
- `POST /api/vpn/routes` - Get routing table
- `GET /api/vpn/continuous-auth-log` - Get continuous auth logs
- `GET /health` - Health check

### Policy Engine (Port 5002)

- `POST /api/policy/evaluate` - Evaluate access policy
- `POST /api/policy/continuous-auth` - Continuous authentication
- `POST /api/policy/session-status` - Get session status
- `POST /api/policy/anomaly-detect` - Detect anomalies
- `GET /api/policy/location-detect` - Detect location from IP
- `GET /api/policy/policies` - Get policy configuration
- `GET /api/policy/access-metrics` - Get access metrics
- `GET /api/policy/threat-users` - Get threat users (clearance 3+)
- `POST /api/policy/threat-users/<email>` - Update threat user (clearance 4+)
- `GET /api/policy/resources` - Get resources list
- `GET /health` - Health check

## Configuration

### Environment Variables

```bash
export JWT_SECRET="your-super-secret-key"
export VPN_SUBNET="10.8.0.0/24"
```

### User Accounts

Default users are defined in `auth_server.py`:

- `alice@company.com` / `password123` - Developer (Clearance 3)
- `bob@company.com` / `securepass` - Admin (Clearance 5)
- `charlie@company.com` / `userpass` - Analyst (Clearance 2)
- `diana@company.com` / `security123` - Security (Clearance 4)
- `eve@company.com` / `audit123` - Auditor (Clearance 3)
- `frank@company.com` / `manager123` - Manager (Clearance 2)
- `grace@company.com` / `intern123` - Intern (Clearance 1)

## Log Files

All logs are stored in `logs/` directory:

- `access_log.json` - All access attempts
- `anomalies_log.json` - Detected anomalies
- `continuous_auth_log.json` - Continuous authentication events
- `threat_users.json` - Threat user intelligence

Logs are automatically persisted and loaded on startup.

## VPN Connection Modes

1. **OpenVPN Mode**: Full OpenVPN tunnel (requires OpenVPN installation)
2. **Secure Tunnel Mode**: Simulated secure tunnel (works without OpenVPN)

The system automatically falls back to secure tunnel mode if OpenVPN is unavailable.

## Security Features

### Continuous Authentication
- Periodic risk assessment every 5 minutes
- Automatic connection termination on high risk
- Risk score tracking per connection

### Anomaly Detection
- Location-based anomalies
- Device compliance checks
- Velocity anomaly detection
- IP reputation checking

### Threat Intelligence
- Threat user tracking
- Activity pattern analysis
- Risk score aggregation
- Clearance-based access control

## Testing

### Quick Test
```bash
source venv/bin/activate
python test_openvpn_setup.py
```

### Connection Test
```bash
source venv/bin/activate
python test_openvpn_connection.py
```

## Troubleshooting

### OpenVPN Issues
- System works in secure tunnel mode without OpenVPN
- Check OpenVPN installation: `which openvpn`
- Verify server config: `server.ovpn`

### Port Conflicts
- Ensure ports 5000, 5001, 5002 are available
- Check firewall settings
- Verify no other services are using these ports

### Connection Issues
- Check VPN gateway logs
- Verify policy engine is running
- Check authentication token validity

## Development

### Adding New Risk Factors
Edit `RISK_FACTORS` in `policy_engine.py`:

```python
RISK_FACTORS = {
    'new_factor': 25,  # Risk score (0-100)
    ...
}
```

### Adding New Resources
Edit `RESOURCE_POLICIES` in `policy_engine.py`:

```python
RESOURCE_POLICIES = {
    'new-resource': {
        'sensitivity': 'high',
        'require_mfa': True,
        'require_low_risk': True,
        ...
    }
}
```

### Updating Threat Users
Threat users are stored in `logs/threat_users.json` and can be:
- Viewed via API (clearance 3+)
- Updated via API (clearance 4+)
- Automatically updated by anomaly detection

## License

See LICENSE file for details.
