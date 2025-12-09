# VPN Gateway (vpn_gateway.py)

## Overview

The VPN Gateway manages VPN connections, IP address assignments, and OpenVPN integration. It handles client certificate generation, connection lifecycle management, and provides real-time status monitoring. The gateway supports both OpenVPN (full VPN tunnel) and mock mode (simulated secure tunnel) for testing.

**Port:** 5001  
**Base URL:** `http://localhost:5001`

## Working Mechanism

### Connection Flow

1. **Authentication**: User authenticates with Auth Server and receives VPN token
2. **Policy Evaluation**: VPN Gateway calls Policy Engine to evaluate access request
3. **Certificate Generation**: Per-user client certificate generated (cached for reuse)
4. **OpenVPN Client Start**: Client process started with user-specific certificate
5. **IP Assignment**: VPN IP assigned from pool (10.8.0.2 - 10.8.0.254)
6. **Connection Tracking**: Connection tracked in `connections` dictionary
7. **Continuous Auth**: Periodic risk checks every 5 minutes
8. **Disconnection**: Cleanup of IP assignment and connection tracking

### IP Assignment System

**Single Source of Truth Approach:**
- `assigned_ips` dictionary is the **only** source of truth for IP assignments
- OpenVPN files (`ipp.txt`, `openvpn-status.log`) are for reference/debugging only
- IPs are assigned immediately when connection is created
- IPs are released immediately when connection is disconnected
- Lowest available IP is always assigned (starts from 10.8.0.2)

**IP Pool:**
- Range: 10.8.0.2 to 10.8.0.254 (253 available IPs)
- 10.8.0.1 is reserved for VPN server
- IPs are reused immediately when freed

### Connection Modes

1. **OpenVPN Mode**: Full OpenVPN tunnel (requires OpenVPN installation)
   - Real VPN connection with TUN/TAP interface
   - Requires root privileges for TUN/TAP device
   - Uses client certificates for authentication

2. **Mock Mode**: Simulated secure tunnel (works without OpenVPN)
   - Simulates VPN connection without actual tunnel
   - No root privileges required
   - Used for testing and development

3. **Mock Fallback**: Automatic fallback when OpenVPN fails
   - OpenVPN client process fails to start
   - System automatically falls back to mock mode
   - Connection still tracked and functional

## Certificate Requirements

### Why Certificates Are Needed

OpenVPN uses **Public Key Infrastructure (PKI)** for authentication:

1. **Mutual Authentication**: Both client and server verify each other's identity
2. **Encryption**: Certificates enable TLS encryption of VPN traffic
3. **User Identification**: Certificate Common Name (CN) identifies the user
4. **Non-Repudiation**: Cryptographic proof of user identity

### Certificate Files Explained

#### CA Certificate (`ca.crt` and `ca.key`)

**Purpose:** Certificate Authority that signs all certificates

**Why needed:**
- **Trust Anchor**: Establishes trust hierarchy
- **Certificate Signing**: Signs server and client certificates
- **Verification**: Clients verify server certificate using CA cert
- **Server Verification**: Server verifies client certificates using CA cert

**Generation:**
```bash
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
    -days 3650 -nodes \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=IT/CN=ZTNA-CA"
```

**Security:**
- `ca.key` must be kept secret (permissions: 600)
- `ca.crt` is public and distributed to all clients
- If CA key is compromised, entire PKI is compromised

---

#### Server Certificate (`server.crt` and `server.key`)

**Purpose:** Identifies the VPN server to clients

**Why needed:**
- **Server Authentication**: Clients verify they're connecting to legitimate server
- **TLS Handshake**: Required for TLS encryption establishment
- **Man-in-the-Middle Prevention**: Prevents attackers from impersonating server

**Generation:**
```bash
# 1. Generate private key
openssl genrsa -out server.key 2048

# 2. Generate certificate signing request
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Server/CN=server"

# 3. Sign with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 3650 \
    -extensions v3_req -extfile server.ext
```

**Key Usage Extension:**
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = serverAuth`
- Required for OpenVPN to properly identify server certificate

---

#### Client Certificates (`client_<user>@company.com.crt` and `.key`)

**Purpose:** Identifies individual users connecting to VPN

**Why needed:**
- **User Authentication**: Server verifies user identity via certificate CN
- **Per-User Certificates**: Each user gets unique certificate with email as CN
- **Revocation Capability**: Individual certificates can be revoked
- **Audit Trail**: Certificate CN provides user identification in logs

**Generation Process:**
1. **Private Key**: Generated per user (2048-bit RSA)
2. **Certificate Signing Request (CSR)**: Contains user email as CN
3. **CA Signing**: CA signs certificate with Key Usage extension
4. **Verification**: Certificate verified to have correct CN and Key Usage

**Certificate CN Format:**
```
CN=alice@company.com
```

**Key Usage Extension:**
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = clientAuth`
- Required for OpenVPN to extract CN from certificate

**Caching:**
- Certificates are cached per user (generated once, reused)
- Validated on each use (checks expiration and CN)
- Regenerated if expired or CN mismatch

---

#### Diffie-Hellman Parameters (`dh2048.pem`)

**Purpose:** Enables secure key exchange for TLS

**Why needed:**
- **Perfect Forward Secrecy**: Ensures past sessions can't be decrypted if keys are compromised
- **Key Exchange**: Enables secure exchange of encryption keys
- **TLS Requirement**: Required by OpenVPN for TLS handshake

**Generation:**
```bash
openssl dhparam -out dh2048.pem 2048
```

**Note:** Generation takes several minutes (computationally intensive)

---

### Certificate Chain of Trust

```
CA Certificate (ca.crt)
    ├── Signs Server Certificate (server.crt)
    │       └── Used by OpenVPN server
    │
    └── Signs Client Certificates (client_*.crt)
            ├── client_alice@company.com.crt
            ├── client_bob@company.com.crt
            └── ...
```

**Verification Flow:**
1. Client receives server certificate
2. Client verifies server cert is signed by CA (using `ca.crt`)
3. Server receives client certificate
4. Server verifies client cert is signed by CA (using `ca.crt`)
5. Both parties trust certificates signed by same CA

---

### Common Certificate Issues

#### "UNDEF" Common Name

**Problem:** OpenVPN shows "UNDEF" instead of user email in status log

**Causes:**
1. Missing Key Usage extension in certificate
2. Certificate CN format issue
3. OpenVPN server configuration issue

**Solution:**
- Ensure Key Usage extension includes `digitalSignature` and `keyEncipherment`
- Verify CN format: `CN=user@email.com`
- Regenerate certificate with proper extensions

#### Certificate Expiration

**Problem:** Certificate expired, connection fails

**Solution:**
- Certificates are valid for 1 year
- System automatically regenerates expired certificates
- Check certificate: `openssl x509 -in client_*.crt -noout -dates`

#### Certificate CN Mismatch

**Problem:** Certificate CN doesn't match user email

**Solution:**
- System detects mismatch and regenerates certificate
- Verify CN: `openssl x509 -in client_*.crt -noout -subject`
- Ensure CN matches user email exactly

## API Endpoints

### Connection Management

#### 1. `/api/vpn/connect` (POST)

**Purpose:** Establish VPN connection for authenticated user

**Request Body:**
```json
{
  "vpn_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "device": {
    "os_type": "macOS",
    "os_version": "12.0",
    "encrypted": true,
    "rooted": false
  },
  "client_ip": "192.168.1.100",
  "location": {
    "country": "US",
    "city": "New York"
  }
}
```

**Response (Success):**
```json
{
  "connection_id": "vpn-alice@company.com-1765284778",
  "real_client_ip": "192.168.1.100",
  "location": {
    "country": "US",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "status": "connected",
  "ip": "10.8.0.2",
  "routes": ["10.0.0.0/8", "192.168.0.0/16"],
  "connection_mode": "openvpn"
}
```

**Response (Error):**
```json
{
  "error": "Access denied by policy",
  "reason": "High risk",
  "risk_score": 75
}
```
Status: 403 Forbidden

**How it works:**
1. **Token Validation**: Decodes and validates VPN token from Auth Server
2. **Single Connection Enforcement**: Removes all existing connections for user
3. **Policy Evaluation**: Calls Policy Engine to evaluate access request
4. **Real IP/Location Detection**: Captures real client IP and location BEFORE VPN
5. **OpenVPN Daemon Start**: Ensures OpenVPN server is running
6. **Certificate Generation**: Generates or retrieves cached client certificate
7. **Client Config Creation**: Creates `.ovpn` config file with:
   - CA certificate reference
   - Client certificate and key
   - Server address (127.0.0.1:1194)
   - Routes (10.0.0.0/8, 192.168.0.0/16)
8. **OpenVPN Client Start**: Starts OpenVPN client process
9. **IP Assignment**: Waits for OpenVPN to assign IP, or assigns from pool
10. **Connection Tracking**: Stores connection in `connections` dictionary with:
    - Real client IP and location (BEFORE VPN)
    - VPN-assigned IP (AFTER VPN)
    - Connection metadata
11. **IP Tracking**: Adds IP to `assigned_ips` dictionary

**Important Notes:**
- Real client IP/location is stored BEFORE VPN connection
- This ensures Policy Engine uses real location, not VPN IP location
- Connection is tracked immediately, even if OpenVPN process fails
- Falls back to mock mode if OpenVPN unavailable

---

#### 2. `/api/vpn/disconnect` (POST)

**Purpose:** Disconnect VPN connection and release resources

**Request Body:**
```json
{
  "connection_id": "vpn-alice@company.com-1765284778",
  "user_email": "alice@company.com"  // Optional, used if connection_id not provided
}
```

**Response:**
```json
{
  "status": "disconnected",
  "connection_id": "vpn-alice@company.com-1765284778",
  "vpn_ip": "10.8.0.2",
  "connection_mode": "openvpn",
  "message": "Disconnected successfully",
  "ip_released": true
}
```

**How it works:**
1. **Find Connection**: Locates connection by ID or user email
2. **Kill OpenVPN Client**: Terminates OpenVPN client process (multiple methods)
3. **Immediate IP Release**: Removes IP from `assigned_ips` dictionary immediately
4. **Connection Removal**: Deletes connection from `connections` dictionary
5. **Duplicate Cleanup**: Removes all other connections for same user
6. **File Cleanup**: Removes `.ovpn` and `.log` files
7. **Status Log Verification**: Waits for OpenVPN status log to update (up to 36 seconds)
8. **Final Cleanup**: Cleans up `ipp.txt` and verifies cleanup

**Why Immediate Cleanup:**
- Backend dictionaries are single source of truth
- IP is immediately available for reuse
- Dashboard updates immediately show correct state
- OpenVPN files update asynchronously (every 10 seconds)

---

#### 3. `/api/vpn/status` (GET/POST)

**Purpose:** Get status of VPN connection

**Query Parameters (GET) or Body (POST):**
- `connection_id`: Connection ID (optional)
- `user_email`: User email (optional)

**Response:**
```json
{
  "status": "active",
  "uptime": 3600,
  "user": "alice@company.com",
  "connected_at": "2025-12-09T14:30:00",
  "real_client_ip": "192.168.1.100",
  "location": {
    "country": "US",
    "city": "New York"
  },
  "vpn_ip": "10.8.0.2",
  "vpn_routes": ["10.0.0.0/8", "192.168.0.0/16"],
  "last_continuous_auth": "2025-12-09T15:25:00",
  "last_risk_score": 15,
  "device": {
    "os_type": "macOS",
    "os_version": "12.0"
  }
}
```

**How it works:**
- Looks up connection in `connections` dictionary
- Calculates uptime from `connected_at` timestamp
- Returns all connection metadata
- Uses backend dictionary as single source of truth

---

#### 4. `/api/vpn/check-connection` (GET)

**Purpose:** Quick check if user has active connection

**Query Parameters:**
- `user_email`: User email (required)

**Response (Connected):**
```json
{
  "connected": true,
  "connection_id": "vpn-alice@company.com-1765284778",
  "connected_at": "2025-12-09T14:30:00",
  "vpn_ip": "10.8.0.2",
  "real_client_ip": "192.168.1.100",
  "location": {...},
  "last_continuous_auth": "2025-12-09T15:25:00",
  "last_risk_score": 15,
  "connection_mode": "openvpn"
}
```

**Response (Not Connected):**
```json
{
  "connected": false,
  "user": "alice@company.com",
  "message": "No active connection found"
}
```

---

### Connection Listing

#### 5. `/api/vpn/connections` (GET)

**Purpose:** List all connections (can filter by user)

**Query Parameters:**
- `user_email`: Filter by user email (optional)

**Response:**
```json
{
  "connections": [
    {
      "connection_id": "vpn-alice@company.com-1765284778",
      "user": "alice@company.com",
      "vpn_ip": "10.8.0.2",
      "real_client_ip": "192.168.1.100",
      "status": "active",
      "connected_at": "2025-12-09T14:30:00",
      "connection_mode": "openvpn",
      "location": {...},
      "device": {...},
      "last_continuous_auth": "2025-12-09T15:25:00",
      "last_risk_score": 15
    }
  ],
  "count": 1
}
```

---

### Dashboard & Monitoring

#### 6. `/api/vpn/dashboard` (GET)

**Purpose:** Get dashboard data (routing table, assigned IPs, active clients)

**Response:**
```json
{
  "routing_table": [
    {
      "virtual_address": "10.8.0.2",
      "common_name": "alice@company.com",
      "real_address": "192.168.1.100:54321"
    }
  ],
  "assigned_ips": [
    {
      "vpn_ip": "10.8.0.2",
      "connection_id": "vpn-alice@company.com-1765284778"
    }
  ],
  "active_clients": [
    {
      "common_name": "alice@company.com",
      "virtual_address": "10.8.0.2",
      "real_address": "192.168.1.100:54321",
      "connected_at": "2025-12-09T14:30:00",
      "status": "active",
      "connection_id": "vpn-alice@company.com-1765284778",
      "connection_mode": "openvpn"
    }
  ],
  "routing_table_count": 1,
  "assigned_ips_count": 1,
  "active_clients_count": 1,
  "updated_at": "2025-12-09T15:30:00",
  "source": "backend_single_source_of_truth"
}
```

**How it works:**
- Builds data from `connections` dictionary (single source of truth)
- Filters only active connections (`status` in ['active', 'connected'])
- Sorts by IP for routing table, by connected_at for clients
- **Does NOT** read from OpenVPN files (backend is authoritative)

---

#### 7. `/api/vpn/openvpn-status` (GET)

**Purpose:** Get detailed OpenVPN status from status log (for debugging)

**Response:**
```json
{
  "status_log": {
    "clients": [...],
    "routing_table": [...],
    "global_stats": {}
  },
  "ip_pool": {
    "assignments": [
      {
        "common_name": "alice@company.com",
        "ip_address": "10.8.0.2"
      }
    ]
  },
  "clients_count": 1,
  "routing_table_count": 1,
  "ipp_assignments_count": 1,
  "issues": [],
  "routing_table_sync": {
    "clients_count": 1,
    "routes_count": 1,
    "matches": true,
    "filtered": true,
    "original_clients_count": 1,
    "original_routes_count": 1
  }
}
```

**Filtering:**
- Filters clients/routes to only show those with active backend connections
- Matches by IP only (not CN) to prevent showing disconnected clients
- Ensures dashboard shows accurate data even if OpenVPN files are stale

---

#### 8. `/api/vpn/ip-assignments` (GET)

**Purpose:** Get current IP assignment tracking

**Response:**
```json
{
  "assigned_ips": {
    "10.8.0.2": "vpn-alice@company.com-1765284778"
  },
  "total_assigned": 1,
  "ip_counter": 2,
  "active_connections": 1,
  "ipp_file_content": {...},
  "status_log_clients": [...],
  "routing_table": [...],
  "routing_table_count": 1,
  "sync_info": {
    "assigned_ips_count": 1,
    "routing_table_count": 1,
    "client_list_count": 1,
    "in_sync": true,
    "filtered": true
  }
}
```

---

### Continuous Authentication

#### 9. `/api/vpn/continuous-auth-log` (GET)

**Purpose:** Get continuous authentication monitoring log

**Query Parameters:**
- `connection_id`: Filter by connection ID (optional)
- `limit`: Maximum entries to return (default: 100)

**Response:**
```json
{
  "total_entries": 50,
  "filtered_entries": 10,
  "log": [
    {
      "timestamp": "2025-12-09T15:25:00",
      "connection_id": "vpn-alice@company.com-1765284778",
      "user": "alice@company.com",
      "action": "request",
      "real_client_ip": "192.168.1.100",
      "location": "US",
      "status": "pending"
    },
    {
      "timestamp": "2025-12-09T15:25:01",
      "action": "response",
      "status": "success",
      "status_code": 200,
      "risk_score": 15,
      "policy_status": "verified"
    }
  ]
}
```

**How Continuous Auth Works:**
1. Background thread runs every 5 minutes
2. For each active connection:
   - Gets stored real IP/location (from BEFORE VPN)
   - Calls Policy Engine `/api/policy/continuous-auth`
   - Updates connection with risk score
   - Terminates connection if risk > threshold
3. All checks logged to `continuous_auth_log`

---

### Diagnostics

#### 10. `/api/vpn/diagnose-files` (GET)

**Purpose:** Diagnose issues with OpenVPN files

**Response:**
```json
{
  "status_log": {
    "exists": true,
    "size": 1024,
    "readable": true,
    "has_clients": true,
    "undef_cns": 0,
    "clients_without_ip": 0,
    "issues": []
  },
  "ipp_file": {
    "exists": true,
    "size": 256,
    "readable": true,
    "has_assignments": true,
    "assignments_count": 1,
    "issues": []
  },
  "openvpn_server": {
    "running": true,
    "process_count": 1
  },
  "recommendations": []
}
```

---

#### 11. `/api/vpn/verify-openvpn` (GET)

**Purpose:** Comprehensive OpenVPN verification

**Response:**
```json
{
  "installed": true,
  "running": true,
  "port_1194_open": true,
  "process_running": true,
  "status_log_exists": true,
  "ipp_file_exists": true,
  "certificates_exist": true,
  "connection_mode": "openvpn",
  "status_log_info": {
    "clients_count": 1,
    "routing_entries": 1
  },
  "ipp_file_info": {
    "assignments_count": 1
  },
  "active_connections": 1
}
```

---

### Maintenance

#### 12. `/api/vpn/cleanup-ipp` (POST)

**Purpose:** Manually clean up stale entries in `ipp.txt`

**Response:**
```json
{
  "success": true,
  "message": "Cleaned ipp.txt: removed 2 stale entries",
  "before_count": 5,
  "after_count": 3,
  "removed_count": 2
}
```

---

## OpenVPN File Management

### File: `openvpn-status.log`

**Purpose:** OpenVPN server status log (updated every 10 seconds)

**Format:** CSV format with sections:
- `CLIENT_LIST`: Active clients with CN, IP, real address
- `ROUTING_TABLE`: Active routes with virtual IP, CN, real address
- `GLOBAL_STATS`: Server statistics

**Behavior:**
- Rewritten every 10 seconds by OpenVPN server
- Shows only active connections
- Empty when no clients connected
- Used for reference/debugging only (not source of truth)

**Example:**
```
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since
CLIENT_LIST,alice@company.com,127.0.0.1:54321,10.8.0.2,1024,2048,2025-12-09 14:30:00
HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref
ROUTING_TABLE,10.8.0.2,alice@company.com,127.0.0.1:54321,2025-12-09 15:30:00
END
```

---

### File: `ipp.txt`

**Purpose:** IP pool persistence file (persists across restarts)

**Format:** One assignment per line
```
alice@company.com,10.8.0.2,
bob@company.com,10.8.0.3,
```

**Behavior:**
- Persists across OpenVPN server restarts
- Can accumulate stale entries
- Automatically cleaned by backend
- Used for reference/debugging only (not source of truth)

**Cleanup:**
- Backend removes entries not in active connections
- Cleaned automatically on disconnect
- Can be manually cleaned via `/api/vpn/cleanup-ipp`

---

## Single Connection Per User Enforcement

The system enforces **strict single connection per user**:

1. **On Connect**: Removes ALL existing connections for user before creating new one
2. **On Disconnect**: Removes ALL other connections for same user
3. **Safety Function**: `enforce_single_connection_per_user()` called periodically
4. **Race Condition Protection**: Checks for duplicate connections during setup

**Why:**
- Prevents IP conflicts
- Ensures accurate tracking
- Simplifies connection management
- Backend dict is single source of truth

## IP Assignment Logic

### Assignment Process

1. **Get Next Available IP**: `get_next_available_ip()`
   - Starts from 10.8.0.2
   - Finds first IP not in `assigned_ips` dictionary
   - Returns lowest available IP

2. **Immediate Assignment**: IP added to `assigned_ips` immediately
   - Key: IP address (e.g., "10.8.0.2")
   - Value: Connection ID (e.g., "vpn-alice@company.com-1765284778")

3. **OpenVPN Verification**: Waits for OpenVPN to assign IP (up to 72 seconds)
   - Checks `openvpn-status.log` every 12 seconds
   - Checks `ipp.txt` for persistent assignments
   - Matches by Common Name (CN) or real address

4. **Fallback Assignment**: If OpenVPN doesn't assign, uses assigned IP from pool

### Release Process

1. **Immediate Release**: IP removed from `assigned_ips` immediately on disconnect
2. **Connection Removal**: Connection removed from `connections` dictionary
3. **File Cleanup**: Stale entries removed from `ipp.txt`
4. **Status Log Update**: Waits for OpenVPN to update status log (asynchronous)

**Why Immediate:**
- IP is immediately available for reuse
- Dashboard shows correct state immediately
- Prevents IP conflicts
- Backend dict is authoritative

## Certificate Generation Process

### Step-by-Step

1. **Check Cache**: Look for existing certificate for user
2. **Validate Cache**: Check expiration and CN match
3. **Generate Private Key**: `openssl genrsa -out client_<user>.key 2048`
4. **Create CSR**: Certificate Signing Request with user email as CN
5. **Create Extensions File**: Key Usage extension configuration
6. **Sign with CA**: `openssl x509 -req -in <csr> -CA ca.crt -CAkey ca.key -out <cert>`
7. **Verify Certificate**: Check CN and Key Usage extension
8. **Set Permissions**: Key file (600), cert file (644)
9. **Cleanup**: Remove temporary CSR and extensions files

### Key Usage Extension

**Why Critical:**
- OpenVPN requires Key Usage extension to extract CN from certificate
- Without it, CN shows as "UNDEF" in status log
- Prevents proper user identification

**Required Extensions:**
```
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
```

## Continuous Authentication Integration

### Background Thread

```python
def continuous_auth_monitor():
    while True:
        time.sleep(300)  # Every 5 minutes
        for conn_id, conn in active_connections:
            # Get stored real IP/location (BEFORE VPN)
            real_ip = conn.get('real_client_ip')
            location = conn.get('location')
            
            # Call Policy Engine
            response = requests.post(
                'http://127.0.0.1:5002/api/policy/continuous-auth',
                headers={'Authorization': f'Bearer {token}'},
                json={'device': device, 'location': location, 'client_ip': real_ip}
            )
            
            # Update risk score
            conn['last_risk_score'] = response.json().get('risk_score', 0)
            
            # Terminate if high risk
            if risk_score > threshold:
                conn['status'] = 'terminated'
                kill_openvpn_client(conn_id)
```

**Why Real IP/Location:**
- VPN IP (10.8.0.x) would show server location, not user location
- Policy Engine needs real location for geo-fencing
- Stored BEFORE VPN connection to preserve accuracy

## Error Handling

### OpenVPN Client Failures

**Scenario:** OpenVPN client process exits immediately

**Handling:**
1. Console logs error (not shown to frontend)
2. Checks if connection succeeded in status log
3. Falls back to mock mode if connection failed
4. Connection still tracked and functional

**Why Mock Fallback:**
- System remains functional even if OpenVPN unavailable
- Allows testing without root privileges
- Provides graceful degradation

### Certificate Generation Failures

**Scenario:** Certificate generation fails

**Handling:**
1. Returns error response to client
2. Cleans up partial files
3. Suggests running `install.sh` to generate CA certificates

**Common Causes:**
- Missing CA certificates (`ca.crt`, `ca.key`)
- OpenSSL not installed
- Permission issues
- Disk space issues

## Integration Points

### With Auth Server (Port 5000)
- Receives VPN tokens from `/api/access/request-vpn`
- Validates tokens using shared `SECRET_KEY`
- Uses clearance level for access decisions

### With Policy Engine (Port 5002)
- Calls `/api/policy/evaluate` before allowing connections
- Calls `/api/policy/continuous-auth` every 5 minutes
- Provides real client IP/location (stored before VPN)
- Receives risk scores and termination signals

## Security Features

### Certificate-Based Authentication
- Each user gets unique certificate
- Certificate CN matches user email
- CA-signed certificates provide cryptographic proof
- Certificates cached but validated on each use

### IP Address Management
- Single source of truth prevents conflicts
- Immediate cleanup prevents IP leaks
- Lowest available IP assignment ensures efficient use
- Strict single connection per user

### Real Location Preservation
- Real client IP/location stored BEFORE VPN connection
- Policy Engine uses real location for risk scoring
- Prevents VPN IP location from affecting policies
- Enables accurate geo-fencing

### Continuous Monitoring
- Periodic risk assessment
- Automatic connection termination on high risk
- Risk score tracking per connection
- Comprehensive audit logging

## Troubleshooting

### Common Issues

1. **"OpenVPN client process exited immediately"**
   - **Cause**: Permission issue (TUN/TAP requires root)
   - **Solution**: System automatically falls back to mock mode
   - **Note**: Error is console-logged, not shown to frontend

2. **"Certificate generation failed"**
   - **Cause**: Missing CA certificates
   - **Solution**: Run `install.sh` to generate CA certificates
   - **Check**: Verify `ca.crt` and `ca.key` exist

3. **"UNDEF Common Name"**
   - **Cause**: Certificate missing Key Usage extension
   - **Solution**: Regenerate certificate with proper extensions
   - **Verify**: `openssl x509 -in client_*.crt -noout -text | grep "Key Usage"`

4. **"No available IPs to connect"**
   - **Cause**: All 253 IPs are assigned
   - **Solution**: Disconnect some connections
   - **Check**: `/api/vpn/ip-assignments` to see assigned IPs

5. **"Connection not found in status log"**
   - **Cause**: OpenVPN status log updates every 10 seconds (asynchronous)
   - **Solution**: Wait for status log update, or check backend dict
   - **Note**: Backend dict is authoritative, status log is for reference

6. **Routing table shows disconnected clients**
   - **Cause**: OpenVPN status log is stale (updates every 10 seconds)
   - **Solution**: Dashboard endpoint filters by active backend connections
   - **Note**: Use `/api/vpn/dashboard` for accurate data

## Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT validation (must match Auth Server)

### Constants

- `POLICY_ENGINE_URL`: Policy Engine endpoint (default: `http://127.0.0.1:5002`)
- `ip_counter`: Starting IP number (default: 2, meaning 10.8.0.2)
- IP range: 10.8.0.2 to 10.8.0.254 (253 available IPs)

### OpenVPN Configuration

**Server Config (`server.ovpn`):**
- Port: 1194 (UDP)
- Protocol: UDP4
- CA: `ca.crt`
- Server cert: `server.crt`
- Server key: `server.key`
- DH params: `dh2048.pem`
- Status log: `openvpn-status.log` (updates every 10 seconds)
- IP pool: `ipp.txt`

**Client Config (generated per user):**
- CA: `ca.crt` (shared)
- Client cert: `client_<user>.crt` (per user)
- Client key: `client_<user>.key` (per user)
- Server: `127.0.0.1:1194`
- Routes: `10.0.0.0/8`, `192.168.0.0/16`

## Example Usage Flow

```python
# 1. Get VPN token from Auth Server
POST http://localhost:5000/api/access/request-vpn
Headers: Authorization: Bearer <auth_token>
# Returns: VPN token

# 2. Connect to VPN
POST http://localhost:5001/api/vpn/connect
Body: {
  "vpn_token": "<vpn_token>",
  "device": {...},
  "location": {...}
}
# Returns: Connection ID, VPN IP, routes

# 3. Check connection status
GET http://localhost:5001/api/vpn/status?user_email=alice@company.com
# Returns: Connection details, uptime, risk score

# 4. Get dashboard data
GET http://localhost:5001/api/vpn/dashboard
# Returns: Routing table, assigned IPs, active clients

# 5. Disconnect
POST http://localhost:5001/api/vpn/disconnect
Body: {"connection_id": "vpn-alice@company.com-1765284778"}
# Returns: Disconnect confirmation
```

## File Structure

```
.
├── ca.crt              # CA certificate (public, distributed to clients)
├── ca.key              # CA private key (SECRET, keep secure)
├── server.crt          # Server certificate
├── server.key          # Server private key (SECRET)
├── dh2048.pem          # Diffie-Hellman parameters
├── server.ovpn         # OpenVPN server configuration
├── openvpn-status.log  # OpenVPN status log (updated every 10s)
├── ipp.txt             # IP pool persistence file
├── client_*.crt        # Client certificates (per user)
├── client_*.key        # Client private keys (per user, SECRET)
├── vpn-*.ovpn          # Client config files (generated per connection)
└── vpn-*.log           # Client log files (generated per connection)
```

## Security Considerations

1. **Certificate Security**:
   - CA private key (`ca.key`) must be kept secret
   - Client private keys must be kept secret
   - Use proper file permissions (600 for keys, 644 for certs)

2. **Token Security**:
   - VPN tokens should be stored securely on client
   - Use HTTPS in production
   - Tokens expire after 30 minutes

3. **IP Assignment**:
   - Backend dict is single source of truth
   - OpenVPN files are for reference only
   - Immediate cleanup prevents IP leaks

4. **Real Location**:
   - Real IP/location stored before VPN connection
   - Prevents VPN IP from affecting policies
   - Enables accurate risk scoring

5. **OpenVPN Security**:
   - Requires root privileges for TUN/TAP device
   - Uses strong encryption (AES-256-GCM)
   - Certificate-based mutual authentication

## Best Practices

1. **Certificate Management**:
   - Generate CA certificates once during setup
   - Regenerate client certificates if compromised
   - Monitor certificate expiration dates

2. **Connection Management**:
   - Always disconnect properly (don't just close client)
   - Monitor active connections regularly
   - Clean up stale connections periodically

3. **Monitoring**:
   - Use `/api/vpn/dashboard` for accurate real-time data
   - Check `/api/vpn/openvpn-status` for debugging
   - Monitor continuous auth logs for anomalies

4. **Troubleshooting**:
   - Check OpenVPN server is running
   - Verify certificates exist and are valid
   - Check file permissions
   - Review logs for errors

