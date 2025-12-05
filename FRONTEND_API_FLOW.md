# Frontend API Flow Documentation

## Complete API Flow for ZTNA Frontend

### Base URLs
- **Auth Server**: `http://localhost:5000`
- **VPN Gateway**: `http://localhost:5001`
- **Policy Engine**: `http://localhost:5002`

---

## 1. Authentication Flow

### Step 1: Login
```javascript
POST /api/auth/login
Content-Type: application/json

{
  "email": "alice@company.com",
  "password": "password123"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "role": "Developer",
    "clearance": 3,
    "department": "Engineering"
  },
  "latency_ms": 12.5
}
```

**Frontend Implementation:**
```javascript
async function login(email, password) {
  const response = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email, password})
  });
  
  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('authToken', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    return data;
  } else {
    const error = await response.json();
    throw new Error(error.error || 'Login failed');
  }
}
```

### Step 2: Verify Token (Optional - for session check)
```javascript
GET /api/auth/verify
Authorization: Bearer <token>

Response:
{
  "valid": true,
  "user": {...}
}
```

---

## 2. VPN Connection Flow

### Step 1: Check if Already Connected
**IMPORTANT: Always check first to prevent duplicate connections**

```javascript
GET /api/vpn/check-connection?user_email=alice@company.com

Response (if connected):
{
  "connected": true,
  "connection_id": "vpn-alice@company.com-1234567890",
  "connected_at": "2025-01-15T10:30:00",
  "vpn_ip": "10.8.0.2",
  "real_client_ip": "203.0.113.45",
  "location": {"country": "US", "city": "New York"},
  "last_continuous_auth": "2025-01-15T10:35:00",
  "last_risk_score": 15,
  "connection_mode": "openvpn"
}

Response (if not connected):
{
  "connected": false,
  "user": "alice@company.com",
  "message": "No active connection found"
}
```

**Frontend Implementation:**
```javascript
async function checkConnection(userEmail) {
  const response = await fetch(
    `http://localhost:5001/api/vpn/check-connection?user_email=${userEmail}`
  );
  return await response.json();
}

// Before connecting, always check:
const connectionStatus = await checkConnection(userEmail);
if (connectionStatus.connected) {
  console.log('Already connected!', connectionStatus);
  // Show existing connection info, don't allow reconnection
  return;
}
```

### Step 2: Get Client IP and Location
```javascript
// Get client's real IP
const clientIP = await fetch('https://api.ipify.org?format=json')
  .then(r => r.json())
  .then(d => d.ip);

// Get location from IP
const locationData = await fetch(
  `http://localhost:5002/api/policy/location-detect?ip=${clientIP}`
).then(r => r.json());
```

### Step 3: Request VPN Token
```javascript
POST /api/access/request-vpn
Authorization: Bearer <token>

Response:
{
  "vpn_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "vpn_server": "10.8.0.1",
  "vpn_port": 1194
}
```

**Frontend Implementation:**
```javascript
async function requestVPNAccess(token) {
  const response = await fetch('http://localhost:5000/api/access/request-vpn', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.ok) {
    return await response.json();
  } else {
    throw new Error('VPN access request failed');
  }
}
```

### Step 4: Connect to VPN
```javascript
POST /api/vpn/connect
Content-Type: application/json

{
  "vpn_token": "...",
  "device": {
    "os_type": "macOS",
    "os_version": "12.0",
    "encrypted": true,
    "rooted": false
  },
  "client_ip": "203.0.113.45",  // Optional: Frontend-provided
  "location": {                  // Optional: Frontend-provided
    "country": "US",
    "city": "New York"
  }
}

Response (Success):
{
  "connection_id": "vpn-alice@company.com-1234567890",
  "real_client_ip": "203.0.113.45",
  "location": {"country": "US", "city": "New York"},
  "status": "connected",
  "ip": "10.8.0.2",
  "routes": ["10.0.0.0/8", "192.168.0.0/16"],
  "connection_mode": "openvpn"  // or "mock" or "mock_fallback"
}

Response (Already Connected - 409 Conflict):
{
  "error": "User already has an active VPN connection",
  "existing_connection": {
    "connection_id": "...",
    "connected_at": "...",
    "vpn_ip": "10.8.0.2"
  },
  "message": "Please disconnect the existing connection before creating a new one"
}
```

**Frontend Implementation:**
```javascript
async function connectVPN(vpnToken, device, clientIP, location) {
  // First check if already connected
  const user = JSON.parse(localStorage.getItem('user'));
  const checkResult = await checkConnection(user.email || '');
  
  if (checkResult.connected) {
    throw new Error('Already connected. Please disconnect first.');
  }
  
  const response = await fetch('http://localhost:5001/api/vpn/connect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      vpn_token: vpnToken,
      device: device,
      client_ip: clientIP,
      location: location
    })
  });
  
  if (response.status === 409) {
    const data = await response.json();
    throw new Error(data.message || 'Already connected');
  }
  
  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('connectionId', data.connection_id);
    return data;
  } else {
    const error = await response.json();
    throw new Error(error.error || 'Connection failed');
  }
}
```

### Step 5: Monitor VPN Status
```javascript
// Option 1: GET request (simpler)
GET /api/vpn/status?connection_id=<id>
GET /api/vpn/status?user_email=alice@company.com

// Option 2: POST request
POST /api/vpn/status
Content-Type: application/json
{
  "connection_id": "...",
  "user_email": "alice@company.com"  // Optional: alternative to connection_id
}

Response:
{
  "status": "active",
  "uptime": 3600,
  "user": "alice@company.com",
  "connected_at": "2025-01-15T10:30:00",
  "real_client_ip": "203.0.113.45",
  "location": {"country": "US", "city": "New York"},
  "vpn_ip": "10.8.0.2",
  "vpn_routes": ["10.0.0.0/8", "192.168.0.0/16"],
  "last_continuous_auth": "2025-01-15T10:35:00",
  "last_risk_score": 15,
  "device": {...}
}
```

**Frontend Implementation:**
```javascript
// Poll status every 10 seconds
async function pollVPNStatus(connectionId) {
  const response = await fetch(
    `http://localhost:5001/api/vpn/status?connection_id=${connectionId}`
  );
  
  if (response.ok) {
    return await response.json();
  } else if (response.status === 404) {
    return {status: 'inactive'};
  } else {
    throw new Error('Status check failed');
  }
}

// Or use user email
async function pollVPNStatusByUser(userEmail) {
  const response = await fetch(
    `http://localhost:5001/api/vpn/status?user_email=${userEmail}`
  );
  return await response.json();
}
```

### Step 6: Disconnect VPN
```javascript
POST /api/vpn/disconnect
Content-Type: application/json

{
  "connection_id": "vpn-alice@company.com-1234567890"
}

Response:
{
  "status": "disconnected"
}
```

**Frontend Implementation:**
```javascript
async function disconnectVPN(connectionId) {
  const response = await fetch('http://localhost:5001/api/vpn/disconnect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({connection_id: connectionId})
  });
  
  if (response.ok) {
    localStorage.removeItem('connectionId');
    return await response.json();
  } else {
    throw new Error('Disconnect failed');
  }
}
```

---

## 3. Policy Evaluation Flow

### Evaluate Access to Resources
```javascript
POST /api/policy/evaluate
Content-Type: application/json

{
  "user": {"email": "alice@company.com"},
  "resource": "database-prod",  // or "admin-panel", "file-server", "vpn-gateway"
  "device": {
    "os_type": "macOS",
    "os_version": "12.0",
    "encrypted": true,
    "rooted": false
  },
  "location": {
    "country": "US",
    "city": "New York"
  },
  "context": {
    "mfa_verified": true
  }
}

Response (ALLOW):
{
  "decision": "ALLOW",
  "risk_score": 15,
  "risk_factors": [],
  "context": {
    "device": {...},
    "location": {...},
    "session_timeout_minutes": 15
  }
}

Response (DENY):
{
  "decision": "DENY",
  "risk_score": 55,
  "reason": "High risk",
  "risk_factors": ["Unusual location: CN", "Rooted/jailbroken device"],
  "threshold": 30
}

Response (MFA_REQUIRED):
{
  "decision": "MFA_REQUIRED",
  "risk_score": 20,
  "reason": "Multi-factor authentication required"
}
```

**Frontend Implementation:**
```javascript
async function evaluatePolicy(resource, device, location, context = {}) {
  const user = JSON.parse(localStorage.getItem('user'));
  
  const response = await fetch('http://localhost:5002/api/policy/evaluate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      user: {email: user.email},
      resource: resource,
      device: device,
      location: location,
      context: context
    })
  });
  
  const data = await response.json();
  
  if (response.status === 403) {
    // DENY
    return {decision: 'DENY', ...data};
  } else if (response.status === 401) {
    // MFA_REQUIRED
    return {decision: 'MFA_REQUIRED', ...data};
  } else {
    // ALLOW
    return {decision: 'ALLOW', ...data};
  }
}

// Evaluate all resources
async function evaluateAllResources(device, location) {
  const resources = ['database-prod', 'admin-panel', 'file-server', 'vpn-gateway'];
  const results = {};
  
  for (const resource of resources) {
    try {
      const result = await evaluatePolicy(resource, device, location);
      results[resource] = result;
    } catch (error) {
      results[resource] = {error: error.message};
    }
  }
  
  return results;
}
```

### Test Risk Scenarios
```javascript
// Get available test scenarios
GET /api/policy/test-scenarios

Response:
{
  "scenarios": {
    "low_risk": {...},
    "medium_risk_location": {...},
    "high_risk_rooted": {...},
    ...
  }
}

// Test specific scenario
POST /api/policy/test-risk
Content-Type: application/json

{
  "user": {"email": "alice@company.com"},
  "resource": "database-prod",
  "test_risk_score": 45,  // Override risk score for testing
  "test_risk_factors": ["Test: High risk scenario"],
  "device": {...},
  "location": {...}
}
```

---

## 4. Continuous Auth Monitoring

### Get Continuous Auth Log
```javascript
GET /api/vpn/continuous-auth-log?connection_id=<id>&limit=50
GET /api/vpn/continuous-auth-log?limit=100

Response:
{
  "total_entries": 150,
  "filtered_entries": 50,
  "log": [
    {
      "timestamp": "2025-01-15T10:35:00",
      "connection_id": "...",
      "user": "alice@company.com",
      "action": "request",
      "real_client_ip": "203.0.113.45",
      "location": "US",
      "status": "pending"
    },
    {
      "timestamp": "2025-01-15T10:35:01",
      "action": "response",
      "status": "success",
      "status_code": 200,
      "risk_score": 15,
      "policy_status": "verified"
    }
  ]
}
```

### Get Continuous Auth History (Policy Engine)
```javascript
GET /api/policy/continuous-auth-history?user_email=alice@company.com&limit=50

Response:
{
  "total_requests": 100,
  "filtered_requests": 50,
  "history": [
    {
      "timestamp": "2025-01-15T10:35:00",
      "response_time": "2025-01-15T10:35:01",
      "user": "alice@company.com",
      "client_ip": "203.0.113.45",
      "location": "US",
      "status": "verified",
      "risk_score": 15,
      "success": true
    }
  ]
}
```

**Frontend Implementation:**
```javascript
// Poll continuous auth log every 30 seconds
setInterval(async () => {
  const connectionId = localStorage.getItem('connectionId');
  if (connectionId) {
    const log = await fetch(
      `http://localhost:5001/api/vpn/continuous-auth-log?connection_id=${connectionId}&limit=10`
    ).then(r => r.json());
    
    console.log('Recent continuous auth:', log.log);
    // Update UI with latest auth status
  }
}, 30000);
```

---

## 5. Risk Threshold Management

### Get Current Thresholds
```javascript
GET /api/policy/risk-thresholds

Response:
{
  "thresholds": {
    "global_max_risk": 75,
    "critical_resource_threshold": 20,
    "high_resource_threshold": 30,
    "medium_resource_threshold": 50,
    "continuous_auth_max_risk": 75
  },
  "resource_defaults": {...},
  "global_max": 75,
  "continuous_auth_max": 75
}
```

### Update Thresholds
```javascript
POST /api/policy/risk-thresholds
Content-Type: application/json

{
  "global_max_risk": 80,
  "critical_resource_threshold": 25,
  "high_resource_threshold": 35,
  "medium_resource_threshold": 55,
  "continuous_auth_max_risk": 80
}

Response:
{
  "message": "Risk thresholds updated successfully",
  "thresholds": {...}
}
```

### Reset Thresholds
```javascript
POST /api/policy/risk-thresholds/reset

Response:
{
  "message": "Risk thresholds reset to defaults",
  "thresholds": {...}
}
```

---

## 6. OpenVPN Verification

### Verify OpenVPN Setup
```javascript
GET /api/vpn/verify-openvpn

Response:
{
  "installed": true,
  "running": true,
  "port_1194_open": true,
  "process_running": true,
  "status_log_exists": true,
  "certificates_exist": true,
  "connection_mode": "openvpn",
  "active_connections": 1,
  "status_log_info": {
    "clients_found": 1,
    "sample_ips": ["10.8.0.2"]
  }
}
```

---

## Complete Frontend Flow Example

```javascript
class ZTNAClient {
  constructor() {
    this.baseURLs = {
      auth: 'http://localhost:5000',
      vpn: 'http://localhost:5001',
      policy: 'http://localhost:5002'
    };
    this.token = localStorage.getItem('authToken');
    this.user = JSON.parse(localStorage.getItem('user') || '{}');
    this.connectionId = localStorage.getItem('connectionId');
  }
  
  // 1. Login
  async login(email, password) {
    const response = await fetch(`${this.baseURLs.auth}/api/auth/login`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password})
    });
    
    if (!response.ok) throw new Error('Login failed');
    
    const data = await response.json();
    this.token = data.token;
    this.user = data.user;
    localStorage.setItem('authToken', this.token);
    localStorage.setItem('user', JSON.stringify(this.user));
    return data;
  }
  
  // 2. Check if already connected
  async checkConnection() {
    if (!this.user.email) return {connected: false};
    
    const response = await fetch(
      `${this.baseURLs.vpn}/api/vpn/check-connection?user_email=${this.user.email}`
    );
    return await response.json();
  }
  
  // 3. Get client IP and location
  async getClientInfo() {
    const clientIP = await fetch('https://api.ipify.org?format=json')
      .then(r => r.json())
      .then(d => d.ip);
    
    const locationData = await fetch(
      `${this.baseURLs.policy}/api/policy/location-detect?ip=${clientIP}`
    ).then(r => r.json());
    
    return {clientIP, location: locationData.location};
  }
  
  // 4. Request VPN access
  async requestVPN() {
    const response = await fetch(`${this.baseURLs.auth}/api/access/request-vpn`, {
      method: 'POST',
      headers: {'Authorization': `Bearer ${this.token}`}
    });
    
    if (!response.ok) throw new Error('VPN request failed');
    return await response.json();
  }
  
  // 5. Connect VPN (with duplicate check)
  async connectVPN(device) {
    // Check if already connected
    const checkResult = await this.checkConnection();
    if (checkResult.connected) {
      throw new Error('Already connected. Please disconnect first.');
    }
    
    // Get client info
    const {clientIP, location} = await this.getClientInfo();
    
    // Request VPN token
    const vpnData = await this.requestVPN();
    
    // Connect
    const response = await fetch(`${this.baseURLs.vpn}/api/vpn/connect`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        vpn_token: vpnData.vpn_token,
        device: device,
        client_ip: clientIP,
        location: location
      })
    });
    
    if (response.status === 409) {
      const data = await response.json();
      throw new Error(data.message || 'Already connected');
    }
    
    if (!response.ok) throw new Error('Connection failed');
    
    const data = await response.json();
    this.connectionId = data.connection_id;
    localStorage.setItem('connectionId', this.connectionId);
    return data;
  }
  
  // 6. Get VPN status
  async getStatus() {
    if (this.connectionId) {
      const response = await fetch(
        `${this.baseURLs.vpn}/api/vpn/status?connection_id=${this.connectionId}`
      );
      return await response.json();
    } else if (this.user.email) {
      const response = await fetch(
        `${this.baseURLs.vpn}/api/vpn/status?user_email=${this.user.email}`
      );
      return await response.json();
    }
    return {status: 'inactive'};
  }
  
  // 7. Disconnect
  async disconnect() {
    if (!this.connectionId) {
      // Try to find connection by user email
      const checkResult = await this.checkConnection();
      if (!checkResult.connected) {
        throw new Error('No active connection');
      }
      this.connectionId = checkResult.connection_id;
    }
    
    const response = await fetch(`${this.baseURLs.vpn}/api/vpn/disconnect`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({connection_id: this.connectionId})
    });
    
    if (response.ok) {
      this.connectionId = null;
      localStorage.removeItem('connectionId');
      return await response.json();
    }
    throw new Error('Disconnect failed');
  }
  
  // 8. Evaluate policies
  async evaluatePolicy(resource, device, location, context = {}) {
    const response = await fetch(`${this.baseURLs.policy}/api/policy/evaluate`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        user: {email: this.user.email},
        resource: resource,
        device: device,
        location: location,
        context: context
      })
    });
    
    return await response.json();
  }
  
  // 9. Get continuous auth log
  async getContinuousAuthLog(limit = 50) {
    const url = this.connectionId
      ? `${this.baseURLs.vpn}/api/vpn/continuous-auth-log?connection_id=${this.connectionId}&limit=${limit}`
      : `${this.baseURLs.vpn}/api/vpn/continuous-auth-log?limit=${limit}`;
    
    const response = await fetch(url);
    return await response.json();
  }
}

// Usage
const client = new ZTNAClient();

// Login
await client.login('alice@company.com', 'password123');

// Check connection before connecting
const status = await client.checkConnection();
if (!status.connected) {
  // Connect
  const device = {
    os_type: 'macOS',
    os_version: '12.0',
    encrypted: true,
    rooted: false
  };
  await client.connectVPN(device);
}

// Monitor status
setInterval(async () => {
  const status = await client.getStatus();
  console.log('VPN Status:', status);
}, 10000);
```

---

## Key Points for Frontend

1. **Always check connection before connecting** - Use `/api/vpn/check-connection` first
2. **Handle 409 Conflict** - If user tries to connect when already connected
3. **Store connection_id** - Save it in localStorage for status checks
4. **Poll status regularly** - Check VPN status every 10-30 seconds
5. **Monitor continuous auth** - Poll continuous auth log to show risk changes
6. **Handle disconnections** - Check if connection was terminated by continuous auth
7. **Get client IP** - Use external service (ipify.org) for accurate IP detection
8. **Evaluate policies** - Check resource access before allowing actions

---

## Error Handling

- **409 Conflict**: User already connected - show existing connection, don't allow reconnect
- **403 Forbidden**: Access denied by policy - show risk score and reasons
- **401 Unauthorized**: Token expired or MFA required - prompt for re-auth or MFA
- **404 Not Found**: Connection not found - treat as disconnected

