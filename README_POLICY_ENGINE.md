# Policy Engine (policy_engine.py)

## Overview

The Policy Engine is the core security component that evaluates access requests, calculates risk scores, and enforces security policies based on user behavior, device compliance, location, and network characteristics. It provides continuous authentication monitoring and threat detection capabilities.

**Port:** 5002  
**Base URL:** `http://localhost:5002`

## Working Mechanism

### Risk-Based Access Control (RBAC)

The Policy Engine uses a **risk scoring system** (0-100) to make access decisions:

- **Low Risk (0-30)**: Access typically granted
- **Medium Risk (31-50)**: Access granted with warnings
- **High Risk (51-75)**: Access denied or requires MFA
- **Critical Risk (76-100)**: Access automatically denied

### Risk Calculation Process

1. **Initial Risk Score**: Starts at 0
2. **Risk Factor Evaluation**: Adds points based on:
   - Location (unusual countries, geo-fencing violations)
   - Network (public WiFi, TOR exit nodes, malicious IPs)
   - Device (rooted/jailbroken, outdated OS, encryption status)
   - Time (off-hours access, weekend access)
   - Behavior (velocity anomalies, unusual resource access)
3. **Resource Sensitivity**: Critical resources add base risk
4. **MFA Requirements**: Additional risk if MFA required but not verified
5. **Final Score**: Sum of all risk factors

### Continuous Authentication

The Policy Engine performs **continuous authentication** checks:
- Periodic risk assessment every 5 minutes (configurable)
- Monitors active VPN connections
- Automatically terminates connections with high risk scores
- Tracks authentication history and patterns

## Certificate Requirements

**Note:** The Policy Engine does NOT require certificates. Certificates are only needed for the VPN Gateway (OpenVPN).

However, the Policy Engine validates JWT tokens signed by the Auth Server using the shared `SECRET_KEY`.

## API Endpoints

### Core Policy Evaluation

#### 1. `/api/policy/evaluate` (POST)

**Purpose:** Evaluate access request and calculate risk score

**Request Body:**
```json
{
  "user": {
    "email": "alice@company.com"
  },
  "resource": "database-prod",
  "device": {
    "os_type": "macOS",
    "os_version": "12.0",
    "encrypted": true,
    "rooted": false
  },
  "location": {
    "country": "US",
    "city": "New York",
    "latitude": 40.7128,
    "longitude": -74.0060
  },
  "context": {
    "mfa_verified": true
  }
}
```

**Response (Access Granted):**
```json
{
  "decision": "ALLOW",
  "risk_score": 15,
  "risk_factors": [],
  "context": {
    "device": {...},
    "location": {...},
    "session_timeout_minutes": 15
  },
  "vpn_connected": false,
  "location_used": "US"
}
```

**Response (Access Denied):**
```json
{
  "decision": "DENY",
  "risk_score": 75,
  "risk_factors": [
    "Unusual location: CN",
    "Rooted/jailbroken device",
    "Device not encrypted"
  ],
  "threshold": 30,
  "vpn_connected": false,
  "location_used": "CN"
}
```
Status: 403 Forbidden

**How it works:**
1. Validates user and resource
2. Checks if user has active VPN connection (to get real IP/location)
3. Calculates risk score based on:
   - Location (geo-fencing violations)
   - Network (public WiFi, TOR, malicious IPs)
   - Device compliance (OS version, encryption, rooted status)
   - Time-based policies (business hours, weekends)
   - Behavioral patterns (velocity checks)
4. Applies resource-specific policies:
   - IP whitelist/blacklist
   - Rate limiting
   - Admin role requirements
5. Compares risk score to resource threshold
6. Returns decision (ALLOW/DENY/MFA_REQUIRED)
7. Logs access attempt to `access_log.json`

**Risk Factor Examples:**
- Unusual location (outside geo-fence): +15 points
- Public WiFi: +18 points
- Rooted device: +25 points
- TOR exit node: +30 points
- Known malicious IP: +40 points
- Velocity anomaly: +20 points

---

#### 2. `/api/policy/continuous-auth` (POST)

**Purpose:** Continuous authentication check for active VPN connections

**Headers:**
```
Authorization: Bearer <vpn_token>
```

**Request Body:**
```json
{
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
  "client_ip": "192.168.1.100"
}
```

**Response (Verified):**
```json
{
  "status": "verified",
  "user": "alice@company.com",
  "risk_score": 15,
  "expires_at": "2025-12-09T16:00:00"
}
```

**Response (High Risk):**
```json
{
  "status": "failed",
  "reason": "High risk detected",
  "risk_score": 80,
  "threshold": 75
}
```
Status: 401 Unauthorized

**How it works:**
1. Validates JWT token from Authorization header
2. Calculates risk score using device and location data
3. Checks if risk exceeds `continuous_auth_max_risk` threshold (default: 75)
4. Updates active session tracking
5. Logs request to `continuous_auth_log.json`
6. Returns verification status

**Integration with VPN Gateway:**
- VPN Gateway calls this endpoint every 5 minutes
- If risk score > threshold, VPN connection is terminated
- Uses real client IP/location (stored before VPN connection)

---

### Anomaly Detection

#### 3. `/api/policy/anomaly-detect` (POST)

**Purpose:** Detect anomalies for a specific user

**Request Body:**
```json
{
  "email": "alice@company.com"
}
```

**Response:**
```json
{
  "anomalies": 3,
  "recent_anomalies": 1,
  "details": [
    {
      "user": "alice@company.com",
      "resource": "database-prod",
      "risk": 65,
      "risk_factors": ["Unusual location: CN", "Rooted device"],
      "time": "2025-12-09T14:30:00",
      "location": {...},
      "device": {...}
    }
  ],
  "risk_level": "high"
}
```

**How it works:**
- Retrieves all anomalies for the user from `anomalies_log.json`
- Filters recent anomalies (within last hour)
- Calculates risk level based on anomaly count
- Returns last 10 anomalies

---

#### 4. `/api/policy/anomalies` (GET)

**Purpose:** Get all anomalies (requires clearance level 2+)

**Headers:**
```
Authorization: Bearer <token>
```

**Query Parameters:**
- `limit`: Maximum number of anomalies to return (default: 50)

**Response:**
```json
{
  "anomalies": [...],
  "total": 15,
  "filtered": 12,
  "user_clearance": 3
}
```

**Clearance-Based Filtering:**
- **Clearance 2-3**: Can see own anomalies + medium/high risk anomalies
- **Clearance 4**: Can see all anomalies but limited details for critical threats
- **Clearance 5**: Can see all anomalies with full details

---

### Session Management

#### 5. `/api/policy/session-status` (POST)

**Purpose:** Get continuous authentication status for current session

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "status": "active",
  "last_verified": "2025-12-09T15:25:00",
  "minutes_since_verify": 2.5,
  "risk_score": 15,
  "requires_reverify": false
}
```

**How it works:**
- Validates token
- Looks up session in `active_sessions`
- Calculates time since last verification
- Returns session status and risk score

---

### Location Detection

#### 6. `/api/policy/location-detect` (GET/POST)

**Purpose:** Detect location from IP address

**GET Request:**
```
GET /api/policy/location-detect?ip=8.8.8.8
```

**POST Request:**
```json
{
  "ip": "8.8.8.8"
}
```

**Response:**
```json
{
  "ip": "8.8.8.8",
  "location": {
    "country": "US",
    "country_name": "United States",
    "city": "Mountain View",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "isp": "Google",
    "source": "ip-api"
  }
}
```

**How it works:**
- Uses free geolocation API (ip-api.com)
- Handles private IPs (returns "Local" for 127.0.0.1, 192.168.x.x, etc.)
- Returns fallback data if lookup fails
- Used by VPN Gateway to detect real client location before VPN connection

---

### Policy Configuration

#### 7. `/api/policy/policies` (GET)

**Purpose:** Get current policy configuration

**Response:**
```json
{
  "risk_factors": {
    "unusual_location": 15,
    "public_wifi": 18,
    "rooted_device": 25,
    ...
  },
  "time_policies": {
    "business_hours_only": false,
    "business_hours": {"start": 9, "end": 17},
    "weekend_access": true
  },
  "network_policies": {
    "allow_public_wifi": false,
    "geo_fencing": ["US", "CA", "UK", "IN"],
    "block_tor": true
  },
  "device_policies": {
    "require_encryption": true,
    "block_rooted_jailbroken": true,
    "min_os_version": {...}
  },
  "resource_policies": {
    "database-prod": {...},
    "admin-panel": {...},
    ...
  },
  "session_policies": {
    "max_concurrent_sessions": 3,
    "continuous_auth_interval_minutes": 5
  }
}
```

---

### Risk Thresholds

#### 8. `/api/policy/risk-thresholds` (GET)

**Purpose:** Get current risk threshold configuration

**Response:**
```json
{
  "thresholds": {
    "global_max_risk": 75,
    "critical_resource_threshold": 20,
    "high_resource_threshold": 30,
    "medium_resource_threshold": 50,
    "continuous_auth_max_risk": 75
  },
  "resource_defaults": {
    "critical": 20,
    "high": 30,
    "medium": 50
  },
  "global_max": 75,
  "continuous_auth_max": 75
}
```

#### 9. `/api/policy/risk-thresholds` (POST)

**Purpose:** Update risk thresholds (admin only)

**Request Body:**
```json
{
  "global_max_risk": 80,
  "critical_resource_threshold": 25,
  "high_resource_threshold": 35
}
```

**Response:**
```json
{
  "message": "Risk thresholds updated successfully",
  "thresholds": {...}
}
```

---

### Access Metrics

#### 10. `/api/policy/access-metrics` (GET)

**Purpose:** Get access metrics comparing VPN vs non-VPN access

**Query Parameters:**
- `resource`: Filter by resource (optional)
- `user_email`: Filter by user (optional)

**Response:**
```json
{
  "total_attempts": 150,
  "filter": {
    "resource": "all",
    "user": "all"
  },
  "overall": {
    "vpn": {
      "count": 80,
      "allowed": 75,
      "denied": 5,
      "avg_risk_score": 18.5,
      "allow_rate": 93.75
    },
    "non_vpn": {
      "count": 70,
      "allowed": 50,
      "denied": 20,
      "avg_risk_score": 35.2,
      "allow_rate": 71.43
    }
  },
  "by_resource": {
    "database-prod": {
      "vpn": {...},
      "non_vpn": {...}
    }
  },
  "recent_attempts": [...]
}
```

---

### Threat Intelligence

#### 11. `/api/policy/threat-users` (GET)

**Purpose:** Get threat users list (requires clearance level 3+)

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "threat_users": [
    {
      "user_email": "suspicious@company.com",
      "threat_level": "high",
      "risk_score": 85,
      "threat_type": "Multiple failed access attempts",
      "first_seen": "2025-12-08T10:00:00",
      "last_seen": "2025-12-09T14:30:00",
      "attempts": 15,
      "blocked_attempts": 12
    }
  ],
  "total": 5,
  "user_clearance": 4
}
```

**Clearance-Based Access:**
- **Clearance 3**: Can see medium/high threats (not critical)
- **Clearance 4**: Can see all threats but limited details for critical
- **Clearance 5**: Can see all threats with full details

---

### Admin Endpoints

All admin endpoints require admin access (clearance 5 or admin role).

#### 12. `/api/policy/admin/risk-factors` (GET/POST)

**Purpose:** Get or update risk factors

**POST Request:**
```json
{
  "unusual_location": 20,
  "public_wifi": 25,
  "new_factor": 15
}
```

---

#### 13. `/api/policy/admin/resource-policies` (GET/POST)

**Purpose:** Get or update resource policies

**POST Request:**
```json
{
  "resource": "database-prod",
  "updates": {
    "require_mfa": true,
    "session_timeout_minutes": 10
  }
}
```

---

#### 14. `/api/policy/admin/network-policies` (GET/POST)

**Purpose:** Get or update network policies

**POST Request:**
```json
{
  "updates": {
    "allow_public_wifi": true,
    "geo_fencing": ["US", "CA", "UK", "IN", "DE"]
  }
}
```

---

#### 15. `/api/policy/admin/add-resource` (POST)

**Purpose:** Add a new resource with policy

**Request Body:**
```json
{
  "name": "new-resource",
  "policy": {
    "sensitivity": "medium",
    "require_mfa": false,
    "require_low_risk": true,
    "session_timeout_minutes": 30
  }
}
```

---

## Policy Configuration

### Risk Factors

Risk factors determine how many points are added to the risk score:

```python
RISK_FACTORS = {
    'failed_login_attempts': 20,
    'unusual_location': 15,
    'device_age_days': 10,
    'unusual_time_access': 12,
    'public_wifi': 18,
    'unpatched_device': 15,
    'rooted_device': 25,
    'velocity_check': 20,
    'unusual_resource_access': 15,
    'session_timeout': 10,
    'no_mfa_high_risk': 20,
    'tor_exit_node': 30,
    'known_malicious_ip': 40,
}
```

### Resource Policies

Each resource has specific policies:

```python
RESOURCE_POLICIES = {
    'database-prod': {
        'sensitivity': 'high',
        'require_mfa': True,
        'require_low_risk': True,  # Risk < 30
        'session_timeout_minutes': 15,
        'max_concurrent_connections': 5,
        'block_rooted_devices': True,
        'ip_whitelist': [],
        'ip_blacklist': [],
        'rate_limit_per_minute': 100
    },
    'vpn-gateway': {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,
        'session_timeout_minutes': 60,
        'max_concurrent_connections': 1,  # One VPN per user
        'rate_limit_per_minute': 10
    }
}
```

### Network Policies

```python
NETWORK_POLICIES = {
    'allow_public_wifi': False,
    'ip_reputation_check': True,
    'geo_fencing': ['US', 'CA', 'UK', 'IN'],
    'block_tor': True,
    'check_known_malicious_ips': True,
}
```

### Device Policies

```python
DEVICE_POLICIES = {
    'require_encryption': True,
    'require_antivirus': True,
    'block_rooted_jailbroken': True,
    'min_os_version': {
        'iOS': '14.0',
        'Android': '10.0',
        'Windows': '10.0',
        'macOS': '11.0',
        'Linux': '5.0',
    },
}
```

## Log Persistence

The Policy Engine automatically persists logs to JSON files:

- **`logs/access_log.json`**: All access attempts with decisions
- **`logs/anomalies_log.json`**: Detected anomalies
- **`logs/continuous_auth_log.json`**: Continuous authentication events
- **`logs/threat_users.json`**: Threat user intelligence

**Auto-save:** Logs are saved every 30 seconds in a background thread.

## Integration Points

### With Auth Server (Port 5000)
- Validates JWT tokens using shared `SECRET_KEY`
- Uses clearance level from token for access decisions

### With VPN Gateway (Port 5001)
- VPN Gateway calls `/api/policy/evaluate` before allowing connections
- VPN Gateway calls `/api/policy/continuous-auth` every 5 minutes
- Policy Engine uses real client IP/location (from VPN Gateway)

## Risk Score Calculation Example

```python
# User: alice@company.com
# Location: China (CN) - outside geo-fence
# Device: Rooted Android, not encrypted
# Resource: database-prod (high sensitivity)

risk_score = 0
risk_score += 15  # Unusual location (CN not in geo-fence)
risk_score += 25  # Rooted device
risk_score += 15  # Device not encrypted
risk_score += 5   # Base risk for critical resource
risk_score += 20  # No MFA verified (required for high-risk)

total_risk = 80

# Threshold for database-prod: 30
# Decision: DENY (80 > 30)
```

## Behavioral Analytics

The Policy Engine tracks user behavior patterns:

- **User Baselines**: Normal countries, hours, resources per user
- **Access History**: Last 100 access attempts per user
- **Velocity Checks**: Detects rapid location changes
- **Anomaly Detection**: Flags unusual access patterns

## Continuous Authentication Flow

1. **VPN Connection Established**: User connects via VPN Gateway
2. **Initial Risk Check**: Policy Engine evaluates connection request
3. **Periodic Checks**: Every 5 minutes, VPN Gateway calls continuous-auth endpoint
4. **Risk Recalculation**: Policy Engine recalculates risk based on current context
5. **Auto-Termination**: If risk > threshold, VPN Gateway terminates connection
6. **Logging**: All checks logged to `continuous_auth_log.json`

## Security Features

### Geo-Fencing
- Restricts access based on country codes
- Default allowed: US, CA, UK, IN
- Configurable per organization

### Device Compliance
- Checks OS version requirements
- Validates encryption status
- Detects rooted/jailbroken devices
- Blocks non-compliant devices for sensitive resources

### IP Reputation
- Checks for TOR exit nodes
- Validates against known malicious IPs
- Blocks suspicious IP ranges

### Rate Limiting
- Per-resource rate limits
- Prevents brute force attacks
- Configurable per resource

### MFA Requirements
- Critical resources require MFA
- High-risk scenarios trigger MFA
- MFA verification reduces risk score

## Troubleshooting

### Common Issues

1. **"High risk detected"**
   - Check risk factors in response
   - Verify device compliance
   - Check location (geo-fencing)
   - Review network policies

2. **"Access denied"**
   - Risk score exceeds resource threshold
   - Check resource policy requirements
   - Verify user clearance level

3. **"Token expired"**
   - JWT token has expired
   - Re-authenticate with Auth Server

4. **"Insufficient clearance"**
   - User clearance level too low
   - Requires higher clearance for threat users endpoint

## Configuration Files

All policies are defined in `policy_engine.py`:
- `RISK_FACTORS`: Risk scoring weights
- `TIME_POLICIES`: Time-based restrictions
- `NETWORK_POLICIES`: Network security policies
- `DEVICE_POLICIES`: Device compliance requirements
- `RESOURCE_POLICIES`: Resource-specific policies
- `SESSION_POLICIES`: Session management settings
- `DYNAMIC_RISK_THRESHOLDS`: Configurable risk thresholds

## Example Usage Flow

```python
# 1. Evaluate access request
POST /api/policy/evaluate
{
  "user": {"email": "alice@company.com"},
  "resource": "database-prod",
  "device": {...},
  "location": {...}
}
# Returns: Decision (ALLOW/DENY) + risk score

# 2. Continuous authentication (called by VPN Gateway)
POST /api/policy/continuous-auth
Headers: Authorization: Bearer <vpn_token>
Body: {"device": {...}, "location": {...}}
# Returns: Verification status + risk score

# 3. Get anomalies
GET /api/policy/anomalies
Headers: Authorization: Bearer <token>
# Returns: List of anomalies

# 4. Get access metrics
GET /api/policy/access-metrics?resource=database-prod
# Returns: VPN vs non-VPN statistics
```

