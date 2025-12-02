# ZTNA Policy Engine Documentation

## Overview

The enhanced policy engine implements comprehensive Zero Trust Network Access (ZTNA) policies with continuous authentication, risk-based access control, and location-aware security.

## Location Identification

### How Location is Identified

Location is identified using **IP geolocation**:

1. **IP Extraction**: The system extracts the client's IP address from HTTP headers:
   - `X-Forwarded-For` (for proxied requests)
   - `X-Real-IP` (for reverse proxies)
   - `request.remote_addr` (direct connection)

2. **Geolocation Lookup**: The IP address is sent to a geolocation service:
   - **Service Used**: `ip-api.com` (free tier, no API key required)
   - **Returns**: Country, city, latitude, longitude, ISP information
   - **Fallback**: If lookup fails, returns "Unknown" location

3. **Usage**:
   - Location is automatically detected when not provided in requests
   - Used for geo-fencing policies (allowed countries)
   - Used for velocity checks (rapid location changes)
   - Stored with session data for audit trails

### Example Location Data
```json
{
  "country": "US",
  "country_name": "United States",
  "city": "New York",
  "latitude": 40.7128,
  "longitude": -74.0060,
  "isp": "Verizon",
  "source": "ip-api"
}
```

## Continuous Authentication

### How It Works

1. **Initial Authentication**: User logs in and receives a JWT token
2. **Periodic Verification**: Every 5 minutes (configurable), the system:
   - Verifies the JWT token is still valid
   - Checks current risk score based on:
     - Location changes
     - Device status
     - Time of access
     - Behavioral patterns
   - Updates session status

3. **Automatic Termination**: If continuous auth fails:
   - VPN connection is terminated
   - Session is marked as "terminated"
   - Anomaly is logged
   - User must re-authenticate

### Integration Points

- **VPN Gateway**: Background thread checks all active connections every 5 minutes
- **Policy Engine**: `/api/policy/continuous-auth` endpoint performs verification
- **Client**: Can call `/api/policy/session-status` to check verification status

## Policy Categories

### 1. Risk-Based Access Control
- **Risk Scoring**: 0-100 scale
  - < 30: Low risk (allow)
  - 30-50: Medium risk (may require MFA)
  - 50-75: High risk (deny)
  - > 75: Critical risk (immediate deny)

- **Risk Factors**:
  - Failed login attempts: +20
  - Unusual location: +15
  - Public WiFi: +18
  - Rooted device: +25
  - Velocity anomaly: +20
  - No MFA (when required): +20
  - Known malicious IP: +40

### 2. Time-Based Policies
- **Business Hours**: Restrict access to 9 AM - 5 PM
- **Weekend Access**: Allow/block weekend access
- **Timezone Awareness**: Support for different timezones
- **Unusual Time Access**: Flag access outside normal hours

### 3. Network-Based Policies
- **Geo-Fencing**: Allow only specific countries (US, CA, UK)
- **Public WiFi**: Block or allow public WiFi connections
- **IP Reputation**: Check against known malicious IPs
- **Tor Blocking**: Block Tor exit nodes
- **VPN/Proxy Detection**: Allow corporate VPN, block others

### 4. Device Compliance Policies
- **OS Version Requirements**: Minimum OS versions per platform
- **Encryption**: Require device encryption
- **Rooted/Jailbroken**: Block compromised devices
- **Antivirus**: Require antivirus software
- **MDM Enrollment**: Require Mobile Device Management

### 5. Resource Sensitivity Policies
Different policies per resource:

- **Critical Resources** (admin-panel):
  - MFA required
  - Risk threshold: < 20
  - Session timeout: 10 minutes
  - Full audit logging

- **High Sensitivity** (database-prod):
  - MFA required
  - Risk threshold: < 30
  - Session timeout: 15 minutes
  - Full audit logging

- **Medium Sensitivity** (file-server, vpn-gateway):
  - MFA optional
  - Risk threshold: < 50
  - Session timeout: 30-60 minutes

### 6. Session Policies
- **Max Concurrent Sessions**: 3 per user
- **Session Timeout**: 30 minutes default
- **Idle Timeout**: 15 minutes
- **Re-authentication**: Required after 60 minutes
- **Continuous Auth Interval**: 5 minutes

### 7. Behavioral Analytics
- **User Baseline**: Learn normal user behavior
  - Normal countries
  - Normal access hours
  - Normal resources accessed

- **Anomaly Detection**:
  - Velocity checks (rapid location changes)
  - Unusual resource access
  - Access pattern deviations

## API Endpoints

### Policy Evaluation
```
POST /api/policy/evaluate
Body: {
  "user": {"email": "user@example.com"},
  "resource": "database-prod",
  "device": {"os_type": "iOS", "os_version": "15.0", "encrypted": true},
  "location": {"country": "US", "city": "New York"},
  "context": {"mfa_verified": true}
}
Response: {
  "decision": "ALLOW" | "DENY" | "MFA_REQUIRED",
  "risk_score": 25,
  "risk_factors": ["Unusual location: CN"],
  "context": {...}
}
```

### Continuous Authentication
```
POST /api/policy/continuous-auth
Headers: Authorization: Bearer <token>
Body: {
  "device": {...},
  "location": {...}
}
Response: {
  "status": "verified" | "failed",
  "risk_score": 15,
  "user": "user@example.com"
}
```

### Session Status
```
POST /api/policy/session-status
Headers: Authorization: Bearer <token>
Response: {
  "status": "active",
  "last_verified": "2024-01-15T10:30:00",
  "minutes_since_verify": 3.5,
  "risk_score": 10,
  "requires_reverify": false
}
```

### Location Detection
```
GET /api/policy/location-detect?ip=8.8.8.8
Response: {
  "ip": "8.8.8.8",
  "location": {
    "country": "US",
    "city": "Mountain View",
    ...
  }
}
```

### Anomaly Detection
```
POST /api/policy/anomaly-detect
Body: {"email": "user@example.com"}
Response: {
  "anomalies": 2,
  "recent_anomalies": 1,
  "details": [...],
  "risk_level": "medium"
}
```

## Configuration

All policies are configurable in `policy_engine.py`:

```python
# Risk factors
RISK_FACTORS = {
    'failed_login_attempts': 20,
    'unusual_location': 15,
    ...
}

# Time policies
TIME_POLICIES = {
    'business_hours_only': False,
    'weekend_access': True,
    ...
}

# Network policies
NETWORK_POLICIES = {
    'geo_fencing': ['US', 'CA', 'UK'],
    'allow_public_wifi': False,
    ...
}
```

## Usage Flow

1. **User Login** → Receives JWT token
2. **Access Request** → Policy engine evaluates:
   - Risk score calculation
   - Policy compliance check
   - MFA requirement check
3. **VPN Connection** → Gateway:
   - Pre-connection policy check
   - Location detection
   - Connection establishment
4. **Active Session** → Continuous monitoring:
   - Periodic risk assessment (every 5 min)
   - Token validation
   - Automatic termination if risk detected
5. **Access Termination** → On:
   - High risk detection
   - Token expiration
   - Manual disconnect
   - Policy violation

## Security Features

- ✅ JWT token validation
- ✅ Risk-based access control
- ✅ Continuous authentication
- ✅ Location-aware policies
- ✅ Device compliance checks
- ✅ Behavioral anomaly detection
- ✅ Session management
- ✅ Audit logging
- ✅ Automatic threat response

## Future Enhancements

- Machine learning-based risk scoring
- Integration with threat intelligence feeds
- Advanced behavioral analytics
- Real-time policy updates
- Multi-factor authentication integration
- Device fingerprinting
- Network traffic analysis

