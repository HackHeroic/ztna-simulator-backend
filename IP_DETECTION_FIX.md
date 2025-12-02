# IP Detection Fix for VPN Connections

## Problem Solved

When a user connects via VPN, their traffic goes through the VPN tunnel, and the server sees the VPN-assigned IP (e.g., `10.8.0.2`) instead of the real client IP (e.g., `203.0.113.45`). This breaks location-based policies during continuous authentication.

## Solution Implemented

### 1. Store Real IP Before VPN Connection

**File: `vpn_gateway.py`**

- **Before VPN Connection**: Detect and store real client IP and location
- **After VPN Connection**: Store VPN-assigned IP separately
- **During Continuous Auth**: Use stored real IP/location, not VPN IP

### Changes:

```python
# In connect_vpn():
# Priority: Frontend-provided > Headers > Direct connection
client_ip = data.get('client_ip')  # Frontend-provided (most reliable)
location = data.get('location')    # Frontend-provided (most reliable)

# If not provided, detect from request
if not client_ip:
    client_ip = get_client_ip()

# Store BEFORE VPN connection
real_client_ip = client_ip
real_location = location.copy()

# Store in connection record
connections[connection_id] = {
    'real_client_ip': real_client_ip,  # Real IP before VPN
    'location': real_location,         # Real location before VPN
    'vpn_ip': result.get('ip'),        # VPN IP (10.8.0.2)
    ...
}
```

### 2. Use Stored Location in Continuous Auth

**File: `vpn_gateway.py` - `continuous_auth_monitor()`**

- Uses stored `location` and `real_client_ip` from connection record
- Does NOT call `get_client_ip()` which would return VPN IP
- Refreshes location if needed using stored real IP

```python
# IMPORTANT: Use stored location/IP from BEFORE VPN connection
location = conn.get('location')        # Stored real location
real_client_ip = conn.get('real_client_ip')  # Stored real IP

# Send to policy engine
resp = requests.post(
    f'{POLICY_ENGINE_URL}/api/policy/continuous-auth',
    json={
        'device': device,
        'location': location,      # Real location, not VPN IP location
        'client_ip': real_client_ip  # Real IP for reference
    },
    ...
)
```

### 3. Policy Engine Prefers Client-Provided Location

**File: `policy_engine.py` - `continuous_auth()`**

- Prefers client-provided location/IP over detecting from request
- Only detects from request if not provided (for non-VPN scenarios)

```python
# Priority: Use client-provided location/IP (most reliable during VPN)
location = data.get('location')
client_ip = data.get('client_ip')

# Only detect from request if not provided
if not location or location.get('country') in ['Unknown', 'Local']:
    if client_ip:
        location = get_location_from_ip(client_ip)  # Use provided IP
    else:
        location = get_location_from_ip(get_client_ip())  # Fallback
```

## How It Works

### Connection Flow:

```
1. Client requests VPN connection
   ↓
2. Server detects real IP: 203.0.113.45 (BEFORE VPN)
   ↓
3. Server detects location: US, New York (BEFORE VPN)
   ↓
4. Server stores: real_client_ip, location
   ↓
5. VPN connection established
   ↓
6. VPN assigns IP: 10.8.0.2
   ↓
7. Server stores: vpn_ip = 10.8.0.2
```

### Continuous Auth Flow:

```
1. Every 5 minutes, continuous auth runs
   ↓
2. Reads stored: real_client_ip, location (from BEFORE VPN)
   ↓
3. Sends to policy engine: real location, not VPN IP location
   ↓
4. Policy engine evaluates: Uses real location for risk scoring
   ↓
5. If risk too high: Terminates VPN connection
```

## API Changes

### VPN Connect Endpoint

**Request (Optional - Frontend can provide IP/location):**
```json
POST /api/vpn/connect
{
    "vpn_token": "...",
    "device": {...},
    "client_ip": "203.0.113.45",  // Optional: Frontend-provided
    "location": {                  // Optional: Frontend-provided
        "country": "US",
        "city": "New York"
    }
}
```

**Response:**
```json
{
    "connection_id": "vpn-user-1234567890",
    "real_client_ip": "203.0.113.45",
    "location": {
        "country": "US",
        "city": "New York"
    },
    "ip": "10.8.0.2",  // VPN-assigned IP
    "routes": ["10.0.0.0/8", "192.168.0.0/16"]
}
```

### VPN Status Endpoint

**Response now includes:**
```json
{
    "status": "active",
    "real_client_ip": "203.0.113.45",  // Real IP (before VPN)
    "location": {...},                   // Real location (before VPN)
    "vpn_ip": "10.8.0.2",               // VPN-assigned IP
    "last_continuous_auth": "...",
    "last_risk_score": 15
}
```

## Benefits

1. ✅ **Accurate Location Detection**: Always uses real client location, not VPN IP location
2. ✅ **Continuous Auth Works**: Risk scoring based on real location during VPN
3. ✅ **Geo-Fencing Works**: Policies can correctly enforce location restrictions
4. ✅ **Velocity Checks Work**: Can detect rapid location changes correctly
5. ✅ **Frontend Support**: Frontend can provide IP/location for better accuracy

## Testing

### Test 1: Connect VPN and Check Status

```bash
# 1. Login
python ztna_client.py login alice@company.com:password123

# 2. Request VPN
python ztna_client.py request-vpn

# 3. Connect VPN
python ztna_client.py connect-vpn

# 4. Check Status (should show real IP and location)
python ztna_client.py vpn-status
```

### Test 2: Continuous Auth During VPN

```bash
# Connect VPN, then wait 5+ minutes
# Check VPN status - should show:
# - real_client_ip: Your real IP
# - location: Your real location
# - last_continuous_auth: Recent timestamp
# - last_risk_score: Based on real location
```

### Test 3: Frontend-Provided IP

```javascript
// Frontend code
const clientIP = await fetch('https://api.ipify.org?format=json')
    .then(r => r.json())
    .then(d => d.ip);

fetch('/api/vpn/connect', {
    method: 'POST',
    body: JSON.stringify({
        vpn_token: token,
        client_ip: clientIP,  // Frontend provides real IP
        device: {...}
    })
});
```

## Notes

- **Backward Compatible**: If frontend doesn't provide IP/location, server detects automatically
- **VPN IP Still Tracked**: `vpn_ip` field stores VPN-assigned IP for network routing
- **Location Refresh**: If location becomes invalid, system refreshes using stored real IP
- **Security**: Real IP is only used for policy evaluation, not exposed unnecessarily

