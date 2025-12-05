# Admin Access & Metrics Guide

## 🔧 Fixed Issues

### 1. Risk Score Always 15 - FIXED ✅

**Problem:** Risk score was always showing 15 because when VPN was connected, the system was using VPN IP (10.8.0.2) location instead of real location.

**Solution:** 
- System now checks if user has active VPN connection
- If VPN connected, uses stored **real IP and location** (from BEFORE VPN connection)
- If no VPN, detects location from request IP
- Risk calculation now uses **real location** for accurate scoring

**Result:** Risk scores now properly reflect user's actual location, not VPN location.

---

## 👑 Admin/Master Access

### Admin Users

By default, users with:
- Email in `ADMIN_USERS` list: `['bob@company.com']`
- Role: `'Admin'`
- Clearance: `5` or higher

Have admin access to modify policies and risk factors.

### Admin Endpoints

All admin endpoints require `Authorization: Bearer <token>` header with admin user's token.

#### 1. Get Risk Factors
```bash
GET /api/policy/admin/risk-factors
Authorization: Bearer <admin_token>

Response:
{
  "risk_factors": {
    "failed_login_attempts": 20,
    "unusual_location": 15,
    "device_age_days": 10,
    ...
  },
  "modified_by": "bob@company.com",
  "timestamp": "2025-01-15T10:30:00"
}
```

#### 2. Update Risk Factors
```bash
POST /api/policy/admin/risk-factors
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "unusual_location": 20,  # Change from 15 to 20
  "rooted_device": 30,     # Change from 25 to 30
  "public_wifi": 25        # Change from 18 to 25
}

Response:
{
  "message": "Risk factors updated by bob@company.com",
  "updated": ["unusual_location", "rooted_device", "public_wifi"],
  "risk_factors": {...},
  "timestamp": "..."
}
```

#### 3. Get Resource Policies
```bash
GET /api/policy/admin/resource-policies
Authorization: Bearer <admin_token>
```

#### 4. Update Resource Policy
```bash
POST /api/policy/admin/resource-policies
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "resource": "database-prod",
  "updates": {
    "require_mfa": false,           # Change MFA requirement
    "session_timeout_minutes": 20,   # Change timeout
    "sensitivity": "critical"        # Change sensitivity
  }
}
```

#### 5. Get Network Policies
```bash
GET /api/policy/admin/network-policies
Authorization: Bearer <admin_token>
```

#### 6. Update Network Policies
```bash
POST /api/policy/admin/network-policies
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "updates": {
    "geo_fencing": ["US", "CA", "UK", "IN", "DE"],  # Add Germany
    "allow_public_wifi": true,                       # Allow public WiFi
    "block_vpn_proxies": true                        # Block VPN proxies
  }
}
```

#### 7. Add New Resource
```bash
POST /api/policy/admin/add-resource
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "api-gateway",
  "policy": {
    "sensitivity": "high",
    "require_mfa": true,
    "require_low_risk": true,
    "session_timeout_minutes": 20,
    "audit_all_access": true
  }
}
```

#### 8. Remove Resource
```bash
POST /api/policy/admin/remove-resource
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "api-gateway"
}
```

**Note:** Cannot remove critical resources.

---

## 📊 Access Metrics - VPN vs Non-VPN

### Get Access Metrics

Compare access metrics for VPN vs non-VPN access:

```bash
# All resources, all users
GET /api/policy/access-metrics

# Specific resource
GET /api/policy/access-metrics?resource=database-prod

# Specific user
GET /api/policy/access-metrics?user_email=alice@company.com

# Both filters
GET /api/policy/access-metrics?resource=admin-panel&user_email=alice@company.com
```

### Response Format

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
      "denied": 3,
      "mfa_required": 2,
      "avg_risk_score": 18.5,
      "min_risk_score": 10,
      "max_risk_score": 45,
      "allow_rate": 93.75
    },
    "non_vpn": {
      "count": 70,
      "allowed": 65,
      "denied": 4,
      "mfa_required": 1,
      "avg_risk_score": 22.3,
      "min_risk_score": 12,
      "max_risk_score": 55,
      "allow_rate": 92.86
    }
  },
  "by_resource": {
    "database-prod": {
      "vpn": {
        "count": 30,
        "allowed": 28,
        "denied": 1,
        "mfa_required": 1,
        "avg_risk_score": 20.5,
        "allow_rate": 93.33
      },
      "non_vpn": {
        "count": 25,
        "allowed": 23,
        "denied": 2,
        "mfa_required": 0,
        "avg_risk_score": 25.2,
        "allow_rate": 92.0
      }
    },
    "admin-panel": {...},
    "file-server": {...}
  },
  "recent_attempts": [...]
}
```

### Get All Resources

```bash
GET /api/policy/resources

Response:
{
  "resources": [
    {
      "name": "database-prod",
      "sensitivity": "high",
      "require_mfa": true,
      "require_low_risk": true,
      "session_timeout_minutes": 15,
      "audit_all_access": true,
      "time_restricted": false
    },
    ...
  ],
  "count": 4
}
```

---

## 🧪 Testing Examples

### 1. Test Risk Score Fix

```bash
# Login as user
python ztna_client.py login alice@company.com:password123

# Evaluate policy WITHOUT VPN (should use real IP location)
curl -X POST http://localhost:5002/api/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "user": {"email": "alice@company.com"},
    "resource": "database-prod",
    "device": {"os_type": "macOS", "os_version": "12.0", "encrypted": true},
    "location": {"country": "US"}
  }'

# Connect VPN
python ztna_client.py request-vpn
python ztna_client.py connect-vpn

# Evaluate policy WITH VPN (should use stored real location, not VPN IP)
curl -X POST http://localhost:5002/api/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "user": {"email": "alice@company.com"},
    "resource": "database-prod",
    "device": {"os_type": "macOS", "os_version": "12.0", "encrypted": true}
  }'

# Check response - should show:
# - vpn_connected: true
# - location_used: "US" (real location, not "Local")
# - risk_score: Should be same as without VPN (if same location)
```

### 2. Test Admin Access

```bash
# Login as admin (bob@company.com)
python ztna_client.py login bob@company.com:securepass

# Get token from response, then:
TOKEN="<your_token_here>"

# Get risk factors
curl http://localhost:5002/api/policy/admin/risk-factors \
  -H "Authorization: Bearer $TOKEN"

# Update risk factor
curl -X POST http://localhost:5002/api/policy/admin/risk-factors \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"unusual_location": 25}'

# Verify change
curl http://localhost:5002/api/policy/admin/risk-factors \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Test Access Metrics

```bash
# Make some access attempts (with and without VPN)
# Then get metrics:

# All metrics
curl http://localhost:5002/api/policy/access-metrics

# Per resource
curl "http://localhost:5002/api/policy/access-metrics?resource=database-prod"

# Per user
curl "http://localhost:5002/api/policy/access-metrics?user_email=alice@company.com"
```

---

## 📈 Frontend Integration

### Display Access Metrics

```javascript
async function displayMetrics() {
  // Get all resources
  const resources = await fetch('http://localhost:5002/api/policy/resources')
    .then(r => r.json());
  
  // Get metrics for each
  for (const resource of resources.resources) {
    const metrics = await fetch(
      `http://localhost:5002/api/policy/access-metrics?resource=${resource.name}`
    ).then(r => r.json());
    
    console.log(`\n${resource.name}:`);
    console.log(`  VPN: ${metrics.overall.vpn.allow_rate}% allow rate, avg risk: ${metrics.overall.vpn.avg_risk_score}`);
    console.log(`  Non-VPN: ${metrics.overall.non_vpn.allow_rate}% allow rate, avg risk: ${metrics.overall.non_vpn.avg_risk_score}`);
  }
}
```

### Admin Panel Example

```javascript
async function updateRiskFactor(factor, value, token) {
  const response = await fetch('http://localhost:5002/api/policy/admin/risk-factors', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({[factor]: value})
  });
  
  return await response.json();
}

// Update unusual_location risk from 15 to 20
await updateRiskFactor('unusual_location', 20, adminToken);
```

---

## 🔍 Key Changes Summary

1. ✅ **Fixed Risk Calculation** - Now uses real location when VPN connected
2. ✅ **Admin Access Control** - Master users can modify all policies
3. ✅ **Access Metrics Tracking** - Compare VPN vs non-VPN access
4. ✅ **Resource Management** - Add/remove resources via API
5. ✅ **Policy Modification** - Update risk factors, thresholds, policies via API

---

## 🚨 Important Notes

1. **Risk Score Fix**: The system now properly detects if user has VPN and uses stored real location
2. **Admin Access**: Only users with admin role, clearance 5+, or in ADMIN_USERS list can modify policies
3. **Metrics**: All access attempts are logged with VPN status for comparison
4. **Location Detection**: System prioritizes:
   - VPN connected → Use stored real location
   - Frontend-provided location → Use that
   - Detect from request IP → Fallback

---

## 📝 Quick Reference

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/policy/access-metrics` | GET | No | Get access metrics (VPN vs non-VPN) |
| `/api/policy/resources` | GET | No | List all resources |
| `/api/policy/admin/risk-factors` | GET/POST | Admin | Get/update risk factors |
| `/api/policy/admin/resource-policies` | GET/POST | Admin | Get/update resource policies |
| `/api/policy/admin/network-policies` | GET/POST | Admin | Get/update network policies |
| `/api/policy/admin/add-resource` | POST | Admin | Add new resource |
| `/api/policy/admin/remove-resource` | POST | Admin | Remove resource |

