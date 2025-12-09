# Authentication Server (auth_server.py)

## Overview

The Authentication Server is the entry point for user authentication and authorization in the ZTNA system. It handles user login, generates JWT tokens, and validates access permissions based on user roles, clearance levels, and department assignments.

**Port:** 5000  
**Base URL:** `http://localhost:5000`

## Working Mechanism

### Authentication Flow

1. **User Login**: User provides email and password
2. **Credential Validation**: Server checks credentials against the `USERS` dictionary
3. **JWT Token Generation**: If valid, server generates a JWT token containing:
   - User email
   - Role (Admin, Developer, Analyst, etc.)
   - Clearance level (1-5)
   - Department
   - Expiration time (30 minutes by default)
4. **Session Tracking**: Active sessions are tracked in `active_sessions` dictionary
5. **Token Return**: JWT token is returned to the client for subsequent API calls

### Authorization Model

The system uses a **three-tier authorization model**:

1. **Role-Based Access Control (RBAC)**: Users have roles (Admin, Developer, Analyst, Manager, Security, Intern)
2. **Clearance Levels**: Numeric clearance (1-5) where higher numbers = more access
3. **Department-Based Access**: Users belong to departments (Engineering, IT, Finance, Operations, Security, Compliance)

### Access Policies

Resources have access policies defined in `ACCESS_POLICIES`:
- **database-prod**: Requires clearance 3+, specific roles, and allowed departments
- **file-server**: Requires clearance 2+, broader role access
- **admin-panel**: Requires clearance 5+ and Admin role only
- **vpn-gateway**: Requires clearance 1+ (lowest barrier, accessible to all)

## API Endpoints

### 1. `/api/auth/login` (POST)

**Purpose:** Authenticate user and generate JWT token

**Request Body:**
```json
{
  "email": "alice@company.com",
  "password": "password123"
}
```

**Response (Success):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "role": "Developer",
    "clearance": 3,
    "department": "Engineering"
  },
  "latency_ms": 12.45
}
```

**Response (Error):**
```json
{
  "error": "Invalid credentials"
}
```
Status: 401 Unauthorized

**How it works:**
- Validates email/password against `USERS` dictionary
- Creates JWT token with user claims (email, role, clearance, department)
- Sets expiration time (30 minutes default)
- Tracks session in `active_sessions`
- Returns token and user info

---

### 2. `/api/auth/verify` (GET)

**Purpose:** Verify if a JWT token is valid and not expired

**Headers:**
```
Authorization: Bearer <token>
```

**Response (Valid Token):**
```json
{
  "valid": true,
  "user": {
    "email": "alice@company.com",
    "role": "Developer",
    "clearance": 3,
    "department": "Engineering",
    "exp": 1234567890
  }
}
```

**Response (Invalid/Expired Token):**
```json
{
  "valid": false,
  "error": "Token expired" // or "Invalid token"
}
```
Status: 401 Unauthorized

**How it works:**
- Extracts token from `Authorization` header
- Decodes and validates JWT signature using `SECRET_KEY`
- Checks expiration time
- Returns decoded user information if valid

---

### 3. `/api/access/check` (POST)

**Purpose:** Check if user has access to a specific resource based on access policies

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "resource": "database-prod"
}
```

**Response (Access Granted):**
```json
{
  "access": "GRANTED",
  "resource": "database-prod"
}
```

**Response (Access Denied):**
```json
{
  "access": "DENIED",
  "resource": "database-prod"
}
```
Status: 403 Forbidden

**How it works:**
- Validates JWT token
- Looks up resource policy in `ACCESS_POLICIES`
- Checks three conditions:
  1. User role is in `required_role` list
  2. User clearance >= `required_clearance`
  3. User department is in `allowed_departments` list
- Returns GRANTED if all conditions met, DENIED otherwise

**Example Policy Check:**
```python
# For "database-prod" resource:
policy = {
    "required_role": ["Admin", "Developer", "Security"],
    "required_clearance": 3,
    "allowed_departments": ["Engineering", "IT", "Security"]
}

# User: alice@company.com (Developer, clearance 3, Engineering)
# Result: GRANTED ✓ (role ✓, clearance ✓, department ✓)
```

---

### 4. `/api/access/request-vpn` (POST)

**Purpose:** Generate a VPN-specific JWT token for VPN gateway authentication

**Headers:**
```
Authorization: Bearer <token>
```

**Response (Success):**
```json
{
  "vpn_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "vpn_server": "10.8.0.1",
  "vpn_port": 1194
}
```

**How it works:**
- Validates the original JWT token
- Creates a new VPN-specific token containing:
  - User email (as `user` field)
  - Clearance level
  - Expiration time (30 minutes)
- Returns VPN token and server information
- This token is used by VPN gateway to authenticate VPN connection requests

**Why separate VPN token?**
- VPN gateway only needs minimal user info (email, clearance)
- Reduces token size and complexity
- Allows different expiration policies for VPN vs. web access
- Provides additional security layer

---

### 5. `/health` (GET)

**Purpose:** Health check endpoint for monitoring

**Response:**
```json
{
  "status": "healthy",
  "uptime": "2025-12-09T15:30:00.000000"
}
```

---

## User Database

The system includes pre-configured users for testing:

| Email | Password | Role | Clearance | Department |
|-------|----------|------|-----------|------------|
| alice@company.com | password123 | Developer | 3 | Engineering |
| bob@company.com | securepass | Admin | 5 | IT |
| charlie@company.com | userpass | Analyst | 2 | Finance |
| diana@company.com | security123 | Security | 4 | Security |
| eve@company.com | audit123 | Auditor | 3 | Compliance |
| frank@company.com | manager123 | Manager | 2 | Operations |
| grace@company.com | intern123 | Intern | 1 | Engineering |

## Security Features

### JWT Token Security

- **Secret Key**: Uses `JWT_SECRET` environment variable (default: "your-super-secret-key")
- **Algorithm**: HS256 (HMAC-SHA256)
- **Expiration**: 30 minutes (configurable via `TOKEN_EXPIRY_MINUTES`)
- **Token Claims**: Includes user identity, role, clearance, and expiration

### Session Management

- Active sessions tracked in memory (`active_sessions` dictionary)
- Session includes token and login timestamp
- Sessions are not persisted (cleared on server restart)

## Integration Points

### With Policy Engine (Port 5002)
- Policy engine validates tokens using the same `SECRET_KEY`
- Policy engine uses clearance level for risk-based access decisions

### With VPN Gateway (Port 5001)
- VPN gateway receives VPN tokens from this server
- VPN gateway validates tokens before allowing connections
- Clearance level determines VPN access eligibility

## Error Handling

- **400 Bad Request**: Missing email or password
- **401 Unauthorized**: Invalid credentials, expired token, or invalid token
- **403 Forbidden**: Access denied to resource
- **404 Not Found**: Unknown resource requested

## Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT signing (default: "your-super-secret-key")
  - **Important**: Change this in production!

### Constants

- `TOKEN_EXPIRY_MINUTES`: Token expiration time (default: 30 minutes)
- `USERS`: User database (in-memory dictionary)
- `ACCESS_POLICIES`: Resource access policies

## Example Usage Flow

```python
# 1. Login
POST /api/auth/login
{
  "email": "alice@company.com",
  "password": "password123"
}
# Returns: JWT token

# 2. Verify token
GET /api/auth/verify
Headers: Authorization: Bearer <token>
# Returns: User info if valid

# 3. Check access
POST /api/access/check
Headers: Authorization: Bearer <token>
Body: {"resource": "database-prod"}
# Returns: GRANTED or DENIED

# 4. Request VPN token
POST /api/access/request-vpn
Headers: Authorization: Bearer <token>
# Returns: VPN token for VPN gateway
```

## Security Considerations

1. **Password Storage**: Currently stored in plaintext (for demo purposes)
   - **Production**: Use password hashing (bcrypt, argon2)
   
2. **Token Security**: 
   - Tokens should be stored securely on client side
   - Use HTTPS in production
   - Implement token refresh mechanism

3. **Secret Key**:
   - Never commit `JWT_SECRET` to version control
   - Use strong, random secret keys in production
   - Rotate keys periodically

4. **Session Management**:
   - Current implementation is in-memory (lost on restart)
   - Consider Redis/database for production
   - Implement session timeout and cleanup

## Troubleshooting

### Common Issues

1. **"Invalid credentials"**
   - Check email/password spelling
   - Verify user exists in `USERS` dictionary

2. **"Token expired"**
   - Token lifetime is 30 minutes
   - Re-authenticate to get new token

3. **"Access denied"**
   - Check user's role, clearance, and department
   - Verify resource policy requirements
   - Ensure user meets all three conditions (role, clearance, department)

4. **"Invalid token"**
   - Token may be corrupted
   - Ensure `JWT_SECRET` matches across services
   - Check token format (should start with "Bearer ")

