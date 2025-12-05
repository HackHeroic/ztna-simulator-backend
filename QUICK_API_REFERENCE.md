# Quick API Reference

## VPN Gateway Endpoints (Port 5001)

### Connection Management
- `GET /api/vpn/check-connection?user_email=<email>` - Check if user is connected (NEW)
- `POST /api/vpn/connect` - Connect VPN (prevents duplicate connections)
- `POST /api/vpn/disconnect` - Disconnect VPN
- `GET /api/vpn/status?connection_id=<id>` - Get status by connection ID (NEW - GET support)
- `GET /api/vpn/status?user_email=<email>` - Get status by user email (NEW - GET support)
- `POST /api/vpn/status` - Get status (POST method still works)
- `GET /api/vpn/connections?user_email=<email>` - List connections (filtered by user)

### Monitoring
- `GET /api/vpn/continuous-auth-log?connection_id=<id>&limit=50` - Get continuous auth log
- `GET /api/vpn/verify-openvpn` - Verify OpenVPN setup

### Health
- `GET /health` - Health check

## Policy Engine Endpoints (Port 5002)

### Policy Evaluation
- `POST /api/policy/evaluate` - Evaluate access policy
- `POST /api/policy/test-risk` - Test risk scenarios
- `GET /api/policy/test-scenarios` - Get test scenarios

### Continuous Auth
- `POST /api/policy/continuous-auth` - Continuous authentication
- `GET /api/policy/continuous-auth-history?user_email=<email>&limit=50` - Get history

### Risk Thresholds
- `GET /api/policy/risk-thresholds` - Get current thresholds
- `POST /api/policy/risk-thresholds` - Update thresholds
- `POST /api/policy/risk-thresholds/reset` - Reset to defaults

### Location & Policies
- `GET /api/policy/location-detect?ip=<ip>` - Detect location from IP
- `GET /api/policy/policies` - Get all policies

## Auth Server Endpoints (Port 5000)

- `POST /api/auth/login` - Login
- `GET /api/auth/verify` - Verify token
- `POST /api/access/check` - Check resource access
- `POST /api/access/request-vpn` - Request VPN token

---

## Important Notes

1. **Always check connection before connecting:**
   ```javascript
   GET /api/vpn/check-connection?user_email=alice@company.com
   ```

2. **Connection endpoint returns 409 if already connected:**
   ```json
   {
     "error": "User already has an active VPN connection",
     "existing_connection": {...}
   }
   ```

3. **Status endpoint supports both GET and POST:**
   ```javascript
   GET /api/vpn/status?user_email=alice@company.com
   GET /api/vpn/status?connection_id=vpn-...
   POST /api/vpn/status (with JSON body)
   ```

4. **Restart servers after code changes:**
   ```bash
   # Stop existing servers (Ctrl+C)
   # Then restart:
   python auth_server.py
   python vpn_gateway.py
   python policy_engine.py
   ```

