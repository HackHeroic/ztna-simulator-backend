# OpenVPN Status Files Fix

## Problem

The `ipp.txt` and `openvpn-status.log` files were not being updated when OpenVPN was running.

## Root Causes

1. **Missing Update Interval**: The `status` directive in `server.ovpn` needs an update interval (seconds)
2. **File Permissions**: Files might not be writable by OpenVPN process (running as root)
3. **Status Format**: Need to specify status format version for proper parsing
4. **No Monitoring**: No way to verify if files are being updated

## Solutions Implemented

### 1. Fixed OpenVPN Configuration

**File: `server.ovpn`**

Changed:
```
status openvpn-status.log
```

To:
```
status openvpn-status.log 10
status-version 2
```

- `10` = Update status file every 10 seconds
- `status-version 2` = Use version 2 format (more detailed)

### 2. Added Status File Functions

**File: `vpn_gateway.py`**

Added functions to properly read and parse OpenVPN status files:

- `read_openvpn_status()` - Parses `openvpn-status.log` format
- `read_ipp_file()` - Parses `ipp.txt` IP pool assignments
- `ensure_status_files()` - Creates files if they don't exist and sets permissions

### 3. Enhanced IP Detection

Updated VPN connection logic to:
1. First check `ipp.txt` for IP assignments (more reliable)
2. Fallback to `openvpn-status.log` if not found
3. Use proper parsing instead of regex search

### 4. Added Monitoring

- Background thread monitors file sizes every 30 seconds
- Logs when files are updated
- Shows client count and IP assignments

### 5. New API Endpoints

- `GET /api/vpn/openvpn-status` - Get detailed status from files
- Enhanced `GET /api/vpn/verify-openvpn` - Shows file update status

## How It Works Now

### Status File Format (openvpn-status.log)

OpenVPN writes status in this format:
```
OpenVPN CLIENT LIST
Updated,Mon Jan 15 10:30:00 2025
Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since
client1,203.0.113.45:12345,10.8.0.2,12345,67890,Mon Jan 15 10:25:00 2025
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,client1,203.0.113.45:12345,Mon Jan 15 10:30:00 2025
GLOBAL STATS
Max bcast/mcast queue length,0
END
```

### IP Pool File Format (ipp.txt)

Format:
```
client1,10.8.0.2
client2,10.8.0.3
```

## Testing

### 1. Check if OpenVPN is Running

```bash
# Check process
ps aux | grep openvpn | grep server.ovpn

# Check port
lsof -i :1194
```

### 2. Check Status Files

```bash
# Check if files exist and have content
ls -lh openvpn-status.log ipp.txt

# View status log
cat openvpn-status.log

# View IP pool
cat ipp.txt
```

### 3. Use API Endpoints

```bash
# Get detailed status
curl http://localhost:5001/api/vpn/openvpn-status

# Verify OpenVPN (shows file update status)
curl http://localhost:5001/api/vpn/verify-openvpn
```

### 4. Monitor Updates

The background thread will log updates:
```
[2025-01-15T10:30:00] OpenVPN status log updated: 512 bytes (was 256)
  Active clients: 2
[2025-01-15T10:30:00] IP pool file updated: 64 bytes (was 32)
  IP assignments: 2
```

## Troubleshooting

### Files Still Empty?

1. **Check OpenVPN is actually running:**
   ```bash
   ps aux | grep openvpn
   ```

2. **Check file permissions:**
   ```bash
   ls -la openvpn-status.log ipp.txt
   # Should be writable (666 or 644)
   ```

3. **Check OpenVPN is writing:**
   ```bash
   # Watch file size
   watch -n 1 'ls -lh openvpn-status.log ipp.txt'
   ```

4. **Restart OpenVPN with new config:**
   ```bash
   # Kill existing
   sudo pkill -f "openvpn.*server.ovpn"
   
   # Restart
   sudo openvpn --config server.ovpn --daemon
   ```

5. **Check OpenVPN logs:**
   ```bash
   tail -f openvpn.log
   ```

### Files Not Updating?

1. **Verify status directive:**
   ```bash
   grep "status" server.ovpn
   # Should show: status openvpn-status.log 10
   ```

2. **Check if clients are connecting:**
   - Status file only updates when clients connect
   - If no clients, file stays empty

3. **Verify working directory:**
   - OpenVPN must run from directory containing `server.ovpn`
   - Files are created in same directory

## Expected Behavior

### When OpenVPN Starts:
1. Creates `openvpn-status.log` (if doesn't exist)
2. Creates `ipp.txt` (if doesn't exist)
3. Updates status every 10 seconds (even with no clients)

### When Client Connects:
1. `ipp.txt` gets entry: `client-name,10.8.0.2`
2. `openvpn-status.log` gets client entry in CLIENT LIST
3. `openvpn-status.log` gets routing entry in ROUTING TABLE
4. Files update every 10 seconds with current stats

### When Client Disconnects:
1. Entry removed from `openvpn-status.log` after timeout
2. Entry may remain in `ipp.txt` (for persistence)

## API Response Examples

### GET /api/vpn/openvpn-status

```json
{
  "status_log": {
    "clients": [
      {
        "common_name": "vpn-alice@company.com-1234567890",
        "real_address": "203.0.113.45:54321",
        "virtual_address": "10.8.0.2",
        "bytes_received": "12345",
        "bytes_sent": "67890",
        "connected_since": "Mon Jan 15 10:25:00 2025"
      }
    ],
    "routing_table": [
      {
        "virtual_address": "10.8.0.2",
        "common_name": "vpn-alice@company.com-1234567890",
        "real_address": "203.0.113.45:54321",
        "last_ref": "Mon Jan 15 10:30:00 2025"
      }
    ],
    "last_updated": "2025-01-15T10:30:00"
  },
  "ip_pool": {
    "assignments": [
      {
        "common_name": "vpn-alice@company.com-1234567890",
        "ip_address": "10.8.0.2"
      }
    ],
    "count": 1
  },
  "status_log_size": 512,
  "ipp_file_size": 64
}
```

## Key Changes Summary

1. ✅ Added update interval to `status` directive (10 seconds)
2. ✅ Added `status-version 2` for better format
3. ✅ Added proper parsing functions for status files
4. ✅ Enhanced IP detection to use `ipp.txt` first
5. ✅ Added file monitoring thread
6. ✅ Added API endpoints to view status
7. ✅ Added file creation and permission handling

## Next Steps

1. **Restart OpenVPN server** with new configuration:
   ```bash
   sudo pkill -f "openvpn.*server.ovpn"
   sudo openvpn --config server.ovpn --daemon
   ```

2. **Restart VPN Gateway** to load new code:
   ```bash
   # Stop current server (Ctrl+C)
   python vpn_gateway.py
   ```

3. **Connect a client** and verify files update:
   ```bash
   python ztna_client.py login alice@company.com:password123
   python ztna_client.py request-vpn
   python ztna_client.py connect-vpn
   
   # Wait 10-20 seconds, then check:
   cat openvpn-status.log
   cat ipp.txt
   ```

4. **Check API**:
   ```bash
   curl http://localhost:5001/api/vpn/openvpn-status | jq
   ```

