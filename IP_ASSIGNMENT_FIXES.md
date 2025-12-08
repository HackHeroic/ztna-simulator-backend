# IP Assignment Fixes

## Problems Fixed

### 1. **Duplicate IP Assignment (10.8.0.2 for all users)**
   - **Root Cause**: Hardcoded fallback IP `10.8.0.2` when OpenVPN status couldn't be read
   - **Fix**: 
     - Implemented `get_next_available_ip()` function to assign sequential IPs (10.8.0.2, 10.8.0.3, etc.)
     - Added `assigned_ips` dictionary to track IP assignments and prevent duplicates
     - Removed hardcoded fallback, now assigns next available IP based on connection order

### 2. **UNDEF Common Name Issue**
   - **Root Cause**: OpenVPN showing "UNDEF" instead of certificate CN, causing CN matching to fail
   - **Fix**:
     - Added matching by `real_address` when CN is UNDEF
     - Improved matching logic to handle both CN and real_address
     - Added fallback IP assignment when UNDEF is detected

### 3. **Empty ipp.txt File**
   - **Root Cause**: File might not exist or have wrong permissions
   - **Fix**:
     - Improved `ensure_status_files()` to set proper permissions (666)
     - Enhanced `read_ipp_file()` to handle various formats and edge cases
     - Added `sync_ip_assignments_from_openvpn()` to sync IPs on startup
     - Better error handling and logging for ipp.txt reading

## New Features

1. **IP Assignment Tracking**: Tracks all assigned IPs to prevent duplicates
2. **Real Address Matching**: Matches connections by real_address when CN is UNDEF
3. **IP Sync on Startup**: Syncs existing IP assignments from OpenVPN status log and ipp.txt
4. **New Endpoint**: `/api/vpn/ip-assignments` to check current IP assignments
5. **Better Logging**: More detailed logging for IP assignment process

## Testing

After restarting the VPN Gateway, test with:

```bash
# Check IP assignments
curl http://127.0.0.1:5001/api/vpn/ip-assignments | jq

# Connect multiple users and verify they get different IPs
# Alice should get 10.8.0.2
# Bob should get 10.8.0.3
# Charlie should get 10.8.0.4
```

## Notes

- IPs are assigned sequentially starting from 10.8.0.2
- When a connection disconnects, the IP is released and can be reused
- If OpenVPN status log shows UNDEF, the system will match by real_address
- ipp.txt should be automatically populated by OpenVPN when clients connect

