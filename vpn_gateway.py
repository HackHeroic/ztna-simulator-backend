# vpn_gateway.py

import os
import re
import subprocess
import threading
import time
import jwt
import requests
from flask import Flask, request, jsonify
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')
POLICY_ENGINE_URL = 'http://127.0.0.1:5002'  # Policy engine endpoint

# Mock active connections (in-memory for preview)
connections = {}
openvpn_process = None

# IP assignment tracking (to avoid duplicates and track assignments)
assigned_ips = {}  # Maps IP address to connection_id
ip_counter = 2  # Start from 10.8.0.2 (10.8.0.1 is server)

# Continuous auth monitoring log
continuous_auth_log = []  # Store continuous auth history

# Continuous auth background thread
def continuous_auth_monitor():
    """
    Background thread to periodically verify active VPN connections.
    Uses stored real client IP/location (from BEFORE VPN connection) to avoid
    detecting VPN IP (10.8.0.x) instead of real client IP.
    """
    while True:
        time.sleep(300)  # Check every 5 minutes
        for conn_id, conn in list(connections.items()):
            if conn.get('status') == 'active':
                try:
                    # Get the original token from connection
                    token = conn.get('token')
                    if not token:
                        continue
                    
                    # IMPORTANT: Use stored location/IP from BEFORE VPN connection
                    # NOT: get_client_ip() which would return VPN IP (10.8.0.x)
                    device = conn.get('device', {})
                    location = conn.get('location', {})  # Stored real location
                    real_client_ip = conn.get('real_client_ip')  # Stored real IP
                    
                    # If location is missing or invalid, try to refresh from stored IP
                    if not location or location.get('country') in ['Unknown', 'Local']:
                        if real_client_ip:
                            location = get_location_from_ip(real_client_ip)
                            conn['location'] = location  # Update stored location
                    
                    # Log the request
                    request_timestamp = datetime.now().isoformat()
                    log_entry = {
                        'timestamp': request_timestamp,
                        'connection_id': conn_id,
                        'user': conn.get('user'),
                        'action': 'request',
                        'real_client_ip': real_client_ip,
                        'location': location.get('country', 'Unknown'),
                        'status': 'pending'
                    }
                    continuous_auth_log.append(log_entry)
                    print(f"[{request_timestamp}] Continuous auth REQUEST for {conn_id}")
                    print(f"  - User: {conn.get('user')}")
                    print(f"  - Real IP: {real_client_ip}")
                    print(f"  - Location: {location.get('country', 'Unknown')}")
                    
                    # Call policy engine for continuous auth with REAL location
                    headers = {'Authorization': f'Bearer {token}'}
                    resp = requests.post(
                        f'{POLICY_ENGINE_URL}/api/policy/continuous-auth',
                        json={
                            'device': device,
                            'location': location,  # Real location, not VPN IP location
                            'client_ip': real_client_ip  # Real IP for reference
                        },
                        headers=headers,
                        timeout=5
                    )
                    
                    # Log the response
                    response_timestamp = datetime.now().isoformat()
                    if resp.status_code != 200:
                        # Continuous auth failed - disconnect
                        log_entry['action'] = 'response'
                        log_entry['status'] = 'failed'
                        log_entry['status_code'] = resp.status_code
                        log_entry['error'] = resp.text[:200] if resp.text else 'Unknown error'
                        continuous_auth_log.append(log_entry)
                        
                        print(f"[{response_timestamp}] Continuous auth FAILED for {conn_id}")
                        print(f"  - Status Code: {resp.status_code}")
                        print(f"  - Error: {resp.text[:200] if resp.text else 'Unknown'}")
                        
                        conn['status'] = 'terminated'
                        conn['termination_reason'] = 'continuous_auth_failed'
                        conn['terminated_at'] = response_timestamp
                        # Optionally kill the OpenVPN process
                        if is_openvpn_installed():
                            subprocess.run(['pkill', '-f', conn_id], capture_output=True)
                    else:
                        result = resp.json()
                        log_entry['action'] = 'response'
                        log_entry['status'] = 'success'
                        log_entry['status_code'] = resp.status_code
                        log_entry['risk_score'] = result.get('risk_score', 0)
                        log_entry['policy_status'] = result.get('status', 'unknown')
                        continuous_auth_log.append(log_entry)
                        
                        conn['last_continuous_auth'] = response_timestamp
                        conn['last_risk_score'] = result.get('risk_score', 0)
                        
                        print(f"[{response_timestamp}] Continuous auth SUCCESS for {conn_id}")
                        print(f"  - Status: {result.get('status')}")
                        print(f"  - Risk Score: {result.get('risk_score', 0)}")
                    
                    # Keep only last 1000 entries
                    if len(continuous_auth_log) > 1000:
                        continuous_auth_log[:] = continuous_auth_log[-1000:]
                        
                except Exception as e:
                    error_timestamp = datetime.now().isoformat()
                    log_entry = {
                        'timestamp': error_timestamp,
                        'connection_id': conn_id,
                        'action': 'error',
                        'status': 'error',
                        'error': str(e)
                    }
                    continuous_auth_log.append(log_entry)
                    print(f"[{error_timestamp}] Continuous auth ERROR for {conn_id}: {e}")

# Start continuous auth monitor thread
auth_monitor_thread = threading.Thread(target=continuous_auth_monitor, daemon=True)
auth_monitor_thread.start()

def is_openvpn_installed():
    try:
        subprocess.run(['openvpn', '--version'], capture_output=True, check=True)
        return True
    except:
        return False

def is_openvpn_running():
    """Check if OpenVPN is already running on the system."""
    try:
        # Check if port 1194 is in use (OpenVPN default port)
        result = subprocess.run(
            ['lsof', '-i', ':1194'],
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0 and result.stdout:
            return True
        
        # Also check for OpenVPN processes
        result = subprocess.run(
            ['pgrep', '-f', 'openvpn.*server.ovpn'],
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0 and result.stdout:
            return True
    except:
        pass
    return False

def ensure_status_files():
    """Ensure OpenVPN status files exist and are writable."""
    status_file = 'openvpn-status.log'
    ipp_file = 'ipp.txt'
    
    # Create files if they don't exist
    if not os.path.exists(status_file):
        try:
            with open(status_file, 'w') as f:
                f.write('')  # Create empty file
            print(f"Created {status_file}")
        except Exception as e:
            print(f"Warning: Could not create {status_file}: {e}")
    
    if not os.path.exists(ipp_file):
        try:
            with open(ipp_file, 'w') as f:
                f.write('')  # Create empty file
            print(f"Created {ipp_file}")
        except Exception as e:
            print(f"Warning: Could not create {ipp_file}: {e}")
    
    # Try to make files writable (if running as root, OpenVPN can write)
    try:
        os.chmod(status_file, 0o666)  # Read/write for all
        os.chmod(ipp_file, 0o666)
        print(f"[VPN] Set permissions on {status_file} and {ipp_file} to 666")
    except Exception as e:
        print(f"[VPN] Warning: Could not set file permissions: {e}")

def sync_ip_assignments_from_openvpn():
    """Sync IP assignments from OpenVPN status log and ipp.txt on startup."""
    global assigned_ips
    
    print("[VPN] Syncing IP assignments from OpenVPN...")
    
    # Read from status log
    status_data = read_openvpn_status()
    for client in status_data.get('clients', []):
        vpn_ip = client.get('virtual_address', '').strip()
        cn = client.get('common_name', '').strip()
        if vpn_ip and vpn_ip.startswith('10.8.0.'):
            # Create a temporary connection ID for tracking
            temp_id = f"openvpn-{cn}-{vpn_ip}"
            assigned_ips[vpn_ip] = temp_id
            print(f"[VPN] Synced IP {vpn_ip} from status log (CN: {cn})")
    
    # Read from ipp.txt
    ipp_data = read_ipp_file()
    for assignment in ipp_data.get('assignments', []):
        ip_addr = assignment.get('ip_address', '').strip()
        cn = assignment.get('common_name', '').strip()
        if ip_addr and ip_addr.startswith('10.8.0.'):
            temp_id = f"ipp-{cn}-{ip_addr}"
            assigned_ips[ip_addr] = temp_id
            print(f"[VPN] Synced IP {ip_addr} from ipp.txt (CN: {cn})")
    
    print(f"[VPN] Synced {len(assigned_ips)} IP assignments")

def start_openvpn_daemon():
    """
    Start OpenVPN daemon if not already running.
    Detects existing OpenVPN instances and handles errors gracefully.
    """
    global openvpn_process
    
    # Ensure status files exist
    ensure_status_files()
    
    # Check if our tracked process is running
    if openvpn_process and openvpn_process.poll() is None:
        print("OpenVPN daemon already running (tracked by this process)")
        return True
    
    if not is_openvpn_installed():
        print("OpenVPN not installed; using mock mode.")
        return True  # Mock success for preview
    
    # Check if OpenVPN is already running on the system (manually started or by another process)
    if is_openvpn_running():
        print("OpenVPN daemon already running (detected on port 1194 or as process)")
        # Create a dummy process object to track that it's running
        try:
            openvpn_process = subprocess.Popen(['echo'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            pass
        return True
    
    # Try to start OpenVPN daemon
    try:
        print("Starting OpenVPN daemon...")
        # Ensure we're in the right directory
        cwd = os.getcwd()
        print(f"Working directory: {cwd}")
        print(f"Config file exists: {os.path.exists('server.ovpn')}")
        
        # Try to start OpenVPN (will fail without sudo, but we'll catch the error)
        openvpn_process = subprocess.Popen(
            ['openvpn', '--config', 'server.ovpn', '--daemon'],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=cwd  # Ensure we're in the right directory for config files
        )
        time.sleep(2)  # Wait a bit for process to start or fail
        
        # Check if process exited immediately (indicates error)
        if openvpn_process.poll() is not None:
            # Process exited, read the error
            error_msg = "Unknown error"
            try:
                stdout_output, stderr_output = openvpn_process.communicate(timeout=2)
                if stderr_output:
                    error_msg = stderr_output.decode('utf-8', errors='ignore')
                elif stdout_output:
                    error_msg = stdout_output.decode('utf-8', errors='ignore')
            except:
                # Try reading from log file if available
                try:
                    if os.path.exists('openvpn.log'):
                        with open('openvpn.log', 'r') as f:
                            log_lines = f.readlines()
                            if log_lines:
                                error_msg = ''.join(log_lines[-5:])  # Last 5 lines
                except:
                    pass
            
            # Check if error is "port already in use" - means OpenVPN is already running
            error_lower = error_msg.lower()
            if ('address already in use' in error_lower or 'bind' in error_lower or 
                'EADDRINUSE' in error_msg or 'port is already in use' in error_lower):
                print("OpenVPN daemon already running (port 1194 in use)")
                # Double-check by testing if it's actually running
                if is_openvpn_running():
                    return True
                # If not actually running, continue to permission check
            
            # Check if it's a permission error (most common issue)
            if ('permission denied' in error_lower or 'errno=13' in error_msg or 
                'EACCES' in error_msg or 'root' in error_lower or 
                'cannot open' in error_lower and 'log' in error_lower):
                print("⚠ OpenVPN requires root privileges to start.")
                print("   Error details:", error_msg[:300] if len(error_msg) > 0 else "Permission denied")
                print("   Please start OpenVPN manually with:")
                print("   sudo openvpn --config server.ovpn --daemon")
                print("   Or use: ./restart_openvpn.sh")
                print("   Falling back to mock mode for testing")
                return True  # Fall back to mock mode
            
            # Other errors
            print(f"⚠ OpenVPN daemon failed to start")
            print(f"   Error: {error_msg[:300] if error_msg else 'Unknown error'}")
            print("   Falling back to mock mode for testing")
            return True  # Fall back to mock mode instead of failing
        
        # Check again if OpenVPN is now running
        if is_openvpn_running():
            print("OpenVPN daemon started successfully.")
            # Wait a bit more for status file to be created
            time.sleep(2)
            # Check if status file is being written
            if os.path.exists('openvpn-status.log'):
                size = os.path.getsize('openvpn-status.log')
                print(f"Status log file size: {size} bytes")
            return True
        else:
            print("OpenVPN process started but may not be listening. Falling back to mock mode.")
            return True  # Fall back to mock mode
        
    except Exception as e:
        print(f"Error starting OpenVPN: {e}")
        print("Falling back to mock mode for testing")
        return True  # Fall back to mock mode

def read_openvpn_status():
    """Read and parse OpenVPN status log file."""
    status_file = 'openvpn-status.log'
    if not os.path.exists(status_file):
        return {'clients': [], 'routing_table': [], 'global_stats': {}}
    
    try:
        with open(status_file, 'r') as f:
            content = f.read()
        
        clients = []
        routing_table = []
        global_stats = {}
        
        # Parse OpenVPN status format (version 2 - CSV format)
        lines = content.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for CSV format (CLIENT_LIST, ROUTING_TABLE headers)
            if line.startswith('HEADER,CLIENT_LIST'):
                current_section = 'clients'
                continue
            elif line.startswith('HEADER,ROUTING_TABLE'):
                current_section = 'routing'
                continue
            elif line.startswith('GLOBAL_STATS'):
                current_section = 'stats'
                continue
            elif line.startswith('END'):
                current_section = None
                continue
            # Legacy format support
            elif line.startswith('OpenVPN CLIENT LIST'):
                current_section = 'clients'
                continue
            elif line.startswith('ROUTING TABLE'):
                current_section = 'routing'
                continue
            elif line.startswith('GLOBAL STATS'):
                current_section = 'stats'
                continue
            
            # Parse CSV format CLIENT_LIST
            if current_section == 'clients' and line.startswith('CLIENT_LIST,'):
                parts = [p.strip() for p in line.split(',')]
                # Format: CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,...
                if len(parts) >= 4:
                    common_name = parts[1] if len(parts) > 1 and parts[1] else 'MURALI'
                    virtual_address = parts[3] if len(parts) > 3 and parts[3] else ''
                    real_address = parts[2] if len(parts) > 2 and parts[2] else ''
                    
                    # Log warning if UNDEF is found to help debugging
                    if common_name == 'UNDEF' or not common_name:
                        print(f"[VPN] ⚠ WARNING: Found UNDEF CN in status log (Real Address: {real_address})")
                        print(f"[VPN]   This indicates OpenVPN cannot extract CN from certificate")
                        print(f"[VPN]   Possible causes:")
                        print(f"[VPN]   1. Certificate missing Key Usage extension")
                        print(f"[VPN]   2. Certificate CN format issue")
                        print(f"[VPN]   3. OpenVPN server configuration issue")
                    
                    clients.append({
                        'common_name': common_name.strip() if common_name else 'MURALI',
                        'real_address': real_address,
                        'virtual_address': virtual_address.strip(),  # May be empty if IP not assigned yet
                        'bytes_received': parts[5] if len(parts) > 5 else '0',
                        'bytes_sent': parts[6] if len(parts) > 6 else '0',
                        'connected_since': parts[7] if len(parts) > 7 else ''
                    })
            # Parse legacy format
            elif current_section == 'clients' and line.startswith('Common Name'):
                continue  # Skip header
            elif current_section == 'clients' and ',' in line and not line.startswith('CLIENT_LIST'):
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 4:
                    clients.append({
                        'common_name': parts[0].strip(),
                        'real_address': parts[1].strip(),
                        'virtual_address': parts[2].strip(),
                        'bytes_received': parts[3] if len(parts) > 3 else '0',
                        'bytes_sent': parts[4] if len(parts) > 4 else '0',
                        'connected_since': parts[5] if len(parts) > 5 else ''
                    })
            
            # Parse routing table (CSV format)
            elif current_section == 'routing' and line.startswith('ROUTING_TABLE,'):
                parts = [p.strip() for p in line.split(',')]
                # Format: ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,...
                if len(parts) >= 3:
                    routing_table.append({
                        'virtual_address': parts[1] if len(parts) > 1 else '',
                        'common_name': parts[2] if len(parts) > 2 else '',
                        'real_address': parts[3] if len(parts) > 3 else '',
                        'last_ref': parts[4] if len(parts) > 4 else ''
                    })
            # Parse legacy routing table
            elif current_section == 'routing' and line.startswith('Virtual Address'):
                continue  # Skip header
            elif current_section == 'routing' and ',' in line and not line.startswith('ROUTING_TABLE'):
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    routing_table.append({
                        'virtual_address': parts[0],
                        'common_name': parts[1],
                        'real_address': parts[2] if len(parts) > 2 else '',
                        'last_ref': parts[3] if len(parts) > 3 else ''
                    })
        
        return {
            'clients': clients,
            'routing_table': routing_table,
            'global_stats': global_stats,
            'last_updated': datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error reading OpenVPN status: {e}")
        return {'clients': [], 'routing_table': [], 'global_stats': {}, 'error': str(e)}

def read_ipp_file():
    """Read OpenVPN IP pool persistence file."""
    ipp_file = 'ipp.txt'
    if not os.path.exists(ipp_file):
        return {'assignments': []}
    
    try:
        with open(ipp_file, 'r') as f:
            content = f.read()
        
        assignments = []
        for line in content.split('\n'):
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # OpenVPN ipp.txt format: CN,IP (comma-separated)
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    cn = parts[0]
                    ip = parts[1]
                    # Validate IP format
                    if ip and (ip.startswith('10.8.0.') or ip.count('.') == 3):
                        assignments.append({
                            'common_name': cn,
                            'ip_address': ip
                        })
                    else:
                        print(f"[VPN] Warning: Invalid IP format in ipp.txt: {ip}")
            # Also handle space-separated format (some OpenVPN versions)
            elif ' ' in line:
                parts = line.split()
                if len(parts) >= 2:
                    cn = parts[0].strip()
                    ip = parts[1].strip()
                    if ip and (ip.startswith('10.8.0.') or ip.count('.') == 3):
                        assignments.append({
                            'common_name': cn,
                            'ip_address': ip
                        })
        
        if assignments:
            print(f"[VPN] Read {len(assignments)} IP assignments from ipp.txt")
        
        return {
            'assignments': assignments,
            'count': len(assignments),
            'last_updated': datetime.now().isoformat(),
            'file_size': os.path.getsize(ipp_file) if os.path.exists(ipp_file) else 0
        }
    except Exception as e:
        print(f"[VPN] Error reading ipp.txt: {e}")
        import traceback
        traceback.print_exc()
        return {'assignments': [], 'error': str(e)}

def generate_client_certificate(user_email):
    """
    Generate a unique client certificate for each user with their email as CN.
    Certificates are cached per user (generated once, reused for subsequent connections).
    
    Returns: (cert_file, key_file) tuple, or raises exception on error
    """
    # Sanitize email for filename (safe for filesystem)
    safe_email = user_email.replace('@', '_at_').replace('.', '_')
    cert_file = f'client_{safe_email}.crt'
    key_file = f'client_{safe_email}.key'
    
    # Check if certificate already exists (cached)
    if os.path.exists(cert_file) and os.path.exists(key_file):
        # Verify certificate is still valid and has correct CN
        try:
            # Check validity
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert_file, '-noout', '-checkend', '86400'],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                # Verify CN matches user_email
                cn_result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_file, '-noout', '-subject'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if cn_result.returncode == 0:
                    cn_output = cn_result.stdout.strip()
                    # Extract CN from subject line (format: subject=CN = user@email.com, ...)
                    # Check CN in various formats (case-insensitive)
                    cn_output_lower = cn_output.lower()
                    user_email_lower = user_email.lower()
                    if (f'cn={user_email_lower}' in cn_output_lower or 
                        f'/cn={user_email_lower}' in cn_output_lower or
                        f'cn = {user_email_lower}' in cn_output_lower):
                        print(f"[CERT] Using cached certificate for {user_email} (CN verified)")
                        return cert_file, key_file
                    else:
                        print(f"[CERT] Cached certificate CN mismatch. Expected {user_email}, regenerating...")
                        os.remove(cert_file)
                        os.remove(key_file)
                else:
                    print(f"[CERT] Error verifying CN in cached certificate, regenerating...")
                    os.remove(cert_file)
                    os.remove(key_file)
            else:
                # Certificate expired or invalid, regenerate
                print(f"[CERT] Cached certificate for {user_email} expired, regenerating...")
                os.remove(cert_file)
                os.remove(key_file)
        except Exception as e:
            # If check fails, regenerate
            print(f"[CERT] Error checking cached certificate for {user_email}: {e}, regenerating...")
            if os.path.exists(cert_file):
                os.remove(cert_file)
            if os.path.exists(key_file):
                os.remove(key_file)
    
    # Generate new certificate
    print(f"[CERT] Generating new certificate for {user_email} (CN={user_email})")
    csr_file = f'client_{safe_email}.csr'
    extensions_file = f'client_{safe_email}.ext'
    
    try:
        # Check if CA files exist
        if not os.path.exists('ca.crt') or not os.path.exists('ca.key'):
            raise FileNotFoundError("CA certificate (ca.crt) or key (ca.key) not found. Please run install.sh first.")
        
        # Generate private key
        print(f"[CERT] Generating private key...")
        subprocess.run([
            'openssl', 'genrsa', '-out', key_file, '2048'
        ], check=True, capture_output=True, timeout=10)
        
        # Generate certificate signing request with user email as CN
        print(f"[CERT] Generating CSR with CN={user_email}...")
        subprocess.run([
            'openssl', 'req', '-new', '-key', key_file, '-out', csr_file,
            '-subj', f'/C=US/ST=CA/L=SanFrancisco/O=ZTNA/OU=Client/CN={user_email}'
        ], check=True, capture_output=True, timeout=10)
        
        # Create temporary extensions config file with Key Usage extension
        # IMPORTANT: Use proper format for OpenSSL to ensure Key Usage is included
        with open(extensions_file, 'w') as f:
            f.write(f"""[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = {user_email}
email.1 = {user_email}
""")
        
        # Sign certificate with CA (valid for 1 year) with Key Usage extension
        print(f"[CERT] Signing certificate with CA...")
        sign_result = subprocess.run([
            'openssl', 'x509', '-req', '-in', csr_file,
            '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
            '-out', cert_file, '-days', '365',
            '-extensions', 'v3_req', '-extfile', extensions_file
        ], check=True, capture_output=True, timeout=10, text=True)
        
        # Log any warnings from OpenSSL
        if sign_result.stderr:
            print(f"[CERT] OpenSSL signing stderr: {sign_result.stderr}")
        
        # Verify the certificate file was created and has content
        if not os.path.exists(cert_file):
            raise Exception("Certificate file was not created after signing")
        
        cert_size = os.path.getsize(cert_file)
        if cert_size == 0:
            raise Exception("Certificate file is empty")
        
        print(f"[CERT] Certificate file created: {cert_file} ({cert_size} bytes)")
        
        # Verify Key Usage extension was added
        print(f"[CERT] Verifying Key Usage extension...")
        verify_ku = subprocess.run(
            ['openssl', 'x509', '-in', cert_file, '-noout', '-text'],
            capture_output=True,
            text=True,
            timeout=2
        )
        if verify_ku.returncode == 0:
            # Check for Key Usage in various formats (case-insensitive)
            output_lower = verify_ku.stdout.lower()
            # OpenSSL outputs "X509v3 Key Usage" or "Key Usage"
            has_key_usage = ('key usage' in output_lower or 'x509v3 key usage' in output_lower)
            # OpenSSL outputs "Digital Signature" (with space) or "digitalSignature" (no space)
            has_digital_signature = ('digital signature' in output_lower or 'digitalsignature' in output_lower or 'digital_signature' in output_lower)
            
            if has_key_usage and has_digital_signature:
                print(f"[CERT] ✓ Key Usage extension verified in certificate")
            else:
                print(f"[CERT] ⚠ WARNING: Key Usage extension not found in certificate")
                print(f"[CERT]   Searching for 'Key Usage': {has_key_usage}")
                print(f"[CERT]   Searching for 'Digital Signature': {has_digital_signature}")
                # Extract and show the extensions section for debugging
                if 'x509v3 extensions' in output_lower:
                    ext_start = verify_ku.stdout.lower().find('x509v3 extensions')
                    ext_section = verify_ku.stdout[ext_start:ext_start+800]
                    print(f"[CERT]   Extensions section:")
                    print(ext_section)
                else:
                    print(f"[CERT]   Certificate output (first 1500 chars):")
                    print(verify_ku.stdout[:1500])
                raise Exception("Key Usage extension not properly set in certificate")
        else:
            print(f"[CERT] ⚠ WARNING: Could not verify Key Usage extension")
            print(f"[CERT]   OpenSSL error: {verify_ku.stderr}")
            raise Exception(f"Failed to verify certificate: {verify_ku.stderr}")
        
        # Verify the certificate was created correctly
        if not os.path.exists(cert_file):
            raise Exception("Certificate file was not created")
        
        # Verify CN in the generated certificate
        verify_result = subprocess.run(
            ['openssl', 'x509', '-in', cert_file, '-noout', '-subject'],
            capture_output=True,
            text=True,
            timeout=2
        )
        if verify_result.returncode != 0:
            raise Exception(f"Failed to verify certificate: {verify_result.stderr}")
        
        cn_output = verify_result.stdout.strip()
        # Check CN in various formats (case-insensitive)
        cn_output_lower = cn_output.lower()
        user_email_lower = user_email.lower()
        if (f'cn={user_email_lower}' not in cn_output_lower and 
            f'/cn={user_email_lower}' not in cn_output_lower and
            f'cn = {user_email_lower}' not in cn_output_lower):
            raise Exception(f"Certificate CN mismatch. Expected {user_email}, got: {cn_output}")
        
        # Clean up CSR and extensions file
        for f in [csr_file, extensions_file]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
        
        # Set proper permissions
        os.chmod(key_file, 0o600)  # Read/write for owner only
        os.chmod(cert_file, 0o644)  # Read for all, write for owner
        
        print(f"[CERT] ✓ Successfully generated and verified certificate for {user_email}")
        return cert_file, key_file
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8') if e.stderr else str(e)
        print(f"[CERT] ✗ Error generating certificate for {user_email}: {error_msg}")
        # Clean up partial files
        for f in [cert_file, key_file, csr_file, extensions_file]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
        raise Exception(f"Certificate generation failed: {error_msg}")
    except Exception as e:
        print(f"[CERT] ✗ Unexpected error generating certificate for {user_email}: {e}")
        # Clean up partial files
        for f in [cert_file, key_file, csr_file, extensions_file]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
        raise

def cidr_to_openvpn_route(cidr):
    """Convert CIDR notation (e.g., '10.0.0.0/8') to OpenVPN route format."""
    try:
        if '/' in cidr:
            network, prefix = cidr.split('/')
            prefix = int(prefix)
            if prefix < 0 or prefix > 32:
                raise ValueError(f"Invalid prefix length: {prefix}")
            # Calculate netmask from prefix length
            mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            netmask = f"{mask >> 24}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
            route_line = f"route {network} {netmask}"
            print(f"[VPN] Converted route: {cidr} -> {route_line}")
            return route_line
        else:
            # If no prefix, assume /32 (single host)
            route_line = f"route {cidr} 255.255.255.255"
            print(f"[VPN] Converted route (no prefix): {cidr} -> {route_line}")
            return route_line
    except Exception as e:
        print(f"[VPN] Error converting CIDR {cidr}: {e}")
        return None

def format_routes_for_openvpn(routes):
    """Format routes list for OpenVPN config file (one route per line)."""
    if not routes:
        print("[VPN] No routes provided, skipping route configuration")
        return ''
    formatted_routes = []
    for route in routes:
        if not route or not isinstance(route, str):
            print(f"[VPN] Warning: Skipping invalid route: {route}")
            continue
        ovpn_route = cidr_to_openvpn_route(route.strip())
        if ovpn_route:
            formatted_routes.append(ovpn_route)
    if not formatted_routes:
        print("[VPN] Warning: No valid routes were formatted")
        return ''
    routes_config = '\n'.join(formatted_routes)
    print(f"[VPN] Formatted {len(formatted_routes)} route(s) for OpenVPN config")
    return routes_config

def get_next_available_ip():
    """Get the next available IP in the 10.8.0.x range, avoiding duplicates."""
    global ip_counter
    # Find next available IP (10.8.0.2 to 10.8.0.254)
    max_ip = 254
    start_counter = ip_counter
    
    while ip_counter <= max_ip:
        ip = f'10.8.0.{ip_counter}'
        # Check if IP is already assigned
        if ip not in assigned_ips:
            return ip
        ip_counter += 1
    
    # If we've exhausted the range, start from 2 again and find gaps
    ip_counter = 2
    while ip_counter <= max_ip:
        ip = f'10.8.0.{ip_counter}'
        if ip not in assigned_ips:
            return ip
        ip_counter += 1
    
    # If all IPs are taken, return None (shouldn't happen in practice)
    print(f"[VPN] ⚠ WARNING: All IPs in range 10.8.0.2-10.8.0.254 are assigned!")
    return None

def find_ip_by_real_address(real_address, status_data, ipp_data):
    """Find IP assignment by matching real_address when CN is UNDEF."""
    # Extract IP:port from real_address (format: "127.0.0.1:54338")
    if ':' in real_address:
        real_ip = real_address.split(':')[0]
    else:
        real_ip = real_address
    
    # Check status log for matching real_address
    for client in status_data.get('clients', []):
        client_real = client.get('real_address', '')
        if ':' in client_real:
            client_ip = client_real.split(':')[0]
        else:
            client_ip = client_real
        
        if client_ip == real_ip:
            virtual_ip = client.get('virtual_address', '').strip()
            if virtual_ip and virtual_ip.startswith('10.8.0.'):
                return virtual_ip
    
    # Check ipp.txt for matching real_address (less reliable, but try)
    # Note: ipp.txt uses CN, not real_address, so this is a fallback
    return None

def mock_connect(user_email, routes):
    """Mock tunnel for preview (simulates 10.8.0.x assignment)"""
    time.sleep(1)  # Simulate connection time
    ip = get_next_available_ip() or '10.8.0.2'  # Fallback only for mock
    return {'status': 'connected', 'ip': ip, 'routes': routes}

def get_client_ip():
    """Extract client IP from request headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'

def get_location_from_ip(ip_address):
    """Get location from IP using policy engine."""
    try:
        resp = requests.get(f'{POLICY_ENGINE_URL}/api/policy/location-detect?ip={ip_address}', timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('location', {})
    except:
        pass
    return {'country': 'Unknown', 'city': 'Unknown'}

@app.route('/api/vpn/connect', methods=['POST'])
def connect_vpn():
    data = request.get_json()
    vpn_token = data.get('vpn_token')
    device = data.get('device', {})
    
    try:
        # Decode and validate JWT
        decoded = jwt.decode(vpn_token, SECRET_KEY, algorithms=['HS256'])
        user_email = decoded.get('email') or decoded.get('user')
        clearance = decoded.get('clearance', 0)
        
        if clearance < 1:
            return jsonify({'error': 'Insufficient clearance'}), 403
        
        # Check if user already has an active connection
        # IMPORTANT: Check BEFORE creating new connection
        existing_connection = None
        for conn_id, conn in list(connections.items()):  # Use list() to avoid modification during iteration
            # Check if connection is active and belongs to this user
            # Note: status can be 'active' or 'connected' (both mean active)
            conn_status = conn.get('status', '')
            is_active = conn_status in ['active', 'connected']
            
            if (conn.get('user') == user_email and 
                is_active and
                conn_id.startswith(f'vpn-{user_email}-')):  # Extra check to ensure it's a VPN connection
                existing_connection = {
                    'connection_id': conn_id,
                    'connected_at': conn.get('connected_at'),
                    'vpn_ip': conn.get('vpn_ip'),
                    'real_client_ip': conn.get('real_client_ip'),
                    'location': conn.get('location'),
                    'connection_mode': conn.get('connection_mode', 'unknown'),
                    'status': conn_status
                }
                print(f"[DEBUG] Found existing connection for {user_email}: {conn_id} (status: {conn_status})")
                break
        
        if existing_connection:
            print(f"[DEBUG] Rejecting duplicate connection attempt for {user_email}")
            return jsonify({
                'error': 'User already has an active VPN connection',
                'existing_connection': existing_connection,
                'message': 'Please disconnect the existing connection before creating a new one'
            }), 409  # 409 Conflict
        
        # Get real client IP and location BEFORE VPN connection
        # Priority: Frontend-provided > Headers > Direct connection
        client_ip = data.get('client_ip')  # Frontend-provided IP (most reliable)
        location = data.get('location')  # Frontend-provided location (most reliable)
        
        # If not provided by frontend, detect from request
        if not client_ip:
            client_ip = get_client_ip()
        
        # If location not provided, detect from IP
        if not location or location.get('country') in ['Unknown', 'Local']:
            detected_location = get_location_from_ip(client_ip)
            if location:
                location.update(detected_location)
            else:
                location = detected_location
        
        # Store real client IP and location BEFORE VPN connection
        real_client_ip = client_ip
        real_location = location.copy() if location else {}
        
        # Perform policy evaluation before connecting
        try:
            policy_resp = requests.post(
                f'{POLICY_ENGINE_URL}/api/policy/evaluate',
                json={
                    'user': {'email': user_email},
                    'resource': 'vpn-gateway',
                    'device': device,
                    'location': location
                },
                timeout=5
            )
            
            if policy_resp.status_code == 403:
                policy_data = policy_resp.json()
                return jsonify({
                    'error': 'Access denied by policy',
                    'reason': policy_data.get('reason'),
                    'risk_score': policy_data.get('risk_score')
                }), 403
        except Exception as e:
            print(f"Policy evaluation error: {e}")
            # Continue with connection if policy engine is unavailable
        
        connection_id = f"vpn-{user_email}-{int(time.time())}"
        routes = ['10.0.0.0/8', '192.168.0.0/16']  # From proposal
        
        # Try to start OpenVPN daemon (but don't fail if it doesn't - will use mock mode)
        daemon_started = start_openvpn_daemon()
        openvpn_available = is_openvpn_installed() and (is_openvpn_running() or daemon_started)
        
        if openvpn_available:
            # Generate per-user certificate (cached, generated once per user)
            try:
                client_cert, client_key = generate_client_certificate(user_email)
            except Exception as cert_error:
                print(f"[VPN] ✗ Certificate generation failed: {cert_error}")
                return jsonify({
                    'error': 'Certificate generation failed',
                    'details': str(cert_error),
                    'message': 'Please ensure CA certificates exist (run install.sh)'
                }), 500
            
            # Full client config based on your openvpn-client.ovpn + dynamic routes (IPv4 fix)
            try:
                # Format routes properly for OpenVPN (one route per line)
                routes_config = format_routes_for_openvpn(routes)
                
                # Build client config with proper route formatting
                client_config_lines = [
                    "client",
                    "dev tun",
                    "proto udp4",
                    "remote 127.0.0.1 1194",
                    "resolv-retry infinite",
                    "nobind",
                    "persist-key",
                    "persist-tun",
                    "ca ca.crt",
                    f"cert {client_cert}",
                    f"key {client_key}",
                    "remote-cert-tls server",
                    "cipher AES-256-GCM",
                    "auth SHA512",
                    "verb 3"
                ]
                
                # Add routes if any were formatted
                if routes_config:
                    client_config_lines.append("")
                    client_config_lines.append("# Routes")
                    for route_line in routes_config.split('\n'):
                        if route_line.strip():
                            client_config_lines.append(route_line)
                
                # Add comments
                client_config_lines.append("")
                client_config_lines.append("# JWT stub: In prod, use --auth-user-pass for token validation")
                client_config_lines.append(f"# Certificate CN: {user_email}")
                
                client_config = '\n'.join(client_config_lines) + '\n'
                ovpn_file = f'{connection_id}.ovpn'
                with open(ovpn_file, 'w') as f:
                    f.write(client_config)
                
                # Try to start OpenVPN client
                print(f"[VPN] Starting OpenVPN client with config: {ovpn_file}")
                print(f"[VPN] Using certificate: {client_cert} (CN should be: {user_email})")
                
                # Start client with output to log file for debugging
                log_file = f'{connection_id}.log'
                with open(log_file, 'w') as log_f:
                    client_proc = subprocess.Popen(
                        ['openvpn', '--config', ovpn_file], 
                        stdout=log_f,
                        stderr=subprocess.STDOUT,  # Redirect stderr to stdout
                        cwd=os.getcwd()
                    )
                
                # Wait longer for TLS handshake and connection
                time.sleep(8)  # Increased wait time for full connection
                
                # Check if process is still running
                if client_proc.poll() is not None:
                    # Client process exited, read error from log
                    error_msg = "Unknown error"
                    try:
                        with open(log_file, 'r') as f:
                            error_msg = f.read()[-500:]  # Last 500 chars
                    except:
                        pass
                    print(f"[VPN] OpenVPN client failed: {error_msg[:300]}")
                    # Fall back to mock mode
                    result = mock_connect(user_email, routes)
                    result['connection_mode'] = 'mock_fallback'
                    result['error'] = f"OpenVPN client failed: {error_msg[:100]}"
                else:
                    print(f"[VPN] OpenVPN client process running (PID: {client_proc.pid})")
                    # Check log for connection status
                    try:
                        with open(log_file, 'r') as f:
                            log_content = f.read()
                            if 'Initialization Sequence Completed' in log_content:
                                print(f"[VPN] OpenVPN client connected successfully")
                            elif 'TLS handshake' in log_content or 'Peer Connection Initiated' in log_content:
                                print(f"[VPN] OpenVPN TLS handshake in progress...")
                    except:
                        pass
                    # Try to get real IP from status log or ipp.txt
                    vpn_ip = None
                    max_retries = 6  # Increased retries to account for 10-second status log update interval
                    retry_delay = 12  # Wait 12 seconds between retries (status log updates every 10 seconds)
                    
                    # Get client's real address for matching (when CN is UNDEF)
                    client_real_address = None
                    try:
                        # Try to get real address from the client process or connection
                        # We'll use this to match when CN is UNDEF
                        pass  # Will be set from status log
                    except:
                        pass
                    
                    for retry in range(max_retries):
                        try:
                            # Wait for OpenVPN to complete connection and assign IP
                            # Status log updates every 10 seconds, so we wait longer between retries
                            if retry > 0:
                                print(f"[VPN] Retry {retry}/{max_retries}: Waiting {retry_delay}s for status log update...")
                                time.sleep(retry_delay)
                            else:
                                print(f"[VPN] Waiting for OpenVPN connection to complete and IP assignment...")
                                time.sleep(8)  # Initial wait for TLS handshake and connection
                            
                            # Read status log
                            status_data = read_openvpn_status()
                            print(f"[VPN] Checking status log for {user_email}...")
                            print(f"[VPN] Found {len(status_data.get('clients', []))} clients in status log")
                            
                            # Find client connection by Common Name (should be user_email)
                            for client in status_data.get('clients', []):
                                cn = client.get('common_name', '').strip()
                                real_addr = client.get('real_address', '')
                                virtual_ip = client.get('virtual_address', '').strip()
                                print(f"[VPN] Client: CN={cn}, Real={real_addr}, Virtual={virtual_ip}")
                                
                                # Store real_address for UNDEF matching
                                if not client_real_address and real_addr:
                                    client_real_address = real_addr
                                
                                # Match by exact CN (case-insensitive, trimmed)
                                cn_normalized = cn.lower().strip()
                                user_email_normalized = user_email.lower().strip()
                                
                                if cn_normalized == user_email_normalized:
                                    if virtual_ip and virtual_ip.startswith('10.8.0.'):
                                        vpn_ip = virtual_ip
                                        print(f"[VPN] ✓ Found assigned IP {vpn_ip} for {user_email} (CN: {cn})")
                                        break
                                    else:
                                        print(f"[VPN] Found client with CN={cn} but no Virtual IP yet (waiting...)")
                                # Also check if CN contains user_email (in case of formatting differences)
                                elif user_email_normalized in cn_normalized or cn_normalized in user_email_normalized:
                                    if virtual_ip and virtual_ip.startswith('10.8.0.'):
                                        vpn_ip = virtual_ip
                                        print(f"[VPN] ✓ Found assigned IP {vpn_ip} for {user_email} (CN: {cn})")
                                        break
                            
                            # If CN matching failed, try matching by real_address (for UNDEF cases)
                            if not vpn_ip and client_real_address:
                                print(f"[VPN] CN matching failed, trying to match by real_address: {client_real_address}")
                                for client in status_data.get('clients', []):
                                    cn = client.get('common_name', '').strip()
                                    real_addr = client.get('real_address', '')
                                    virtual_ip = client.get('virtual_address', '').strip()
                                    
                                    # Match by real_address (handle UNDEF CNs)
                                    if real_addr == client_real_address or (real_addr and client_real_address and 
                                        real_addr.split(':')[0] == client_real_address.split(':')[0]):
                                        if virtual_ip and virtual_ip.startswith('10.8.0.'):
                                            vpn_ip = virtual_ip
                                            print(f"[VPN] ✓ Found assigned IP {vpn_ip} by real_address match (CN: {cn}, Real: {real_addr})")
                                            break
                                        elif cn == 'UNDEF':
                                            print(f"[VPN] Found UNDEF client with matching real_address but no IP yet (waiting...)")
                            
                            # If found in status log, break retry loop
                            if vpn_ip:
                                break
                            
                            # Also check ipp.txt (persistent IP assignments) - check this on every retry
                            ipp_data = read_ipp_file()
                            if retry == 0 or retry % 2 == 0:  # Check ipp.txt every other retry to reduce I/O
                                print(f"[VPN] Checking ipp.txt: {len(ipp_data.get('assignments', []))} assignments")
                            for assignment in ipp_data.get('assignments', []):
                                cn = assignment.get('common_name', '').strip()
                                ip_addr = assignment.get('ip_address', '').strip()
                                cn_normalized = cn.lower().strip()
                                user_email_normalized = user_email.lower().strip()
                                if (cn_normalized == user_email_normalized or 
                                    user_email_normalized in cn_normalized) and ip_addr and ip_addr.startswith('10.8.0.'):
                                    vpn_ip = ip_addr
                                    print(f"[VPN] ✓ Found IP {vpn_ip} in ipp.txt for {user_email} (CN: {cn})")
                                    break
                            
                            # If found in ipp.txt, break retry loop
                            if vpn_ip:
                                break
                            
                            # If still not found and this is not the last retry, continue
                            if retry < max_retries - 1:
                                print(f"[VPN] IP not assigned yet, will retry in {retry_delay}s...")
                            else:
                                print(f"[VPN] ⚠ IP assignment not found after {max_retries} retries")
                                # Last resort: check if there's any client with UNDEF that might be ours
                                for client in status_data.get('clients', []):
                                    cn = client.get('common_name', '')
                                    if cn == 'UNDEF':
                                        print(f"[VPN] ⚠ WARNING: Found UNDEF client - certificate CN may not be recognized by OpenVPN")
                                        print(f"[VPN]   This usually means the certificate CN is not being read correctly")
                                        print(f"[VPN]   Expected CN: {user_email}")
                                        print(f"[VPN]   Check certificate: openssl x509 -in {client_cert} -noout -subject")
                                
                                # Log all clients for debugging
                                if status_data.get('clients'):
                                    print(f"[VPN] Available clients in status log:")
                                    for client in status_data.get('clients', []):
                                        print(f"[VPN]   - CN: '{client.get('common_name', '')}', Real: '{client.get('real_address', '')}', Virtual IP: '{client.get('virtual_address', '')}'")
                                
                                # If we have a real_address match but no IP yet, assign next available
                                if client_real_address:
                                    # Check if any UNDEF client matches our real_address
                                    for client in status_data.get('clients', []):
                                        if (client.get('common_name', '').strip() == 'UNDEF' and 
                                            client.get('real_address', '') == client_real_address):
                                            # This is likely our connection, assign next available IP
                                            vpn_ip = get_next_available_ip()
                                            if vpn_ip:
                                                print(f"[VPN] ⚠ Assigning next available IP {vpn_ip} (CN is UNDEF, matched by real_address)")
                                                # Track this assignment
                                                assigned_ips[vpn_ip] = connection_id
                                                break
                                
                        except Exception as e:
                            print(f"[VPN] Error reading OpenVPN status files (retry {retry+1}/{max_retries}): {e}")
                            if retry == max_retries - 1:
                                print(f"[VPN] Failed to read IP assignment after all retries")
                    
                    # If still no IP found, assign next available IP (instead of hardcoded fallback)
                    if not vpn_ip:
                        vpn_ip = get_next_available_ip()
                        if vpn_ip:
                            print(f"[VPN] ⚠ Could not determine assigned IP from OpenVPN, assigning next available: {vpn_ip}")
                            print(f"[VPN]   This may indicate OpenVPN status log is not updating properly")
                            # Track this assignment
                            assigned_ips[vpn_ip] = connection_id
                        else:
                            print(f"[VPN] ✗ ERROR: Could not assign IP - all IPs in range are taken!")
                            # Last resort: use a calculated IP based on connection count
                            connection_count = len([c for c in connections.values() if c.get('status') in ['active', 'connected']])
                            vpn_ip = f'10.8.0.{min(2 + connection_count, 254)}'
                            print(f"[VPN] ⚠ Using calculated IP based on connection count: {vpn_ip}")
                            assigned_ips[vpn_ip] = connection_id
                    
                    result = {
                        'status': 'connected', 
                        'ip': vpn_ip, 
                        'routes': routes,
                        'connection_mode': 'openvpn'
                    }
            except Exception as e:
                print(f"Error setting up OpenVPN client: {e}")
                result = mock_connect(user_email, routes)
                result['connection_mode'] = 'mock_fallback'
                result['error'] = str(e)
        else:
            result = mock_connect(user_email, routes)
            result['connection_mode'] = 'mock'
        
        # Get the assigned VPN IP
        assigned_vpn_ip = result.get('ip')
        
        # Track IP assignment to avoid duplicates
        if assigned_vpn_ip and assigned_vpn_ip.startswith('10.8.0.'):
            if assigned_vpn_ip in assigned_ips and assigned_ips[assigned_vpn_ip] != connection_id:
                # IP already assigned to another connection - this shouldn't happen, but handle it
                print(f"[VPN] ⚠ WARNING: IP {assigned_vpn_ip} already assigned to {assigned_ips[assigned_vpn_ip]}")
            assigned_ips[assigned_vpn_ip] = connection_id
        
        # Store connection with real IP/location (before VPN) and VPN IP (after VPN)
        # IMPORTANT: Store AFTER checking for duplicates
        # Use 'active' status to match the check logic
        connections[connection_id] = {
            'user': user_email,
            'connected_at': datetime.now().isoformat(),
            'status': 'active',  # Use 'active' consistently (not 'connected')
            'token': vpn_token,  # Store token for continuous auth
            'device': device,
            # Real client information (BEFORE VPN connection)
            'real_client_ip': real_client_ip,  # Real IP before VPN
            'location': real_location,  # Real location before VPN
            # VPN-assigned information (AFTER VPN connection)
            'vpn_ip': assigned_vpn_ip,  # VPN-assigned IP (e.g., 10.8.0.2)
            'vpn_routes': result.get('routes', []),
            # Continuous auth tracking
            'last_continuous_auth': datetime.now().isoformat(),
            'last_risk_score': 0,
            **result
        }
        print(f"[DEBUG] Stored new connection: {connection_id} for user: {user_email}")
        active_count = len([c for c in connections.values() if c.get('status') in ['active', 'connected']])
        print(f"[DEBUG] Total active connections: {active_count}")
        return jsonify({
            'connection_id': connection_id,
            'real_client_ip': real_client_ip,
            'location': real_location,
            **result
        })
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except KeyError as e:
        return jsonify({'error': f'Missing JWT claim: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vpn/disconnect', methods=['POST'])
def disconnect_vpn():
    data = request.get_json()
    connection_id = data.get('connection_id')
    if connection_id not in connections:
        return jsonify({'error': 'Connection not found'}), 404
    
    # Get VPN IP before deleting connection
    conn = connections[connection_id]
    vpn_ip = conn.get('vpn_ip')
    
    # Simulate disconnect
    if is_openvpn_installed():
        subprocess.run(['pkill', '-f', connection_id], capture_output=True)  # Kill client process
        # Clean up ovpn file
        ovpn_file = f'{connection_id}.ovpn'
        if os.path.exists(ovpn_file):
            os.remove(ovpn_file)
        # Clean up log file
        log_file = f'{connection_id}.log'
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
                print(f"[VPN] Cleaned up log file: {log_file}")
            except Exception as e:
                print(f"[VPN] Warning: Could not remove log file {log_file}: {e}")
    
    # Remove IP assignment tracking
    if vpn_ip and vpn_ip in assigned_ips:
        if assigned_ips[vpn_ip] == connection_id:
            del assigned_ips[vpn_ip]
            print(f"[VPN] Released IP assignment: {vpn_ip}")
    
    del connections[connection_id]
    return jsonify({'status': 'disconnected'})

@app.route('/api/vpn/status', methods=['GET', 'POST'])
def vpn_status():
    """Get VPN status. Can use GET with query param or POST with JSON body."""
    if request.method == 'GET':
        connection_id = request.args.get('connection_id')
        user_email = request.args.get('user_email')
    else:
        data = request.get_json() or {}
        connection_id = data.get('connection_id')
        user_email = data.get('user_email')
    
    # If user_email provided, find their active connection
    if user_email and not connection_id:
        for conn_id, conn in list(connections.items()):  # Use list() to avoid modification during iteration
            # Check for both 'active' and 'connected' status
            conn_status = conn.get('status', '')
            is_active = conn_status in ['active', 'connected']
            
            if (conn.get('user') == user_email and 
                is_active and
                conn_id.startswith(f'vpn-{user_email}-')):  # Ensure it's a VPN connection
                connection_id = conn_id
                break
    
    if not connection_id:
        # Return status for user if provided, otherwise inactive
        if user_email:
            return jsonify({
                'status': 'inactive',
                'user': user_email,
                'message': 'No active connection found for this user'
            })
        return jsonify({'status': 'inactive', 'error': 'connection_id or user_email required'}), 400
    
    if connection_id not in connections:
        return jsonify({'status': 'inactive', 'error': 'Connection not found'}), 404
    
    conn = connections[connection_id]
    
    # Check if connection was terminated by continuous auth
    if conn.get('status') == 'terminated':
        return jsonify({
            'status': 'terminated',
            'reason': conn.get('termination_reason', 'unknown'),
            'connected_at': conn.get('connected_at'),
            'terminated_at': conn.get('terminated_at')
        }), 403
    
    # Check if still active (simplified; in prod, poll OpenVPN status.log)
    conn['uptime'] = (datetime.now() - datetime.fromisoformat(conn['connected_at'])).total_seconds()
    
    # Include continuous auth info and IP information
    status_response = {
        'status': conn.get('status', 'active'),
        'uptime': conn.get('uptime', 0),
        'user': conn.get('user'),
        'connected_at': conn.get('connected_at'),
        # Real client information (from before VPN)
        'real_client_ip': conn.get('real_client_ip'),
        'location': conn.get('location'),
        # VPN-assigned information
        'vpn_ip': conn.get('vpn_ip'),
        'vpn_routes': conn.get('vpn_routes', []),
        # Continuous auth tracking
        'last_continuous_auth': conn.get('last_continuous_auth'),
        'last_risk_score': conn.get('last_risk_score', 0),
        'device': conn.get('device', {})
    }
    
    return jsonify(status_response)

@app.route('/api/vpn/connections', methods=['GET'])
def list_connections():
    """List all connections. Can filter by user_email."""
    user_email = request.args.get('user_email')
    if user_email:
        # Use list() to avoid modification during iteration
        user_connections = [
            conn for conn_id, conn in list(connections.items()) 
            if conn.get('user') == user_email and conn_id.startswith(f'vpn-{user_email}-')
        ]
        return jsonify({
            'user': user_email,
            'connections': user_connections,
            'count': len(user_connections)
        })
    return jsonify({
        'connections': list(connections.values()),
        'count': len(connections)
    })

@app.route('/api/vpn/check-connection', methods=['GET'])
def check_connection():
    """Check if user has an active connection (frontend-friendly endpoint)."""
    user_email = request.args.get('user_email')
    if not user_email:
        return jsonify({'error': 'user_email parameter required'}), 400
    
    # Find active connection for user
    # Use list() to avoid modification during iteration
    for conn_id, conn in list(connections.items()):
        # Check for both 'active' and 'connected' status
        conn_status = conn.get('status', '')
        is_active = conn_status in ['active', 'connected']
        
        if (conn.get('user') == user_email and 
            is_active and
            conn_id.startswith(f'vpn-{user_email}-')):  # Ensure it's a VPN connection
            print(f"[DEBUG] Found active connection for {user_email}: {conn_id} (status: {conn_status})")
            return jsonify({
                'connected': True,
                'connection_id': conn_id,
                'connected_at': conn.get('connected_at'),
                'vpn_ip': conn.get('vpn_ip'),
                'real_client_ip': conn.get('real_client_ip'),
                'location': conn.get('location'),
                'last_continuous_auth': conn.get('last_continuous_auth'),
                'last_risk_score': conn.get('last_risk_score', 0),
                'connection_mode': conn.get('connection_mode', 'unknown')
            })
    
    print(f"[DEBUG] No active connection found for {user_email}. Total connections: {len(connections)}")
    return jsonify({
        'connected': False,
        'user': user_email,
        'message': 'No active connection found'
    })

@app.route('/api/vpn/routes', methods=['POST'])
def get_routes():
    data = request.get_json()
    connection_id = data.get('connection_id')
    if connection_id in connections:
        return jsonify({'routes': connections[connection_id]['routes']})
    return jsonify({'error': 'Connection not found'}), 404

@app.route('/api/vpn/continuous-auth-log', methods=['GET'])
def get_continuous_auth_log():
    """Get continuous authentication monitoring log."""
    connection_id = request.args.get('connection_id')
    limit = int(request.args.get('limit', 100))
    
    if connection_id:
        filtered_log = [entry for entry in continuous_auth_log if entry.get('connection_id') == connection_id]
    else:
        filtered_log = continuous_auth_log
    
    # Return most recent entries
    return jsonify({
        'total_entries': len(continuous_auth_log),
        'filtered_entries': len(filtered_log),
        'log': filtered_log[-limit:]
    })

@app.route('/api/vpn/openvpn-status', methods=['GET'])
def get_openvpn_status():
    """Get detailed OpenVPN status from status log file."""
    status_data = read_openvpn_status()
    ipp_data = read_ipp_file()
    
    # Check for issues
    issues = []
    if not os.path.exists('openvpn-status.log'):
        issues.append('Status log file does not exist')
    elif os.path.getsize('openvpn-status.log') == 0:
        issues.append('Status log file is empty')
    
    if not os.path.exists('ipp.txt'):
        issues.append('IP pool file does not exist')
    elif os.path.getsize('ipp.txt') == 0:
        issues.append('IP pool file is empty')
    
    # Check for UNDEF CNs
    undef_count = sum(1 for client in status_data.get('clients', []) if client.get('common_name') == 'UNDEF')
    if undef_count > 0:
        issues.append(f'{undef_count} client(s) with UNDEF Common Name (certificate issue)')
    
    # Check for clients without Virtual IP
    no_ip_count = sum(1 for client in status_data.get('clients', []) if not client.get('virtual_address'))
    if no_ip_count > 0:
        issues.append(f'{no_ip_count} client(s) without Virtual IP assigned')
    
    return jsonify({
        'status_log': status_data,
        'ip_pool': ipp_data,
        'status_log_file': 'openvpn-status.log',
        'ipp_file': 'ipp.txt',
        'status_log_exists': os.path.exists('openvpn-status.log'),
        'ipp_file_exists': os.path.exists('ipp.txt'),
        'status_log_size': os.path.getsize('openvpn-status.log') if os.path.exists('openvpn-status.log') else 0,
        'ipp_file_size': os.path.getsize('ipp.txt') if os.path.exists('ipp.txt') else 0,
        'issues': issues,
        'clients_count': len(status_data.get('clients', [])),
        'ipp_assignments_count': len(ipp_data.get('assignments', []))
    })

@app.route('/api/vpn/diagnose-files', methods=['GET'])
def diagnose_files():
    """Diagnose issues with ipp.txt and openvpn-status.log files."""
    diagnosis = {
        'status_log': {
            'exists': os.path.exists('openvpn-status.log'),
            'size': 0,
            'readable': False,
            'has_clients': False,
            'undef_cns': 0,
            'clients_without_ip': 0,
            'last_update': None,
            'issues': []
        },
        'ipp_file': {
            'exists': os.path.exists('ipp.txt'),
            'size': 0,
            'readable': False,
            'has_assignments': False,
            'assignments_count': 0,
            'last_update': None,
            'issues': []
        },
        'openvpn_server': {
            'running': is_openvpn_running(),
            'process_count': 0
        },
        'recommendations': []
    }
    
    # Check status log
    if diagnosis['status_log']['exists']:
        diagnosis['status_log']['size'] = os.path.getsize('openvpn-status.log')
        try:
            status_data = read_openvpn_status()
            diagnosis['status_log']['readable'] = True
            diagnosis['status_log']['has_clients'] = len(status_data.get('clients', [])) > 0
            diagnosis['status_log']['undef_cns'] = sum(1 for c in status_data.get('clients', []) if c.get('common_name') == 'UNDEF')
            diagnosis['status_log']['clients_without_ip'] = sum(1 for c in status_data.get('clients', []) if not c.get('virtual_address'))
            
            if diagnosis['status_log']['undef_cns'] > 0:
                diagnosis['status_log']['issues'].append(f'{diagnosis["status_log"]["undef_cns"]} clients with UNDEF CN - certificate Key Usage extension may be missing')
                diagnosis['recommendations'].append('Regenerate client certificates with Key Usage extension')
            
            if diagnosis['status_log']['clients_without_ip'] > 0:
                diagnosis['status_log']['issues'].append(f'{diagnosis["status_log"]["clients_without_ip"]} clients without Virtual IP')
                diagnosis['recommendations'].append('Wait for OpenVPN to assign IPs (status log updates every 10 seconds)')
            
            if diagnosis['status_log']['size'] == 0:
                diagnosis['status_log']['issues'].append('Status log file is empty')
                diagnosis['recommendations'].append('Restart OpenVPN server to initialize status log')
        except Exception as e:
            diagnosis['status_log']['issues'].append(f'Error reading status log: {str(e)}')
    
    # Check ipp.txt
    if diagnosis['ipp_file']['exists']:
        diagnosis['ipp_file']['size'] = os.path.getsize('ipp.txt')
        try:
            ipp_data = read_ipp_file()
            diagnosis['ipp_file']['readable'] = True
            diagnosis['ipp_file']['has_assignments'] = len(ipp_data.get('assignments', [])) > 0
            diagnosis['ipp_file']['assignments_count'] = len(ipp_data.get('assignments', []))
            
            if diagnosis['ipp_file']['size'] == 0:
                diagnosis['ipp_file']['issues'].append('IP pool file is empty')
                diagnosis['recommendations'].append('Connect a client - ipp.txt updates when clients connect')
        except Exception as e:
            diagnosis['ipp_file']['issues'].append(f'Error reading ipp.txt: {str(e)}')
    
    # Check OpenVPN server
    if not diagnosis['openvpn_server']['running']:
        diagnosis['recommendations'].append('Start OpenVPN server: sudo openvpn --config server.ovpn --daemon')
    
    # General recommendations
    if diagnosis['status_log']['undef_cns'] > 0:
        diagnosis['recommendations'].append('Delete old certificates and reconnect: rm client_*.crt client_*.key')
    
    return jsonify(diagnosis)

@app.route('/api/vpn/ip-assignments', methods=['GET'])
def get_ip_assignments():
    """Get current IP assignment tracking."""
    return jsonify({
        'assigned_ips': assigned_ips,
        'total_assigned': len(assigned_ips),
        'ip_counter': ip_counter,
        'active_connections': len([c for c in connections.values() if c.get('status') in ['active', 'connected']]),
        'ipp_file_content': read_ipp_file(),
        'status_log_clients': read_openvpn_status().get('clients', [])
    })

@app.route('/api/vpn/verify-openvpn', methods=['GET'])
def verify_openvpn():
    """Comprehensive OpenVPN verification endpoint."""
    verification = {
        'installed': is_openvpn_installed(),
        'running': is_openvpn_running(),
        'port_1194_open': False,
        'process_running': False,
        'status_log_exists': os.path.exists('openvpn-status.log'),
        'ipp_file_exists': os.path.exists('ipp.txt'),
        'status_log_size': 0,
        'ipp_file_size': 0,
        'certificates_exist': all(os.path.exists(f) for f in ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'client.key', 'dh2048.pem']),
        'connection_mode': 'unknown'
    }
    
    # Check file sizes
    if verification['status_log_exists']:
        verification['status_log_size'] = os.path.getsize('openvpn-status.log')
    if verification['ipp_file_exists']:
        verification['ipp_file_size'] = os.path.getsize('ipp.txt')
    
    # Check port
    try:
        result = subprocess.run(['lsof', '-i', ':1194'], capture_output=True, timeout=2)
        verification['port_1194_open'] = result.returncode == 0 and bool(result.stdout)
    except:
        pass
    
    # Check process
    try:
        result = subprocess.run(['pgrep', '-f', 'openvpn'], capture_output=True, timeout=2)
        verification['process_running'] = result.returncode == 0 and bool(result.stdout)
    except:
        pass
    
    # Check connection mode from active connections
    if connections:
        for conn in connections.values():
            mode = conn.get('connection_mode', 'unknown')
            if mode in ['openvpn', 'mock', 'mock_fallback']:
                verification['connection_mode'] = mode
                break
    
    # Read status log if exists
    status_data = read_openvpn_status()
    ipp_data = read_ipp_file()
    
    verification['status_log_info'] = {
        'clients_count': len(status_data.get('clients', [])),
        'routing_entries': len(status_data.get('routing_table', [])),
        'clients': status_data.get('clients', [])[:5]  # First 5 clients
    }
    
    verification['ipp_file_info'] = {
        'assignments_count': len(ipp_data.get('assignments', [])),
        'assignments': ipp_data.get('assignments', [])[:5]  # First 5 assignments
    }
    
    verification['active_connections'] = len([c for c in connections.values() if c.get('status') == 'active'])
    
    # Check if files are being updated (not empty and recent)
    verification['files_updating'] = {
        'status_log': verification['status_log_size'] > 0,
        'ipp_file': verification['ipp_file_size'] > 0
    }
    
    return jsonify(verification)

@app.route('/health', methods=['GET'])
def health():
    vpn_running = (openvpn_process is not None and openvpn_process.poll() is None) or is_openvpn_running()
    return jsonify({
        'status': 'healthy', 
        'openvpn_running': vpn_running,
        'openvpn_installed': is_openvpn_installed()
    })

# Background thread to clean up old certificate files (older than 30 days)
def cleanup_old_certificates():
    """Clean up certificate files for users who haven't connected in 30+ days."""
    while True:
        time.sleep(3600)  # Run every hour
        try:
            current_time = time.time()
            cert_files = [f for f in os.listdir('.') if f.startswith('client_') and f.endswith('.crt')]
            
            for cert_file in cert_files:
                try:
                    # Get file modification time
                    file_time = os.path.getmtime(cert_file)
                    age_days = (current_time - file_time) / 86400  # Convert to days
                    
                    # Delete if older than 30 days
                    if age_days > 30:
                        key_file = cert_file.replace('.crt', '.key')
                        print(f"[CLEANUP] Removing old certificate: {cert_file} (age: {age_days:.1f} days)")
                        if os.path.exists(cert_file):
                            os.remove(cert_file)
                        if os.path.exists(key_file):
                            os.remove(key_file)
                except Exception as e:
                    print(f"[CLEANUP] Error cleaning up {cert_file}: {e}")
        except Exception as e:
            print(f"[CLEANUP] Error in certificate cleanup: {e}")

# Background thread to monitor OpenVPN status files
def monitor_openvpn_files():
    """Monitor OpenVPN status files and log updates."""
    last_status_size = 0
    last_ipp_size = 0
    
    while True:
        time.sleep(30)  # Check every 30 seconds
        try:
            if os.path.exists('openvpn-status.log'):
                current_size = os.path.getsize('openvpn-status.log')
                if current_size != last_status_size:
                    print(f"[{datetime.now().isoformat()}] OpenVPN status log updated: {current_size} bytes (was {last_status_size})")
                    last_status_size = current_size
                    # Read and log client count
                    status_data = read_openvpn_status()
                    client_count = len(status_data.get('clients', []))
                    if client_count > 0:
                        print(f"  Active clients: {client_count}")
            
            if os.path.exists('ipp.txt'):
                current_size = os.path.getsize('ipp.txt')
                if current_size != last_ipp_size:
                    print(f"[{datetime.now().isoformat()}] IP pool file updated: {current_size} bytes (was {last_ipp_size})")
                    last_ipp_size = current_size
                    # Read and log assignments
                    ipp_data = read_ipp_file()
                    assignment_count = len(ipp_data.get('assignments', []))
                    if assignment_count > 0:
                        print(f"  IP assignments: {assignment_count}")
        except Exception as e:
            print(f"Error monitoring OpenVPN files: {e}")

# Start file monitor thread
file_monitor_thread = threading.Thread(target=monitor_openvpn_files, daemon=True)
file_monitor_thread.start()

# Start certificate cleanup thread
cert_cleanup_thread = threading.Thread(target=cleanup_old_certificates, daemon=True)
cert_cleanup_thread.start()

if __name__ == '__main__':
    ensure_status_files()  # Ensure files exist before starting
    start_openvpn_daemon()  # Start on boot
    
    # Wait a bit for OpenVPN to start, then sync IP assignments
    time.sleep(3)
    sync_ip_assignments_from_openvpn()
    
    app.run(host='0.0.0.0', port=5001, debug=True)