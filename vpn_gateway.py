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
    except:
        pass  # Ignore permission errors

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
        
        openvpn_process = subprocess.Popen(
            ['openvpn', '--config', 'server.ovpn', '--daemon'],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=cwd  # Ensure we're in the right directory for config files
        )
        time.sleep(5)  # Wait longer for startup and status file creation
        
        if openvpn_process.poll() is not None:
            # Process exited, read the error
            try:
                _, stderr_output = openvpn_process.communicate(timeout=1)
                error_msg = stderr_output.decode('utf-8') if stderr_output else "Unknown error"
            except:
                error_msg = "Process exited immediately"
            
            # Check if error is "port already in use" - means OpenVPN is already running
            if 'address already in use' in error_msg.lower() or 'bind' in error_msg.lower() or 'EADDRINUSE' in error_msg:
                print("OpenVPN daemon already running (port 1194 in use)")
                return True  # Treat as success - OpenVPN is running
            
            # Check if it's a permission error
            if 'permission denied' in error_msg.lower() or 'root' in error_msg.lower() or 'EACCES' in error_msg:
                print("OpenVPN requires root privileges. Please start manually with: sudo openvpn --config server.ovpn --daemon")
                print("Falling back to mock mode for testing")
                return True  # Fall back to mock mode
            
            print(f"OpenVPN daemon failed to start")
            print(f"Error: {error_msg[:200]}")  # Print first 200 chars
            print("Falling back to mock mode for testing")
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
                    clients.append({
                        'common_name': parts[1] if len(parts) > 1 else 'UNDEF',
                        'real_address': parts[2] if len(parts) > 2 else '',
                        'virtual_address': parts[3] if len(parts) > 3 else '',  # May be empty if IP not assigned yet
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
                        'common_name': parts[0],
                        'real_address': parts[1],
                        'virtual_address': parts[2],
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
            if line and ',' in line:
                parts = line.split(',')
                if len(parts) >= 2:
                    assignments.append({
                        'common_name': parts[0].strip(),
                        'ip_address': parts[1].strip()
                    })
        
        return {
            'assignments': assignments,
            'count': len(assignments),
            'last_updated': datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error reading ipp.txt: {e}")
        return {'assignments': [], 'error': str(e)}

def mock_connect(user_email, routes):
    """Mock tunnel for preview (simulates 10.8.0.x assignment)"""
    time.sleep(1)  # Simulate connection time
    return {'status': 'connected', 'ip': '10.8.0.2', 'routes': routes}

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
            # Full client config based on your openvpn-client.ovpn + dynamic routes (IPv4 fix)
            try:
                client_config = f"""client
dev tun
proto udp4
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
route {' '.join(routes)}
# JWT stub: In prod, use --auth-user-pass for token validation
"""
                ovpn_file = f'{connection_id}.ovpn'
                with open(ovpn_file, 'w') as f:
                    f.write(client_config)
                
                # Try to start OpenVPN client
                print(f"Starting OpenVPN client with config: {ovpn_file}")
                client_proc = subprocess.Popen(
                    ['openvpn', '--config', ovpn_file], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    cwd=os.getcwd()
                )
                time.sleep(5)  # Wait for TLS handshake
                
                if client_proc.poll() is not None:
                    # Client process exited, read error
                    _, stderr_output = client_proc.communicate()
                    error_msg = stderr_output.decode('utf-8') if stderr_output else "Unknown error"
                    print(f"OpenVPN client failed: {error_msg[:200]}")
                    # Fall back to mock mode
                    result = mock_connect(user_email, routes)
                    result['connection_mode'] = 'mock_fallback'
                    result['error'] = f"OpenVPN client failed: {error_msg[:100]}"
                else:
                    # Try to get real IP from status log or ipp.txt
                    vpn_ip = '10.8.0.2'  # Default
                    try:
                        # First try ipp.txt (more reliable for IP assignments)
                        ipp_data = read_ipp_file()
                        # Find IP for this user (common name format: vpn-{email}-{timestamp})
                        for assignment in ipp_data.get('assignments', []):
                            if user_email in assignment.get('common_name', ''):
                                vpn_ip = assignment.get('ip_address', '10.8.0.2')
                                break
                        
                        # If not found in ipp.txt, try status log
                        if vpn_ip == '10.8.0.2':
                            status_data = read_openvpn_status()
                            # Find most recent client connection for this user
                            for client in status_data.get('clients', []):
                                if user_email in client.get('common_name', ''):
                                    vpn_ip = client.get('virtual_address', '10.8.0.2')
                                    break
                            
                            # Fallback: search for any 10.8.0.x IP in status log
                            if vpn_ip == '10.8.0.2':
                                status_data = read_openvpn_status()
                                for client in status_data.get('clients', []):
                                    ip = client.get('virtual_address', '')
                                    if ip.startswith('10.8.0.'):
                                        vpn_ip = ip
                                        break
                    except Exception as e:
                        print(f"Error reading OpenVPN status files: {e}")
                        pass
                    
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
            'vpn_ip': result.get('ip'),  # VPN-assigned IP (e.g., 10.8.0.2)
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
    # Simulate disconnect
    if is_openvpn_installed():
        subprocess.run(['pkill', '-f', connection_id], capture_output=True)  # Kill client process
        # Clean up ovpn file
        ovpn_file = f'{connection_id}.ovpn'
        if os.path.exists(ovpn_file):
            os.remove(ovpn_file)
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
    
    return jsonify({
        'status_log': status_data,
        'ip_pool': ipp_data,
        'status_log_file': 'openvpn-status.log',
        'ipp_file': 'ipp.txt',
        'status_log_exists': os.path.exists('openvpn-status.log'),
        'ipp_file_exists': os.path.exists('ipp.txt'),
        'status_log_size': os.path.getsize('openvpn-status.log') if os.path.exists('openvpn-status.log') else 0,
        'ipp_file_size': os.path.getsize('ipp.txt') if os.path.exists('ipp.txt') else 0
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

if __name__ == '__main__':
    ensure_status_files()  # Ensure files exist before starting
    start_openvpn_daemon()  # Start on boot
    app.run(host='0.0.0.0', port=5001, debug=True)