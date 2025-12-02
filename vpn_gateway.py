import os
import re
import subprocess
import threading
import time
import jwt
import requests
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')
POLICY_ENGINE_URL = 'http://127.0.0.1:5002'  # Policy engine endpoint

# Mock active connections (in-memory for preview)
connections = {}
openvpn_process = None

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
                    
                    if resp.status_code != 200:
                        # Continuous auth failed - disconnect
                        print(f"Continuous auth failed for {conn_id}, disconnecting...")
                        conn['status'] = 'terminated'
                        conn['termination_reason'] = 'continuous_auth_failed'
                        conn['terminated_at'] = datetime.now().isoformat()
                        # Optionally kill the OpenVPN process
                        if is_openvpn_installed():
                            subprocess.run(['pkill', '-f', conn_id], capture_output=True)
                    else:
                        result = resp.json()
                        conn['last_continuous_auth'] = datetime.now().isoformat()
                        conn['last_risk_score'] = result.get('risk_score', 0)
                        
                        # Log continuous auth success
                        print(f"Continuous auth verified for {conn_id}: risk_score={result.get('risk_score', 0)}")
                        
                except Exception as e:
                    print(f"Continuous auth check error for {conn_id}: {e}")

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

def start_openvpn_daemon():
    """
    Start OpenVPN daemon if not already running.
    Detects existing OpenVPN instances and handles errors gracefully.
    """
    global openvpn_process
    
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
        openvpn_process = subprocess.Popen(
            ['openvpn', '--config', 'server.ovpn', '--daemon'],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.getcwd()  # Ensure we're in the right directory for config files
        )
        time.sleep(3)  # Wait a bit longer for startup
        
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
            return True
        else:
            print("OpenVPN process started but may not be listening. Falling back to mock mode.")
            return True  # Fall back to mock mode
        
    except Exception as e:
        print(f"Error starting OpenVPN: {e}")
        print("Falling back to mock mode for testing")
        return True  # Fall back to mock mode

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
                    # Try to get real IP from status log
                    vpn_ip = '10.8.0.2'  # Default
                    try:
                        if os.path.exists('openvpn-status.log'):
                            with open('openvpn-status.log', 'r') as f:
                                content = f.read()
                                # Parse for client IP (simplified)
                                match = re.search(r'10\.8\.0\.\d+', content)
                                if match:
                                    vpn_ip = match.group(0)
                    except:
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
        connections[connection_id] = {
            'user': user_email,
            'connected_at': datetime.now().isoformat(),
            'status': 'active',
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

@app.route('/api/vpn/status', methods=['POST'])
def vpn_status():
    data = request.get_json()
    connection_id = data.get('connection_id')
    if connection_id not in connections:
        return jsonify({'status': 'inactive'}), 404
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
    return jsonify(list(connections.values()))

@app.route('/api/vpn/routes', methods=['POST'])
def get_routes():
    data = request.get_json()
    connection_id = data.get('connection_id')
    if connection_id in connections:
        return jsonify({'routes': connections[connection_id]['routes']})
    return jsonify({'error': 'Connection not found'}), 404

@app.route('/health', methods=['GET'])
def health():
    vpn_running = (openvpn_process is not None and openvpn_process.poll() is None) or is_openvpn_running()
    return jsonify({
        'status': 'healthy', 
        'openvpn_running': vpn_running,
        'openvpn_installed': is_openvpn_installed()
    })

if __name__ == '__main__':
    start_openvpn_daemon()  # Start on boot
    app.run(host='0.0.0.0', port=5001, debug=True)