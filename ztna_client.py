import requests
import sys
import jwt
import os
import json  # New: For session persistence

BASE_URL = 'http://127.0.0.1'  # IPv4 for macOS compatibility
AUTH_PORT = 5000
VPN_PORT = 5001
POLICY_PORT = 5002
SECRET_KEY = 'your-super-secret-key'  # Match servers
SESSION_FILE = 'ztna_session.json'  # New: Persistent state file

# Globals (loaded from file)
token = None
vpn_token = None
conn_id = None

def load_session():
    global token, vpn_token, conn_id
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            session = json.load(f)
            token = session.get('token')
            vpn_token = session.get('vpn_token')
            conn_id = session.get('conn_id')
        print("📂 Session loaded from file.")

def save_session():
    session = {'token': token, 'vpn_token': vpn_token, 'conn_id': conn_id}
    with open(SESSION_FILE, 'w') as f:
        json.dump(session, f)
    print("💾 Session saved to file.")

def clear_session():
    global token, vpn_token, conn_id
    token = vpn_token = conn_id = None
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
    print("🗑️ Session cleared.")

def safe_json(resp):
    try:
        return resp.json()
    except requests.exceptions.JSONDecodeError:
        print(f"✗ Server error: {resp.status_code} - {resp.text[:100]}")
        return {'error': 'Server not responding'}

def login(email, password):
    global token
    resp = requests.post(f'{BASE_URL}:{AUTH_PORT}/api/auth/login', json={'email': email, 'password': password})
    if resp.status_code == 200:
        data = safe_json(resp)
        token = data['token']
        safe_user = {k: v for k, v in data['user'].items() if k != 'password'}
        print(f"✓ Login successful!\n  User: {email}\n  Role: {data['user']['role']}\n  Department: {data['user']['department']}\n  Clearance: {data['user']['clearance']}\n  Latency: {data['latency_ms']:.2f}ms")
        save_session()  # New: Persist
        return True
    data = safe_json(resp)
    print(f"✗ Login failed: {data.get('error', 'Unknown')}")
    return False

def check_access(resource):
    global token
    if not token:
        load_session()  # New: Try load
        if not token:
            print("✗ No token. Login first.")
            return
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.post(f'{BASE_URL}:{AUTH_PORT}/api/access/check', json={'resource': resource}, headers=headers)
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ Access {data['access']} to '{resource}'")
    else:
        print(f"✗ Access {data.get('access', 'DENIED')} to '{resource}': {data.get('reason', data.get('error', 'Unknown'))}")
    save_session()  # Persist in case updated

def request_vpn():
    global vpn_token
    if not token:
        load_session()
        if not token:
            print("✗ No token. Login first.")
            return
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.post(f'{BASE_URL}:{AUTH_PORT}/api/access/request-vpn', headers=headers)
    data = safe_json(resp)
    if resp.status_code == 200:
        vpn_token = data['vpn_token']
        print(f"✓ VPN access granted!\n  VPN Server: {data['vpn_server']}\n  VPN Port: {data['vpn_port']}")
    else:
        print(f"✗ VPN request failed: {data.get('error', 'Unknown')}")
    save_session()

def connect_vpn():
    global conn_id
    if not vpn_token:
        load_session()
        if not vpn_token:
            print("✗ No VPN token. Request VPN first.")
            return
    resp = requests.post(f'{BASE_URL}:{VPN_PORT}/api/vpn/connect', json={'vpn_token': vpn_token})
    data = safe_json(resp)
    if resp.status_code == 200:
        conn_id = data['conn_id']
        print(f"✓ VPN connection established!\n  Connection ID: {conn_id}\n  VPN IP: {data['vpn_ip']}\n  DNS Servers: {data['dns']}\n  Routes: {', '.join(data['routes'])}\n  Connect Time: {data['connect_time_ms']:.2f}ms\n  Throughput: {data['throughput_mbps']} Mbps")
    else:
        print(f"✗ VPN connect failed: {data.get('error', 'Unknown')}")
    save_session()

def vpn_status():
    if not conn_id:
        load_session()
        if not conn_id:
            print("✗ No active connection. Connect first.")
            return
    resp = requests.post(f'{BASE_URL}:{VPN_PORT}/api/vpn/status', json={'conn_id': conn_id})
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ VPN Status: {data['status']}\n  Latency: {data['latency_ms']}ms\n  Throughput: {data.get('throughput_mbps', 'N/A')} Mbps")
    else:
        print(f"✗ Status check failed: {data.get('status', data.get('error', 'Unknown'))}")
    save_session()

def disconnect_vpn():
    global conn_id
    if not conn_id:
        load_session()
        if not conn_id:
            print("✗ No active connection.")
            return
    resp = requests.post(f'{BASE_URL}:{VPN_PORT}/api/vpn/disconnect', json={'conn_id': conn_id})
    data = safe_json(resp)
    if resp.status_code == 200:
        print("✓ VPN disconnected!")
        conn_id = None
    else:
        print(f"✗ Disconnect failed: {data.get('error', 'Unknown')}")
    save_session()

def logout():
    global token, vpn_token, conn_id
    if token:
        headers = {'Authorization': f'Bearer {token}'}
        requests.post(f'{BASE_URL}:{AUTH_PORT}/api/auth/logout', headers=headers)
    clear_session()  # New: Wipe file
    print("✓ Logged out.")

def evaluate_policy():
    # Hardcoded for alice; load email from session if needed
    resp = requests.post(f'{BASE_URL}:{POLICY_PORT}/api/policy/evaluate', json={
        'user': {'email': 'alice@company.com'},
        'resource': 'database-prod',
        'device': {'os_type': 'linux', 'os_version': '5.0', 'encrypted': True},
        'location': {'country': 'US'}
    })
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ Policy Eval: {data['decision']} (Risk: {data['risk_score']})")
    else:
        print(f"✗ Policy Eval failed: {data.get('reason', data.get('error', 'Unknown'))}")

if __name__ == '__main__':
    load_session()  # New: Always try load on start
    if len(sys.argv) < 2:
        print("Usage: python ztna_client.py [login|check-access|request-vpn|connect-vpn|vpn-status|disconnect-vpn|logout|evaluate-policy] [args]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'login' and len(sys.argv) == 3:
        parts = sys.argv[2].split(':')
        if len(parts) == 2:
            login(parts[0], parts[1])
        else:
            print("✗ Login format: email:password")
    elif cmd == 'check-access' and len(sys.argv) == 3:
        check_access(sys.argv[2])
    elif cmd == 'request-vpn':
        request_vpn()
    elif cmd == 'connect-vpn':
        connect_vpn()
    elif cmd == 'vpn-status':
        vpn_status()
    elif cmd == 'disconnect-vpn':
        disconnect_vpn()
    elif cmd == 'logout':
        logout()
    elif cmd == 'evaluate-policy':
        evaluate_policy()
    else:
        print("Invalid command.")