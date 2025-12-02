import requests
import sys
import jwt
import os
import json

BASE_URL = 'http://127.0.0.1'  # Fixed: IPv4 explicit
AUTH_PORT = 5000
VPN_PORT = 5001
POLICY_PORT = 5002
SECRET_KEY = 'your-super-secret-key'
SESSION_FILE = 'ztna_session.json'

# Globals
token = None
vpn_token = None
conn_id = None
user_email = None  # New: Track for policy

def load_session():
    global token, vpn_token, conn_id, user_email
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            session = json.load(f)
            token = session.get('token')
            vpn_token = session.get('vpn_token')
            conn_id = session.get('conn_id')
            user_email = session.get('user_email')
        print("📂 Session loaded from file.")

def save_session():
    session = {'token': token, 'vpn_token': vpn_token, 'conn_id': conn_id, 'user_email': user_email}
    with open(SESSION_FILE, 'w') as f:
        json.dump(session, f)
    print("💾 Session saved to file.")

def clear_session():
    global token, vpn_token, conn_id, user_email
    token = vpn_token = conn_id = user_email = None
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
    global token, user_email
    resp = requests.post(f'{BASE_URL}:{AUTH_PORT}/api/auth/login', json={'email': email, 'password': password})
    if resp.status_code == 200:
        data = safe_json(resp)
        token = data['token']
        user_email = email
        safe_user = {k: v for k, v in data['user'].items() if k != 'password'}
        print(f"✓ Login successful!\n  User: {email}\n  Role: {safe_user['role']}\n  Department: {safe_user['department']}\n  Clearance: {safe_user['clearance']}\n  Latency: {data['latency_ms']:.2f}ms")
        save_session()
        return True
    data = safe_json(resp)
    print(f"✗ Login failed: {data.get('error', 'Unknown')}")
    return False

def check_access(resource):
    global token
    if not token:
        load_session()
        if not token:
            print("✗ No token. Login first.")
            return
    headers = {'Authorization': f'Bearer {token}'}
    resp = requests.post(f'{BASE_URL}:{AUTH_PORT}/api/access/check', json={'resource': resource}, headers=headers)
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ Access {data['access']} to '{resource}'")
    elif resp.status_code == 403:
        print(f"✗ Access {data.get('access', 'DENIED')} to '{resource}'")
    else:
        print(f"✗ Access check failed: {data.get('error', 'Unknown')}")
    save_session()

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
        conn_id = data['connection_id']  # Fixed: 'connection_id'
        print(f"✓ VPN connection established!\n  Connection ID: {conn_id}\n  IP: {data['ip']}\n  Routes: {', '.join(data['routes'])}")  # Fixed keys
    else:
        print(f"✗ VPN connect failed: {data.get('error', 'Unknown')}")
    save_session()

def vpn_status():
    if not conn_id:
        load_session()
        if not conn_id:
            print("✗ No active connection. Connect first.")
            return
    resp = requests.post(f'{BASE_URL}:{VPN_PORT}/api/vpn/status', json={'connection_id': conn_id})  # Fixed key
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ VPN Status: {data['status']} | Uptime: {data['uptime']}s")  # Fixed key
    else:
        print(f"✗ Status check failed: {data.get('error', 'Unknown')}")
    save_session()

def disconnect_vpn():
    global conn_id
    if not conn_id:
        load_session()
        if not conn_id:
            print("✗ No active connection.")
            return
    resp = requests.post(f'{BASE_URL}:{VPN_PORT}/api/vpn/disconnect', json={'connection_id': conn_id})  # Fixed key
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
        requests.post(f'{BASE_URL}:{AUTH_PORT}/api/auth/logout', headers=headers)  # Stub; implement if needed
    clear_session()
    print("✓ Logged out.")

def evaluate_policy(resource):  # New: Full command
    global token, user_email
    if not token:
        load_session()
        if not token:
            print("✗ No token. Login first.")
            return
    resp = requests.post(f'{BASE_URL}:{POLICY_PORT}/api/policy/evaluate', json={
        'user': {'email': user_email or 'alice@company.com'},
        'resource': resource,
        'device': {'os_version': '5.0', 'encrypted': True},
        'location': {'country': 'US'}
    })
    data = safe_json(resp)
    if resp.status_code == 200:
        print(f"✓ Policy Eval: {data['decision']} (Risk: {data['risk_score']})")
    else:
        print(f"✗ Policy Eval failed: {data.get('reason', data.get('error', 'Unknown'))}")

if __name__ == '__main__':
    load_session()
    if len(sys.argv) < 2:
        print("Usage: python ztna_client.py [login|check-access|request-vpn|connect-vpn|vpn-status|disconnect-vpn|logout|check-policy] [args]")
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
    elif cmd == 'check-policy' and len(sys.argv) == 3:  # New command
        evaluate_policy(sys.argv[2])
    else:
        print("Invalid command.")