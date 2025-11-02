import os
import jwt
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
TOKEN_EXPIRY_MINUTES = 30
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')

# Mock user DB (in-memory; replace with DB later)
USERS = {
    'bob@company.com': {'password': 'securepass', 'role': 'Admin', 'clearance': 5, 'department': 'IT'},
    'alice@company.com': {'password': 'password123', 'role': 'Developer', 'clearance': 3, 'department': 'Engineering'},
    'charlie@company.com': {'password': 'userpass', 'role': 'Analyst', 'clearance': 2, 'department': 'Finance'}
}

# Mock sessions
active_sessions = {}

# Access policies (resource -> requirements)
ACCESS_POLICIES = {
    'database-prod': {'required_role': ['Admin', 'Developer'], 'required_clearance': 3, 'allowed_departments': ['Engineering', 'IT']},
    'admin-panel': {'required_role': ['Admin'], 'required_clearance': 5, 'allowed_departments': ['IT']},
    'file-server': {'required_role': ['Admin', 'Developer', 'Analyst'], 'required_clearance': 2, 'allowed_departments': ['Engineering', 'IT', 'Finance']},
    'vpn-gateway': {'required_role': ['Admin', 'Developer', 'Analyst'], 'required_clearance': 1, 'allowed_departments': ['Engineering', 'IT', 'Finance']}
}

@app.route('/api/auth/login', methods=['POST'])
def login():
    start_time = datetime.now()
    data = request.json
    email, password = data['email'], data['password']
    if email in USERS and USERS[email]['password'] == password:
        user = USERS[email]
        token = jwt.encode({
            'email': email,
            'role': user['role'],
            'clearance': user['clearance'],
            'department': user['department'],
            'exp': datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
        }, SECRET_KEY, algorithm='HS256')
        active_sessions[email] = {'token': token, 'login_time': start_time}
        latency = (datetime.now() - start_time).total_seconds() * 1000
        return jsonify({'token': token, 'user': user, 'latency_ms': latency})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/verify', methods=['GET'])
def verify_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'valid': True, 'user': decoded})
    except:
        return jsonify({'valid': False}), 401

@app.route('/api/access/check', methods=['POST'])
def check_access():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    resource = request.json['resource']
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        policy = ACCESS_POLICIES.get(resource, {})
        if (decoded['role'] in policy.get('required_role', []) and
            decoded['clearance'] >= policy.get('required_clearance', 0) and
            decoded['department'] in policy.get('allowed_departments', [])):
            return jsonify({'access': 'GRANTED', 'resource': resource})
        return jsonify({'access': 'DENIED', 'resource': resource}), 403
    except:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/access/request-vpn', methods=['POST'])
def request_vpn():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # Simple VPN token (mock)
        vpn_token = jwt.encode({'user': decoded['email'], 'exp': datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)}, SECRET_KEY)
        return jsonify({'vpn_token': vpn_token, 'vpn_server': '10.8.0.1', 'vpn_port': 1194})
    except:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(port=5000, debug=True)