import os
from flask import Flask, request, jsonify
import jwt
import time
from datetime import datetime

app = Flask(__name__)
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')

# Mock active connections
connections = {}

@app.route('/api/vpn/connect', methods=['POST'])
def connect_vpn():
    start_time = time.time()
    data = request.json
    vpn_token = data['vpn_token']
    try:
        decoded = jwt.decode(vpn_token, SECRET_KEY, algorithms=['HS256'])
        conn_id = f"vpn-{decoded['user']}-{int(time.time())}"
        # Simulate tunnel setup delay (200ms)
        time.sleep(0.2)
        connections[conn_id] = {
            'user': decoded['user'],
            'vpn_ip': '10.8.0.2',
            'dns': ['10.8.0.1'],
            'routes': ['10.0.0.0/8', '192.168.0.0/16'],
            'throughput_mbps': 1000,  # Mock baseline
            'connect_time_ms': (time.time() - start_time) * 1000
        }
        return jsonify({'conn_id': conn_id, **connections[conn_id]})
    except:
        return jsonify({'error': 'Invalid VPN token'}), 401

@app.route('/api/vpn/disconnect', methods=['POST'])
def disconnect_vpn():
    data = request.json
    conn_id = data.get('conn_id')
    if conn_id in connections:
        del connections[conn_id]
        return jsonify({'status': 'disconnected'})
    return jsonify({'error': 'No connection'}), 404

@app.route('/api/vpn/status', methods=['POST'])
def vpn_status():
    data = request.json
    conn_id = data.get('conn_id')
    if conn_id in connections:
        # Mock latency check
        latency_ms = 50  # Baseline
        connections[conn_id]['latency_ms'] = latency_ms
        return jsonify({'status': 'active', 'latency_ms': latency_ms, **connections[conn_id]})
    return jsonify({'status': 'inactive'}), 404

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(port=5001, debug=True)