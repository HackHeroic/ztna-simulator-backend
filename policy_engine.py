import os
from flask import Flask, request, jsonify
import jwt
from datetime import datetime

app = Flask(__name__)
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')

# Risk factors (simple scoring: >50 = high risk)
RISK_FACTORS = {
    'failed_login_attempts': 20,
    'unusual_location': 15,
    'device_age_days': 10  # e.g., old device
}

# Mock anomaly log
anomalies = []

@app.route('/api/policy/evaluate', methods=['POST'])
def evaluate_policy():
    data = request.json
    user_email = data['user']['email']
    resource = data['resource']
    device = data.get('device', {})
    location = data.get('location', {})

    # Mock risk score
    risk_score = 0
    if location.get('country') != 'US':  # Unusual location
        risk_score += RISK_FACTORS['unusual_location']
    if device.get('os_version', '0') < '5.0':
        risk_score += RISK_FACTORS['device_age_days']
    # Add more context checks...

    # Continuous auth: Check if score < threshold
    if risk_score > 50:
        anomalies.append({'user': user_email, 'resource': resource, 'risk': risk_score, 'time': datetime.now()})
        return jsonify({'decision': 'DENY', 'risk_score': risk_score, 'reason': 'High risk'}), 403

    # Integrate with access policy (call auth server internally if needed)
    return jsonify({'decision': 'ALLOW', 'risk_score': risk_score, 'context': {'device': device, 'location': location}})

@app.route('/api/policy/continuous-auth', methods=['POST'])
def continuous_auth():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'status': 'verified'})
    except:
        return jsonify({'status': 'failed'}), 401

@app.route('/api/policy/anomaly-detect', methods=['POST'])
def anomaly_detect():
    data = request.json
    # Simple mock: Flag if >1 anomaly for user
    user_anoms = [a for a in anomalies if a['user'] == data['email']]
    return jsonify({'anomalies': len(user_anoms), 'details': user_anoms[-5:]})  # Last 5

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(port=5002, debug=True)