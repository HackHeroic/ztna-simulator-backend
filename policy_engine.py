# policy_engine.py

import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')

# ======================================================
# POLICY CONFIGURATIONS
# ======================================================

# Risk factors (scoring: >50 = high risk, >75 = critical)
RISK_FACTORS = {
    'failed_login_attempts': 20,
    'unusual_location': 15,
    'device_age_days': 10,
    'unusual_time_access': 12,
    'public_wifi': 18,
    'unpatched_device': 15,
    'rooted_device': 25,
    'velocity_check': 20,  # Multiple locations in short time
    'unusual_resource_access': 15,
    'session_timeout': 10,
    'no_mfa_high_risk': 20,
    'tor_exit_node': 30,
    'known_malicious_ip': 40,
}

# Time-based policies
TIME_POLICIES = {
    'business_hours_only': False,  # Set to True to restrict to 9 AM - 5 PM
    'business_hours': {'start': 9, 'end': 17},  # 9 AM to 5 PM
    'weekend_access': True,  # Allow weekend access
    'timezone_aware': True,
    'timezone': 'US/Eastern',  # Default timezone
}

# Network-based policies
NETWORK_POLICIES = {
    'allow_public_wifi': False,  # Block public WiFi
    'require_corporate_network': False,
    'ip_reputation_check': True,
    'geo_fencing': ['US', 'CA', 'UK'],  # Allowed countries
    'block_tor': True,
    'block_vpn_proxies': False,  # Allow corporate VPN
    'check_known_malicious_ips': True,
}

# Device compliance policies
DEVICE_POLICIES = {
    'require_encryption': True,
    'require_antivirus': True,
    'require_patch_level': 'latest',  # 'latest', 'recent', 'none'
    'block_rooted_jailbroken': True,
    'require_mdm_enrollment': False,  # Mobile Device Management
    'min_os_version': {
        'iOS': '14.0',
        'Android': '10.0',
        'Windows': '10.0',
        'macOS': '11.0',
        'Linux': '5.0',
    },
}

# Resource sensitivity policies
RESOURCE_POLICIES = {
    'database-prod': {
        'sensitivity': 'high',
        'require_mfa': True,
        'require_low_risk': True,  # Risk score < 30
        'session_timeout_minutes': 15,
        'audit_all_access': True,
        'time_restricted': False,
    },
    'file-server': {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,  # Risk score < 50
        'session_timeout_minutes': 30,
        'audit_all_access': False,
    },
    'admin-panel': {
        'sensitivity': 'critical',
        'require_mfa': True,
        'require_low_risk': True,  # Risk score < 20
        'session_timeout_minutes': 10,
        'audit_all_access': True,
        'time_restricted': True,  # Business hours only
    },
    'vpn-gateway': {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,
        'session_timeout_minutes': 60,
    },
}

# Session policies
SESSION_POLICIES = {
    'max_concurrent_sessions': 3,
    'default_session_timeout_minutes': 30,
    'idle_timeout_minutes': 15,
    'require_reauthentication_after_minutes': 60,
    'continuous_auth_interval_minutes': 5,  # Check every 5 minutes
}

# Behavioral analytics (user baseline)
user_baselines = {}  # Track normal user behavior
user_access_history = {}  # Track access patterns

# Anomaly log
anomalies = []

# Active sessions with continuous auth tracking
active_sessions = {}  # {user_email: {last_verified: datetime, risk_score: int, ...}}

# ======================================================
# LOCATION IDENTIFICATION
# ======================================================

def is_private_ip(ip_address):
    """Check if IP address is private/localhost."""
    if not ip_address:
        return True
    
    # Localhost addresses
    if ip_address in ['127.0.0.1', '::1', 'localhost']:
        return True
    
    # Private IP ranges
    parts = ip_address.split('.')
    if len(parts) == 4:
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
            # 169.254.0.0/16 (link-local)
            if first_octet == 169 and second_octet == 254:
                return True
        except ValueError:
            pass
    
    return False

def get_location_from_ip(ip_address):
    """
    Identify location from IP address using free geolocation API.
    Returns: {'country': 'US', 'city': 'New York', 'lat': 40.7128, 'lon': -74.0060}
    
    Note: Private/localhost IPs (127.0.0.1, 192.168.x.x, etc.) don't have geographic locations
    and will return 'Local' instead of attempting geolocation lookup.
    """
    # Handle private/localhost IPs - these don't have geographic locations
    if is_private_ip(ip_address):
        return {
            'country': 'Local',
            'country_name': 'Local Network',
            'city': 'Localhost' if ip_address in ['127.0.0.1', '::1'] else 'Private Network',
            'latitude': None,
            'longitude': None,
            'isp': 'Local',
            'source': 'private_ip',
            'note': 'Private/localhost IP - no geographic location available'
        }
    
    try:
        # Using ip-api.com (free, no API key needed for limited use)
        # In production, use paid services like MaxMind GeoIP2, IPinfo, etc.
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,lat,lon,isp', timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('countryCode', 'Unknown'),
                    'country_name': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp', 'Unknown'),
                    'source': 'ip-api'
                }
    except Exception as e:
        print(f"Location lookup failed for {ip_address}: {e}")
    
    # Fallback: return default/unknown
    return {
        'country': 'Unknown',
        'country_name': 'Unknown',
        'city': 'Unknown',
        'latitude': None,
        'longitude': None,
        'isp': 'Unknown',
        'source': 'fallback',
        'note': 'Geolocation lookup failed'
    }

def get_client_ip():
    """Extract client IP from request headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'

def compare_versions(version1, version2):
    """
    Compare two version strings (e.g., "8.0" vs "10.0").
    Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
    """
    def normalize_version(v):
        parts = v.split('.')
        return tuple(int(part) if part.isdigit() else 0 for part in parts)
    
    try:
        v1 = normalize_version(str(version1))
        v2 = normalize_version(str(version2))
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        return 0
    except:
        # If parsing fails, fall back to string comparison
        return -1 if str(version1) < str(version2) else (1 if str(version1) > str(version2) else 0)

# ======================================================
# RISK SCORING FUNCTIONS
# ======================================================

def calculate_risk_score(user_email, resource, device, location, context=None):
    """Calculate comprehensive risk score based on all policies."""
    risk_score = 0
    risk_factors = []
    
    # Location-based checks
    country = location.get('country', 'Unknown')
    if country not in NETWORK_POLICIES.get('geo_fencing', []):
        risk_score += RISK_FACTORS['unusual_location']
        risk_factors.append(f'Unusual location: {country}')
    
    # Network checks
    isp = location.get('isp', '').lower()
    if 'public' in isp or 'wifi' in isp:
        if not NETWORK_POLICIES.get('allow_public_wifi', False):
            risk_score += RISK_FACTORS['public_wifi']
            risk_factors.append('Public WiFi detected')
    
    # Device compliance checks
    os_type = device.get('os_type', '').lower()
    os_version = device.get('os_version', '0')
    min_version = DEVICE_POLICIES.get('min_os_version', {}).get(os_type, '0')
    
    if compare_versions(os_version, min_version) < 0:
        risk_score += RISK_FACTORS['device_age_days']
        risk_factors.append(f'Outdated OS: {os_version} < {min_version}')
    
    if device.get('rooted', False) and DEVICE_POLICIES.get('block_rooted_jailbroken', True):
        risk_score += RISK_FACTORS['rooted_device']
        risk_factors.append('Rooted/jailbroken device')
    
    if not device.get('encrypted', False) and DEVICE_POLICIES.get('require_encryption', True):
        risk_score += RISK_FACTORS['unpatched_device']
        risk_factors.append('Device not encrypted')
    
    # Time-based checks
    current_hour = datetime.now().hour
    if TIME_POLICIES.get('business_hours_only', False):
        business_start = TIME_POLICIES['business_hours']['start']
        business_end = TIME_POLICIES['business_hours']['end']
        if not (business_start <= current_hour < business_end):
            risk_score += RISK_FACTORS['unusual_time_access']
            risk_factors.append(f'Access outside business hours: {current_hour}:00')
    
    # Weekend check
    if not TIME_POLICIES.get('weekend_access', True):
        if datetime.now().weekday() >= 5:  # Saturday = 5, Sunday = 6
            risk_score += RISK_FACTORS['unusual_time_access']
            risk_factors.append('Weekend access')
    
    # Behavioral checks
    if user_email in user_access_history:
        history = user_access_history[user_email]
        # Velocity check: multiple locations in short time
        if len(history) > 1:
            last_access = history[-1]
            time_diff = (datetime.now() - last_access.get('time', datetime.now())).total_seconds() / 3600
            if time_diff < 1 and last_access.get('country') != country:
                risk_score += RISK_FACTORS['velocity_check']
                risk_factors.append('Velocity anomaly: rapid location change')
    
    # Resource sensitivity
    resource_policy = RESOURCE_POLICIES.get(resource, {})
    if resource_policy.get('sensitivity') == 'critical':
        risk_score += 5  # Base risk for critical resources
    
    # MFA check for high-risk scenarios
    if risk_score > 30 and not context.get('mfa_verified', False):
        if resource_policy.get('require_mfa', False):
            risk_score += RISK_FACTORS['no_mfa_high_risk']
            risk_factors.append('MFA required but not verified')
    
    # Update user baseline
    if user_email not in user_baselines:
        user_baselines[user_email] = {
            'normal_countries': [country],
            'normal_hours': [current_hour],
            'normal_resources': [resource],
        }
    else:
        baseline = user_baselines[user_email]
        if country not in baseline['normal_countries']:
            baseline['normal_countries'].append(country)
        if current_hour not in baseline['normal_hours']:
            baseline['normal_hours'].append(current_hour)
    
    # Update access history
    if user_email not in user_access_history:
        user_access_history[user_email] = []
    user_access_history[user_email].append({
        'time': datetime.now(),
        'resource': resource,
        'country': country,
        'risk_score': risk_score,
    })
    # Keep only last 100 entries
    if len(user_access_history[user_email]) > 100:
        user_access_history[user_email] = user_access_history[user_email][-100:]
    
    return risk_score, risk_factors

# ======================================================
# CONTINUOUS AUTHENTICATION
# ======================================================

def verify_token_and_context(token, device=None, location=None):
    """Verify JWT token and perform context checks."""
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_email = decoded.get('email') or decoded.get('user')
        
        # Check if token is expired
        exp = decoded.get('exp')
        if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
            return {'status': 'failed', 'reason': 'Token expired'}, None
        
        # Perform context checks if provided
        risk_score = 0
        if device or location:
            risk_score, _ = calculate_risk_score(
                user_email, 
                'continuous-auth', 
                device or {}, 
                location or {}
            )
        
        return {
            'status': 'verified',
            'user': user_email,
            'risk_score': risk_score,
            'expires_at': datetime.utcfromtimestamp(exp).isoformat() if exp else None
        }, decoded
        
    except jwt.ExpiredSignatureError:
        return {'status': 'failed', 'reason': 'Token expired'}, None
    except jwt.InvalidTokenError as e:
        return {'status': 'failed', 'reason': f'Invalid token: {str(e)}'}, None
    except Exception as e:
        return {'status': 'failed', 'reason': f'Verification error: {str(e)}'}, None

# ======================================================
# API ENDPOINTS
# ======================================================

@app.route('/api/policy/evaluate', methods=['POST'])
def evaluate_policy():
    """Evaluate access policy with comprehensive risk scoring."""
    data = request.json
    user_email = data.get('user', {}).get('email')
    resource = data.get('resource')
    device = data.get('device', {})
    location = data.get('location', {})
    context = data.get('context', {})
    
    # If location not provided, try to get from IP
    if not location or location.get('country') == 'Unknown':
        client_ip = get_client_ip()
        detected_location = get_location_from_ip(client_ip)
        location.update(detected_location)
    
    # Calculate risk score
    risk_score, risk_factors = calculate_risk_score(user_email, resource, device, location, context)
    
    # Get resource policy
    resource_policy = RESOURCE_POLICIES.get(resource, {})
    required_risk_threshold = 50  # Default
    if resource_policy.get('sensitivity') == 'critical':
        required_risk_threshold = 20
    elif resource_policy.get('sensitivity') == 'high':
        required_risk_threshold = 30
    
    # Check if access should be denied
    if risk_score > required_risk_threshold:
        anomaly = {
            'user': user_email,
            'resource': resource,
            'risk': risk_score,
            'risk_factors': risk_factors,
            'time': datetime.now().isoformat(),
            'location': location,
            'device': device
        }
        anomalies.append(anomaly)
        return jsonify({
            'decision': 'DENY',
            'risk_score': risk_score,
            'reason': 'High risk',
            'risk_factors': risk_factors,
            'threshold': required_risk_threshold
        }), 403
    
    # Check MFA requirement
    if resource_policy.get('require_mfa', False) and not context.get('mfa_verified', False):
        return jsonify({
            'decision': 'MFA_REQUIRED',
            'risk_score': risk_score,
            'reason': 'Multi-factor authentication required'
        }), 401
    
    # Access granted
    return jsonify({
        'decision': 'ALLOW',
        'risk_score': risk_score,
        'context': {
            'device': device,
            'location': location,
            'session_timeout_minutes': resource_policy.get('session_timeout_minutes', SESSION_POLICIES['default_session_timeout_minutes'])
        },
        'risk_factors': risk_factors
    })

@app.route('/api/policy/continuous-auth', methods=['POST'])
def continuous_auth():
    """
    Enhanced continuous authentication with context-aware verification.
    Prefers client-provided location/IP (from VPN gateway) over detecting from request,
    since during VPN connection, request IP would be VPN IP (10.8.0.x) not real client IP.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'status': 'failed', 'reason': 'No token provided'}), 401
    
    # Get device and location from request
    data = request.json or {}
    device = data.get('device', {})
    location = data.get('location', {})
    client_ip = data.get('client_ip')  # Client-provided IP (from VPN gateway)
    
    # Priority: Use client-provided location/IP (most reliable during VPN)
    # Only detect from request if not provided (for non-VPN requests)
    if not location or location.get('country') in ['Unknown', 'Local']:
        if client_ip:
            # Use client-provided IP to detect location
            detected_location = get_location_from_ip(client_ip)
            if location:
                location.update(detected_location)
            else:
                location = detected_location
        else:
            # Fallback: detect from request (only for non-VPN scenarios)
            request_ip = get_client_ip()
            detected_location = get_location_from_ip(request_ip)
            if location:
                location.update(detected_location)
            else:
                location = detected_location
    
    # Verify token and context
    result, decoded = verify_token_and_context(token, device, location)
    
    if result['status'] == 'verified':
        user_email = decoded.get('email') or decoded.get('user')
        
        # Update active session
        active_sessions[user_email] = {
            'last_verified': datetime.now().isoformat(),
            'risk_score': result.get('risk_score', 0),
            'location': location,
            'device': device
        }
        
        # Check if risk is too high
        if result.get('risk_score', 0) > 75:
            return jsonify({
                'status': 'failed',
                'reason': 'High risk detected',
                'risk_score': result['risk_score']
            }), 401
        
        return jsonify(result)
    else:
        return jsonify(result), 401

@app.route('/api/policy/anomaly-detect', methods=['POST'])
def anomaly_detect():
    """Detect and return anomalies for a user."""
    data = request.json
    user_email = data.get('email')
    
    if not user_email:
        return jsonify({'error': 'Email required'}), 400
    
    # Get user anomalies
    user_anoms = [a for a in anomalies if a.get('user') == user_email]
    
    # Calculate anomaly score
    anomaly_count = len(user_anoms)
    recent_anoms = [a for a in user_anoms 
                   if (datetime.now() - datetime.fromisoformat(a['time'])).total_seconds() < 3600]
    
    return jsonify({
        'anomalies': anomaly_count,
        'recent_anomalies': len(recent_anoms),
        'details': user_anoms[-10:],  # Last 10
        'risk_level': 'high' if anomaly_count > 3 else 'medium' if anomaly_count > 1 else 'low'
    })

@app.route('/api/policy/session-status', methods=['POST'])
def session_status():
    """Get continuous authentication status for a session."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'No token provided'}), 401
    
    result, decoded = verify_token_and_context(token)
    if result['status'] != 'verified':
        return jsonify(result), 401
    
    user_email = decoded.get('email') or decoded.get('user')
    session = active_sessions.get(user_email, {})
    
    if session:
        last_verified = datetime.fromisoformat(session.get('last_verified', datetime.now().isoformat()))
        minutes_since_verify = (datetime.now() - last_verified).total_seconds() / 60
        
        return jsonify({
            'status': 'active',
            'last_verified': session.get('last_verified'),
            'minutes_since_verify': round(minutes_since_verify, 2),
            'risk_score': session.get('risk_score', 0),
            'requires_reverify': minutes_since_verify > SESSION_POLICIES['continuous_auth_interval_minutes']
        })
    else:
        return jsonify({
            'status': 'no_session',
            'message': 'No active session found'
        })

@app.route('/api/policy/location-detect', methods=['GET', 'POST'])
def location_detect():
    """Detect location from client IP."""
    if request.method == 'POST':
        ip = request.json.get('ip') if request.json else None
    else:
        ip = request.args.get('ip')
    
    if not ip:
        ip = get_client_ip()
    
    location = get_location_from_ip(ip)
    return jsonify({
        'ip': ip,
        'location': location
    })

@app.route('/api/policy/policies', methods=['GET'])
def get_policies():
    """Get current policy configuration."""
    return jsonify({
        'risk_factors': RISK_FACTORS,
        'time_policies': TIME_POLICIES,
        'network_policies': NETWORK_POLICIES,
        'device_policies': DEVICE_POLICIES,
        'resource_policies': RESOURCE_POLICIES,
        'session_policies': SESSION_POLICIES
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'active_sessions': len(active_sessions),
        'anomalies_count': len(anomalies),
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
