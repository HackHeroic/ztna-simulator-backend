# policy_engine.py

import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import threading
import time
import json
from pathlib import Path

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

SECRET_KEY = os.environ.get('JWT_SECRET', 'your-super-secret-key')

# ======================================================
# LOG PERSISTENCE
# ======================================================
LOG_DIR = Path(__file__).parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)

ACCESS_LOG_FILE = LOG_DIR / 'access_log.json'
ANOMALIES_LOG_FILE = LOG_DIR / 'anomalies_log.json'
CONTINUOUS_AUTH_LOG_FILE = LOG_DIR / 'continuous_auth_log.json'
THREAT_USERS_FILE = LOG_DIR / 'threat_users.json'

def load_logs_from_file(file_path, default=[]):
    """Load logs from JSON file."""
    try:
        if file_path.exists():
            with open(file_path, 'r') as f:
                data = json.load(f)
                # Convert timestamp strings back to datetime-aware format
                return data if isinstance(data, list) else default
    except Exception as e:
        print(f"Error loading logs from {file_path}: {e}")
    return default

def save_logs_to_file(file_path, logs, max_entries=10000):
    """Save logs to JSON file, keeping only recent entries."""
    try:
        # Keep only last max_entries
        logs_to_save = logs[-max_entries:] if len(logs) > max_entries else logs
        with open(file_path, 'w') as f:
            json.dump(logs_to_save, f, indent=2, default=str)
    except Exception as e:
        print(f"Error saving logs to {file_path}: {e}")

def auto_save_logs():
    """Background thread to periodically save logs."""
    while True:
        time.sleep(30)  # Save every 30 seconds
        try:
            save_logs_to_file(ACCESS_LOG_FILE, access_log)
            save_logs_to_file(ANOMALIES_LOG_FILE, anomalies)
            save_logs_to_file(CONTINUOUS_AUTH_LOG_FILE, continuous_auth_requests)
            save_logs_to_file(THREAT_USERS_FILE, threat_users)
        except Exception as e:
            print(f"Error in auto_save_logs: {e}")

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
    'geo_fencing': ['US', 'CA', 'UK','IN'],  # Allowed countries
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
        'max_concurrent_connections': 5,
        'require_encrypted_connection': True,
        'block_rooted_devices': True,
        'require_recent_login': True,  # Must have logged in within last 7 days
        'ip_whitelist': [],  # Empty = no whitelist
        'ip_blacklist': [],
        'rate_limit_per_minute': 100,
        'require_device_compliance': True,
    },
    'file-server': {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,  # Risk score < 50
        'session_timeout_minutes': 30,
        'audit_all_access': False,
        'max_concurrent_connections': 10,
        'require_encrypted_connection': True,
        'block_rooted_devices': False,
        'require_recent_login': False,
        'ip_whitelist': [],
        'ip_blacklist': [],
        'rate_limit_per_minute': 200,
        'require_device_compliance': False,
    },
    'admin-panel': {
        'sensitivity': 'critical',
        'require_mfa': True,
        'require_low_risk': True,  # Risk score < 20
        'session_timeout_minutes': 10,
        'audit_all_access': True,
        'time_restricted': True,  # Business hours only
        'max_concurrent_connections': 2,
        'require_encrypted_connection': True,
        'block_rooted_devices': True,
        'require_recent_login': True,  # Must have logged in within last 3 days
        'ip_whitelist': [],  # Can be configured by admin
        'ip_blacklist': [],
        'rate_limit_per_minute': 50,
        'require_device_compliance': True,
        'require_admin_role': True,
    },
    'vpn-gateway': {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,
        'session_timeout_minutes': 60,
        'max_concurrent_connections': 1,  # One VPN connection per user
        'require_encrypted_connection': True,
        'block_rooted_devices': False,
        'require_recent_login': False,
        'ip_whitelist': [],
        'ip_blacklist': [],
        'rate_limit_per_minute': 10,  # Low rate limit for VPN requests
        'require_device_compliance': False,
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

# Anomaly log (loaded from file on startup)
anomalies = load_logs_from_file(ANOMALIES_LOG_FILE, [])

def seed_sample_anomalies():
    """Seed realistic sample anomalies with different user names for demonstration."""
    sample_users = [
        'alice@company.com',
        'charlie@company.com', 
        'diana@company.com',
        'eve@company.com',
        'frank@company.com',
        'grace@company.com'
    ]
    sample_resources = ['database-prod', 'admin-panel', 'file-server', 'vpn-gateway']
    sample_locations = [
        {'country': 'CN', 'country_name': 'China', 'city': 'Beijing', 'latitude': 39.9042, 'longitude': 116.4074, 'isp': 'China Telecom', 'source': 'ip-api'},
        {'country': 'RU', 'country_name': 'Russia', 'city': 'Moscow', 'latitude': 55.7558, 'longitude': 37.6173, 'isp': 'Rostelecom', 'source': 'ip-api'},
        {'country': 'IN', 'country_name': 'India', 'city': 'Mumbai', 'latitude': 19.0760, 'longitude': 72.8777, 'isp': 'Reliance Jio', 'source': 'ip-api'},
        {'country': 'BR', 'country_name': 'Brazil', 'city': 'São Paulo', 'latitude': -23.5505, 'longitude': -46.6333, 'isp': 'Vivo', 'source': 'ip-api'},
        {'country': 'US', 'country_name': 'United States', 'city': 'New York', 'latitude': 40.7128, 'longitude': -74.0060, 'isp': 'Verizon', 'source': 'ip-api'},
        {'country': 'KP', 'country_name': 'North Korea', 'city': 'Pyongyang', 'latitude': 39.0392, 'longitude': 125.7625, 'isp': 'Korea Post', 'source': 'ip-api'},
        {'country': 'GB', 'country_name': 'United Kingdom', 'city': 'London', 'latitude': 51.5074, 'longitude': -0.1278, 'isp': 'BT Group', 'source': 'ip-api'},
    ]
    sample_risk_factors = [
        ['Unusual location: CN', 'Rooted/jailbroken device', 'Device not encrypted'],
        ['Unusual location: RU', 'Outdated OS: 8.0 < 11.0', 'Public WiFi detected'],
        ['Unusual location: IN', 'Velocity anomaly: rapid location change', 'Device not encrypted'],
        ['Unusual location: BR', 'Rooted/jailbroken device', 'Outdated OS: 9.0 < 12.0'],
        ['Unusual location: CN', 'Public WiFi detected', 'Device not encrypted', 'Velocity anomaly: rapid location change'],
        ['Unusual location: RU', 'Rooted/jailbroken device', 'Outdated OS: 7.0 < 10.0'],
        ['Unusual location: KP', 'High-risk country', 'Suspicious IP range'],
        ['TOR Exit Node detected', 'Anonymous proxy usage', 'High-risk IP reputation'],
        ['Off-hours access attempt', 'Unusual access time', 'Non-VPN access to sensitive resource'],
        ['Unauthorized resource access attempt', 'Insufficient clearance level', 'Privilege escalation attempt'],
        ['Multiple failed access attempts', 'Brute force pattern detected', 'Rate limit exceeded'],
        ['MFA bypass attempt', 'Authentication anomaly', 'Suspicious login pattern'],
    ]
    sample_devices = [
        {'os_type': 'macOS', 'os_version': '10.15', 'encrypted': False, 'rooted': True},
        {'os_type': 'Windows', 'os_version': '8.0', 'encrypted': False, 'rooted': False},
        {'os_type': 'Android', 'os_version': '9.0', 'encrypted': True, 'rooted': True},
        {'os_type': 'iOS', 'os_version': '12.0', 'encrypted': True, 'rooted': True, 'jailbroken': True},
        {'os_type': 'Linux', 'os_version': '4.0', 'encrypted': False, 'rooted': False},
        {'os_type': 'Windows', 'os_version': '11', 'encrypted': True, 'rooted': False},
        {'os_type': 'macOS', 'os_version': '13.5.1', 'encrypted': True, 'rooted': False},
    ]
    
    base_time = datetime.now() - timedelta(days=2)
    seeded_anomalies = []
    
    for i, user in enumerate(sample_users):
        # Create 2-3 anomalies per user (total ~15 anomalies)
        num_anomalies = 2 if i % 2 == 0 else 3
        for j in range(num_anomalies):
            anomaly_time = base_time + timedelta(hours=i*3 + j*2, minutes=j*15)
            risk_score = 45 + (i * 5) + (j * 3)  # Vary risk scores between 45-85
            risk_score = min(risk_score, 90)  # Cap at 90
            
            seeded_anomalies.append({
                'user': user,
                'resource': sample_resources[i % len(sample_resources)],
                'risk': risk_score,
                'risk_factors': sample_risk_factors[(i * 2 + j) % len(sample_risk_factors)][:2 + (j % 2)],
                'time': anomaly_time.isoformat(),
                'location': sample_locations[i % len(sample_locations)],
                'device': sample_devices[i % len(sample_devices)],
                'vpn_connected': j % 2 == 0  # Mix of VPN and non-VPN
            })
    
    return seeded_anomalies

# Seed sample anomalies if none exist (or if only bob entries exist)
if len(anomalies) == 0 or all(a.get('user') == 'bob@company.com' for a in anomalies):
    seeded = seed_sample_anomalies()
    anomalies.extend(seeded)
    save_logs_to_file(ANOMALIES_LOG_FILE, anomalies)
    print(f"[Policy Engine] Seeded {len(seeded)} sample anomalies with diverse users")

# Active sessions with continuous auth tracking
active_sessions = {}  # {user_email: {last_verified: datetime, risk_score: int, ...}}

# Continuous auth request tracking (loaded from file on startup)
continuous_auth_requests = load_logs_from_file(CONTINUOUS_AUTH_LOG_FILE, [])

# Access tracking with VPN status (loaded from file on startup)
access_log = load_logs_from_file(ACCESS_LOG_FILE, [])

# Threat users tracking (loaded from file on startup)
threat_users = load_logs_from_file(THREAT_USERS_FILE, [])

# Admin/Master users (can modify policies and risk factors)
ADMIN_USERS = ['bob@company.com']  # Users with admin role or clearance 5

# Dynamic risk thresholds (can be updated via API)
DYNAMIC_RISK_THRESHOLDS = {
    'global_max_risk': 75,  # Maximum risk before automatic deny
    'critical_resource_threshold': 20,
    'high_resource_threshold': 30,
    'medium_resource_threshold': 50,
    'continuous_auth_max_risk': 75  # Max risk for continuous auth
}

# ======================================================
# LOCATION IDENTIFICATION
# ======================================================


session = requests.Session()
session.trust_env = False  # ignore HTTP(S)_PROXY env vars


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
        response = session.get(
            f'http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,lat,lon,isp',
            timeout=2
        )
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
    
    # Apply custom resource rules
    if 'custom_rules' in resource_policy:
        for rule_name, rule_config in resource_policy['custom_rules'].items():
            rule_type = rule_config.get('type', 'risk_addition')
            if rule_type == 'risk_addition':
                condition = rule_config.get('condition', {})
                # Evaluate condition (e.g., device property, location, etc.)
                condition_met = True
                if 'device_property' in condition:
                    prop = condition['device_property']
                    value = condition.get('value')
                    if device.get(prop) != value:
                        condition_met = False
                if condition_met:
                    risk_score += rule_config.get('risk_value', 0)
                    risk_factors.append(f'Custom rule triggered: {rule_name}')
    
    # Apply custom network rules
    if 'custom_network_rules' in NETWORK_POLICIES:
        for rule_name, rule_config in NETWORK_POLICIES['custom_network_rules'].items():
            condition_met = True
            if 'country_blacklist' in rule_config:
                if country in rule_config['country_blacklist']:
                    risk_score += rule_config.get('risk_value', 20)
                    risk_factors.append(f'Blocked country: {country}')
            if 'isp_blacklist' in rule_config:
                if any(blocked in isp for blocked in rule_config['isp_blacklist']):
                    risk_score += rule_config.get('risk_value', 15)
                    risk_factors.append(f'Blocked ISP detected')
    
    # Apply custom device rules
    if 'custom_device_rules' in DEVICE_POLICIES:
        for rule_name, rule_config in DEVICE_POLICIES['custom_device_rules'].items():
            condition_met = True
            if 'os_blacklist' in rule_config:
                if os_type in rule_config['os_blacklist']:
                    risk_score += rule_config.get('risk_value', 25)
                    risk_factors.append(f'Blocked OS: {os_type}')
            if 'min_version_required' in rule_config:
                min_ver = rule_config['min_version_required'].get(os_type)
                if min_ver and compare_versions(os_version, min_ver) < 0:
                    risk_score += rule_config.get('risk_value', 20)
                    risk_factors.append(f'OS version too old: {os_version} < {min_ver}')
    
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
    try:
        data = request.json or {}
        user_email = data.get('user', {}).get('email')
        resource = data.get('resource')
        device = data.get('device', {})
        location = data.get('location', {})
        context = data.get('context', {})
        
        # Validate required fields
        if not user_email:
            return jsonify({'error': 'User email is required'}), 400
        if not resource:
            return jsonify({'error': 'Resource is required'}), 400
        
        # Check if user has active VPN connection to get real IP/location
        vpn_connected = False
        vpn_ip = None
        real_client_ip = None
        real_location = None
        
        try:
            # Check VPN gateway for active connection
            vpn_resp = requests.get(
                f'http://127.0.0.1:5001/api/vpn/check-connection?user_email={user_email}',
                timeout=2
            )
            if vpn_resp.status_code == 200:
                vpn_data = vpn_resp.json()
                vpn_connected = vpn_data.get('connected', False)
                if vpn_connected:
                    vpn_ip = vpn_data.get('vpn_ip')
                    # Get real IP and location from VPN connection (stored before VPN)
                    real_client_ip = vpn_data.get('real_client_ip')
                    real_location = vpn_data.get('location')
        except:
            pass  # VPN gateway not available, assume no VPN
        
        # IMPORTANT: Use real IP/location if VPN is connected, otherwise detect from request
        if vpn_connected and real_location and real_client_ip:
            # User is connected via VPN - use stored real location (from BEFORE VPN)
            location = real_location.copy() if isinstance(real_location, dict) else {}
            # Ensure we have country info
            if not location.get('country') or location.get('country') in ['Unknown', 'Local']:
                # Re-detect from real IP
                detected_location = get_location_from_ip(real_client_ip)
                location.update(detected_location)
        else:
            # No VPN or real location not available - detect from request
            # If location not provided, try to get from IP
            if not location or location.get('country') in ['Unknown', 'Local']:
                client_ip = data.get('client_ip') or get_client_ip()  # Prefer frontend-provided IP
                detected_location = get_location_from_ip(client_ip)
                if location:
                    location.update(detected_location)
                else:
                    location = detected_location
                real_client_ip = client_ip
        
        # Calculate risk score using REAL location (not VPN IP location)
        risk_score, risk_factors = calculate_risk_score(user_email, resource, device, location, context)
        
        # Get resource policy
        resource_policy = RESOURCE_POLICIES.get(resource, {})
        
        # Enforce resource-specific rules
        client_ip = real_client_ip or get_client_ip()
        
        # Check IP whitelist
        ip_whitelist = resource_policy.get('ip_whitelist', [])
        if ip_whitelist and client_ip not in ip_whitelist:
            return jsonify({
                'decision': 'DENY',
                'risk_score': 100,
                'reason': f'IP {client_ip} not in whitelist for {resource}',
                'vpn_connected': vpn_connected
            }), 403
        
        # Check IP blacklist
        ip_blacklist = resource_policy.get('ip_blacklist', [])
        if client_ip in ip_blacklist:
            return jsonify({
                'decision': 'DENY',
                'risk_score': 100,
                'reason': f'IP {client_ip} is blacklisted for {resource}',
                'vpn_connected': vpn_connected
            }), 403
        
        # Check rate limiting
        rate_limit = resource_policy.get('rate_limit_per_minute', 0)
        if rate_limit > 0:
            # Count requests in last minute
            now = datetime.now()
            recent_requests = [
                e for e in access_log
                if e.get('user') == user_email and 
                e.get('resource') == resource and
                (now - datetime.fromisoformat(e.get('timestamp', now.isoformat()))).total_seconds() < 60
            ]
            if len(recent_requests) >= rate_limit:
                return jsonify({
                    'decision': 'DENY',
                    'risk_score': 50,
                    'reason': f'Rate limit exceeded: {len(recent_requests)}/{rate_limit} requests per minute',
                    'vpn_connected': vpn_connected
                }), 429
        
        # Check max concurrent connections (for VPN gateway resource)
        max_concurrent = resource_policy.get('max_concurrent_connections', 0)
        if max_concurrent > 0 and resource == 'vpn-gateway':
            # This is handled by VPN gateway itself, but we can add a check here too
            pass
        
        # Check require_admin_role
        if resource_policy.get('require_admin_role', False):
            # Check if user has admin role
            try:
                # Extract token from request if available
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                if token:
                    is_admin, admin_user = check_admin_access(token)
                    if not is_admin:
                        return jsonify({
                            'decision': 'DENY',
                            'risk_score': 100,
                            'reason': f'Admin role required for {resource}',
                            'vpn_connected': vpn_connected
                        }), 403
            except Exception as e:
                # If we can't verify admin status, deny access for security
                return jsonify({
                    'decision': 'DENY',
                    'risk_score': 100,
                    'reason': f'Unable to verify admin role for {resource}',
                    'vpn_connected': vpn_connected
                }), 403
        
        # Use dynamic thresholds if available, otherwise defaults
        if resource_policy.get('sensitivity') == 'critical':
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('critical_resource_threshold', 20)
        elif resource_policy.get('sensitivity') == 'high':
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('high_resource_threshold', 30)
        else:
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('medium_resource_threshold', 50)
        
        # Check global max risk
        global_max = DYNAMIC_RISK_THRESHOLDS.get('global_max_risk', 75)
        
        # Determine decision
        decision = 'ALLOW'
        if risk_score > required_risk_threshold:
            decision = 'DENY'
            anomaly = {
                'user': user_email,
                'resource': resource,
                'risk': risk_score,
                'risk_factors': risk_factors,
                'time': datetime.now().isoformat(),
                'location': location,
                'device': device,
                'vpn_connected': vpn_connected
            }
            anomalies.append(anomaly)
            # Save anomalies immediately
            save_logs_to_file(ANOMALIES_LOG_FILE, anomalies)
        elif resource_policy.get('require_mfa', False) and not context.get('mfa_verified', False):
            decision = 'MFA_REQUIRED'
        
        # Log access attempt with VPN status
        access_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user_email,
            'resource': resource,
            'decision': decision,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'vpn_connected': vpn_connected,
            'vpn_ip': vpn_ip,
            'real_ip': real_client_ip or location.get('ip') if isinstance(location, dict) else get_client_ip(),
            'location': location.get('country', 'Unknown') if isinstance(location, dict) else 'Unknown',
            'device': device,
            'threshold': required_risk_threshold
        }
        access_log.append(access_entry)
        
        # Keep only last 10000 entries (auto-save handles persistence)
        if len(access_log) > 10000:
            access_log[:] = access_log[-10000:]
        
        # Save to file immediately for important events
        if decision == 'DENY' or risk_score > 50:
            save_logs_to_file(ACCESS_LOG_FILE, access_log)
        
        # Return response
        if decision == 'DENY':
            return jsonify({
                'decision': 'DENY',
                'risk_score': risk_score,
                'reason': 'High risk',
                'risk_factors': risk_factors,
                'threshold': required_risk_threshold,
                'vpn_connected': vpn_connected,
                'location_used': location.get('country', 'Unknown') if isinstance(location, dict) else 'Unknown'
            }), 403
        
        if decision == 'MFA_REQUIRED':
            return jsonify({
                'decision': 'MFA_REQUIRED',
                'risk_score': risk_score,
                'reason': 'Multi-factor authentication required',
                'vpn_connected': vpn_connected
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
            'risk_factors': risk_factors,
            'vpn_connected': vpn_connected,
            'location_used': location.get('country', 'Unknown') if isinstance(location, dict) else 'Unknown'
        })
    except Exception as e:
        print(f"Error in evaluate_policy: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error during policy evaluation',
            'message': str(e)
        }), 500

@app.route('/api/policy/continuous-auth', methods=['POST'])
def continuous_auth():
    """
    Enhanced continuous authentication with context-aware verification.
    Prefers client-provided location/IP (from VPN gateway) over detecting from request,
    since during VPN connection, request IP would be VPN IP (10.8.0.x) not real client IP.
    """
    try:
        request_timestamp = datetime.now().isoformat()
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'status': 'failed', 'reason': 'No token provided'}), 401
        
        # Get device and location from request
        data = request.json or {}
        device = data.get('device', {})
        location = data.get('location', {})
        client_ip = data.get('client_ip')  # Client-provided IP (from VPN gateway)
        
        # Log the request
        print(f"[{request_timestamp}] Policy Engine: Continuous auth REQUEST")
        print(f"  - IP: {client_ip or get_client_ip()}")
        print(f"  - Location: {location.get('country', 'Unknown')}")
        
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
        
        # Log the response
        response_timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': request_timestamp,
            'response_time': response_timestamp,
            'user': decoded.get('email') if decoded else 'unknown',
            'client_ip': client_ip or get_client_ip(),
            'location': location.get('country', 'Unknown'),
            'status': result.get('status'),
            'risk_score': result.get('risk_score', 0),
            'success': result.get('status') == 'verified'
        }
        continuous_auth_requests.append(log_entry)
        
        # Keep only last 1000 entries (auto-save handles persistence)
        if len(continuous_auth_requests) > 1000:
            continuous_auth_requests[:] = continuous_auth_requests[-1000:]
        
        # Save periodically (every 10th request)
        if len(continuous_auth_requests) % 10 == 0:
            save_logs_to_file(CONTINUOUS_AUTH_LOG_FILE, continuous_auth_requests)
        
        if result['status'] == 'verified':
            user_email = decoded.get('email') or decoded.get('user')
            
            print(f"[{response_timestamp}] Policy Engine: Continuous auth VERIFIED")
            print(f"  - User: {user_email}")
            print(f"  - Risk Score: {result.get('risk_score', 0)}")
            
            # Update active session
            active_sessions[user_email] = {
                'last_verified': datetime.now().isoformat(),
                'risk_score': result.get('risk_score', 0),
                'location': location,
                'device': device
            }
            
            # Check if risk is too high (use dynamic threshold)
            max_risk = DYNAMIC_RISK_THRESHOLDS.get('continuous_auth_max_risk', 75)
            if result.get('risk_score', 0) > max_risk:
                print(f"[{response_timestamp}] Policy Engine: HIGH RISK DETECTED - {result.get('risk_score', 0)}")
                return jsonify({
                    'status': 'failed',
                    'reason': 'High risk detected',
                    'risk_score': result['risk_score'],
                    'threshold': max_risk
                }), 401
            
            return jsonify(result)
        else:
            print(f"[{response_timestamp}] Policy Engine: Continuous auth FAILED - {result.get('reason')}")
            return jsonify(result), 401
    except Exception as e:
        print(f"Error in continuous_auth: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'failed',
            'reason': 'Internal server error during continuous authentication',
            'error': str(e)
        }), 500

@app.route('/api/policy/anomaly-detect', methods=['POST'])
def anomaly_detect():
    """Detect and return anomalies for a user."""
    try:
        data = request.json or {}
        user_email = data.get('email')
        
        if not user_email:
            return jsonify({'error': 'Email required'}), 400
        
        # Get user anomalies
        user_anoms = [a for a in anomalies if a.get('user') == user_email]
        
        # Calculate anomaly score
        anomaly_count = len(user_anoms)
        recent_anoms = []
        for a in user_anoms:
            try:
                time_str = a.get('time')
                if time_str:
                    if isinstance(time_str, str):
                        time_obj = datetime.fromisoformat(time_str)
                    else:
                        time_obj = time_str
                    if (datetime.now() - time_obj).total_seconds() < 3600:
                        recent_anoms.append(a)
            except Exception as e:
                print(f"Error parsing anomaly time: {e}")
                continue
        
        return jsonify({
            'anomalies': anomaly_count,
            'recent_anomalies': len(recent_anoms),
            'details': user_anoms[-10:],  # Last 10
            'risk_level': 'high' if anomaly_count > 3 else 'medium' if anomaly_count > 1 else 'low'
        })
    except Exception as e:
        print(f"Error in anomaly_detect: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error during anomaly detection',
            'message': str(e)
        }), 500

@app.route('/api/policy/anomalies', methods=['GET'])
def get_all_anomalies():
    """Get all anomalies - requires clearance level 2+."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_clearance = decoded.get('clearance', 0)
        user_email = decoded.get('email')
        
        if user_clearance < 2:
            return jsonify({'error': 'Insufficient clearance level. Requires clearance 2+'}), 403
        
        # Filter anomalies based on clearance
        filtered_anomalies = anomalies
        if user_clearance < 4:
            # Clearance 2-3 can see their own and medium/high risk anomalies
            filtered_anomalies = [a for a in anomalies if a.get('user') == user_email or a.get('risk', 0) >= 50]
        elif user_clearance < 5:
            # Clearance 4 can see all but not critical details
            filtered_anomalies = anomalies
        
        # Sort by time (most recent first)
        filtered_anomalies.sort(key=lambda x: x.get('time', ''), reverse=True)
        
        limit = int(request.args.get('limit', 50))
        
        return jsonify({
            'anomalies': filtered_anomalies[:limit],
            'total': len(anomalies),
            'filtered': len(filtered_anomalies),
            'user_clearance': user_clearance
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policy/session-status', methods=['POST'])
def session_status():
    """Get continuous authentication status for a session."""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        result, decoded = verify_token_and_context(token)
        if result['status'] != 'verified':
            return jsonify(result), 401
        
        user_email = decoded.get('email') or decoded.get('user')
        session = active_sessions.get(user_email, {})
        
        if session:
            try:
                last_verified_str = session.get('last_verified', datetime.now().isoformat())
                if isinstance(last_verified_str, str):
                    last_verified = datetime.fromisoformat(last_verified_str)
                else:
                    last_verified = last_verified_str
                minutes_since_verify = (datetime.now() - last_verified).total_seconds() / 60
            except Exception as e:
                print(f"Error parsing last_verified: {e}")
                minutes_since_verify = 0
            
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
    except Exception as e:
        print(f"Error in session_status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error during session status check',
            'message': str(e)
        }), 500

@app.route('/api/policy/location-detect', methods=['GET', 'POST'])
def location_detect():
    """Detect location from client IP."""
    try:
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
    except Exception as e:
        print(f"Error in location_detect: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error during location detection',
            'message': str(e),
            'ip': ip if 'ip' in locals() else None
        }), 500

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

@app.route('/api/policy/test-risk', methods=['POST'])
def test_risk_scenario():
    """
    Test endpoint to simulate different risk scenarios for frontend visualization.
    Allows setting specific risk scores and factors for testing.
    """
    try:
        data = request.json or {}
        
        # Allow overriding risk score for testing
        test_risk_score = data.get('test_risk_score')
        test_risk_factors = data.get('test_risk_factors', [])
        test_decision = data.get('test_decision')  # 'ALLOW', 'DENY', 'MFA_REQUIRED'
        
        user_email = data.get('user', {}).get('email', 'test@company.com')
        resource = data.get('resource', 'database-prod')
        device = data.get('device', {})
        location = data.get('location', {})
        context = data.get('context', {})
        
        # If test mode, use provided values
        if test_risk_score is not None:
            risk_score = test_risk_score
            risk_factors = test_risk_factors if test_risk_factors else [f'Test mode: Risk score {risk_score}']
        else:
            # Normal calculation
            risk_score, risk_factors = calculate_risk_score(user_email, resource, device, location, context)
        
        # Get resource policy
        resource_policy = RESOURCE_POLICIES.get(resource, {})
        
        # Use dynamic thresholds
        if resource_policy.get('sensitivity') == 'critical':
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('critical_resource_threshold', 20)
        elif resource_policy.get('sensitivity') == 'high':
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('high_resource_threshold', 30)
        else:
            required_risk_threshold = DYNAMIC_RISK_THRESHOLDS.get('medium_resource_threshold', 50)
        
        # Override decision if test mode
        if test_decision:
            decision = test_decision
        elif risk_score > required_risk_threshold:
            decision = 'DENY'
        elif resource_policy.get('require_mfa', False) and not context.get('mfa_verified', False):
            decision = 'MFA_REQUIRED'
        else:
            decision = 'ALLOW'
        
        response_data = {
            'decision': decision,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'threshold': required_risk_threshold,
            'test_mode': test_risk_score is not None,
            'context': {
                'device': device,
                'location': location,
                'session_timeout_minutes': resource_policy.get('session_timeout_minutes', 30)
            }
        }
        
        # Return appropriate status code
        if decision == 'DENY':
            return jsonify(response_data), 403
        elif decision == 'MFA_REQUIRED':
            return jsonify(response_data), 401
        else:
            return jsonify(response_data)
    except Exception as e:
        print(f"Error in test_risk_scenario: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error during risk scenario test',
            'message': str(e)
        }), 500

@app.route('/api/policy/test-scenarios', methods=['GET'])
def get_test_scenarios():
    """
    Get predefined test scenarios for frontend visualization.
    """
    scenarios = {
        'low_risk': {
            'name': 'Low Risk (Normal Access)',
            'description': 'Standard access from trusted location with compliant device',
            'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': False},
            'location': {'country': 'US', 'city': 'New York'},
            'context': {'mfa_verified': True},
            'expected_risk': 15,
            'expected_decision': 'ALLOW'
        },
        'medium_risk_location': {
            'name': 'Medium Risk (Unusual Location)',
            'description': 'Access from non-geofenced country',
            'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': False},
            'location': {'country': 'CN', 'city': 'Beijing'},
            'context': {'mfa_verified': False},
            'expected_risk': 30,
            'expected_decision': 'ALLOW'
        },
        'high_risk_rooted': {
            'name': 'High Risk (Rooted Device)',
            'description': 'Rooted device from unusual location',
            'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': True},
            'location': {'country': 'CN', 'city': 'Beijing'},
            'context': {'mfa_verified': False},
            'expected_risk': 55,
            'expected_decision': 'DENY'
        },
        'critical_risk_multiple': {
            'name': 'Critical Risk (Multiple Factors)',
            'description': 'Old OS, not encrypted, rooted, unusual location',
            'device': {'os_type': 'macOS', 'os_version': '8.0', 'encrypted': False, 'rooted': True},
            'location': {'country': 'RU', 'city': 'Moscow'},
            'context': {'mfa_verified': False},
            'expected_risk': 75,
            'expected_decision': 'DENY'
        },
        'mfa_required': {
            'name': 'MFA Required',
            'description': 'Access to critical resource without MFA',
            'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': False},
            'location': {'country': 'US', 'city': 'New York'},
            'context': {'mfa_verified': False},
            'resource': 'admin-panel',
            'expected_risk': 20,
            'expected_decision': 'MFA_REQUIRED'
        }
    }
    
    return jsonify({
        'scenarios': scenarios,
        'usage': 'POST to /api/policy/test-risk with scenario data to test'
    })

@app.route('/api/policy/continuous-auth-history', methods=['GET'])
def get_continuous_auth_history():
    """Get continuous authentication request history."""
    user_email = request.args.get('user_email')
    limit = int(request.args.get('limit', 100))
    
    if user_email:
        filtered = [entry for entry in continuous_auth_requests if entry.get('user') == user_email]
    else:
        filtered = continuous_auth_requests
    
    return jsonify({
        'total_requests': len(continuous_auth_requests),
        'filtered_requests': len(filtered),
        'history': filtered[-limit:]
    })

@app.route('/api/policy/risk-thresholds', methods=['GET'])
def get_risk_thresholds():
    """Get current risk threshold configuration."""
    return jsonify({
        'thresholds': DYNAMIC_RISK_THRESHOLDS,
        'resource_defaults': {
            'critical': DYNAMIC_RISK_THRESHOLDS.get('critical_resource_threshold', 20),
            'high': DYNAMIC_RISK_THRESHOLDS.get('high_resource_threshold', 30),
            'medium': DYNAMIC_RISK_THRESHOLDS.get('medium_resource_threshold', 50)
        },
        'global_max': DYNAMIC_RISK_THRESHOLDS.get('global_max_risk', 75),
        'continuous_auth_max': DYNAMIC_RISK_THRESHOLDS.get('continuous_auth_max_risk', 75)
    })

@app.route('/api/policy/risk-thresholds', methods=['POST'])
def set_risk_thresholds():
    """Update risk threshold configuration."""
    data = request.json or {}
    
    # Validate and update thresholds
    if 'global_max_risk' in data:
        value = int(data['global_max_risk'])
        if 0 <= value <= 100:
            DYNAMIC_RISK_THRESHOLDS['global_max_risk'] = value
        else:
            return jsonify({'error': 'global_max_risk must be between 0 and 100'}), 400
    
    if 'critical_resource_threshold' in data:
        value = int(data['critical_resource_threshold'])
        if 0 <= value <= 100:
            DYNAMIC_RISK_THRESHOLDS['critical_resource_threshold'] = value
        else:
            return jsonify({'error': 'critical_resource_threshold must be between 0 and 100'}), 400
    
    if 'high_resource_threshold' in data:
        value = int(data['high_resource_threshold'])
        if 0 <= value <= 100:
            DYNAMIC_RISK_THRESHOLDS['high_resource_threshold'] = value
        else:
            return jsonify({'error': 'high_resource_threshold must be between 0 and 100'}), 400
    
    if 'medium_resource_threshold' in data:
        value = int(data['medium_resource_threshold'])
        if 0 <= value <= 100:
            DYNAMIC_RISK_THRESHOLDS['medium_resource_threshold'] = value
        else:
            return jsonify({'error': 'medium_resource_threshold must be between 0 and 100'}), 400
    
    if 'continuous_auth_max_risk' in data:
        value = int(data['continuous_auth_max_risk'])
        if 0 <= value <= 100:
            DYNAMIC_RISK_THRESHOLDS['continuous_auth_max_risk'] = value
        else:
            return jsonify({'error': 'continuous_auth_max_risk must be between 0 and 100'}), 400
    
    return jsonify({
        'message': 'Risk thresholds updated successfully',
        'thresholds': DYNAMIC_RISK_THRESHOLDS
    })

@app.route('/api/policy/risk-thresholds/reset', methods=['POST'])
def reset_risk_thresholds():
    """Reset risk thresholds to default values."""
    DYNAMIC_RISK_THRESHOLDS.update({
        'global_max_risk': 75,
        'critical_resource_threshold': 20,
        'high_resource_threshold': 30,
        'medium_resource_threshold': 50,
        'continuous_auth_max_risk': 75
    })
    return jsonify({
        'message': 'Risk thresholds reset to defaults',
        'thresholds': DYNAMIC_RISK_THRESHOLDS
    })

def check_admin_access(token):
    """Check if user has admin access."""
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_email = decoded.get('email') or decoded.get('user')
        role = decoded.get('role', '')
        clearance = decoded.get('clearance', 0)
        
        # Check if user is in admin list, has admin role, or clearance 5
        if user_email in ADMIN_USERS or role == 'Admin' or clearance >= 5:
            return True, user_email
        return False, user_email
    except:
        return False, None

@app.route('/api/policy/access-metrics', methods=['GET'])
def get_access_metrics():
    """Get access metrics comparing VPN vs non-VPN access."""
    resource = request.args.get('resource')  # Optional: filter by resource
    user_email = request.args.get('user_email')  # Optional: filter by user
    
    # Filter access log
    filtered_log = access_log
    if resource:
        filtered_log = [entry for entry in filtered_log if entry.get('resource') == resource]
    if user_email:
        filtered_log = [entry for entry in filtered_log if entry.get('user') == user_email]
    
    # Calculate metrics
    total_attempts = len(filtered_log)
    vpn_attempts = [e for e in filtered_log if e.get('vpn_connected', False)]
    non_vpn_attempts = [e for e in filtered_log if not e.get('vpn_connected', False)]
    
    def calculate_stats(attempts):
        if not attempts:
            return {
                'count': 0,
                'allowed': 0,
                'denied': 0,
                'mfa_required': 0,
                'avg_risk_score': 0,
                'min_risk_score': 0,
                'max_risk_score': 0,
                'allow_rate': 0
            }
        
        allowed = len([e for e in attempts if e.get('decision') == 'ALLOW'])
        denied = len([e for e in attempts if e.get('decision') == 'DENY'])
        mfa_required = len([e for e in attempts if e.get('decision') == 'MFA_REQUIRED'])
        risk_scores = [e.get('risk_score', 0) for e in attempts]
        
        return {
            'count': len(attempts),
            'allowed': allowed,
            'denied': denied,
            'mfa_required': mfa_required,
            'avg_risk_score': round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
            'min_risk_score': min(risk_scores) if risk_scores else 0,
            'max_risk_score': max(risk_scores) if risk_scores else 0,
            'allow_rate': round((allowed / len(attempts)) * 100, 2) if attempts else 0
        }
    
    vpn_stats = calculate_stats(vpn_attempts)
    non_vpn_stats = calculate_stats(non_vpn_attempts)
    
    # Per-resource breakdown
    resources = {}
    for entry in filtered_log:
        res = entry.get('resource', 'unknown')
        if res not in resources:
            resources[res] = {'vpn': [], 'non_vpn': []}
        
        if entry.get('vpn_connected', False):
            resources[res]['vpn'].append(entry)
        else:
            resources[res]['non_vpn'].append(entry)
    
    resource_breakdown = {}
    for res, data in resources.items():
        resource_breakdown[res] = {
            'vpn': calculate_stats(data['vpn']),
            'non_vpn': calculate_stats(data['non_vpn'])
        }
    
    return jsonify({
        'total_attempts': total_attempts,
        'filter': {
            'resource': resource or 'all',
            'user': user_email or 'all'
        },
        'overall': {
            'vpn': vpn_stats,
            'non_vpn': non_vpn_stats
        },
        'by_resource': resource_breakdown,
        'recent_attempts': filtered_log[-50:]  # Last 50 attempts
    })

@app.route('/api/policy/resources', methods=['GET'])
def get_resources():
    """Get list of all resources and their policies."""
    resources = []
    for resource_name, policy in RESOURCE_POLICIES.items():
        resources.append({
            'name': resource_name,
            'sensitivity': policy.get('sensitivity', 'medium'),
            'require_mfa': policy.get('require_mfa', False),
            'require_low_risk': policy.get('require_low_risk', True),
            'session_timeout_minutes': policy.get('session_timeout_minutes', 30),
            'audit_all_access': policy.get('audit_all_access', False),
            'time_restricted': policy.get('time_restricted', False)
        })
    
    return jsonify({
        'resources': resources,
        'count': len(resources)
    })

@app.route('/api/policy/threat-users', methods=['GET'])
def get_threat_users():
    """Get threat users list - requires clearance level 3+."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_clearance = decoded.get('clearance', 0)
        
        if user_clearance < 3:
            return jsonify({'error': 'Insufficient clearance level. Requires clearance 3+'}), 403
        
        # Filter by threat level based on clearance
        filtered_threats = threat_users
        if user_clearance < 4:
            # Clearance 3 can only see medium/high threats
            filtered_threats = [t for t in threat_users if t.get('threat_level') != 'critical']
        elif user_clearance < 5:
            # Clearance 4 can see all threats but with limited details for critical threats
            filtered_threats = []
            for t in threat_users:
                if t.get('threat_level') == 'critical':
                    # Remove sensitive details for critical threats
                    limited_threat = {k: v for k, v in t.items() if k not in ['activities', 'devices', 'locations']}
                    filtered_threats.append(limited_threat)
                else:
                    filtered_threats.append(t)
        
        return jsonify({
            'threat_users': filtered_threats,
            'total': len(filtered_threats),
            'user_clearance': user_clearance
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/policy/threat-users/<user_email>', methods=['POST'])
def update_threat_user(user_email):
    """Update threat user data - requires clearance level 4+."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_clearance = decoded.get('clearance', 0)
        
        if user_clearance < 4:
            return jsonify({'error': 'Insufficient clearance level. Requires clearance 4+'}), 403
        
        data = request.json or {}
        
        # Find existing threat user or create new
        threat_user = None
        for i, tu in enumerate(threat_users):
            if tu.get('user_email') == user_email:
                threat_user = tu
                # Update existing
                threat_users[i].update(data)
                threat_users[i]['last_updated'] = datetime.now().isoformat()
                threat_user = threat_users[i]
                break
        
        if not threat_user:
            # Create new threat user
            new_threat = {
                'user_email': user_email,
                'threat_level': data.get('threat_level', 'medium'),
                'risk_score': data.get('risk_score', 50),
                'threat_type': data.get('threat_type', 'Unknown'),
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'attempts': data.get('attempts', 0),
                'blocked_attempts': data.get('blocked_attempts', 0),
                'locations': data.get('locations', []),
                'devices': data.get('devices', []),
                'activities': data.get('activities', []),
                'last_updated': datetime.now().isoformat()
            }
            threat_users.append(new_threat)
            threat_user = new_threat
        
        # Save to file
        save_logs_to_file(THREAT_USERS_FILE, threat_users)
        
        return jsonify({
            'success': True,
            'threat_user': threat_user,
            'updated_by': decoded.get('email')
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ======================================================
# ADMIN ENDPOINTS - Require admin access
# ======================================================

@app.route('/api/policy/admin/risk-factors', methods=['GET'])
def get_risk_factors():
    """Get current risk factors (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    return jsonify({
        'risk_factors': RISK_FACTORS,
        'modified_by': user,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/risk-factors', methods=['POST'])
def update_risk_factors():
    """Update or add risk factors (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    
    # Update or add risk factors
    updated = []
    added = []
    for factor, value in data.items():
        if isinstance(value, (int, float)) and 0 <= value <= 100:
            if factor in RISK_FACTORS:
                RISK_FACTORS[factor] = int(value)
                updated.append(factor)
            else:
                # Add new risk factor
                RISK_FACTORS[factor] = int(value)
                added.append(factor)
        else:
            return jsonify({'error': f'Invalid value for {factor}: must be 0-100'}), 400
    
    message = []
    if updated:
        message.append(f'Updated {len(updated)} risk factors')
    if added:
        message.append(f'Added {len(added)} new risk factors')
    
    return jsonify({
        'message': f'{"; ".join(message)} by {user}',
        'updated': updated,
        'added': added,
        'risk_factors': RISK_FACTORS,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/resource-policies', methods=['GET'])
def get_resource_policies_admin():
    """Get all resource policies (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    return jsonify({
        'resource_policies': RESOURCE_POLICIES,
        'modified_by': user,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/resource-policies', methods=['POST'])
def update_resource_policies():
    """Update resource policies (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    resource_name = data.get('resource')
    
    if not resource_name or resource_name not in RESOURCE_POLICIES:
        return jsonify({'error': f'Resource {resource_name} not found'}), 404
    
    # Update policy
    updates = data.get('updates', {})
    updated_fields = []
    
    for field, value in updates.items():
        if field in RESOURCE_POLICIES[resource_name]:
            RESOURCE_POLICIES[resource_name][field] = value
            updated_fields.append(field)
    
    return jsonify({
        'message': f'Resource policy updated by {user}',
        'resource': resource_name,
        'updated_fields': updated_fields,
        'policy': RESOURCE_POLICIES[resource_name],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/network-policies', methods=['GET'])
def get_network_policies_admin():
    """Get network policies (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    return jsonify({
        'network_policies': NETWORK_POLICIES,
        'modified_by': user,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/network-policies', methods=['POST'])
def update_network_policies():
    """Update network policies (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    updates = data.get('updates', {})
    updated_fields = []
    
    for field, value in updates.items():
        if field in NETWORK_POLICIES:
            NETWORK_POLICIES[field] = value
            updated_fields.append(field)
    
    return jsonify({
        'message': f'Network policies updated by {user}',
        'updated_fields': updated_fields,
        'network_policies': NETWORK_POLICIES,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/add-resource', methods=['POST'])
def add_resource():
    """Add a new resource (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    resource_name = data.get('name')
    policy = data.get('policy', {})
    
    if not resource_name:
        return jsonify({'error': 'Resource name required'}), 400
    
    if resource_name in RESOURCE_POLICIES:
        return jsonify({'error': f'Resource {resource_name} already exists'}), 409
    
    # Set defaults
    default_policy = {
        'sensitivity': 'medium',
        'require_mfa': False,
        'require_low_risk': True,
        'session_timeout_minutes': 30,
        'audit_all_access': False,
        'time_restricted': False
    }
    default_policy.update(policy)
    
    RESOURCE_POLICIES[resource_name] = default_policy
    
    return jsonify({
        'message': f'Resource added by {user}',
        'resource': resource_name,
        'policy': RESOURCE_POLICIES[resource_name],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/remove-resource', methods=['POST'])
def remove_resource():
    """Remove a resource (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    resource_name = data.get('name')
    
    if not resource_name:
        return jsonify({'error': 'Resource name required'}), 400
    
    if resource_name not in RESOURCE_POLICIES:
        return jsonify({'error': f'Resource {resource_name} not found'}), 404
    
    # Don't allow removing critical resources
    if RESOURCE_POLICIES[resource_name].get('sensitivity') == 'critical':
        return jsonify({'error': 'Cannot remove critical resources'}), 403
    
    del RESOURCE_POLICIES[resource_name]
    
    return jsonify({
        'message': f'Resource removed by {user}',
        'resource': resource_name,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/policy/admin/add-custom-metric', methods=['POST'])
def add_custom_metric():
    """Add a custom risk evaluation metric/rule (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json or {}
    metric_name = data.get('name')
    metric_type = data.get('type', 'risk_factor')  # 'risk_factor', 'resource_rule', 'network_rule', 'device_rule'
    metric_config = data.get('config', {})
    
    if not metric_name:
        return jsonify({'error': 'Metric name required'}), 400
    
    # Add to appropriate category
    if metric_type == 'risk_factor':
        if 'risk_value' not in metric_config:
            return jsonify({'error': 'risk_value required for risk_factor type'}), 400
        RISK_FACTORS[metric_name] = int(metric_config.get('risk_value', 0))
        return jsonify({
            'message': f'Custom risk factor added by {user}',
            'metric_name': metric_name,
            'type': metric_type,
            'risk_factors': RISK_FACTORS,
            'timestamp': datetime.now().isoformat()
        })
    elif metric_type == 'resource_rule':
        resource = metric_config.get('resource')
        if not resource:
            return jsonify({'error': 'resource required for resource_rule type'}), 400
        if resource not in RESOURCE_POLICIES:
            return jsonify({'error': f'Resource {resource} not found'}), 404
        # Add custom rule to resource
        if 'custom_rules' not in RESOURCE_POLICIES[resource]:
            RESOURCE_POLICIES[resource]['custom_rules'] = {}
        RESOURCE_POLICIES[resource]['custom_rules'][metric_name] = metric_config.get('rule_config', {})
        return jsonify({
            'message': f'Custom resource rule added by {user}',
            'metric_name': metric_name,
            'resource': resource,
            'policy': RESOURCE_POLICIES[resource],
            'timestamp': datetime.now().isoformat()
        })
    elif metric_type == 'network_rule':
        rule_config = metric_config.get('rule_config', {})
        if 'custom_network_rules' not in NETWORK_POLICIES:
            NETWORK_POLICIES['custom_network_rules'] = {}
        NETWORK_POLICIES['custom_network_rules'][metric_name] = rule_config
        return jsonify({
            'message': f'Custom network rule added by {user}',
            'metric_name': metric_name,
            'network_policies': NETWORK_POLICIES,
            'timestamp': datetime.now().isoformat()
        })
    elif metric_type == 'device_rule':
        rule_config = metric_config.get('rule_config', {})
        if 'custom_device_rules' not in DEVICE_POLICIES:
            DEVICE_POLICIES['custom_device_rules'] = {}
        DEVICE_POLICIES['custom_device_rules'][metric_name] = rule_config
        return jsonify({
            'message': f'Custom device rule added by {user}',
            'metric_name': metric_name,
            'device_policies': DEVICE_POLICIES,
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({'error': f'Invalid metric type: {metric_type}'}), 400

@app.route('/api/policy/admin/custom-metrics', methods=['GET'])
def get_custom_metrics():
    """Get all custom metrics/rules (admin only)."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    is_admin, user = check_admin_access(token)
    if not is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    custom_metrics = {
        'risk_factors': RISK_FACTORS,
        'resource_custom_rules': {},
        'network_custom_rules': NETWORK_POLICIES.get('custom_network_rules', {}),
        'device_custom_rules': DEVICE_POLICIES.get('custom_device_rules', {})
    }
    
    # Extract custom rules from resources
    for resource, policy in RESOURCE_POLICIES.items():
        if 'custom_rules' in policy:
            custom_metrics['resource_custom_rules'][resource] = policy['custom_rules']
    
    return jsonify({
        'custom_metrics': custom_metrics,
        'modified_by': user,
        'timestamp': datetime.now().isoformat()
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
    # Start background thread for auto-saving logs
    save_thread = threading.Thread(target=auto_save_logs, daemon=True)
    save_thread.start()
    print(f"[Policy Engine] Log persistence enabled. Logs saved to: {LOG_DIR}")
    print(f"[Policy Engine] Loaded {len(access_log)} access logs, {len(anomalies)} anomalies, {len(continuous_auth_requests)} continuous auth requests")
    app.run(host='0.0.0.0', port=5002, debug=True)
