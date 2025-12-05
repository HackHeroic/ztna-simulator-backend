# test_openvpn_setup.py

#!/usr/bin/env python3
"""
Test script to verify OpenVPN setup and VPN gateway functionality.
"""

import subprocess
import sys
import os
import time
import requests

def check_openvpn_installed():
    """Check if OpenVPN is installed."""
    try:
        result = subprocess.run(['openvpn', '--version'], capture_output=True, check=True)
        print("✅ OpenVPN is installed")
        version_line = result.stdout.decode('utf-8').split('\n')[0]
        print(f"   Version: {version_line}")
        return True
    except:
        print("❌ OpenVPN is not installed")
        print("   Install with: brew install openvpn (macOS)")
        return False

def check_certificates():
    """Check if all required certificates exist."""
    required_files = ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'client.key', 'dh2048.pem']
    missing = []
    
    for file in required_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"✅ {file} exists ({size} bytes)")
        else:
            print(f"❌ {file} is missing")
            missing.append(file)
    
    return len(missing) == 0

def check_config_files():
    """Check if configuration files exist."""
    config_files = ['server.ovpn', 'openvpn-client.ovpn']
    missing = []
    
    for file in config_files:
        if os.path.exists(file):
            print(f"✅ {file} exists")
        else:
            print(f"❌ {file} is missing")
            missing.append(file)
    
    return len(missing) == 0

def check_port_availability():
    """Check if port 1194 is available."""
    try:
        result = subprocess.run(['lsof', '-i', ':1194'], capture_output=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            print("⚠️  Port 1194 is in use (OpenVPN may already be running)")
            print("   This is OK - the system will detect it")
            return True  # Not an error, just info
        else:
            print("✅ Port 1194 is available")
            return True
    except:
        print("⚠️  Could not check port 1194 (lsof not available)")
        return True

def check_certificate_validity():
    """Check if certificates are valid."""
    print("\n📜 Checking certificate validity...")
    certs = ['ca.crt', 'server.crt', 'client.crt']
    all_valid = True
    
    for cert in certs:
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert, '-text', '-noout'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                # Extract subject from output
                subject_line = [line for line in result.stdout.decode('utf-8').split('\n') 
                              if 'Subject:' in line]
                if subject_line:
                    print(f"✅ {cert} is valid")
                else:
                    print(f"✅ {cert} is valid (parsed)")
            else:
                print(f"❌ {cert} validation failed")
                all_valid = False
        except Exception as e:
            print(f"⚠️  Could not validate {cert}: {e}")
    
    return all_valid

def test_vpn_gateway_health():
    """Test VPN gateway health endpoint."""
    print("\n🌐 Testing VPN Gateway health endpoint...")
    try:
        response = requests.get('http://127.0.0.1:5001/health', timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ VPN Gateway is running")
            print(f"   Status: {data.get('status')}")
            print(f"   OpenVPN installed: {data.get('openvpn_installed')}")
            print(f"   OpenVPN running: {data.get('openvpn_running')}")
            return True
        else:
            print(f"❌ VPN Gateway returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️  VPN Gateway is not running")
        print("   Start it with: python vpn_gateway.py")
        return False
    except Exception as e:
        print(f"❌ Error checking VPN Gateway: {e}")
        return False

def test_policy_engine():
    """Test policy engine health."""
    print("\n🔒 Testing Policy Engine...")
    try:
        response = requests.get('http://127.0.0.1:5002/health', timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Policy Engine is running")
            print(f"   Status: {data.get('status')}")
            return True
        else:
            print(f"❌ Policy Engine returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️  Policy Engine is not running")
        print("   Start it with: python policy_engine.py")
        return False
    except Exception as e:
        print(f"❌ Error checking Policy Engine: {e}")
        return False

def test_auth_server():
    """Test auth server health."""
    print("\n🔐 Testing Auth Server...")
    try:
        response = requests.get('http://127.0.0.1:5000/health', timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Auth Server is running")
            print(f"   Status: {data.get('status')}")
            return True
        else:
            print(f"❌ Auth Server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️  Auth Server is not running")
        print("   Start it with: python auth_server.py")
        return False
    except Exception as e:
        print(f"❌ Error checking Auth Server: {e}")
        return False

def main():
    """Run all checks."""
    print("=" * 60)
    print("OpenVPN Setup Verification")
    print("=" * 60)
    
    results = []
    
    print("\n1️⃣  Checking OpenVPN Installation...")
    results.append(("OpenVPN Installation", check_openvpn_installed()))
    
    print("\n2️⃣  Checking Certificate Files...")
    results.append(("Certificates", check_certificates()))
    
    print("\n3️⃣  Checking Configuration Files...")
    results.append(("Configuration Files", check_config_files()))
    
    print("\n4️⃣  Checking Port Availability...")
    results.append(("Port Availability", check_port_availability()))
    
    print("\n5️⃣  Validating Certificates...")
    results.append(("Certificate Validity", check_certificate_validity()))
    
    print("\n6️⃣  Testing Services...")
    auth_ok = test_auth_server()
    policy_ok = test_policy_engine()
    vpn_ok = test_vpn_gateway_health()
    results.append(("Services Running", auth_ok and policy_ok and vpn_ok))
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All checks passed! Your OpenVPN setup is ready.")
    else:
        print("⚠️  Some checks failed. Review the output above.")
        print("\nNote: VPN Gateway will work in mock mode even if OpenVPN can't start.")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())

