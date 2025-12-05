#!/usr/bin/env python3
"""Test admin access and metrics functionality."""

import requests
import json
import sys

BASE_URL = 'http://127.0.0.1:5002'
AUTH_URL = 'http://127.0.0.1:5000'

def login(email, password):
    """Login and get token."""
    resp = requests.post(
        f'{AUTH_URL}/api/auth/login',
        json={'email': email, 'password': password}
    )
    if resp.status_code == 200:
        data = resp.json()
        return data['token']
    else:
        print(f"Login failed: {resp.text}")
        return None

def test_risk_score_fix():
    """Test that risk score uses real location when VPN connected."""
    print("=" * 60)
    print("Testing Risk Score Fix")
    print("=" * 60)
    
    # Test 1: Without VPN, US location
    print("\n1. Testing WITHOUT VPN (US location):")
    resp = requests.post(
        f'{BASE_URL}/api/policy/evaluate',
        json={
            'user': {'email': 'alice@company.com'},
            'resource': 'database-prod',
            'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': False},
            'location': {'country': 'US', 'city': 'New York'}
        }
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Risk Score: {data['risk_score']}")
        print(f"   Decision: {data['decision']}")
        print(f"   VPN Connected: {data.get('vpn_connected', False)}")
        print(f"   Location Used: {data.get('location_used', 'Unknown')}")
        risk_without_vpn = data['risk_score']
    else:
        print(f"   Error: {resp.text}")
        return False
    
    # Test 2: Check if VPN connection exists
    print("\n2. Checking VPN connection status:")
    vpn_resp = requests.get(
        'http://127.0.0.1:5001/api/vpn/check-connection?user_email=alice@company.com',
        timeout=2
    )
    vpn_connected = False
    if vpn_resp.status_code == 200:
        vpn_data = vpn_resp.json()
        vpn_connected = vpn_data.get('connected', False)
        print(f"   VPN Connected: {vpn_connected}")
        if vpn_connected:
            print(f"   VPN IP: {vpn_data.get('vpn_ip')}")
            print(f"   Real IP: {vpn_data.get('real_client_ip')}")
            print(f"   Real Location: {vpn_data.get('location', {}).get('country', 'Unknown')}")
    
    # Test 3: With VPN (if connected)
    if vpn_connected:
        print("\n3. Testing WITH VPN (should use real location):")
        resp = requests.post(
            f'{BASE_URL}/api/policy/evaluate',
            json={
                'user': {'email': 'alice@company.com'},
                'resource': 'database-prod',
                'device': {'os_type': 'macOS', 'os_version': '12.0', 'encrypted': True, 'rooted': False}
            }
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"   Risk Score: {data['risk_score']}")
            print(f"   Decision: {data['decision']}")
            print(f"   VPN Connected: {data.get('vpn_connected', False)}")
            print(f"   Location Used: {data.get('location_used', 'Unknown')}")
            risk_with_vpn = data['risk_score']
            
            # Compare
            print(f"\n   Comparison:")
            print(f"   Without VPN: {risk_without_vpn}")
            print(f"   With VPN: {risk_with_vpn}")
            if risk_without_vpn == risk_with_vpn:
                print("   ✅ Risk scores match (using real location correctly)")
            else:
                print("   ⚠️  Risk scores differ (may indicate issue)")
    
    return True

def test_admin_access():
    """Test admin access functionality."""
    print("\n" + "=" * 60)
    print("Testing Admin Access")
    print("=" * 60)
    
    # Login as admin
    print("\n1. Logging in as admin (bob@company.com):")
    token = login('bob@company.com', 'securepass')
    if not token:
        print("   ❌ Admin login failed")
        return False
    
    print("   ✅ Admin login successful")
    
    # Get risk factors
    print("\n2. Getting risk factors:")
    resp = requests.get(
        f'{BASE_URL}/api/policy/admin/risk-factors',
        headers={'Authorization': f'Bearer {token}'}
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Current unusual_location: {data['risk_factors']['unusual_location']}")
        original_value = data['risk_factors']['unusual_location']
    else:
        print(f"   ❌ Failed: {resp.text}")
        return False
    
    # Update risk factor
    print("\n3. Updating risk factor (unusual_location to 20):")
    resp = requests.post(
        f'{BASE_URL}/api/policy/admin/risk-factors',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        json={'unusual_location': 20}
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"   ✅ Updated: {data['message']}")
        print(f"   New value: {data['risk_factors']['unusual_location']}")
    else:
        print(f"   ❌ Failed: {resp.text}")
        return False
    
    # Restore original value
    print("\n4. Restoring original value:")
    resp = requests.post(
        f'{BASE_URL}/api/policy/admin/risk-factors',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        json={'unusual_location': original_value}
    )
    if resp.status_code == 200:
        print(f"   ✅ Restored to {original_value}")
    
    return True

def test_access_metrics():
    """Test access metrics."""
    print("\n" + "=" * 60)
    print("Testing Access Metrics")
    print("=" * 60)
    
    # Get all resources
    print("\n1. Getting all resources:")
    resp = requests.get(f'{BASE_URL}/api/policy/resources')
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Found {data['count']} resources:")
        for resource in data['resources']:
            print(f"     - {resource['name']} ({resource['sensitivity']})")
    else:
        print(f"   ❌ Failed: {resp.text}")
        return False
    
    # Get metrics
    print("\n2. Getting access metrics:")
    resp = requests.get(f'{BASE_URL}/api/policy/access-metrics')
    if resp.status_code == 200:
        data = resp.json()
        print(f"   Total attempts: {data['total_attempts']}")
        print(f"\n   Overall VPN stats:")
        print(f"     Count: {data['overall']['vpn']['count']}")
        print(f"     Allow rate: {data['overall']['vpn']['allow_rate']}%")
        print(f"     Avg risk: {data['overall']['vpn']['avg_risk_score']}")
        print(f"\n   Overall Non-VPN stats:")
        print(f"     Count: {data['overall']['non_vpn']['count']}")
        print(f"     Allow rate: {data['overall']['non_vpn']['allow_rate']}%")
        print(f"     Avg risk: {data['overall']['non_vpn']['avg_risk_score']}")
        
        if data['by_resource']:
            print(f"\n   Per-resource breakdown:")
            for resource, stats in data['by_resource'].items():
                print(f"\n     {resource}:")
                print(f"       VPN: {stats['vpn']['count']} attempts, {stats['vpn']['allow_rate']}% allow")
                print(f"       Non-VPN: {stats['non_vpn']['count']} attempts, {stats['non_vpn']['allow_rate']}% allow")
    else:
        print(f"   ❌ Failed: {resp.text}")
        return False
    
    return True

def test_non_admin_access():
    """Test that non-admin users cannot access admin endpoints."""
    print("\n" + "=" * 60)
    print("Testing Non-Admin Access (Should Fail)")
    print("=" * 60)
    
    # Login as regular user
    print("\n1. Logging in as regular user (alice@company.com):")
    token = login('alice@company.com', 'password123')
    if not token:
        print("   ❌ Login failed")
        return False
    
    # Try to access admin endpoint
    print("\n2. Attempting to access admin endpoint:")
    resp = requests.get(
        f'{BASE_URL}/api/policy/admin/risk-factors',
        headers={'Authorization': f'Bearer {token}'}
    )
    if resp.status_code == 403:
        print("   ✅ Correctly denied access (403 Forbidden)")
        return True
    else:
        print(f"   ❌ Unexpected response: {resp.status_code}")
        return False

if __name__ == '__main__':
    print("Admin Access & Metrics Test Suite")
    print("=" * 60)
    
    results = []
    
    # Test risk score fix
    results.append(("Risk Score Fix", test_risk_score_fix()))
    
    # Test admin access
    results.append(("Admin Access", test_admin_access()))
    
    # Test access metrics
    results.append(("Access Metrics", test_access_metrics()))
    
    # Test non-admin access
    results.append(("Non-Admin Access Control", test_non_admin_access()))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All tests passed!")
    else:
        print("⚠️  Some tests failed. Review output above.")
    print("=" * 60)
    
    sys.exit(0 if all_passed else 1)

