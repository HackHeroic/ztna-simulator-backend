#!/usr/bin/env python3
"""Test OpenVPN connection and verify setup."""

import requests
import subprocess
import sys
import time

BASE_URL = 'http://127.0.0.1:5001'

def test_openvpn_verification():
    """Test the verification endpoint."""
    print("=" * 60)
    print("OpenVPN Connection Verification")
    print("=" * 60)
    
    try:
        resp = requests.get(f'{BASE_URL}/api/vpn/verify-openvpn', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            
            print("\n📋 OpenVPN Status:")
            print(f"  Installed: {'✅' if data['installed'] else '❌'}")
            print(f"  Running: {'✅' if data['running'] else '❌'}")
            print(f"  Port 1194 Open: {'✅' if data['port_1194_open'] else '❌'}")
            print(f"  Process Running: {'✅' if data['process_running'] else '❌'}")
            print(f"  Certificates Exist: {'✅' if data['certificates_exist'] else '❌'}")
            print(f"  Status Log Exists: {'✅' if data['status_log_exists'] else '❌'}")
            print(f"  Connection Mode: {data['connection_mode']}")
            print(f"  Active Connections: {data['active_connections']}")
            
            if data['status_log_info']:
                print(f"\n📊 Status Log Info:")
                print(f"  Clients Found: {data['status_log_info']['clients_found']}")
                print(f"  Sample IPs: {data['status_log_info']['sample_ips']}")
            
            return data
        else:
            print(f"❌ Verification endpoint failed: {resp.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error: {e}")
        print("   Make sure VPN Gateway is running on port 5001")
        return None

def test_manual_openvpn_check():
    """Manually check OpenVPN."""
    print("\n" + "=" * 60)
    print("Manual OpenVPN Checks")
    print("=" * 60)
    
    # Check installation
    try:
        result = subprocess.run(['openvpn', '--version'], capture_output=True, timeout=2)
        if result.returncode == 0:
            version = result.stdout.decode().split('\n')[0]
            print(f"✅ OpenVPN Installed: {version}")
        else:
            print("❌ OpenVPN not found")
    except:
        print("❌ OpenVPN not found")
    
    # Check port
    try:
        result = subprocess.run(['lsof', '-i', ':1194'], capture_output=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            print("✅ Port 1194 is in use (OpenVPN likely running)")
            output = result.stdout.decode().strip()
            lines = output.split('\n')
            if len(lines) > 1:
                print(f"   {lines[1][:100]}")
        else:
            print("⚠️  Port 1194 is not in use")
    except:
        print("⚠️  Could not check port 1194")
    
    # Check processes
    try:
        result = subprocess.run(['pgrep', '-f', 'openvpn'], capture_output=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            pids = result.stdout.decode().strip().split('\n')
            print(f"✅ OpenVPN processes running: {len(pids)}")
            for pid in pids[:3]:
                print(f"   PID: {pid}")
        else:
            print("⚠️  No OpenVPN processes found")
    except:
        print("⚠️  Could not check processes")

def test_health_endpoint():
    """Test VPN Gateway health endpoint."""
    print("\n" + "=" * 60)
    print("VPN Gateway Health Check")
    print("=" * 60)
    
    try:
        resp = requests.get(f'{BASE_URL}/health', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"✅ Status: {data['status']}")
            print(f"  OpenVPN Running: {'✅' if data['openvpn_running'] else '❌'}")
            print(f"  OpenVPN Installed: {'✅' if data['openvpn_installed'] else '❌'}")
            return True
        else:
            print(f"❌ Health check failed: {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        print("   Make sure VPN Gateway is running on port 5001")
        return False

if __name__ == '__main__':
    test_manual_openvpn_check()
    test_health_endpoint()
    test_openvpn_verification()
    
    print("\n" + "=" * 60)
    print("💡 Tips:")
    print("  - If OpenVPN is not running, VPN Gateway uses mock mode")
    print("  - Mock mode works for all testing except actual network tunneling")
    print("  - To start OpenVPN: sudo openvpn --config server.ovpn --daemon")
    print("  - Check connection mode in VPN status to see if using OpenVPN or mock")
    print("=" * 60)

