#!/bin/bash
# Script to restart OpenVPN server with updated config

echo "Stopping existing OpenVPN server..."
sudo pkill -f "openvpn.*server.ovpn"

echo "Waiting 2 seconds..."
sleep 2

echo "Starting OpenVPN server with updated config..."
cd /Users/madhav/ztna-vpntest/ztna-simulator-backend
sudo openvpn --config server.ovpn --daemon

echo "Waiting 3 seconds for startup..."
sleep 3

echo "Checking if OpenVPN is running..."
ps aux | grep "openvpn.*server.ovpn" | grep -v grep

echo "Checking status log file..."
ls -lh openvpn-status.log ipp.txt

echo "Done!"

