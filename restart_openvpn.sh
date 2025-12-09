#!/bin/bash
# Script to restart OpenVPN server with updated config

echo "Stopping existing OpenVPN server..."
sudo pkill -f "openvpn.*server.ovpn"

echo "Waiting 2 seconds..."
sleep 2

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Note: openvpn-status.log will be automatically cleared/reset when server starts
# (it only shows active connections, so will be empty until clients connect)
# ipp.txt persists across restarts (by design) to maintain IP assignments

echo "Starting OpenVPN server with updated config..."
sudo openvpn --config server.ovpn --daemon

echo "Waiting 3 seconds for startup..."
sleep 3

echo "Checking if OpenVPN is running..."
ps aux | grep "openvpn.*server.ovpn" | grep -v grep

echo ""
echo "File Status:"
echo "============"
echo "openvpn-status.log:"
if [ -f "openvpn-status.log" ]; then
    ls -lh openvpn-status.log
    echo "  (This file shows only ACTIVE connections - empty until clients connect)"
else
    echo "  File does not exist (will be created when first client connects)"
fi

echo ""
echo "ipp.txt:"
if [ -f "ipp.txt" ]; then
    ls -lh ipp.txt
    echo "  (This file persists IP assignments across restarts)"
    if [ -s "ipp.txt" ]; then
        echo "  Current entries:"
        cat ipp.txt | grep -v "^$" | while read line; do
            echo "    $line"
        done
        echo "  Note: Stale entries (from disconnected clients) may remain."
        echo "        The VPN gateway will clean these up automatically."
    else
        echo "  File is empty (no IP assignments yet)"
    fi
else
    echo "  File does not exist (will be created when first client connects)"
fi

echo ""
echo "Done!"

