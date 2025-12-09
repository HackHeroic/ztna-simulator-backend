# auth_server.py

import os
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)


CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})


SECRET_KEY = os.environ.get("JWT_SECRET", "your-super-secret-key")
TOKEN_EXPIRY_MINUTES = 30


USERS = {
    "alice@company.com": {
        "password": "password123",
        "role": "Developer",
        "clearance": 3,
        "department": "Engineering",
    },
    "bob@company.com": {
        "password": "securepass",
        "role": "Admin",
        "clearance": 5,
        "department": "IT",
    },
    "charlie@company.com": {
        "password": "userpass",
        "role": "Analyst",
        "clearance": 2,
        "department": "Finance",
    },
    "diana@company.com": {
        "password": "security123",
        "role": "Security",
        "clearance": 4,
        "department": "Security",
    },
    "eve@company.com": {
        "password": "audit123",
        "role": "Auditor",
        "clearance": 3,
        "department": "Compliance",
    },
    "frank@company.com": {
        "password": "manager123",
        "role": "Manager",
        "clearance": 2,
        "department": "Operations",
    },
    "grace@company.com": {
        "password": "intern123",
        "role": "Intern",
        "clearance": 1,
        "department": "Engineering",
    },
}


active_sessions = {}


ACCESS_POLICIES = {
    "database-prod": {
        "required_role": ["Admin", "Developer", "Security"],
        "required_clearance": 3,
        "allowed_departments": ["Engineering", "IT", "Security"],
    },
    "file-server": {
        "required_role": ["Admin", "Developer", "Analyst", "Manager", "Security"],
        "required_clearance": 2,
        "allowed_departments": ["Engineering", "IT", "Finance", "Operations", "Security"],
    },
    "admin-panel": {
        "required_role": ["Admin"],
        "required_clearance": 5,
        "allowed_departments": ["IT"],
    },
    "vpn-gateway": {
        "required_role": ["Admin", "Developer", "Analyst", "Manager", "Security", "Intern"],
        "required_clearance": 1,
        "allowed_departments": ["Engineering", "IT", "Finance", "Operations", "Security"],
    },
}



# LOGIN ENDPOINT
@app.route("/api/auth/login", methods=["POST"])
def login():
    start_time = datetime.now()
    data = request.get_json()

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Missing email or password"}), 400

    email = data["email"].strip().lower()
    password = data["password"]

    if email in USERS and USERS[email]["password"] == password:
        user = USERS[email]
        exp_time = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
        token = jwt.encode(
            {
                "email": email,
                "role": user["role"],
                "clearance": user["clearance"],
                "department": user["department"],
                "exp": exp_time,
            },
            SECRET_KEY,
            algorithm="HS256",
        )

        active_sessions[email] = {"token": token, "login_time": start_time}
        latency = (datetime.now() - start_time).total_seconds() * 1000

        return jsonify(
            {"token": token, "user": user, "latency_ms": round(latency, 2)}
        )

    return jsonify({"error": "Invalid credentials"}), 401



# VERIFY TOKEN
@app.route("/api/auth/verify", methods=["GET"])
def verify_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"valid": False, "error": "No token provided"}), 401

    token = auth_header.replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "user": decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401



# ACCESS CHECK

@app.route("/api/access/check", methods=["POST"])
def check_access():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.replace("Bearer ", "")
    resource = request.json.get("resource")

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        policy = ACCESS_POLICIES.get(resource)
        if not policy:
            return jsonify({"error": "Unknown resource"}), 404

        if (
            decoded["role"] in policy["required_role"]
            and decoded["clearance"] >= policy["required_clearance"]
            and decoded["department"] in policy["allowed_departments"]
        ):
            return jsonify({"access": "GRANTED", "resource": resource})

        return jsonify({"access": "DENIED", "resource": resource}), 403

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401



# VPN REQUEST

@app.route("/api/access/request-vpn", methods=["POST"])
def request_vpn():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.replace("Bearer ", "")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        vpn_token = jwt.encode(
            {
                "user": decoded["email"],
                "clearance": decoded["clearance"],
                "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES),
            },
            SECRET_KEY,
            algorithm="HS256",
        )
        return jsonify(
            {"vpn_token": vpn_token, "vpn_server": "10.8.0.1", "vpn_port": 1194}
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401



# HEALTH CHECK

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "uptime": datetime.utcnow().isoformat()})



# START SERVER

if __name__ == "__main__":
    app.run(port=5000, debug=True)