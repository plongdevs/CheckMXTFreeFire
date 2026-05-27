from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from passlib.context import CryptContext
from datetime import timedelta
import json
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from garena_tools import (
    add_recovery_email, check_recovery_email, check_platforms,
    cancel_recovery_email, revoke_token, extract_eat_from_input,
    eat_to_access, eat_to_jwt, access_to_jwt, guest_to_jwt, decode_jwt
)

app = Flask(__name__)

# CORS
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database (JSON file for simplicity)
DB_FILE = os.environ.get('DB_FILE', 'users.json')

def load_users():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(DB_FILE, 'w') as f:
        json.dump(users, f)

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    users = load_users()
    
    if username in users:
        return jsonify({"message": "Username already registered"}), 400
    
    for u in users.values():
        if u.get("email") == email:
            return jsonify({"message": "Email already registered"}), 400
    
    users[username] = {
        "username": username,
        "email": email,
        "hashed_password": get_password_hash(password),
        "created_at": str(timedelta(seconds=0))
    }
    
    save_users(users)
    return jsonify({"message": "User registered successfully"}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    users = load_users()
    user = users.get(username)
    
    if not user or not verify_password(password, user["hashed_password"]):
        return jsonify({"message": "Incorrect username or password"}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token, "token_type": "bearer"}), 200

@app.route('/api/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user = get_jwt_identity()
    users = load_users()
    user = users.get(current_user)
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    return jsonify({
        "username": user["username"],
        "email": user["email"],
        "created_at": user["created_at"]
    }), 200

# Garena Tools Endpoints
@app.route('/api/add-recovery-email', methods=['POST'])
@jwt_required()
def api_add_recovery_email():
    data = request.get_json()
    result = add_recovery_email(
        data.get('email'),
        data.get('access_token'),
        data.get('otp'),
        data.get('security_code')
    )
    return jsonify(result), 200

@app.route('/api/check-recovery-email', methods=['POST'])
@jwt_required()
def api_check_recovery_email():
    data = request.get_json()
    result = check_recovery_email(data.get('access_token'))
    return jsonify(result), 200

@app.route('/api/check-platforms', methods=['POST'])
@jwt_required()
def api_check_platforms():
    data = request.get_json()
    result = check_platforms(data.get('access_token'))
    return jsonify(result), 200

@app.route('/api/cancel-recovery-email', methods=['POST'])
@jwt_required()
def api_cancel_recovery_email():
    data = request.get_json()
    result = cancel_recovery_email(data.get('access_token'))
    return jsonify(result), 200

@app.route('/api/revoke-token', methods=['POST'])
@jwt_required()
def api_revoke_token():
    data = request.get_json()
    result = revoke_token(data.get('access_token'))
    return jsonify(result), 200

@app.route('/api/eat-to-access', methods=['POST'])
@jwt_required()
def api_eat_to_access():
    data = request.get_json()
    eat = extract_eat_from_input(data.get('eat_token', ''))
    if not eat:
        return jsonify({"success": False, "message": "Không tách được EAT token!"}), 400
    try:
        access = eat_to_access(eat)
        if access:
            return jsonify({"success": True, "access_token": access}), 200
        else:
            return jsonify({"success": False, "message": "Không lấy được Access Token"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

@app.route('/api/eat-to-jwt', methods=['POST'])
@jwt_required()
def api_eat_to_jwt():
    data = request.get_json()
    eat = extract_eat_from_input(data.get('eat_token', ''))
    if not eat:
        return jsonify({"success": False, "message": "Không tách được EAT token!"}), 400
    try:
        jwt_token = eat_to_jwt(eat)
        decoded = decode_jwt(jwt_token)
        return jsonify({"success": True, "jwt_token": jwt_token, "decoded": decoded}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

@app.route('/api/access-to-jwt', methods=['POST'])
@jwt_required()
def api_access_to_jwt():
    data = request.get_json()
    try:
        jwt_token = access_to_jwt(data.get('access_token'))
        decoded = decode_jwt(jwt_token)
        return jsonify({"success": True, "jwt_token": jwt_token, "decoded": decoded}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

@app.route('/api/guest-to-jwt', methods=['POST'])
@jwt_required()
def api_guest_to_jwt():
    data = request.get_json()
    try:
        jwt_token = guest_to_jwt(data.get('uid'), data.get('password'))
        decoded = decode_jwt(jwt_token)
        return jsonify({"success": True, "jwt_token": jwt_token, "decoded": decoded}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

# Vercel handler
def handler(environ, start_response):
    return app(environ, start_response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
