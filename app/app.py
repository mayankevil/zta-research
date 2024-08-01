from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
jwt = JWTManager(app)

# Example user data, in a real app this should come from a database
users = {
    "testuser": generate_password_hash("password123", method='pbkdf2:sha256')
}

# OPA URL
OPA_URL = "http://opa:8181/v1/data/example/authz"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    if username not in users or not check_password_hash(users[username], password):
        return jsonify({"msg": "Invalid username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    # Query OPA for authorization decision
    payload = {
        "input": {
            "user": current_user,
            "action": "read",
            "resource": "protected"
        }
    }
    response = requests.post(OPA_URL, json=payload)
    if response.json().get("result", {}).get("allow"):
        return jsonify(logged_in_as=current_user), 200
    return jsonify({"msg": "Unauthorized"}), 403

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

