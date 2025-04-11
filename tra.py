from flask import Flask, request, jsonify
import secrets
import hashlib
import hmac

app = Flask(__name__)
registered_entities = {}
TRA_SECRET_KEY = secrets.token_bytes(32)  # Master secret key

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    entity_id = data.get('entity_id')
    entity_type = data.get('entity_type')

    if not entity_id or not entity_type:
        return jsonify({"error": "Missing entity_id/entity_type"}), 400

    if entity_id in registered_entities:
        return jsonify({"error": "Entity already registered"}), 409

    # Generate session key and credentials
    session_key = secrets.token_bytes(32)
    registered_entities[entity_id] = {
        "type": entity_type,
        "session_key": session_key.hex(),
        "status": "active"
    }

    return jsonify({
        "session_key": session_key.hex(),
        "message": "Registration successful"
    }), 201

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    entity_id = data.get('entity_id')
    nonce = data.get('nonce')
    received_hmac = data.get('hmac')

    if not all([entity_id, nonce, received_hmac]):
        return jsonify({"error": "Missing authentication parameters"}), 400

    entity = registered_entities.get(entity_id)
    if not entity:
        return jsonify({"error": "Unknown entity"}), 404

    # Validate HMAC
    session_key = bytes.fromhex(entity['session_key'])
    valid_hmac = hmac.new(session_key, nonce.encode(), hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(received_hmac, valid_hmac):
        return jsonify({"status": "authenticated"}), 200
    else:
        return jsonify({"error": "Authentication failed"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6000)