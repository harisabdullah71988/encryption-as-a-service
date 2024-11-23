from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
import sqlite3

# Flask app setup
app = Flask(__name__)
DB_FILE = 'services.db'

# Utility functions
def generate_aes_key():
    """Generate a random AES-256 key."""
    return os.urandom(32)  # 32 bytes = 256 bits

def generate_iv():
    """Generate a random Initialization Vector (IV)."""
    return os.urandom(16)  # 16 bytes for AES block size

def initialize_database():
    """Initialize the database to store services, keys, and IVs."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            aes_key TEXT NOT NULL,
            iv TEXT
        )
    """)
    conn.commit()
    conn.close()

# Initialize the database
initialize_database()

# Routes
@app.route('/create_service', methods=['POST'])
def create_service():
    """
    Create a new service with an AES-256 key and optional hardcoded IV.
    Parameters:
    - service_name: Name of the service.
    - hardcoded_iv: Boolean to determine if IV is hardcoded.
    """
    data = request.get_json()
    service_name = data.get('service_name')
    hardcoded_iv = data.get('hardcoded_iv', False)

    if not service_name:
        return jsonify({"error": "Service name is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if the service already exists
    cursor.execute("SELECT * FROM services WHERE service_name = ?", (service_name,))
    if cursor.fetchone():
        return jsonify({"error": "Service already exists"}), 400

    # Generate AES key and IV
    aes_key = generate_aes_key()
    iv = generate_iv() if hardcoded_iv else None

    # Save to database
    cursor.execute("""
        INSERT INTO services (service_name, aes_key, iv)
        VALUES (?, ?, ?)
    """, (service_name, b64encode(aes_key).decode(), b64encode(iv).decode() if iv else None))
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Service '{service_name}' created successfully",
        "aes_key": b64encode(aes_key).decode(),
        "iv": b64encode(iv).decode() if iv else None
    })


@app.route('/<service_name>/update_key', methods=['POST'])
def update_key(service_name):
    """
    Generate a new key (and IV if applicable) for a service.
    This creates a new version of the key.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if the service exists
    cursor.execute("SELECT COUNT(*) FROM services WHERE service_name = ?", (service_name,))
    current_version_count = cursor.fetchone()[0]
    if current_version_count == 0:
        conn.close()
        return jsonify({"error": "Service not found"}), 404

    data = request.get_json()
    hardcoded_iv = data.get('hardcoded_iv', False)

    new_key = generate_aes_key()
    new_iv = generate_iv() if hardcoded_iv else None
    new_version = f"{service_name}_v{current_version_count + 1}"

    # Save the new key and IV as a new version
    cursor.execute("""
        INSERT INTO services (service_name, aes_key, iv)
        VALUES (?, ?, ?)
    """, (new_version, b64encode(new_key).decode(), b64encode(new_iv).decode() if new_iv else None))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Service '{service_name}' updated to version {new_version}"})


@app.route('/<service_name>/encrypt', methods=['POST'])
def encrypt(service_name):
    """
    Encrypt data using the latest version of the AES key and IV for a service.
    Parameters:
    - plaintext: Data to encrypt.
    """
    data = request.get_json()
    plaintext = data.get('plaintext')
    service_name = request.view_args['service_name']

    if not plaintext:
        return jsonify({"error": "Plaintext is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get the latest version of the service
    cursor.execute("""
        SELECT aes_key, iv FROM services WHERE service_name = ?
        ORDER BY id DESC LIMIT 1
    """, (service_name,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Service not found"}), 404

    aes_key = b64decode(row[0])
    iv = b64decode(row[1]) if row[1] else generate_iv()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return jsonify({"ciphertext": ciphertext.hex(), "iv": iv.hex()})


@app.route('/<service_name>/decrypt', methods=['POST'])
def decrypt(service_name):
    """
    Decrypt data using the latest version of the AES key and IV for a service.
    Parameters:
    - ciphertext: Data to decrypt (hex-encoded).
    """
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    service_name = request.view_args['service_name']

    if not ciphertext:
        return jsonify({"error": "Ciphertext is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get the latest version of the service
    cursor.execute("""
        SELECT aes_key, iv FROM services WHERE service_name = ?
        ORDER BY id DESC LIMIT 1
    """, (service_name,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Service not found"}), 404

    aes_key = b64decode(row[0])
    iv = b64decode(row[1]) if row[1] else generate_iv()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(bytes.fromhex(ciphertext)) + decryptor.finalize()

    return jsonify({"plaintext": plaintext.decode()})


if __name__ == '__main__':
    app.run(debug=True)
