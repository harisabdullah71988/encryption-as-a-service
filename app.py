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

    # Create the services table if it does not exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            aes_key TEXT NOT NULL,
            key_version INTEGER NOT NULL,
            use_fixed_iv BOOLEAN NOT NULL,
            fixed_iv TEXT
        )
    """)

    # Commit and close connection
    conn.commit()
    conn.close()

# Initialize the database
initialize_database()

# Routes
@app.route('/create_service', methods=['POST'])
def create_service():
    """
    Create a new service with an AES-256 key.
    Parameters:
    - service_name: Name of the service.
    - use_fixed_iv: Whether to use a fixed IV (true/false).
    """
    data = request.get_json()
    service_name = data.get('service_name')
    use_fixed_iv = data.get('use_fixed_iv', False)  # Default to False

    if not service_name:
        return jsonify({"error": "Service name is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if the service already exists
    cursor.execute("SELECT * FROM services WHERE service_name = ?", (service_name,))
    if cursor.fetchone():
        return jsonify({"error": "Service already exists"}), 400

    # Generate AES key
    aes_key = generate_aes_key()

    # Generate fixed IV if required
    fixed_iv = b64encode(generate_iv()).decode() if use_fixed_iv else None

    # Default key version is 1 for the first key
    key_version = 1

    # Save to database with versioning
    cursor.execute("""
        INSERT INTO services (service_name, aes_key, key_version, use_fixed_iv, fixed_iv)
        VALUES (?, ?, ?, ?, ?)
    """, (service_name, b64encode(aes_key).decode(), key_version, use_fixed_iv, fixed_iv))
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Service '{service_name}' created successfully",
        "aes_key": b64encode(aes_key).decode(),
        "fixed_iv": fixed_iv if fixed_iv else "IV will be generated per encryption"
    })

@app.route('/<service_name>/encrypt', methods=['POST'])
def encrypt(service_name):
    """
    Encrypt data using the AES key for a service and key version.
    Parameters:
    - plaintext: Data to encrypt.
    - key_version: The version of the AES key to use.
    """
    data = request.get_json()
    plaintext = data.get('plaintext')
    key_version = data.get('key_version', 1)  # Default to version 1

    if not plaintext:
        return jsonify({"error": "Plaintext is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get the AES key and IV policy for the service and the specified key version
    cursor.execute("""
        SELECT aes_key, use_fixed_iv, fixed_iv FROM services
        WHERE service_name = ? AND key_version = ?
    """, (service_name, key_version))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": f"Service with version {key_version} not found"}), 404

    aes_key = b64decode(row[0])
    use_fixed_iv = row[1]
    fixed_iv = b64decode(row[2]) if row[2] else None

    # Determine IV
    if use_fixed_iv:
        if not fixed_iv:
            return jsonify({"error": "Fixed IV is missing for this service version"}), 500
        iv = fixed_iv
    else:
        iv = generate_iv()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Embed IV with the ciphertext if not using a fixed IV
    if not use_fixed_iv:
        combined_data = iv + ciphertext
        ciphertext = b64encode(combined_data).decode()
    else:
        ciphertext = b64encode(ciphertext).decode()

    return jsonify({
        "ciphertext": ciphertext
    })


@app.route('/<service_name>/decrypt', methods=['POST'])
def decrypt(service_name):
    """
    Decrypt data using the AES key for a service.
    Parameters:
    - ciphertext: Data to decrypt (base64-encoded).
    - key_version: Version of the key to use for decryption.
    """
    data = request.get_json()
    ciphertext = data.get('ciphertext')
    key_version = data.get('key_version', 1)  # Default to version 1

    if not ciphertext:
        return jsonify({"error": "Ciphertext is required"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get the AES key and IV policy for the service and key version
    cursor.execute("""
        SELECT aes_key, use_fixed_iv, fixed_iv FROM services
        WHERE service_name = ? AND key_version = ?
    """, (service_name, key_version))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": f"Service with version {key_version} not found"}), 404

    aes_key = b64decode(row[0])
    use_fixed_iv = row[1]
    fixed_iv = b64decode(row[2]) if row[2] else None

    # Determine IV
    if use_fixed_iv:
        if not fixed_iv:
            return jsonify({"error": "Fixed IV is missing for this service"}), 500
        iv = fixed_iv
        ciphertext = b64decode(ciphertext)
    else:
        combined_data = b64decode(ciphertext)
        iv = combined_data[:16]
        ciphertext = combined_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return jsonify({"plaintext": plaintext.decode()})


@app.route('/<service_name>/update_key', methods=['POST'])
def update_key(service_name):
    """
    Update the AES key (and optionally the IV) for an existing service.
    The AES key will be automatically generated.
    If the service uses a fixed IV, a new IV will be generated and hardcoded.
    Parameters:
    - use_fixed_iv: Whether to use a fixed IV (true/false).
    - fixed_iv: New fixed IV (base64-encoded, required if use_fixed_iv is true).
    """
    data = request.get_json()
    use_fixed_iv = data.get('use_fixed_iv', False)

    # Automatically generate a new AES key
    new_aes_key = generate_aes_key()

    if use_fixed_iv:
        # Generate a new IV and hardcode it for services using a fixed IV
        fixed_iv = generate_iv()
        fixed_iv_base64 = b64encode(fixed_iv).decode()
    else:
        # If not using a fixed IV, don't change IV (it will be generated dynamically during encryption)
        fixed_iv_base64 = None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if the service exists
    cursor.execute("SELECT * FROM services WHERE service_name = ?", (service_name,))
    if not cursor.fetchone():
        return jsonify({"error": "Service not found"}), 404

    # Increment the key version for the update
    cursor.execute("SELECT MAX(key_version) FROM services WHERE service_name = ?", (service_name,))
    current_version = cursor.fetchone()[0] or 0
    new_version = current_version + 1

    # Update the service with new AES key and fixed IV (if applicable)
    cursor.execute("""
        INSERT INTO services (service_name, aes_key, key_version, use_fixed_iv, fixed_iv)
        VALUES (?, ?, ?, ?, ?)
    """, (service_name, b64encode(new_aes_key).decode(), new_version, use_fixed_iv, fixed_iv_base64))

    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Service '{service_name}' updated successfully",
        "new_aes_key": b64encode(new_aes_key).decode(),
        "fixed_iv": fixed_iv_base64 if fixed_iv_base64 else "IV will be generated per encryption"
    })

if __name__ == '__main__':
    app.run(debug=True)
