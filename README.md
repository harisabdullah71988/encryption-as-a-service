# AES256 Encryption Service API

A simple Flask-based API that provides AES256 encryption services with key versioning and secure storage.

## Features

- Create encryption services with unique AES256 keys and optional initialization vectors (IVs).
- Encrypt and decrypt data using service-specific endpoints.
- Manage multiple key versions for each service.
- Persistently store keys and IVs in a secure SQLite database.

## How It Works

1. **Service Creation**:
   - Create a service by providing a unique name.
   - Optionally set a hardcoded IV for deterministic encryption results.

2. **Encrypt & Decrypt**:
   - Use `/encrypt` and `/decrypt` endpoints to process data with the service's key.

3. **Key Versioning**:
   - Update keys (and IVs if applicable) for a service.
   - Specify which version to use for encryption or decryption.

4. **Persistent Storage**:
   - All keys and IVs are stored in a secure SQLite database for persistence across application restarts.

---

## API Endpoints

### 1. Create a Service
- **Endpoint**: `POST /create_service`
- **Description**: Create a new service with a unique AES256 key and optional IV.
- **Parameters**:
  - `service_name`: Unique name for the service.
  - `hardcoded_iv`: Boolean to indicate whether the IV should be hardcoded.

### 2. Update Key and IV
- **Endpoint**: `POST /<service_name>/update_key`
- **Description**: Generate a new key (and IV if applicable) for the service. Keeps track of versions.

### 3. Encrypt Data
- **Endpoint**: `POST /<service_name>/encrypt`
- **Description**: Encrypt plaintext using the service's key and IV (latest or specified version).

### 4. Decrypt Data
- **Endpoint**: `POST /<service_name>/decrypt`
- **Description**: Decrypt ciphertext using the specified key version.

---

## How to Use

1. **Install the Dependencies**:
   ```bash
   pip install -r requirements.txt

2. **Run the Application**:
   Once the dependencies are installed, start the application by running:
   ```bash
   python app.py
