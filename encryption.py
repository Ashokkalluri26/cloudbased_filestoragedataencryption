from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import hashlib
import hmac
import secrets
import json
from datetime import datetime

class AdvancedEncryption:
    """Advanced encryption class with multiple layers of security"""
    
    def __init__(self, master_key=None):
        self.master_key = master_key or os.getenv('ENCRYPTION_KEY', '').encode()
        if not self.master_key:
            self.master_key = Fernet.generate_key()
    
    def generate_salt(self, length=32):
        """Generate cryptographically secure salt"""
        return secrets.token_bytes(length)
    
    def derive_key_pbkdf2(self, password, salt, iterations=100000):
        """Derive key using PBKDF2 with SHA-256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_data(self, data, additional_data=None):
        """Encrypt data with AES-256-GCM for authenticated encryption"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate random IV
        iv = os.urandom(12)  # 96-bit IV for GCM
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.master_key[:32]), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # Add additional authenticated data if provided
        if additional_data:
            encryptor.authenticate_additional_data(additional_data.encode())
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + tag + ciphertext (all base64 encoded)
        encrypted_package = {
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return base64.b64encode(json.dumps(encrypted_package).encode()).decode()
    
    def decrypt_data(self, encrypted_data, additional_data=None):
        """Decrypt data encrypted with AES-256-GCM"""
        try:
            # Decode the package
            package = json.loads(base64.b64decode(encrypted_data).decode())
            
            iv = base64.b64decode(package['iv'])
            tag = base64.b64decode(package['tag'])
            ciphertext = base64.b64decode(package['ciphertext'])
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.master_key[:32]), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            
            # Add additional authenticated data if provided
            if additional_data:
                decryptor.authenticate_additional_data(additional_data.encode())
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def generate_rsa_keypair(self, key_size=2048):
        """Generate RSA key pair for asymmetric encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def rsa_encrypt(self, data, public_key_pem):
        """Encrypt data using RSA public key"""
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode()
    
    def rsa_decrypt(self, encrypted_data, private_key_pem):
        """Decrypt data using RSA private key"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
    
    def create_hmac(self, data, key=None):
        """Create HMAC for data integrity verification"""
        if key is None:
            key = self.master_key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    def verify_hmac(self, data, signature, key=None):
        """Verify HMAC signature"""
        if key is None:
            key = self.master_key
        
        expected_signature = self.create_hmac(data, key)
        return hmac.compare_digest(signature, expected_signature)

# Initialize global encryption instance
encryption = AdvancedEncryption()

def generate_encryption_key():
    """Generate a new encryption key for file encryption"""
    return Fernet.generate_key()

def generate_file_key():
    """Generate a new file encryption key (alias for generate_encryption_key)"""
    return generate_encryption_key()

def encrypt_file(input_path, output_path, key):
    """Encrypt a file using AES-256 encryption with integrity check"""
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as file:
        file_data = file.read()
    
    # Create file hash for integrity
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    # Create metadata
    metadata = {
        'original_hash': file_hash,
        'timestamp': datetime.utcnow().isoformat(),
        'size': len(file_data)
    }
    
    # Encrypt file data
    encrypted_data = fernet.encrypt(file_data)
    
    # Encrypt metadata
    encrypted_metadata = fernet.encrypt(json.dumps(metadata).encode())
    
    # Write encrypted file with metadata header
    with open(output_path, 'wb') as file:
        # Write metadata length (4 bytes)
        metadata_length = len(encrypted_metadata)
        file.write(metadata_length.to_bytes(4, byteorder='big'))
        
        # Write encrypted metadata
        file.write(encrypted_metadata)
        
        # Write encrypted file data
        file.write(encrypted_data)

def decrypt_file(input_path, output_path, key):
    """Decrypt a file using AES-256 encryption with integrity verification"""
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as file:
        # Read metadata length
        metadata_length = int.from_bytes(file.read(4), byteorder='big')
        
        # Read encrypted metadata
        encrypted_metadata = file.read(metadata_length)
        
        # Read encrypted file data
        encrypted_data = file.read()
    
    # Decrypt metadata
    metadata = json.loads(fernet.decrypt(encrypted_metadata).decode())
    
    # Decrypt file data
    decrypted_data = fernet.decrypt(encrypted_data)
    
    # Verify file integrity
    file_hash = hashlib.sha256(decrypted_data).hexdigest()
    if file_hash != metadata['original_hash']:
        raise ValueError("File integrity check failed - file may be corrupted")
    
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)

def derive_key_from_password(password, salt=None):
    """Derive encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_sensitive_data(data):
    """Encrypt sensitive data for database storage"""
    return encryption.encrypt_data(data)

def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data from database"""
    return encryption.decrypt_data(encrypted_data)

def generate_secure_token(length=32):
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)

def hash_password_secure(password, salt=None):
    """Secure password hashing with salt"""
    if salt is None:
        salt = secrets.token_bytes(32)
    
    # Use PBKDF2 with high iteration count
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=200000,  # Higher iterations for password hashing
    )
    
    key = kdf.derive(password.encode())
    return base64.b64encode(salt + key).decode()

def verify_password_secure(password, hashed_password):
    """Verify password against secure hash"""
    try:
        decoded = base64.b64decode(hashed_password)
        salt = decoded[:32]
        stored_key = decoded[32:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=200000,
        )
        
        key = kdf.derive(password.encode())
        return hmac.compare_digest(stored_key, key)
    except:
        return False
