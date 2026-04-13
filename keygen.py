import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

def _get_encryption_algorithm(password):
    if password:
        password_bytes = password.encode('utf-8')
        return serialization.BestAvailableEncryption(password_bytes)
    return serialization.NoEncryption()

def generate_rsa_keys(password=None, key_size=2048):
    """Generates RSA key pair and saves to keys/ directory."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    private_path = os.path.join('keys', 'rsa_private.pem')
    public_path = os.path.join('keys', 'rsa_public.pem')
    
    # Save private key
    with open(private_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_get_encryption_algorithm(password)
        ))
        
    # Save public key
    public_key = private_key.public_key()
    with open(public_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    return private_path, public_path

def generate_ecdsa_keys(password=None):
    """Generates ECDSA key pair using SECP256R1 and saves to keys/ directory."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    private_path = os.path.join('keys', 'ecdsa_private.pem')
    public_path = os.path.join('keys', 'ecdsa_public.pem')
    
    # Save private key
    with open(private_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=_get_encryption_algorithm(password)
        ))
        
    # Save public key
    public_key = private_key.public_key()
    with open(public_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    return private_path, public_path

def load_private_key(path, password=None):
    """Loads a PEM private key from a file."""
    password_bytes = password.encode('utf-8') if password else None
    with open(path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password_bytes
        )
    return private_key

def load_public_key(path):
    """Loads a PEM public key from a file."""
    with open(path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key
