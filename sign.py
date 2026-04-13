import os
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from utils import hash_file, encode_signature, write_log
from keygen import load_private_key

def sign_file(file_path, private_key_path, algorithm="RSA", password=None, signer_name="Unknown"):
    """
    Signs a file using the specified algorithm and private key.
    Calculates file hash, signs it, and saves a .sig JSON file.
    """
    try:
        # Load private key
        private_key = load_private_key(private_key_path, password)
        
        # Calculate file hash using SHA-256 for the JSON output and signing
        file_hash_hex = hash_file(file_path)
        # Convert hex digest back to bytes for Prehashed signing
        digest_bytes = bytes.fromhex(file_hash_hex)
        
        # Determine algorithm and sign
        if algorithm == "RSA":
            signature_bytes = private_key.sign(
                digest_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                Prehashed(hashes.SHA256())
            )
        elif algorithm == "ECDSA":
            signature_bytes = private_key.sign(
                digest_bytes,
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        # Encode signature
        sig_base64 = encode_signature(signature_bytes)
        
        # Prepare saving path
        filename = os.path.basename(file_path)
        sig_filename = f"{filename}.sig"
        sig_path = os.path.join('signed_files', sig_filename)
        
        # Construct .sig JSON
        sig_data = {
            "signer": signer_name,
            "file": filename,
            "file_hash": file_hash_hex,
            "algorithm": algorithm,
            "timestamp": datetime.now().isoformat(),
            "signature": sig_base64
        }
        
        # Save .sig file
        with open(sig_path, 'w', encoding='utf-8') as f:
            json.dump(sig_data, f, indent=4)
            
        # Write to audit log
        write_log("Sign File", filename, "Success", f"Algorithm: {algorithm}, Signer: {signer_name}")
        
        return sig_path, file_hash_hex
        
    except Exception as e:
        write_log("Sign Failed", os.path.basename(file_path), "Failed", f"Error: {str(e)}")
        raise e

def sign_multiple_files(file_paths, private_key_path, algorithm="RSA", password=None, signer_name="Unknown"):
    """Batch signs multiple files."""
    results = []
    for filepath in file_paths:
        try:
            sig_path, f_hash = sign_file(filepath, private_key_path, algorithm, password, signer_name)
            results.append({"file": filepath, "status": "Success", "sig_path": sig_path, "hash": f_hash})
        except Exception as e:
            results.append({"file": filepath, "status": "Failed", "error": str(e)})
    return results
