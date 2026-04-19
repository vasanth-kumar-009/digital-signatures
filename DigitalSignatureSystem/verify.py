import os
import json
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from utils import hash_file, decode_signature, write_log
from keygen import load_public_key

def verify_file(file_path, sig_path, public_key_path):
    """
    Verifies a file against its .sig file using the provided public key.
    """
    try:
        # Load .sig JSON
        with open(sig_path, 'r', encoding='utf-8') as f:
            sig_data = json.load(f)
            
        original_hash = sig_data.get('file_hash')
        algorithm = sig_data.get('algorithm')
        signer = sig_data.get('signer')
        signed_on = sig_data.get('timestamp')
        sig_base64 = sig_data.get('signature')
        
        # Decode signature from base64
        signature_bytes = decode_signature(sig_base64)
        
        # Compute current file hash
        current_hash = hash_file(file_path)
        hash_match = (current_hash == original_hash)
        
        # Load public key
        public_key = load_public_key(public_key_path)
        
        # Convert original hash to bytes for verification
        digest_bytes = bytes.fromhex(original_hash)
        
        # Verify using correct algorithm
        valid = False
        message = ""
        try:
            if algorithm == "RSA":
                public_key.verify(
                    signature_bytes,
                    digest_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    Prehashed(hashes.SHA256())
                )
            elif algorithm == "ECDSA":
                public_key.verify(
                    signature_bytes,
                    digest_bytes,
                    ec.ECDSA(Prehashed(hashes.SHA256()))
                )
            else:
                raise ValueError(f"Unknown algorithm specified in signature file: {algorithm}")
                
            # If verify() doesn't raise an exception, signature is technically valid for the hash
            # We also ensure the file hash hasn't altered
            if hash_match:
                valid = True
                message = "Valid Signature"
            else:
                valid = False
                message = "Invalid: File content modified (hash mismatch)"
                
        except InvalidSignature:
            valid = False
            message = "Invalid Signature: Cryptographic verification failed"
            
        details = {
            "signer": signer,
            "algorithm": algorithm,
            "signed_on": signed_on,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "hash_match": hash_match
        }
        
        # Write to audit log
        log_res = "Valid" if valid else "Invalid"
        write_log("Verify File", os.path.basename(file_path), log_res, f"Algorithm: {algorithm}, Signer: {signer}")
        
        return {"valid": valid, "message": message, "details": details}
        
    except Exception as e:
        write_log("Verify Failed", os.path.basename(file_path), "Error", f"Message: {str(e)}")
        return {
            "valid": False, 
            "message": f"Error loading or validating signature: {str(e)}", 
            "details": {}
        }

def tamper_and_verify(file_path, sig_path, public_key_path):
    """
    Creates a tampered copy of the file and demonstrates verification failure.
    """
    temp_path = file_path + ".tampered"
    try:
        # Copy file to a temp .tampered copy
        shutil.copy2(file_path, temp_path)
        
        # Append b" [TAMPERED]" to it
        with open(temp_path, 'ab') as f:
            f.write(b" [TAMPERED]")
            
        # Verify the tampered copy against original signature
        result = verify_file(temp_path, sig_path, public_key_path)
        
        return result
    finally:
        # Delete temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
