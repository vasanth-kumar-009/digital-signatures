import time
import os
from keygen import generate_rsa_keys, generate_ecdsa_keys
from sign import sign_file
from verify import verify_file

def _get_file_size(filepath):
    """Returns size of a file in bytes."""
    return os.path.getsize(filepath) if os.path.exists(filepath) else 0

def run_comparison(file_path):
    """
    Runs a performance comparison between RSA and ECDSA.
    Returns metrics for key generation, signing, and verification in ms,
    and key/signature sizes in bytes.
    """
    metrics = {
        "RSA": {},
        "ECDSA": {}
    }
    
    # --- RSA Benchmark ---
    
    # 1. RSA Key Generation
    start_time = time.perf_counter()
    rsa_priv_path, rsa_pub_path = generate_rsa_keys(key_size=2048)
    metrics["RSA"]["keygen_ms"] = (time.perf_counter() - start_time) * 1000
    metrics["RSA"]["priv_key_size"] = _get_file_size(rsa_priv_path)
    metrics["RSA"]["pub_key_size"] = _get_file_size(rsa_pub_path)
    
    # 2. RSA Signing
    start_time = time.perf_counter()
    rsa_sig_path, _ = sign_file(file_path, rsa_priv_path, algorithm="RSA", signer_name="Benchmark")
    metrics["RSA"]["sign_ms"] = (time.perf_counter() - start_time) * 1000
    metrics["RSA"]["sig_size"] = _get_file_size(rsa_sig_path)
    
    # 3. RSA Verification
    start_time = time.perf_counter()
    verify_file(file_path, rsa_sig_path, rsa_pub_path)
    metrics["RSA"]["verify_ms"] = (time.perf_counter() - start_time) * 1000
    
    
    # --- ECDSA Benchmark ---
    
    # 1. ECDSA Key Generation
    start_time = time.perf_counter()
    ecdsa_priv_path, ecdsa_pub_path = generate_ecdsa_keys()
    metrics["ECDSA"]["keygen_ms"] = (time.perf_counter() - start_time) * 1000
    metrics["ECDSA"]["priv_key_size"] = _get_file_size(ecdsa_priv_path)
    metrics["ECDSA"]["pub_key_size"] = _get_file_size(ecdsa_pub_path)
    
    # 2. ECDSA Signing
    start_time = time.perf_counter()
    ecdsa_sig_path, _ = sign_file(file_path, ecdsa_priv_path, algorithm="ECDSA", signer_name="Benchmark")
    metrics["ECDSA"]["sign_ms"] = (time.perf_counter() - start_time) * 1000
    metrics["ECDSA"]["sig_size"] = _get_file_size(ecdsa_sig_path)
    
    # 3. ECDSA Verification
    start_time = time.perf_counter()
    verify_file(file_path, ecdsa_sig_path, ecdsa_pub_path)
    metrics["ECDSA"]["verify_ms"] = (time.perf_counter() - start_time) * 1000

    return metrics
