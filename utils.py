import hashlib
import base64
import json
import os
import time
from datetime import datetime

# Initialize required directories
for folder in ['keys', 'signed_files', 'logs']:
    os.makedirs(folder, exist_ok=True)

def hash_file(filepath):
    """Reads a file in 8KB chunks and returns its SHA-256 hex digest."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def hash_string(text):
    """Hashes a plain string using SHA-256."""
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.hexdigest()

def encode_signature(sig_bytes):
    """Encodes signature bytes to base64 string."""
    return base64.b64encode(sig_bytes).decode('utf-8')

def decode_signature(sig_str):
    """Decodes base64 signature string to bytes."""
    return base64.b64decode(sig_str.encode('utf-8'))

def write_log(action, filename, result, extra=""):
    """Appends a JSON entry to logs/audit_log.json."""
    log_file = os.path.join('logs', 'audit_log.json')
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "filename": filename,
        "result": result,
        "extra": extra
    }
    
    logs = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if content:
                    logs = json.loads(content)
        except json.JSONDecodeError:
            pass
            
    logs.append(entry)
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=4)

def read_logs():
    """Returns all log entries from the audit log."""
    log_file = os.path.join('logs', 'audit_log.json')
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if content:
                    return json.loads(content)
        except json.JSONDecodeError:
            pass
    return []

def get_file_info(filepath):
    """Returns a dict with name, size (formatted KB/MB), and file type/extension."""
    if not os.path.exists(filepath):
        return None
        
    size_bytes = os.path.getsize(filepath)
    if size_bytes >= 1024 * 1024:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        size_str = f"{size_bytes / 1024:.2f} KB"
    else:
        size_str = f"{size_bytes} Bytes"
        
    name = os.path.basename(filepath)
    _, ext = os.path.splitext(name)
    
    return {
        "name": name,
        "size": size_str,
        "type": ext.lstrip('.') if ext else 'unknown',
        "size_bytes": size_bytes
    }
