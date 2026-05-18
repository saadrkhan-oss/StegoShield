import secrets
import os
import struct
from utils.helpers import save_file, save_bytes
from flask import current_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_and_embed(cover_path, secret_path, password, cover_ext=".png", secret_ext=".txt"):
    """Encrypt secret file with AES-GCM and append to cover file."""
    with open(cover_path, "rb") as c:
        cover_bytes = c.read()

    with open(secret_path, "rb") as s:
        secret_bytes = s.read()

    # AES-GCM Encryption
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # Encrypt the secret
    encrypted_secret = aesgcm.encrypt(nonce, secret_bytes, None)
    
    # Pack extension
    ext_bytes = secret_ext.encode('utf-8')
    ext_len_bytes = struct.pack(">I", len(ext_bytes))
    
    # Save the standalone encrypted file to ENCRYPTED_FOLDER
    encrypted_filename = f"encrypted_{secrets.token_hex(4)}.bin"
    # Create ENCRYPTED_FOLDER if it doesn't exist
    encrypted_folder = current_app.config.get('ENCRYPTED_FOLDER')
    if not os.path.exists(encrypted_folder):
        os.makedirs(encrypted_folder)
        
    save_bytes(
        encrypted_secret,
        encrypted_folder,
        encrypted_filename
    )
    
    # Structure V3:
    # [Cover] + [Salt(16)] + [Nonce(12)] + [EncryptedSecret] + [ExtBytes] + [ExtLen(4)] + [TotalSecretLen(4)]
    # TotalSecretLen will just cover [Salt + Nonce + EncryptedSecret]
    
    total_secret = salt + nonce + encrypted_secret
    total_secret_len_bytes = struct.pack(">I", len(total_secret))

    stego_filename = f"stego_{secrets.token_hex(4)}{cover_ext}"
    final_data = cover_bytes + total_secret + ext_bytes + ext_len_bytes + total_secret_len_bytes

    stego_path = save_bytes(
        final_data, 
        current_app.config['STEGO_FOLDER'], 
        stego_filename
    )

    return stego_filename, stego_path, encrypted_filename


def extract_secret(stego_path, password):
    """Extract and decrypt secret from stego file using V3 structure."""
    with open(stego_path, "rb") as f:
        stego_bytes = f.read()

    if len(stego_bytes) < 8:
        raise ValueError("File too short to contain embedded data")

    try:
        # V3 check: Last 8 bytes -> [ExtLen(4)] + [TotalSecretLen(4)]
        ext_len = struct.unpack(">I", stego_bytes[-8:-4])[0]
        total_secret_len = struct.unpack(">I", stego_bytes[-4:])[0]
        
        # Sanity check
        if ext_len > 100 or total_secret_len > len(stego_bytes):
            raise ValueError("Corrupted or unsupported stego file format.")
            
        start_pos = len(stego_bytes) - 8 - ext_len - total_secret_len
        ext_start = len(stego_bytes) - 8 - ext_len
        
        file_ext = stego_bytes[ext_start : len(stego_bytes)-8].decode('utf-8')
        total_secret = stego_bytes[start_pos : ext_start]
        
        # Parse V3 secret structure: [Salt(16)] + [Nonce(12)] + [EncryptedSecret]
        if len(total_secret) < 28:
            raise ValueError("Embedded data is too short to be V3.")
            
        salt = total_secret[:16]
        nonce = total_secret[16:28]
        encrypted_secret = total_secret[28:]
        
    except Exception as e:
        raise ValueError(f"Failed to parse stego structure: {str(e)}")

    # Decrypt
    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        extracted_secret = aesgcm.decrypt(nonce, encrypted_secret, None)
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.")

    extracted_filename = f"extracted_{secrets.token_hex(4)}{file_ext}"
    extracted_path = save_bytes(
        extracted_secret, 
        current_app.config['EXTRACTED_FOLDER'], 
        extracted_filename
    )

    return extracted_secret, extracted_filename
