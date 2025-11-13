from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

BLOCK_SIZE = 128

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError('AES-128 requires 16-byte key')
    pt = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()
    return ct

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError('AES-128 requires 16-byte key')
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(pt)

def encrypt_ecb_b64(key: bytes, plaintext: bytes) -> str:
    return base64.b64encode(encrypt_ecb(key, plaintext)).decode()

def decrypt_ecb_b64(key: bytes, b64ct: str) -> bytes:
    return decrypt_ecb(key, base64.b64decode(b64ct))
