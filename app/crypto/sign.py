from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

def rsa_sign(private_key, data: bytes) -> bytes:
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return sig

def rsa_sign_b64(private_key, data: bytes) -> str:
    return base64.b64encode(rsa_sign(private_key, data)).decode()

def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
