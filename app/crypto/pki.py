from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import datetime

def load_cert(path: str) -> x509.Certificate:
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())

def load_private_key(path: str, password=None):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def verify_cert_with_ca(cert: x509.Certificate, ca_cert: x509.Certificate):
    # Verify signature using CA public key and basic validity period check
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError('Certificate signature verification failed: ' + str(e))

    # Check validity dates
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError('Certificate expired or not yet valid')

def cert_cn_matches(cert: x509.Certificate, hostname: str) -> bool:
    # Simple CN match (not full SAN handling)
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value == hostname
    return False
