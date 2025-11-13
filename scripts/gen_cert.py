import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from pathlib import Path

CERTS = Path('certs')
CERTS.mkdir(exist_ok=True)

def gen_cert(common_name: str, out_key: Path, out_crt: Path):
    # load CA
    ca_key = serialization.load_pem_private_key((CERTS/'ca.key').read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((CERTS/'ca.crt').read_bytes())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([ x509.NameAttribute(NameOID.COMMON_NAME, common_name) ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        ca_cert.subject
    ).public_key(key.public_key()).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    out_key.write_bytes(key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption()))
    out_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f'Wrote {out_key} and {out_crt}')

if __name__=='__main__':
    if len(sys.argv)<2:
        print('Usage: gen_cert.py <common-name> (example: server.local)')
        sys.exit(1)
    name = sys.argv[1]
    gen_cert(name, CERTS/f"{name}.key", CERTS/f"{name}.crt")
