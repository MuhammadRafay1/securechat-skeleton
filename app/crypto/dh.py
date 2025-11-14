import hashlib

def dh_generate_private(qbits=256):
    import secrets
    return secrets.randbelow(2**qbits - 2) + 2

def dh_public(g: int, p: int, priv: int) -> int:
    return pow(g, priv, p)

def dh_shared_secret(their_pub: int, priv: int, p: int) -> int:
    return pow(their_pub, priv, p)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    ks_bytes = ks_int.to_bytes((ks_int.bit_length()+7)//8 or 1, byteorder='big')
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]
