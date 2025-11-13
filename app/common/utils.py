import base64, hashlib, time

def b64u_encode(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64u_decode(s: str) -> bytes:
    return base64.b64decode(s)

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
