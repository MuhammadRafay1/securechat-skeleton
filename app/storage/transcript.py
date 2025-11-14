import os, hashlib, json
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

TRANSCRIPTS_DIR = Path('transcripts')
TRANSCRIPTS_DIR.mkdir(exist_ok=True)

class Transcript:
    def __init__(self, name: str):
        self.name = name
        self.path = TRANSCRIPTS_DIR / f"{name}.log"
        # ensure file exists
        self.path.touch(exist_ok=True)

    def append_line(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fp: str):
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}\n"
        with open(self.path, 'a') as f:
            f.write(line)

    def compute_transcript_hash(self) -> str:
        with open(self.path, 'rb') as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()

    def export_receipt(self, private_key, peer: str, first_seq: int, last_seq: int) -> dict:
        tx_hash = self.compute_transcript_hash()
        # Sign tx_hash (hex) bytes - FIXED: proper imports
        sig = private_key.sign(
            tx_hash.encode(), 
            padding.PKCS1v15(), 
            hashes.SHA256()
        )
        import base64
        receipt = {
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": tx_hash,
            "sig": base64.b64encode(sig).decode()
        }
        # write receipt file
        with open(TRANSCRIPTS_DIR / f"{self.name}.receipt.json", 'w') as f:
            json.dump(receipt, f, indent=2)
        return receipt