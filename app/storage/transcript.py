import os, hashlib
from pathlib import Path

TRANSCRIPTS_DIR = Path('transcripts')
TRANSCRIPTS_DIR.mkdir(exist_ok=True)

class Transcript:
    def __init__(self, name: str):
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
