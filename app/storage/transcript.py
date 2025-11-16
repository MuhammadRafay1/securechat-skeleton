

import hashlib
import os
import json
import base64
from typing import Optional
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

TRANSCRIPT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "transcripts"
)


def ensure_transcript_dir():
    """Create transcripts directory if it doesn't exist"""
    os.makedirs(TRANSCRIPT_DIR, exist_ok=True)


def compute_hash(entry: str, prev_hash: Optional[str]) -> str:
    """Compute chained hash: SHA256(entry + prev_hash)"""
    return hashlib.sha256((entry + (prev_hash or "")).encode()).hexdigest()


class Transcript:
    def __init__(self, peer_name: str):
        ensure_transcript_dir()
        self.file_path = os.path.join(TRANSCRIPT_DIR, f"{peer_name}_transcript.txt")
        self.peer_name = peer_name
        self.lines = []  # in-memory lines for export_receipt

        # Load existing transcript into memory
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                for line in f.read().splitlines():
                    fields = line.split("|")
                    if len(fields) >= 6:
                        seq, ts, ct, sig, cert_fp = fields[:5]
                        self.lines.append({
                            'seq': int(seq),
                            'ts': int(ts),
                            'ct': ct,
                            'sig': sig,
                            'peer_fp': cert_fp
                        })

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, cert_fp: str):
        """Append message with blockchain hash to file AND memory"""
        entry = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{cert_fp}"
        # compute chain hash for file storage
        prev_hash = None
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                lines = f.read().splitlines()
                if lines:
                    prev_hash = lines[-1].split("|")[-1]
        chain_hash = compute_hash(entry, prev_hash)
        # write to file
        with open(self.file_path, "a") as f:
            f.write(f"{entry}|{chain_hash}\n")
        # add to in-memory lines
        self.lines.append({
            'seq': seqno,
            'ts': ts,
            'ct': ct_b64,
            'sig': sig_b64,
            'peer_fp': cert_fp
        })

    def append_line(self, seqno, ts, ct_b64, sig_b64, cert_fp):
        """Compatibility wrapper"""
        return self.append(seqno, ts, ct_b64, sig_b64, cert_fp)

    def verify(self) -> bool:
        """Verify integrity of entire transcript chain"""
        prev_hash = None
        if not os.path.exists(self.file_path):
            return True

        with open(self.file_path, "r") as f:
            for line in f:
                fields = line.strip().split("|")
                if len(fields) < 6:
                    return False
                entry = "|".join(fields[:-1])
                stored_hash = fields[-1]
                calc_hash = compute_hash(entry, prev_hash)
                if calc_hash != stored_hash:
                    return False
                prev_hash = stored_hash
        return True

    def read_all(self) -> list[str]:
        """Read all transcript lines"""
        if not os.path.exists(self.file_path):
            return []
        with open(self.file_path, "r") as f:
            return f.readlines()

    def compute_transcript_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript content"""
        lines = self.read_all()
        content = "".join(lines)
        return hashlib.sha256(content.encode()).hexdigest()

    def get_sequence_range(self) -> tuple[int, int]:
        """Get first and last sequence numbers"""
        lines = self.read_all()
        if not lines:
            return 0, 0
        first_seq = int(lines[0].split("|")[0])
        last_seq = int(lines[-1].split("|")[0])
        return first_seq, last_seq

    def export_receipt(self, signing_key, role, session_id, last_seq):
        """
        Create a signed receipt proving the conversation integrity.
        Uses self.lines (in-memory transcript).
        """
        # Filter messages up to last_seq
        relevant = [l for l in self.lines if l['seq'] <= last_seq]

        payload = {
            'role': role,
            'session_id': session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'messages': relevant
        }

        # Convert to JSON bytes
        msg_bytes = json.dumps(payload).encode()

        # Sign the payload using RSA key
        signature = signing_key.sign(
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        receipt = {
            'payload': base64.b64encode(msg_bytes).decode(),
            'signature': base64.b64encode(signature).decode()
        }

        return receipt

    def clear(self):
        """Clear transcript file and memory (for testing)"""
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        self.lines = []


# --- Helper functions for backward compatibility ---
def get_transcript(peer_name: str) -> Transcript:
    """Get Transcript instance for a peer"""
    return Transcript(peer_name)


def append_message(peer_name: str, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_pem: bytes):
    """Append message to transcript with cert fingerprint"""
    cert_fp = hashlib.sha256(peer_cert_pem).hexdigest()
    transcript = Transcript(peer_name)
    transcript.append(seqno, ts, ct_b64, sig_b64, cert_fp)


def verify_transcript(peer_name: str) -> bool:
    """Verify transcript integrity"""
    transcript = Transcript(peer_name)
    return transcript.verify()


def compute_transcript_hash(peer_name: str) -> str:
    """Compute hash of entire transcript"""
    transcript = Transcript(peer_name)
    return transcript.compute_transcript_hash()

