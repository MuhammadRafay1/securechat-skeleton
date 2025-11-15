
# SecureChat 

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Set up environment**:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

2. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

3. **Create tables**:
   ```bash
   python -m app.storage.db --init
   ```

4. **Generate certificates** (after implementing the scripts):
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

7. **Run components** (after implementation):
   ```bash
   python -m app.server
   # in another terminal:
   python -m app.client
   ```


## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  
