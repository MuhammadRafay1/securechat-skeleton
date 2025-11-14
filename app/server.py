# app/server.py (fixed and synced with client)
import socket, threading, json, os
from app.crypto import pki, dh, aes, sign
from app.common import utils
from app.storage import db, transcript
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64, time

CERTS = Path('certs')
CA_CERT = CERTS/'ca.crt'
SERVER_KEY = CERTS/'server.local.key'
SERVER_CERT = CERTS/'server.local.crt'

TIME_SKEW_MS = 60 * 1000

def load_priv_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

def now_ms():
    return int(time.time() * 1000)


def recv_json_line(sock, timeout=None):
    """
    Read bytes from `sock` until a newline and return the parsed JSON object.
    Returns None on EOF/timeout.
    """
    buf = []
    sock.settimeout(timeout)
    try:
        while True:
            ch = sock.recv(1)
            if not ch:
                return None
            if ch == b'\n':
                break
            buf.append(ch)
    except socket.timeout:
        return None
    finally:
        sock.settimeout(None)
    try:
        raw = b''.join(buf).decode()
        return json.loads(raw)
    except Exception:
        raise

def handle_client(conn, addr):
    print('Client connected', addr)
    # HELLO (line-framed)
    try:
        hello = recv_json_line(conn, timeout=5)
        if not hello:
            print('Bad hello: no data')
            conn.close()
            return
    except Exception as e:
        print('Bad hello:', e)
        conn.close()
        return

    # validate client cert
    ca = pki.load_cert(str(CA_CERT))
    client_cert_pem = hello.get('cert')
    if not client_cert_pem:
        conn.sendall((json.dumps({'type':'bad cert','msg':'no cert provided'})+'\n').encode())
        conn.close()
        return
    try:
        client_cert = pki.load_cert_bytes(client_cert_pem.encode())
        pki.verify_cert_with_ca(client_cert, ca)
        if not pki.cert_cn_matches(client_cert, 'client.local'):
            raise ValueError('Client CN mismatch expected client.local')
    except Exception as e:
        conn.sendall((json.dumps({'type':'bad cert','msg':str(e)}) ) .encode()+b'\n')
        conn.close()
        return

    # send server hello (line-framed)
    nonce = base64.b64encode(os.urandom(12)).decode()
    srv_hello = {'type':'server hello','cert': SERVER_CERT.read_text(), 'nonce': nonce}
    conn.sendall((json.dumps(srv_hello)+'\n').encode())

    # ---------- DH1 (temporary) for registration/login ----------
    dhc = recv_json_line(conn, timeout=10)
    if not dhc:
        print("Connection closed before DH1")
        conn.close()
        return
    try:
        g = dhc['g']; p = dhc['p']; A = dhc['A']
    except Exception as e:
        print("Expected DH client message for DH1, got:", dhc, "error:", e)
        conn.close()
        return

    b = dh.dh_generate_private(128)
    B = dh.dh_public(g, p, b)
    conn.sendall((json.dumps({'type':'dh server','B':B})+'\n').encode())
    ks = dh.dh_shared_secret(A, b, p)
    K = dh.derive_aes_key_from_ks(ks)

    # Now handle encrypted payloads until a successful login
    db.init_db()

    while True:
        msg = recv_json_line(conn, timeout=None)
        if not msg:
            print("Client closed connection while waiting for registration/login.")
            conn.close()
            return

        if msg.get('type') != 'enc':
            print("Unexpected message type while awaiting register/login:", msg.get('type'))
            conn.sendall((json.dumps({'type':'error','msg':'expected enc payload'})+'\n').encode())
            conn.close()
            return

        # decrypt payload using temporary AES key K
        try:
            ct_b64 = msg['payload']
            pt = aes.decrypt_ecb_b64(K, ct_b64).decode()
            obj = json.loads(pt)
        except Exception as e:
            print("Decryption/parsing error for enc payload:", e)
            conn.sendall((json.dumps({'type':'register result','ok':False,'msg':'decrypt error'})+'\n').encode())
            conn.close()
            return

        # Handle register or login
        try:
            if obj.get('type') == 'register':
                try:
                    ok = db.register_user(obj['email'], obj['username'], base64.b64decode(obj['pwd']).decode())
                except Exception as e:
                    print("DB ERROR DURING REGISTRATION:", e)
                    ok = False
                conn.sendall((json.dumps({'type':'register result','ok': ok})+'\n').encode())
                if not ok:
                    print("Registration failed for", obj.get('username'))
                    conn.close()
                    return
                else:
                    print("Registration succeeded for", obj.get('username'))
                    # Continue loop: expect a login enc next from client
                    continue

            elif obj.get('type') == 'login':
                try:
                    ok = db.verify_user(obj['email'], base64.b64decode(obj['pwd']).decode())
                except Exception as e:
                    print("DB ERROR DURING LOGIN:", e)
                    ok = False
                conn.sendall((json.dumps({'type':'login result','ok': ok})+'\n').encode())
                if not ok:
                    print("Login failed for", obj.get('email'))
                    conn.close()
                    return
                # login succeeded -> break out and continue to session DH
                print("Login succeeded for", obj.get('email'))
                break
            else:
                conn.sendall((json.dumps({'type':'error','msg':'unknown payload type'})+'\n').encode())
                conn.close()
                return
        except Exception as e:
            print("Exception handling enc payload:", e)
            conn.close()
            return

    # ---------- Now perform fresh DH with client for session key ----------
    # Expect client's DH client message (A2)
    dhc2 = recv_json_line(conn, timeout=10)
    if not dhc2:
        print("No DH2 from client (timeout/closed)")
        conn.close()
        return
    try:
        g2 = dhc2['g']; p2 = dhc2['p']; A2 = dhc2['A']
    except Exception as e:
        print("Malformed DH2 from client:", e, "data:", dhc2)
        conn.close()
        return

    # server generates b2 and sends B2
    b2 = dh.dh_generate_private(128)
    B2 = dh.dh_public(g2, p2, b2)
    conn.sendall((json.dumps({'type':'dh server','B':B2})+'\n').encode())

    ks2 = dh.dh_shared_secret(A2, b2, p2)
    K_sess = dh.derive_aes_key_from_ks(ks2)

    # ---------- Messaging loop using K_sess ----------
    my_key = load_priv_key(SERVER_KEY)
    server_cert = pki.load_cert(str(SERVER_CERT))
    client_cert = pki.load_cert_bytes(client_cert_pem.encode())
    client_fp = pki.fingerprint_sha256_hex(client_cert)

    tx = transcript.Transcript('server_session')
    last_seq_received = 0
    seqno_to_client = 0

    while True:
        obj = recv_json_line(conn, timeout=None)
        if not obj:
            break
        if obj.get('type') == 'msg':
            rseq = obj['seqno']; rts = obj['ts']; rct = obj['ct']; rsig = obj['sig']
            # timestamp check
            if abs(now_ms() - rts) > TIME_SKEW_MS:
                print('Dropping message with bad timestamp')
                continue
            if rseq <= last_seq_received:
                print('Replay detected; dropping')
                continue
            # verify signature
            sender_pub = client_cert.public_key()
            meta = f"{rseq}|{rts}|{rct}".encode()
            import hashlib
            if not sign.rsa_verify_b64(sender_pub, hashlib.sha256(meta).digest(), rsig):
                print('Signature invalid; dropping')
                continue
            # decrypt and display
            try:
                pt = aes.decrypt_ecb_b64(K_sess, rct).decode()
            except Exception as e:
                print('Decrypt failed', e); continue
            print(f"[client] {pt}")
            last_seq_received = rseq
            tx.append_line(rseq, rts, rct, rsig, client_fp)

            # send an echoed message back signed
            seqno_to_client += 1
            ts = now_ms()
            reply = f"ECHO: {pt}"
            ct_b64 = aes.encrypt_ecb_b64(K_sess, reply.encode())
            meta2 = f"{seqno_to_client}|{ts}|{ct_b64}".encode()
            sig_b64 = sign.rsa_sign_b64(my_key, __import__('hashlib').sha256(meta2).digest())
            send_obj = {'type':'msg','seqno':seqno_to_client,'ts':ts,'ct':ct_b64,'sig':sig_b64}
            conn.sendall((json.dumps(send_obj)+'\n').encode())
            tx.append_line(seqno_to_client, ts, ct_b64, sig_b64, client_fp)
        elif obj.get('type') == 'receipt':
            # client sent its receipt; verify and reply ack
            print('Received receipt from client:', obj.get('payload',{}).get('transcript_sha256'))
            receipt = tx.export_receipt(my_key, 'server', 1, last_seq_received or 0)
            conn.sendall((json.dumps({'type':'receipt_ack','payload':receipt})+'\n').encode())
        else:
            print('Unknown message type', obj.get('type'))

    conn.close()

def run_server(host='0.0.0.0', port=9000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print('Server listening', host, port)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__=='__main__':
    run_server()