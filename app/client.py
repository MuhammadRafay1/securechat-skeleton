import socket, json, os
from app.common import utils, protocol
from app.crypto import pki, dh, aes, sign
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64, time

CERTS = Path('certs')
CA_CERT = CERTS/'ca.crt'
CLIENT_KEY = CERTS/'client.local.key'
CLIENT_CERT = CERTS/'client.local.crt'

TIME_SKEW_MS = 60 * 1000  # 60 seconds allowed skew

def load_priv_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

def now_ms():
    return int(time.time() * 1000)

def run_client(server_host='127.0.0.1', server_port=9000):
    # load client cert/key
    ca = pki.load_cert(str(CA_CERT))
    my_key = load_priv_key(CLIENT_KEY)
    my_cert_pem = CLIENT_CERT.read_text()
    my_cert = pki.load_cert_bytes(my_cert_pem.encode())

    s = socket.create_connection((server_host, server_port))
    # send hello with cert and nonce
    nonce = base64.b64encode(os.urandom(12)).decode()
    hello = {'type':'hello', 'cert': my_cert_pem, 'nonce': nonce}
    s.sendall((json.dumps(hello)+'\n').encode())

    # receive server hello
    data = s.recv(65536).decode()
    srv = json.loads(data.strip())
    srv_cert_pem = srv['cert']
    server_cert = pki.load_cert_bytes(srv_cert_pem.encode())
    # verify server cert using CA and CN match to server_host
    try:
        pki.verify_cert_with_ca(server_cert, ca)
        if not pki.cert_cn_matches(server_cert, 'server.local'):
            raise ValueError('Server CN does not match expected name server.local')
    except Exception as e:
        print('Server certificate validation failed:', e)
        s.close()
        return
    print('Server certificate validated')

    # temporary DH to derive AES for registration/login
    p = 0xFFFFFFFB
    g = 5
    a = dh.dh_generate_private(128)
    A = dh.dh_public(g, p, a)
    dhmsg = {'type':'dh client','g':g,'p':p,'A':A}
    s.sendall((json.dumps(dhmsg)+'\n').encode())
    data = s.recv(65536).decode()
    srvB = json.loads(data.strip())
    B = srvB['B']
    ks = dh.dh_shared_secret(B, a, p)
    K = dh.derive_aes_key_from_ks(ks)

    # Choose action
    action = input('action (register/login): ').strip().lower()
    if action == 'register':
        email = input('Email: ')
        username = input('Username: ')
        password = input('Password: ')
        payload = {'type':'register','email':email,'username':username,'pwd':base64.b64encode(password.encode()).decode()}
        ct = aes.encrypt_ecb_b64(K, json.dumps(payload).encode())
        s.sendall((json.dumps({'type':'enc','payload':ct})+'\n').encode())
        data = s.recv(65536).decode()
        res = json.loads(data.strip())
        print('Register result:', res)
        s.close()
        return

    # LOGIN flow
    if action == 'login':
        email = input('Email: ')
        password = input('Password: ')
        payload = {'type':'login','email':email,'pwd':base64.b64encode(password.encode()).decode()}
        ct = aes.encrypt_ecb_b64(K, json.dumps(payload).encode())
        s.sendall((json.dumps({'type':'enc','payload':ct})+'\n').encode())
        data = s.recv(65536).decode()
        res = json.loads(data.strip())
        if not res.get('ok'):
            print('Login failed:', res.get('msg'))
            s.close()
            return
        print('Login OK. Proceeding to session DH...')

    # After successful login, perform a fresh DH for session key
    a2 = dh.dh_generate_private(128)
    A2 = dh.dh_public(g, p, a2)
    s.sendall((json.dumps({'type':'dh client','g':g,'p':p,'A':A2})+'\n').encode())
    data = s.recv(65536).decode()
    srvB2 = json.loads(data.strip())
    B2 = srvB2['B']
    ks2 = dh.dh_shared_secret(B2, a2, p)
    K_sess = dh.derive_aes_key_from_ks(ks2)

    # Enter messaging loop: send messages signed and encrypted
    from app.storage import transcript as txmod
    my_transcript = txmod.Transcript('client_session')
    seqno = 0
    last_received_seq = 0

    print('Enter messages. Type /quit to end and create receipt.')
    while True:
        msg = input('> ')
        if msg.strip() == '/quit':
            break
        seqno += 1
        ts = now_ms()
        ct_b64 = aes.encrypt_ecb_b64(K_sess, msg.encode())
        # compute digest over seqno||ts||ct as bytes
        meta = f"{seqno}|{ts}|{ct_b64}".encode()
        sig_b64 = sign.rsa_sign_b64(my_key, __import__('hashlib').sha256(meta).digest())
        to_send = {'type':'msg','seqno':seqno,'ts':ts,'ct':ct_b64,'sig':sig_b64}
        s.sendall((json.dumps(to_send)+'\n').encode())
        # append our transcript line with peer fingerprint
        peer_fp = pki.fingerprint_sha256_hex(server_cert)
        my_transcript.append_line(seqno, ts, ct_b64, sig_b64, peer_fp)

        # wait for server reply (echo or message)
        try:
            data = s.recv(65536).decode()
            if not data:
                print('Server closed connection')
                break
            obj = json.loads(data.strip())
            if obj.get('type') == 'msg':
                # verify seqno and timestamp
                rseq = obj['seqno']; rts = obj['ts']; rct = obj['ct']; rsig = obj['sig']
                # timestamp check
                now = now_ms()
                if abs(now - rts) > TIME_SKEW_MS:
                    print('Received message with invalid timestamp. Dropping.')
                    continue
                if rseq <= last_received_seq:
                    print('Replay/old message detected. Dropping.')
                    continue
                # verify signature
                sender_pub = pki.load_cert_bytes(srv_cert_pem.encode()).public_key()
                meta_r = f"{rseq}|{rts}|{rct}".encode()
                import base64, hashlib
                if not sign.rsa_verify_b64(sender_pub, __import__('hashlib').sha256(meta_r).digest(), rsig):
                    print('Signature verification failed for incoming message.')
                    continue
                # decrypt
                pt = aes.decrypt_ecb_b64(K_sess, rct).decode()
                print(f"[server] {pt}")
                last_received_seq = rseq
                # append transcript
                my_transcript.append_line(rseq, rts, rct, rsig, pki.fingerprint_sha256_hex(server_cert))
            elif obj.get('type') == 'receipt_ack':
                print('Received server receipt ack:', obj)
        except Exception as e:
            print('Error receiving:', e)
            break

    # session closure: export receipt and send to server
    receipt = my_transcript.export_receipt(my_key, 'client', 1, seqno)
    s.sendall((json.dumps({'type':'receipt','payload':receipt})+'\n').encode())
    print('Sent receipt to server. Closing.')
    s.close()

if __name__=='__main__':
    run_client()
