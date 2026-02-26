# server.py
import socket, os, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import generate_keypair, compute_shared_secret, derive_aes_key
from network_utils import recv_exact, recv_frame, send_frame

host, port = "192.168.1.20", 50000

PSK = b"my-super-secret-preshared-key-32bytes!!"
use_psk = False

def handle_client(conn, addr):
    global use_psk
    # 1. generates keypair
    server_priv, server_pub_bytes = generate_keypair()
    
    try:
        with conn:
            # 2. exchange pub key (receive client pub and send server pub)
            send_frame(conn, server_pub_bytes) # [connect (a)] send public key to client

            client_pub_bytes = recv_frame(conn) # [connect (b)] receive public key from client
            #print(f"[server] received client public key: {client_pub_bytes} (length: {len(client_pub_bytes)})")

            if len(client_pub_bytes) != 32:
                raise ValueError("Invalid client public key length")
            
            # 3. compute shared secret
            shared = compute_shared_secret(server_priv, client_pub_bytes)
            
            # 4. generate a random salt sent to client
            salt = AESGCM.generate_key(bit_length=128) # 16 bytes random       
            send_frame(conn, salt) # [connect (c)] send salt to client
            
            if use_psk:
                # 5. compute and send server tag
                from crypto_utils import verify_psk_auth_tag, compute_psk_auth_tag          
                
                server_tag = compute_psk_auth_tag(PSK, salt, "SERVER", server_pub_bytes, client_pub_bytes, shared)
                send_frame(conn, server_tag) # [connect (d)] send server tag
                
                # 6. receive and verify client tag
                client_tag = recv_frame(conn) # [connect (e)] receive client tag
                if not verify_psk_auth_tag(PSK, salt, "CLIENT", client_pub_bytes, server_pub_bytes, shared, client_tag):
                    print("[Server] Client authentication FAILED!")
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                print("[Server] Client authenticated")
            
            # 7. derive AES key
            key = derive_aes_key(shared, salt)
            aesgcm = AESGCM(key)
            print(f"[server] derived shared key {key} (length: {len(key)})")
            
            # 8. begin encrypted communication
            # 8-1 Receive encrypted message from client: nonce(12) + ciphertext
            while True:
                print(f"[server] waiting for client's message...")
                blob = recv_frame(conn) # [connect (f)] receive encrypted message from client

                if len(blob) < 12:
                    raise ValueError("Invalid encrypted blob")
                nonce, ct = blob[:12], blob[12:]
                #print(f"[server] received nonce: {nonce} (length: {len(nonce)})")

                plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
                print(f"[server] received plaintext: {plaintext.decode('utf-8', errors='replace')}")

                # 8-2 Reply with encrypted "ACK"
                reply = b"ACK from server"
                reply_nonce = os.urandom(12)  # 12 bytes random
                #print(f"[server] generated reply_nonce: {reply_nonce} (length: {len(reply_nonce)})")

                reply_ct = aesgcm.encrypt(reply_nonce, reply, associated_data=None)
                send_frame(conn, reply_nonce + reply_ct) # [connect (g)] send ACK to client
                print("[server] sent encrypted ACK")

    except ConnectionError:
        print(f"[server] Client {addr} closed.")
    except Exception as e:
        print(f"[server] Error occurred: {e}")
    finally:
        print(f"[server] keep listening on {host}:{port}...")

def main():
    global use_psk
    
    print("=" * 50)
    print("Diffie-Hellman Key Exchange Demo (Server)")
    print("=" * 50)
    choice = input("Enable PSK authentication? (y/n, default=n): ").lower()
    use_psk = (choice in ['y', 'yes'])
    
    if use_psk:
        print("PSK mode is turned on!")
    else:
        print("PSK mode is turned off!")
    print("=" * 50)
    
    try:
        # 0-preparation (bind a socket, listening to client and accept connection)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen(1)
            print(f"[server] listening on {host}:{port}...")

            while(True):
                # a new client connects to server
                conn, addr = s.accept()
                print(f"[server] client connected from {addr}")

                # create a new thread to handle the client
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
    except Exception as e:
        print(f"[server] Error occurred: {e}")

if __name__ == "__main__":
    main()
