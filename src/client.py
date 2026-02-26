# client.py
import socket, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import generate_keypair, compute_shared_secret, derive_aes_key
from network_utils import recv_exact, recv_frame, send_frame

server_ip, server_port = "192.168.1.20", 50000

PSK = b"my-super-secret-preshared-key-32bytes!!"

def main(host: str, port: int) -> None:
    print("=" * 50)
    print("Diffie-Hellman Key Exchange Demo (Client)")
    print("=" * 50)
    choice = input("Enable PSK authentication? (y/n, default=n): ").lower()
    use_psk = (choice in ['y', 'yes'])
    
    if use_psk:
        print("PSK mode is turned on!")
    else:
        print("PSK mode is turned off!")
    print("=" * 50)
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
            # 0-prepare socket and connect to server
            c.connect((host, port))
            local_addr = c.getsockname()
            print(f"[client] connected to server '{host}: {port}' from my local port {local_addr[1]}")
            
            # 1-generates keypair
            client_priv, client_pub_bytes = generate_keypair()

            # 2-exchange pub key (receive server pub and send client pub)
            server_pub_bytes = recv_frame(c) # [connect (a)] receive public key from server
            #print(f"[client] received server public key: {server_pub_bytes} (length: {len(server_pub_bytes)})")

            if len(server_pub_bytes) != 32:
                raise ValueError("Invalid server public key length")

            send_frame(c, client_pub_bytes) # [connect (b)] send public key to server
            
            # 3-Compute shared secret
            shared = compute_shared_secret(client_priv, server_pub_bytes)
            
            # 4-receive random salt from server
            salt = recv_frame(c) # [connect-(c)] receive salt from server
            
            if use_psk:
                # 5-receive and verify server tag
                from crypto_utils import verify_psk_auth_tag, compute_psk_auth_tag
                
                server_tag = recv_frame(c) # [connect (d)] receive server tag
                if not verify_psk_auth_tag(PSK, salt, "SERVER", server_pub_bytes, client_pub_bytes, shared, server_tag):
                    print("[Client] Server authentication FAILED!")
                    c.shutdown(socket.SHUT_RDWR)
                    return
                print("[Client] Server authenticated")
                
                # 6-compute and send client tag
                client_tag = compute_psk_auth_tag(PSK, salt, "CLIENT", client_pub_bytes, server_pub_bytes, shared)
                send_frame(c, client_tag)  # [connect (e)] send client tag

            if len(salt) != 16:
                raise ValueError("Invalid salt length")
            
            # 7-derive AES key
            key = derive_aes_key(shared, salt)
            aesgcm = AESGCM(key)
            print(f"[client] derived shared key {key} (length: {len(key)})")

            # 8-begin encrypted communication
            # 8-1 Send encrypted message
            while True:
                user_input = input("Enter message to send (or -1 to exit): ")
                if user_input == "-1":
                    print("[client] Exiting...")
                    c.shutdown(socket.SHUT_RDWR)
                    break

                msg = user_input.encode('utf-8')
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, msg, None)

                send_frame(c, nonce + ct) # [connect (f)] send encrypted message to server
                print(f"[client] sent encrypted message {msg}")

                # 8-2 Receive encrypted ACK
                print(f"[client] waiting for server's message...")
                blob = recv_frame(c) # [connect (g)] receive ACK from client
                if len(blob) < 12:
                    raise ValueError("Invalid encrypted blob")
                r_nonce, r_ct = blob[:12], blob[12:]
                ack = aesgcm.decrypt(r_nonce, r_ct, associated_data=None)
                print(f"[client] received plaintext: {ack.decode('utf-8', errors='replace')}")
    except ConnectionError:
        print(f"[client] Connection closed by server.")
    except Exception as e:
        print(f"[client] Error occurred: {e}")

if __name__ == "__main__":
    main(host = server_ip, port = server_port)
