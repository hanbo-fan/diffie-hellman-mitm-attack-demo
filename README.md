# Diffie-Hellman MITM Attack Demo (Python)
- This project demonstrates a practical Man-in-the-Middle (MITM) attack on the Diffie-Hellman (DH) key exchange protocol using ARP spoofing in a 3-VM isolated lab environment.
- The implementation includes 4 scenarios:
    - Normal DH key exchange
    - MITM attack without authentication
    - MITM prevented by PSK authentication
    - MITM successful with leaked PSK

## 1. Diffie-Hellman Key Exchange
- This project implements an authenticated key exchange based on X25519 (Elliptic Curve Diffie-Hellman).
- During the handshake, both parties exchange public keys and compute a shared secret:
    - shared = priv_A * pub_B = priv_B * pub_A
- The shared secret is then processed through HKDF-SHA256 to derive a 256-bit AES symmetric key for authenticated encryption.
- Optional PSK-based authentication is implemented using HMAC-SHA256 to bind the handshake parameters and prevent MITM attacks.
```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    Note over C,S: Step 1 — Generate Keypair
    Note over C: generate (client_priv, client_pub)
    Note over S: generate (server_priv, server_pub)
    Note over C,S: Step 2 — Exchange Public Keys
    S->>C: server_pub
    C->>S: client_pub
    Note over C,S: Step 3 — Compute Shared Secret
    Note over C: shared = client_priv · server_pub
    Note over S: shared = server_priv · client_pub
    Note over C,S: Step 4 — Salt Transmission
    S->>C: salt (random 16 bytes)
    Note over C,S: Step 5 & 6 — PSK Authentication (optional)
    S->>C: server_tag = HMAC(PSK, "SERVER"||salt||server_pub||client_pub||shared)
    Note over C: verify server_tag
    C->>S: client_tag = HMAC(PSK, "CLIENT"||salt||client_pub||server_pub||shared)
    Note over S: verify client_tag
    Note over C,S: Step 7 — Derive AES Key: key = HKDF(shared, salt)
    Note over C,S: Step 8 — Encrypted Communication
    C->>S: nonce + AES-GCM(key, message)
    S->>C: nonce + AES-GCM(key, "ACK from server")
```

## 2. MITM Attack
- Diffie-Hellman alone does not provide authentication.
- The attacker can:
    - Perform ARP spoofing to intercept traffic
    - Replace public keys during handshake
    - Establish two independent shared secrets:
        - Client ↔ Attacker
        - Attacker ↔ Server
    - Transparently decrypt, modify, and re-encrypt messages
- The attacker then acts as a transparent bidirectional TCP proxy, stripping the encryption of one session and re-encrypting it for the other.
```mermaid
sequenceDiagram
    participant C as Client
    participant M as Attacker (MITM)
    participant S as Server

    Note over C,S: Step 1 — Generate Keypair
    Note over C: generate (client_priv, client_pub)
    Note over M: generate (fake_for_client_priv, fake_for_client_pub)
    Note over M: generate (fake_for_server_priv, fake_for_server_pub)
    Note over S: generate (server_priv, server_pub)

    Note over C,S: Step 2 — Intercept and Hijack Public Keys
    S->>M: server_pub
    M->>C: fake_for_client_pub
    C->>M: client_pub
    M->>S: fake_for_server_pub

    Note over C,S: Step 3 — Compute Two Shared Secrets
    Note over M: shared_client = <br/>fake_for_client_priv · client_pub
    Note over M: shared_server = <br/>fake_for_server_priv · server_pub

    Note over C,S: Step 4 — Salt Transmission
    S->>M: salt
    M->>C: salt

    Note over C,S: Step 5 & 6 — PSK Authentication (optional)
    S->>M: server_tag
    Note over M: ⚠ skip verification
    M->>S: fake_client_tag = HMAC(PSK, <br/>"CLIENT"||salt||fake_for_server_pub<br/>||server_pub||shared_server)
    Note over S: verify fake_client_tag
    M->>C: fake_server_tag = HMAC(PSK, <br/>"SERVER"||salt||fake_for_client_pub<br/>||client_pub||shared_client)
    Note over C: verify fake_server_tag
    C->>M: client_tag
    Note over M: ⚠ skip verification

    Note over C,S: Step 7 — Derive Two AES Keys
    Note over M: key_client = HKDF(shared_client, salt)
    Note over M: key_server = HKDF(shared_server, salt)

    Note over C,S: Step 8 — Intercepted Encrypted Communication
    C->>M: nonce + AES-GCM(key_client, message)
    Note over M: decrypt with key_client → plaintext → tamper → re-encrypt with key_server
    M->>S: nonce + AES-GCM<br/>(key_server, tampered_message)
    S->>M: nonce + AES-GCM<br/>(key_server, "ACK from server")
    Note over M: decrypt with key_server → plaintext → tamper → re-encrypt with key_client
    M->>C: nonce + AES-GCM(key_client, tampered_ACK)
```

## 3. PSK-based Authentication Defense
- To mitigate MITM attacks, a Pre-Shared Key (PSK) is introduced.
- The authentication tag is computed as:
    - HMAC(key = PSK, role || salt || pub_self || pub_peer || shared_secret)
- If the attacker does not possess the correct PSK:
    - Authentication fails
    - The connection is terminated
- If the PSK is leaked:
    - The attacker can successfully authenticate both sides
    - MITM becomes possible again

## 4. Lab Environment
- 3 Virtual Machines under "Internal Network" mode.
    - Client (192.168.1.10)
    - Server (192.168.1.20)
    - Attacker (192.168.1.30)
- ARP spoofing for traffic interception
- Isolated network for safety
```mermaid
graph TD
    subgraph Internal Network 192.168.1.0/24
        C["🖥 Client<br/>192.168.1.10"]
        S["🖥 Server<br/>192.168.1.20"]
        M["🖥 Attacker<br/>192.168.1.30"]
    end

    C -- "TCP :50000<br/>(ARP spoofed → redirected <br/>to Attacker)" --> M
    M -- "TCP :50000<br/>(forwarded to real Server)" --> S
    M -. "ARP spoofing<br/>poison Client's ARP table" .-> C
    M -. "ARP spoofing<br/>poison Server's ARP table" .-> S
```
## 5. How to Run
- Install dependencies
    - pip install cryptography
- Scenario 1: Normal DH
    - python server.py
    - python client.py
- Scenario 2–4: MITM
    - python server.py
    - python attacker.py
    - python client.py
- Scenario 3 (Defense): Attacker uses false PSK -> Authentication fails.
- Scenario 4 (Leaked): Attacker uses true PSK -> MITM succeeds.

- Follow the prompts to enable/disable PSK authentication
- Important: The PSK authentication setting must be consistent across all parties.

## 6. Educational Purpose
**This project is intended for educational and research purposes only.**

## 7. License
- MIT License
