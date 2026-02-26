# crypto_utils.py
import hmac, hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_keypair():
    priv = x25519.X25519PrivateKey.generate() # 32-byte random number
    priv_bytes = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )

    pub = priv.public_key() # 32-byte public key generated from private key.02.032
    pub_bytes = pub.public_bytes(
        encoding = Encoding.Raw,
        format = PublicFormat.Raw
    )

    #print(f"[server] key pair generated with client {addr}")
    #print(f"[server] private key: {priv_bytes} (length: {len(priv_bytes)})")
    #print(f"[server] public key: {pub_bytes} (length: {len(pub_bytes)})")
    return priv, pub_bytes
    
def compute_shared_secret(this_priv, oppo_pub_bytes):
    oppo_pub = x25519.X25519PublicKey.from_public_bytes(oppo_pub_bytes)
    shared = this_priv.exchange(oppo_pub) # shared = this_priv * oppo_pub
    return shared

# Derive 32-byte AES key from ECDH shared secret using HKDF
def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    # Derive 32-byte AES key from ECDH shared secret using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"dh-demo-aesgcm-v1",
    )
    key = hkdf.derive(shared_secret)
    return key

# compute pre-shared key authentication tag
def compute_psk_auth_tag(psk: bytes, salt: bytes, role: str, 
                        my_pub: bytes, peer_pub: bytes, shared_secret: bytes) -> bytes:
    # tag = HMAC-SHA256(key=PSK, msg=role||salt||my_pub||peer_pub||shared_secret)
    message = role.encode() + salt + my_pub + peer_pub + shared_secret
    return hmac.new(psk, message, hashlib.sha256).digest()

# verify pre-shared key authentication tag
def verify_psk_auth_tag(psk: bytes, salt: bytes, role: str, 
                        my_pub: bytes, peer_pub: bytes, shared_secret: bytes,
                        received_tag: bytes) -> bool:
    # recompute tag and compare with the received one
    expected = compute_psk_auth_tag(psk, salt, role, my_pub, peer_pub, shared_secret)
    return hmac.compare_digest(expected, received_tag)
