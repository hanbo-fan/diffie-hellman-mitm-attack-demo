# network_utils.py
import socket, struct

def recv_exact(conn: socket.socket, n: int) -> bytes:
    # Receive exactly n bytes or raise
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data += chunk
    return data

def recv_frame(conn: socket.socket) -> bytes:
    # Frame format: 4-byte big-endian length + payload
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    if length > 10 * 1024 * 1024:
        raise ValueError("Frame too large")
    return recv_exact(conn, length)

def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack("!I", len(payload)) + payload)
