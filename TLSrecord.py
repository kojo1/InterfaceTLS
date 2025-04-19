import struct
import socket

def tls_header(content_type: int, data_len: int):
    version = 0x0303  # TLS 1.2 or 1.3 (use the same record version for both)

    if data_len > 2**14:
        raise ValueError("Data too large for a single TLS record.")

    header = struct.pack('!BHH', content_type, version, data_len)
    return header

def separate_tls_msg(tls_msg: bytes):
    content_type = tls_msg[0]
    version = tls_msg[1:3]
    data_len = tls_msg[3:5]
    data = tls_msg[5:]

    return content_type, version, data_len, data

class TLSrecord:
    def __init__(self, sock: socket.socket):

        self.sock = sock

    def send(self, tls_msg: bytes):
        self.sock.sendall(tls_msg)

    def recv(self):
        header = self._recv_exact(5)
        content_type, version, length = struct.unpack('!BHH', header)
        if length > 2**14:
            raise ValueError("Received record exceeds maximum allowed length.")
        data = self._recv_exact(length)
        return header + data

    def _recv_exact(self, n: int) -> bytes:
        buffer = b''
        while len(buffer) < n:
            chunk = self.sock.recv(n - len(buffer))
            if not chunk:
                raise ConnectionError("Socket connection broken.")
            buffer += chunk
        return buffer
