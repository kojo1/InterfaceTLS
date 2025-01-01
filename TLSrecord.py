import struct
import socket

class TLSrecord:
    def __init__(self, sock: socket.socket):
        """
        Initialize with a socket instance.
        
        :param sock: A socket object used for communication.
        """
        self.sock = sock

    def send(self, content_type: int, data: bytes):
        """
        Send data with a TLS record header.
        
        :param content_type: Content type (e.g., 22 for handshake, 23 for application data).
        :param data: The data to send.
        """
        version = 0x0303  # TLS 1.2 or 1.3 (use the same record version for both)
        length = len(data)

        if length > 2**14:
            raise ValueError("Data too large for a single TLS record.")

        # Create the TLS record header
        header = struct.pack('!BHH', content_type, version, length)

        # Send the header and data
        self.sock.sendall(header + data)

    def recv(self):
        """
        Receive and parse a TLS record.
        
        :return: A tuple (content_type, data).
        """
        # Read the header (5 bytes)
        header = self._recv_exact(5)
        content_type, version, length = struct.unpack('!BHH', header)

        if length > 2**14:
            raise ValueError("Received record exceeds maximum allowed length.")

        # Read the payload
        data = self._recv_exact(length)
        return content_type, data

    def _recv_exact(self, n: int) -> bytes:
        """
        Receive exactly `n` bytes from the socket.
        
        :param n: Number of bytes to read.
        :return: The received bytes.
        """
        buffer = b''
        while len(buffer) < n:
            chunk = self.sock.recv(n - len(buffer))
            if not chunk:
                raise ConnectionError("Socket connection broken.")
            buffer += chunk
        return buffer

# Example usage:
# sock = socket.create_connection(("example.com", 443))
# tls_record = TLSRecord(sock)
# tls_record.send(23, b"Hello, TLS!")
# content_type, data = tls_record.recv()
# print(f"Received content type: {content_type}, data: {data}")
