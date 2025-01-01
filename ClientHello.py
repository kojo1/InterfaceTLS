import os
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

class ClientHello:
    def __init__(self):
        self.legacy_version = 0x0303  # ProtocolVersion
        self.random = os.urandom(32)  # 32 bytes of random data
        self.legacy_session_id_length = b'\x00\x00'  # Length 0
        self.cipher_suites = [0x1301]  # TLS_AES_128_GCM_SHA256 (example cipher suite)
        self.legacy_compression_methods = [0x00]  # NULL compression method
        self.private_key = None  # To store the ECDH private key

    def make(self):
        # Build the non-extension part of ClientHello
        client_hello_base = struct.pack(
            '!H32s2sB', 
            self.legacy_version,
            self.random,
            self.legacy_session_id_length,
            len(self.cipher_suites) * 2
        ) + b''.join(struct.pack('!H', suite) for suite in self.cipher_suites) + struct.pack(
            '!B', 
            len(self.legacy_compression_methods)
        ) + b''.join(struct.pack('!B', method) for method in self.legacy_compression_methods)

        # Add extensions
        extensions = self._build_extensions()
        client_hello_message = client_hello_base + struct.pack('!H', len(extensions)) + extensions
        return client_hello_message

    def _build_extensions(self):
        # Use TLSextention.make to build each extension
        extensions = []

        # supported_versions
        supported_versions = struct.pack('!B', len(b'\x03\x04')) + b'\x03\x04'  # Length 1 byte + TLS 1.3
        extensions.append(self._make_extension(43, supported_versions))

        # signature_algorithms
        signature_algorithms = struct.pack('!H', len(b'\x08\x04')) + b'\x08\x04'  # rsa_pss_rsae_sha256
        extensions.append(self._make_extension(13, signature_algorithms))

        # supported_groups
        supported_groups = struct.pack('!H', len(b'\x00\x17')) + b'\x00\x17'  # secp256r1
        extensions.append(self._make_extension(10, supported_groups))

        # encrypt_then_mac
        extensions.append(self._make_extension(22, b''))

        # key_share
        key_share_data = self._make_key_share()
        extensions.append(self._make_extension(51, key_share_data))

        # Combine all extensions
        return b''.join(extensions)

    def _make_extension(self, extension_type, extension_data):
        extension_length = len(extension_data)
        return struct.pack('!HH', extension_type, extension_length) + extension_data

    def _make_key_share(self):
        # Generate ECDH key pair using secp256r1
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = self.private_key.public_key()

        # Serialize the public key using X9.62 UncompressedPoint format
        serialized_public_key = public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint
        )

        # Construct key_share extension data
        group_id = b'\x00\x17'  # secp256r1
        key_exchange_length = len(serialized_public_key)
        key_share_entry = struct.pack('!H', len(group_id) + 2 + key_exchange_length) + group_id + struct.pack(
            '!H', key_exchange_length
        ) + serialized_public_key

        return key_share_entry

    def getPriv(self):
        """Retrieve the ECDH private key in DER format."""
        if self.private_key is None:
            raise ValueError("Private key has not been generated yet.")
        return self.private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
