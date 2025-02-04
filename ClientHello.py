import os
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

from KeySchedule import KeySchedule

class ClientHello:
    def __init__(self):
        self.legacy_version = 0x0303  # ProtocolVersion
        self.random = os.urandom(32)  # 32 bytes of random data
        self.legacy_session_id_length = b'\x00\x00'  # Length 0
        self.cipher_suites = [0x1301]  # TLS_AES_128_GCM_SHA256 (example cipher suite)
        self.legacy_compression_methods = [0x00]  # NULL compression method
        self.private_key = None  # To store the ECDH private key
        self.supported_groups = [0x0017] # secp256r1
        self.signature_algorithms = [0x0804] # rsa_pss_rsae_sha256

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
        cl_hello_payload = client_hello_base + struct.pack('!H', len(extensions)) + extensions
        #cl_hello_msg = hs_header(1, len(cl_hello_payload)) + cl_hello_payload
        # self.key_sched.addMsg(cl_hello_msg)
        return cl_hello_payload

    def _build_extensions(self):
        # Use TLSextention.make to build each extension
        extensions = []

        # server_name
        # server_name_str = "server".encode()
        # base_server_name = b'\x00' + len(server_name_str).to_bytes(2, 'big') + server_name_str
        # server_name = struct.pack('!H', len(base_server_name)) + base_server_name
        # extensions.append(self._make_extension(0, server_name))

        # renegotiation_info
        # base_renegotiation_info = b"\x00"
        # renegotiation_info = base_renegotiation_info # No length
        # extensions.append(self._make_extension(65281, renegotiation_info))

        # supported_groups
        supported_groups = struct.pack('!H', len(self.supported_groups) * 2) + b''.join(struct.pack('!H', sg) for sg in self.supported_groups)
        extensions.append(self._make_extension(10, supported_groups))

        # session_ticket
        # session_ticket = b""
        # extensions.append(self._make_extension(35, session_ticket))

        # key_share
        key_share_data = self._make_key_share()
        extensions.append(self._make_extension(51, key_share_data))

        # supported_versions
        supported_versions = struct.pack('!B', len(b'\x03\x04')) + b'\x03\x04'  # Length 1 byte + TLS 1.3
        extensions.append(self._make_extension(43, supported_versions))

        # signature_algorithms
        signature_algorithms = struct.pack('!H', len(self.signature_algorithms) * 2) + b''.join(struct.pack('!H', sa) for sa in self.signature_algorithms)
        extensions.append(self._make_extension(13, signature_algorithms))

        # psk_key_exchange_modes
        # psk_key_exchange_mode = struct.pack('!B', len(b'\x01')) + b'\x01' # psk_dhe_ke
        # extensions.append(self._make_extension(45, psk_key_exchange_mode))

        # recode_size_limit
        # recode_size_limit = int(16385).to_bytes(2, 'big')
        # recode_size_limit_data = recode_size_limit
        # extensions.append(self._make_extension(28, recode_size_limit_data))

        # encrypt_then_mac
        extensions.append(self._make_extension(22, b''))

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
