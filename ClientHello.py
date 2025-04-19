import os
import struct

from SslKeyLog import SslKeyLog #keyLog for Wireshark
from wolfcrypt.ciphers import EccPrivate

from KeySchedule import KeySchedule

class ClientHello:
    def __init__(self, keylog):
        self.legacy_version = 0x0303  # ProtocolVersion
        self.random = os.urandom(32)  # 32 bytes of random data
        self.legacy_session_id_length = b'\x00\x00'  # Length 0
        self.cipher_suites = [0x1301]  # TLS_AES_128_GCM_SHA256 (example cipher suite)
        self.legacy_compression_methods = [0x00]  # NULL compression method
        self.private_key = None  # To store the ECDH private key
        self.supported_groups = [0x0017] # secp256r1
        self.signature_algorithms = [0x0804] # rsa_pss_rsae_sha256
        
        self.keylog = keylog #for Wireshark

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

        self.keylog.setClientRnd(self.random)

        return cl_hello_payload

    def _build_extensions(self):
        # Use TLSextention.make to build each extension
        extensions = []

        # supported_groups
        supported_groups = struct.pack('!H', len(self.supported_groups) * 2) + b''.join(struct.pack('!H', sg) for sg in self.supported_groups)
        extensions.append(self._make_extension(10, supported_groups))

        # key_share
        key_share_data = self._make_key_share()
        extensions.append(self._make_extension(51, key_share_data))

        # supported_versions
        supported_versions = struct.pack('!B', len(b'\x03\x04')) + b'\x03\x04'  # Length 1 byte + TLS 1.3
        extensions.append(self._make_extension(43, supported_versions))

        # signature_algorithms
        signature_algorithms = struct.pack('!H', len(self.signature_algorithms) * 2) + b''.join(struct.pack('!H', sa) for sa in self.signature_algorithms)
        extensions.append(self._make_extension(13, signature_algorithms))

        # encrypt_then_mac
        extensions.append(self._make_extension(22, b''))

        # Combine all extensions
        return b''.join(extensions)

    def _make_extension(self, extension_type, extension_data):
        extension_length = len(extension_data)
        return struct.pack('!HH', extension_type, extension_length) + extension_data

    def _make_key_share(self):
        # Generate ECDH key pair using secp256r1
        self.private_key = EccPrivate.make_key(32)  # 32 bytes key length for secp256r1
        qx, qy, d = self.private_key.encode_key_raw()  # qx and qy are the public key, d is the private key
        legacy_form = 4
        serialized_public_key = legacy_form.to_bytes(1, 'big') + qx + qy

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
        return self.private_key
