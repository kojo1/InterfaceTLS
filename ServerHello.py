import logging

from wolfcrypt.ciphers import EccPublic

class ServerHello:
    def __init__(self):
        self.server_version = None
        self.random = None
        self.session_id = None
        self.cipher_suite = None
        self.compression_method = None
        self.extensions = {}
        self.server_pub_key = None
        logging.basicConfig(level=logging.INFO)

    def do(self, msg):
        """
        Parses the ServerHello message and extracts relevant fields, including the server's ECDH public key.
        """
        try:
            # Parse fixed fields
            self.server_version = msg[:2]
            logging.debug(f"Server Version: {self.server_version.hex()}")

            self.random = msg[2:34]
            logging.debug(f"Random: {self.random.hex()}")

            session_id_length = msg[34]
            logging.debug(f"Session ID Length: {session_id_length}")

            if session_id_length == 0:
                self.session_id = None
            else:
                self.session_id = msg[35:35+session_id_length]
            logging.debug(f"Session ID: {self.session_id.hex() if self.session_id else 'None'}")

            offset = 35 + session_id_length
            self.cipher_suite = msg[offset:offset+2]
            logging.debug(f"Cipher Suite: {self.cipher_suite.hex()}")

            offset += 2
            self.compression_method = msg[offset]
            logging.debug(f"Compression Method: {self.compression_method}")

            offset += 1

            # Parse extensions
            extensions_length = int.from_bytes(msg[offset:offset+2], 'big')
            logging.debug(f"Extensions Length: {extensions_length}")

            offset += 2
            extensions_data = msg[offset:offset+extensions_length]
            self._parse_extensions(extensions_data)
        except Exception as e:
            logging.error(f"Failed to process ServerHello message: {e}")
            raise

    def _parse_extensions(self, extensions_data):
        offset = 0
        while offset < len(extensions_data):
            extension_type = int.from_bytes(extensions_data[offset:offset+2], 'big')
            extension_length = int.from_bytes(extensions_data[offset+2:offset+4], 'big')
            extension_value = extensions_data[offset+4:offset+4+extension_length]
            logging.debug(f"Extension Type: {extension_type}, Length: {extension_length}, Value: {extension_value.hex()}")
            offset += 4 + extension_length

            self.extensions[extension_type] = extension_value

            # Extract key share (assuming extension_type for Key Share is 51)
            if extension_type == 51:
                self._extract_key_share(extension_value)

    def _extract_key_share(self, key_share_data):
        try:
            curve_type = key_share_data[:2]  # Curve type (2 bytes)
            key_exchange_len = int.from_bytes(key_share_data[2:4], 'big')  # Key length (2 bytes)
            key_exchange = key_share_data[4:4+key_exchange_len]  # Public key
            legacy_form = key_exchange[0]  # This must be 4
            qx = key_exchange[1:1+32]
            qy = key_exchange[1+32:]
            self.server_pub_key = EccPublic()
            self.server_pub_key.decode_key_raw(qx, qy, 7)  # 7 means secp256r1

        except Exception as e:
            logging.error(f"Failed to extract key share: {e}")
            raise

    def getPub(self):
        if self.server_pub_key is None:
            raise ValueError("Server public key has not been set. Call do(msg) first.")
        return self.server_pub_key
