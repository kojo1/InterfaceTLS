from logger_config import logger

from SslKeyLog import SslKeyLog #keyLog for Wireshark
from wolfcrypt.hashes import Sha256, HmacSha256

def _get_hmac_algo(hashAlgo):
    if hashAlgo == Sha256:
        return HmacSha256
    else:
        raise ValueError("Unsupported hash algorithm")

class KeySchedule:
    def __init__(self, keylog, hashAlgo=Sha256):
        self.hashAlgo = hashAlgo
        self.digest_size = hashAlgo.digest_size
        self.hmacAlgo = _get_hmac_algo(hashAlgo)
        self.early_secret = None # 属性名を変更
        self.derived_secret = None
        self.hs_secret = None
        self.c_hs_traffic = None
        self.s_hs_traffic = None
        self.transcript = b""
        self.shared_secret = None
        self.digest = None
        self.c_hs_key_iv = None
        self.s_hs_key_iv = None
        self.c_app_key_iv = None
        self.s_app_key_iv = None

        self.keylog = keylog

    def hkdf_extract(self, salt, ikm):
        return self.hmacAlgo(salt, ikm).digest()

    def hkdf_expand_label(self, secret, label, ctx, length):
        logger.debug("hkdf_expand_label:" + str(label))
        logger.debug("secret: " + secret.hex())
        logger.debug("ctx: " + ctx.hex())

        full_label = b"tls13 " + label
        hkdf_label = (
            length.to_bytes(2, "big") +                    # uint16 length
            len(full_label).to_bytes(1, "big") + full_label +  # opaque label<7..255>
            len(ctx).to_bytes(1, "big") + ctx         # opaque context<0..255>
        )
        return self.hkdf_expand(secret, hkdf_label, length)

    def hkdf_expand(self, secret, info, length):

        hash_len = self.digest_size
        n = (length + hash_len - 1) // hash_len  # 必要なブロック数
        if n > 255:
            raise ValueError("Too large length for HKDF-Expand")

        output = b""
        previous_block = b""
        for i in range(1, n + 1):
            previous_block = self.hmacAlgo(secret, previous_block + info + bytes([i])).digest()
            output += previous_block
        return output[:length]

    def set_shared_secret(self, secret):
        self.shared_secret = secret
        logger.debug(f"shared_secret   : {self.shared_secret}")

    def set_early_secret(self, psk=None):
        if not psk:
            psk = b'\x00' * self.digest_size
        salt = b'\x00' * self.digest_size
        self.early_secret = self.hkdf_extract(salt, psk)

    def set_derived_secret(self):
        if not self.early_secret:
            raise ValueError("Early secret must be computed before derived secret.")
        hash = self.hashAlgo(b"").digest()
        logger.debug("hash: " + str({''.join(f'{byte:02x}' for byte in hash )}))

        self.derived_secret = self.hkdf_expand_label(
            self.early_secret, b"derived", hash, self.digest_size
        )

    def set_hs_secret(self):
        if not self.derived_secret:
            raise ValueError("Derived secret must be computed before handshake secret.")
        if not self.shared_secret:
            raise ValueError("Shared secret must be computed before handshake secret.")
        self.hs_secret = self.hkdf_extract(self.derived_secret, self.shared_secret)
        logger.debug(f"shared_secret   : {self.shared_secret}")
        logger.debug(f"handshake_secret: {self.hs_secret.hex()}")
        self.digest = self.hashAlgo(self.transcript).digest()
        logger.debug(f"self.digest: {self.digest.hex()}")

    def addMsg(self, handshake_message):
        self.transcript += handshake_message
        return self.transcript

    def set_c_hs_traffic(self):
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before client handshake traffic secret.")
        self.c_hs_traffic = self.hkdf_expand_label(
            self.hs_secret, b"c hs traffic", self.digest, self.digest_size
        )
        self.keylog.writeSecret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", self.c_hs_traffic)

    def set_s_hs_traffic(self):
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before server handshake traffic secret.")

        self.s_hs_traffic = self.hkdf_expand_label(
            self.hs_secret, b"s hs traffic", self.digest, self.digest_size
        )
        self.keylog.writeSecret("SERVER_HANDSHAKE_TRAFFIC_SECRET", self.s_hs_traffic)

    def set_s_hs_key_iv(self):
        KEY_LENGTH = 16
        key = self.hkdf_expand_label(self.s_hs_traffic, b"key", b"", KEY_LENGTH)
        IV_LENGTH = 12
        iv = self.hkdf_expand_label(self.s_hs_traffic, b"iv", b"", IV_LENGTH)
        self.s_hs_key_iv = key, iv

    def get_s_hs_key_iv(self):
        # Need to check self.s_hs_key_iv
        return self.s_hs_key_iv

    def set_c_hs_key_iv(self):
        KEY_LENGTH = 16
        key = self.hkdf_expand_label(self.c_hs_traffic, b"key", b"", KEY_LENGTH)
        IV_LENGTH = 12
        iv = self.hkdf_expand_label(self.c_hs_traffic, b"iv", b"", IV_LENGTH)
        self.c_hs_key_iv = key, iv

    def get_c_hs_key_iv(self):
        # Need to check self.c_hs_key_iv
        return self.c_hs_key_iv

    def set_c_finished(self):
        if not self.c_hs_traffic:
            raise ValueError("Client Handshake Secret must be computed before Client Finished")

        self.c_finished = self.hkdf_expand_label(
           self.c_hs_traffic, b"finished", b"", self.digest_size
        )

    def set_s_finished(self):
        if not self.s_hs_traffic:
            raise ValueError("Server Handshake Secret must be computed before Server Finished")

        self.s_finished = self.hkdf_expand_label(
           self.s_hs_traffic, b"finished", b"", self.digest_size
        )

    def get_s_finished(self):
        return self.s_finished

    def get_c_finished(self):
        return self.c_finished

    def get_secret_for_master(self):
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before secret for master.")

        self.secret_for_master = self.hkdf_expand_label(
            self.hs_secret, b"derived", self.hashAlgo(b"").digest(), self.digest_size
        )
        return self.secret_for_master

    def set_master_secret(self):
        self.master_secret = self.hkdf_extract(self.get_secret_for_master(), b"\x00" * 32) # 32 should be variable

    def set_c_app_traffic(self):
        if not self.master_secret:
            raise ValueError("master secret must be computed before client_application_traffic_secret_0.")

        self.c_app_traffic = self.hkdf_expand_label(
            self.master_secret, b"c ap traffic", self.hashAlgo(self.transcript).digest(), self.digest_size
        )
        return self.c_app_traffic

    def set_s_app_traffic(self):
        if not self.master_secret:
            raise ValueError("master secret must be computed before server_application_traffic_secret_0.")

        self.s_app_traffic = self.hkdf_expand_label(
            self.master_secret, b"s ap traffic", self.hashAlgo(self.transcript).digest(), self.digest_size
        )
        return self.s_app_traffic

    def set_c_app_key_iv(self):
        KEY_LENGTH = 16
        key = self.hkdf_expand_label(self.c_app_traffic, b"key", b"", KEY_LENGTH)
        IV_LENGTH = 12
        iv = self.hkdf_expand_label(self.c_app_traffic, b"iv", b"", IV_LENGTH)
        self.c_app_key_iv = key, iv

    def set_s_app_key_iv(self):
        KEY_LENGTH = 16
        key = self.hkdf_expand_label(self.s_app_traffic, b"key", b"", KEY_LENGTH)
        IV_LENGTH = 12
        iv = self.hkdf_expand_label(self.s_app_traffic, b"iv", b"", IV_LENGTH)
        self.s_app_key_iv = key, iv

    def get_c_app_key_iv(self):
        return self.c_app_key_iv

    def get_s_app_key_iv(self):
        return self.s_app_key_iv

    def record_iv(self, base_iv, recNum: int):
        """
        Calculate record IV using base IV and sequence number.
        :param base_iv: Base IV (12 bytes)
        :param sequence_number: Sequence number (int)
        :return: Record IV (12 bytes)
        """
        # シーケンス番号を 8 バイトに変換し、`base_iv` の最後の 8 バイトと XOR
        seq_bytes = recNum.to_bytes(8, 'big')
        iv = bytearray(base_iv)
        for i in range(8):
            iv[-8 + i] ^= seq_bytes[i]
        return bytes(iv)
