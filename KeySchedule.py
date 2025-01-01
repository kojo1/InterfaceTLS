import hmac
import hashlib

class KeySchedule:
    def __init__(self, hash_algorithm=hashlib.sha256):
        self.hash_algorithm = hash_algorithm
        self.zero_salt = b'\x00' * self.hash_algorithm().digest_size
        self._early_secret = None  # 属性名を変更
        self.derived_secret = None
        self.handshake_secret = None
        self.client_handshake_traffic_secret = None
        self.context = b""  # 初期の Context は空

    def hkdf_extract(self, salt, ikm):
        """HKDF Extract フェーズ"""
        return hmac.new(salt, ikm, self.hash_algorithm).digest()

    def hkdf_expand_label(self, secret, label, context, length):
        """HKDF Expand フェーズ (TLS 1.3 固有のラベル形式)"""
        full_label = b"tls13 " + label
        hkdf_label = (
            len(full_label).to_bytes(1, "big") + full_label +
            len(context).to_bytes(1, "big") + context
        )
        return self.hkdf_extract(secret, hkdf_label)[:length]

    def get_early_secret(self, psk):
        """
        EarlySecret を計算する内部メソッド。
        PSK (pre-shared key) がない場合はゼロバイト列を使用。
        """
        if not psk:
            psk = b'\x00' * self.hash_algorithm().digest_size
        self._early_secret = self.hkdf_extract(self.zero_salt, psk)
        return self._early_secret

    def get_derived_secret(self):
        """DerivedSecret を計算するメソッド"""
        if not self._early_secret:
            raise ValueError("Early secret must be computed before derived secret.")
        self.derived_secret = self.hkdf_expand_label(
            self._early_secret, b"derived", b"", self.hash_algorithm().digest_size
        )
        return self.derived_secret

    def get_handshake_secret(self, shared_secret):
        """Handshake Secret を計算するメソッド"""
        if not self.derived_secret:
            raise ValueError("Derived secret must be computed before handshake secret.")
        self.handshake_secret = self.hkdf_extract(self.derived_secret, shared_secret)
        return self.handshake_secret

    def update_context(self, handshake_message):
        """
        Context を更新するメソッド。
        ハンドシェイクメッセージを内部 Context に追加。
        """
        self.context += handshake_message

    def get_client_handshake_traffic_secret(self):
        """
        Client Handshake Traffic Secret を計算するメソッド。
        """
        if not self.handshake_secret:
            raise ValueError("Handshake secret must be computed before client handshake traffic secret.")
        self.client_handshake_traffic_secret = self.hkdf_expand_label(
            self.handshake_secret, b"c hs traffic", self.context, self.hash_algorithm().digest_size
        )
        return self.client_handshake_traffic_secret

# 使用例
if __name__ == "__main__":
    # 鍵スケジュールを初期化
    key_schedule = KeySchedule()

    # Pre-Shared Key (PSK) を設定
    psk = b"example_psk_12345"
    early_secret = key_schedule.get_early_secret(psk)

    # Derived Secret を計算
    derived_secret = key_schedule.get_derived_secret()

    # 共通鍵 (ECDHなどで得られるShared Secret)
    shared_secret = b"example_shared_secret"
    handshake_secret = key_schedule.get_handshake_secret(shared_secret)

    # Context を更新 (ハンドシェイクメッセージを追加)
    key_schedule.update_context(b"handshake_message_1")
    key_schedule.update_context(b"handshake_message_2")

    # Client Handshake Traffic Secret を計算
    client_hs_secret = key_schedule.get_client_handshake_traffic_secret()

    # 結果を表示
    print("Early Secret:", early_secret.hex())
    print("Derived Secret:", derived_secret.hex())
    print("Handshake Secret:", handshake_secret.hex())
    print("Client Handshake Traffic Secret:", client_hs_secret.hex())
