import hmac
import hashlib

class KeySchedule:
    def __init__(self, hashAlgo=hashlib.sha256):
        self.hashAlgo = hashAlgo
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

    def hkdf_extract(self, salt, ikm):
        """HKDF Extract フェーズ"""
        return hmac.new(salt, ikm, self.hashAlgo).digest()

    def hkdf_expand_label(self, secret, label, ctx, length):
        """
        HKDF Expand Label (TLS 1.3 固有の形式)
        :param secret: HKDF-Expand に渡すシークレット
        :param label: TLS 1.3 のラベル (例: "key", "iv")
        :param context: コンテキスト (例: ハンドシェイクメッセージ)
        :param length: 必要な出力長
        :return: 派生された鍵またはデータ
        """
        print("hkdf_expand_label:" + str(label))
        print("secret: " + secret.hex())
        print("ctx: " + ctx.hex())

        full_label = b"tls13 " + label
        hkdf_label = (
            length.to_bytes(2, "big") +                    # uint16 length
            len(full_label).to_bytes(1, "big") + full_label +  # opaque label<7..255>
            len(ctx).to_bytes(1, "big") + ctx         # opaque context<0..255>
        )
        return self.hkdf_expand(secret, hkdf_label, length)

    def hkdf_expand(self, secret, info, length):
        """
        HKDF Expand フェーズ
        :param secret: HKDF-Extract の出力
        :param info: ラベルなどの拡張情報
        :param length: 必要な出力長
        :return: 長さ指定の鍵またはデータ
        """
        hash_len = self.hashAlgo().digest_size
        n = (length + hash_len - 1) // hash_len  # 必要なブロック数
        if n > 255:
            raise ValueError("Too large length for HKDF-Expand")

        output = b""
        previous_block = b""
        for i in range(1, n + 1):
            previous_block = hmac.new(
                secret,
                previous_block + info + bytes([i]),
                self.hashAlgo
            ).digest()
            output += previous_block
        return output[:length]
    
    def set_shared_secret(self, secret):
        self.shared_secret = secret
        print(f"shared_secret   : {self.shared_secret}")  

    def set_early_secret(self, psk=None):
        """
        EarlySecret を計算する内部メソッド。
        PSK (pre-shared key) がない場合はゼロバイト列を使用。
        """
        if not psk:
            psk = b'\x00' * self.hashAlgo().digest_size
        salt = b'\x00' * self.hashAlgo().digest_size
        self.early_secret = self.hkdf_extract(salt, psk)

    def set_derived_secret(self):
        """DerivedSecret を計算するメソッド"""
        if not self.early_secret:
            raise ValueError("Early secret must be computed before derived secret.")
        hash = self.hashAlgo(b"").digest()
        print("hash: " + str({''.join(f'{byte:02x}' for byte in hash )}))

        self.derived_secret = self.hkdf_expand_label(
            self.early_secret, b"derived", hash, self.hashAlgo().digest_size
        )

    def set_hs_secret(self):
        """Handshake Secret を計算するメソッド"""
        if not self.derived_secret:
            raise ValueError("Derived secret must be computed before handshake secret.")
        if not self.shared_secret:
            raise ValueError("Shared secret must be computed before handshake secret.")
        self.hs_secret = self.hkdf_extract(self.derived_secret, self.shared_secret)
        print(f"shared_secret   : {self.shared_secret}")  
        print(f"handshake_secret: {self.hs_secret.hex()}")        
        self.digest = self.hashAlgo(self.transcript).digest()
        print(f"self.digest: {self.digest.hex()}")

    def addMsg(self, handshake_message):
        """
        Context を更新するメソッド。
        ハンドシェイクメッセージを内部 Transcrypt に追加。
        """
        self.transcript += handshake_message
        return self.transcript

    def set_c_hs_traffic(self):
        """
        Client Handshake Traffic Secret を計算するメソッド。
        """
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before client handshake traffic secret.")
        self.c_hs_traffic = self.hkdf_expand_label(
            self.hs_secret, b"c hs traffic", self.digest, self.hashAlgo().digest_size
        )
    
    def set_s_hs_traffic(self):
        """
        Server Handshake Traffic Secret を計算するメソッド。
        """
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before server handshake traffic secret.")
    
        self.s_hs_traffic = self.hkdf_expand_label(
            self.hs_secret, b"s hs traffic", self.digest, self.hashAlgo().digest_size
        )

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
           self.c_hs_traffic, b"finished", b"", self.hashAlgo().digest_size 
        )

    def set_s_finished(self):
        if not self.s_hs_traffic:
            raise ValueError("Server Handshake Secret must be computed before Server Finished")

        self.s_finished = self.hkdf_expand_label(
           self.s_hs_traffic, b"finished", b"", self.hashAlgo().digest_size 
        )

    def get_s_finished(self):
        return self.s_finished
    
    def get_c_finished(self):
        return self.c_finished

    def get_secret_for_master(self):
        """
        Secret for Master を計算するメソッド。
        """
        if not self.hs_secret:
            raise ValueError("Handshake secret must be computed before secret for master.")
    
        self.secret_for_master = self.hkdf_expand_label(
            self.hs_secret, b"derived", self.hashAlgo(b"").digest(), self.hashAlgo().digest_size
        )
        return self.secret_for_master

    def set_master_secret(self):
        """
        Master Secret を計算する内部メソッド。
        """
        self.master_secret = self.hkdf_extract(self.get_secret_for_master(), b"\x00" * 32) # 32 should be variable

    def set_c_app_traffic(self):
        """
        client_application_traffic_secret_0  を計算するメソッド。
        Need to run just after "Server Finished".
        """
        if not self.master_secret:
            raise ValueError("master secret must be computed before client_application_traffic_secret_0.")
    
        self.c_app_traffic = self.hkdf_expand_label(
            self.master_secret, b"c ap traffic", self.hashAlgo(self.transcript).digest(), self.hashAlgo().digest_size
        )
        return self.c_app_traffic

    def set_s_app_traffic(self):
        """
        server_application_traffic_secret_0 を計算するメソッド。
        Need to run just after "Server Finished".
        """
        if not self.master_secret:
            raise ValueError("master secret must be computed before server_application_traffic_secret_0.")
    
        self.s_app_traffic = self.hkdf_expand_label(
            self.master_secret, b"s ap traffic", self.hashAlgo(self.transcript).digest(), self.hashAlgo().digest_size
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
    # handshake_secret = key_schedule.get_hs_secret(shared_secret)
    handshake_secret = key_schedule.get_hs_secret()

    # Context を更新 (ハンドシェイクメッセージを追加)
    key_schedule.addMsg(b"handshake_message_1")
    key_schedule.addMsg(b"handshake_message_2")

    # Client Handshake Traffic Secret を計算
    client_hs_secret = key_schedule.get_c_hs_traffic()

    # 結果を表示
    print("Early Secret:", early_secret.hex())
    print("Derived Secret:", derived_secret.hex())
    print("Handshake Secret:", handshake_secret.hex())
    print("Client Handshake Traffic Secret:", client_hs_secret.hex())