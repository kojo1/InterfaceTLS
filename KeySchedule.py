import hmac
import hashlib

class KeySchedule:
    def __init__(self, hashAlgo=hashlib.sha256):
        self.hashAlgo = hashAlgo
        self.early_secret = None  # 属性名を変更
        self.derived_secret = None
        self.handshake_secret = None
        self.c_hs_traffic = None
        self.s_hs_traffic = None
        self.transcrypt = b""
        self.shared_secret = None
        self.digest = None

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

    def get_early_secret(self, psk=None):
        """
        EarlySecret を計算する内部メソッド。
        PSK (pre-shared key) がない場合はゼロバイト列を使用。
        """
        if not psk:
            psk = b'\x00' * self.hashAlgo().digest_size
        salt = b'\x00' * self.hashAlgo().digest_size
        self.early_secret = self.hkdf_extract(salt, psk)
        return self.early_secret

    def get_derived_secret(self):
        """DerivedSecret を計算するメソッド"""
        if not self.early_secret:
            raise ValueError("Early secret must be computed before derived secret.")
        hash = self.hashAlgo(b"").digest()
        print("hash: " + str({''.join(f'{byte:02x}' for byte in hash )}))

        self.derived_secret = self.hkdf_expand_label(
            self.early_secret, b"derived", hash, self.hashAlgo().digest_size
        )
        return self.derived_secret

    def get_hs_secret(self):
        """Handshake Secret を計算するメソッド"""
        if not self.derived_secret:
            raise ValueError("Derived secret must be computed before handshake secret.")
        self.handshake_secret = self.hkdf_extract(self.derived_secret, self.shared_secret)
        print(f"shared_secret   : {self.shared_secret}")  
        print(f"handshake_secret: {self.handshake_secret.hex()}")        
        self.digest = self.hashAlgo(self.transcrypt).digest()
        print(f"self.digest: {self.digest.hex()}")
        return self.handshake_secret

    def addMsg(self, handshake_message):
        """
        Context を更新するメソッド。
        ハンドシェイクメッセージを内部 Transcrypt に追加。
        """
        self.transcrypt += handshake_message
        return self.transcrypt

    def get_c_hs_traffic(self):
        """
        Client Handshake Traffic Secret を計算するメソッド。
        """
        if not self.handshake_secret:
            raise ValueError("Handshake secret must be computed before client handshake traffic secret.")
        self.c_hs_traffic = self.hkdf_expand_label(
            self.handshake_secret, b"c hs traffic", self.digest, self.hashAlgo().digest_size
        )
        return self.c_hs_traffic
    
    def get_s_hs_traffic(self):
        """
        Server Handshake Traffic Secret を計算するメソッド。
        """
        if not self.handshake_secret:
            raise ValueError("Handshake secret must be computed before server handshake traffic secret.")
    
        self.s_hs_traffic = self.hkdf_expand_label(
            self.handshake_secret, b"s hs traffic", self.digest, self.hashAlgo().digest_size
        )
        return self.s_hs_traffic
    
    def get_s_hs_key(self):
        KEY_LENGTH = 16
        length = b"\x00\x10"
        label = b"\x09tls13 key"
        context = b"\x00"
        info = length + label + context
        return self.hkdf_expand(self.s_hs_traffic, info, KEY_LENGTH)
    
    def get_s_hs_iv(self):
        IV_LENGTH = 12
        length = b"\x00\x0c"
        label = b"\x08tls13 iv"
        context = b"\x00"
        info = length + label + context
        return self.hkdf_expand(self.s_hs_traffic, info, IV_LENGTH)

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
