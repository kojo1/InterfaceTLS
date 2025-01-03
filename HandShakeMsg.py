from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from TLSrecord import TLSrecord
from KeySchedule import KeySchedule

class HandShakeMsg:
    def __init__(self, socket, keySched):
        """
        コンストラクタ
        :param socket: ソケットオブジェクト
        """
        self.socket = socket
        self.tls_record = TLSrecord(socket)
        self.keySched = keySched
        self.key = None
        self.base_iv = None
        self.recNum = 0

    def send(self, handshake_type, content):
        """
        ハンドシェークメッセージを送信する
        :param handshake_type: ハンドシェークメッセージタイプ (例: ClientHello, ServerHelloなど)
        :param content: ハンドシェークメッセージの内容 (bytes)
        """
        # ハンドシェークメッセージを作成
        handshake_header = handshake_type.to_bytes(1, 'big') + len(content).to_bytes(3, 'big')
        handshake_message = handshake_header + content

        # TLS Recordに送信を委譲
        self.tls_record.send(22, handshake_message)  # 22はHandshakeのレコードタイプ
        self.keySched.addMsg(handshake_message)

    def sendEnc(self, type, content, key, iv):
        handshake_header = handshake_type.to_bytes(1, 'big') + len(content).to_bytes(3, 'big')
        handshake_message = handshake_header + content

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
        encryptor = cipher.encryptor()


    def recv(self):
        # TLS Recordから受信を委譲
        record_header, record_content = self.tls_record.recv()
        print("Message: " + record_header.hex() + "," + record_content.hex())

        record_type = record_header[0]
        if record_type != 22:  # 22はHandshakeのレコードタイプ
            raise ValueError("Unexpected record type: {}".format(record_type))

        # ハンドシェークメッセージを解析
        handshake_type = record_content[0]
        length = int.from_bytes(record_content[1:4], 'big')
        content = record_content[4:4 + length]

        if len(content) != length:
            raise ValueError("Handshake message length mismatch")

        self.keySched.addMsg(record_content)

        return handshake_type, content
    
    def set_s_hs_key(self, key, iv):
        self.key = key
        self.base_iv = iv

    def record_iv(self):
        """
        Calculate record IV using base IV and sequence number.
        :param base_iv: Base IV (12 bytes)
        :param sequence_number: Sequence number (int)
        :return: Record IV (12 bytes)
        """
        # シーケンス番号を 8 バイトに変換し、`base_iv` の最後の 8 バイトと XOR
        seq_bytes = self.recNum.to_bytes(8, 'big')
        iv = bytearray(self.base_iv)
        for i in range(8):
            iv[-8 + i] ^= seq_bytes[i]
        return bytes(iv)

    def recvDec(self):
        # TLS Recordから受信を委譲
        record_header, record_content = self.tls_record.recv()
        print("Encrypted Message: " + record_header.hex() + "," + record_content[:32].hex())

        record_type = record_header[0]
        if record_type != 23:  # Application Record
            raise ValueError("Unexpected record type: {}".format(record_type))
        
        auth_tag = record_content[-16:]  # 最後の16バイトがauth_tag
        ciphertext = record_content[:-16]  # 残りが暗号化されたペイロード
        
        print(f"Auth Tag: {auth_tag.hex()}")
        print(f"ciphertext: {ciphertext[:32].hex()}")
        print(f"key: {self.key.hex()}")
        print(f"IV: {self.record_iv().hex()}")
        print(f"Record Number: {self.recNum}")

        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.record_iv(), auth_tag), backend=backend)
        decryptor = cipher.decryptor()

        decryptor.authenticate_additional_data(record_header)
        plainText = decryptor.update(ciphertext) + decryptor.finalize()

        # ハンドシェークメッセージを解析
        handshake_type = plainText[0]
        length = int.from_bytes(plainText[1:4], 'big')
        content = plainText[4:4 + length]

        if len(content) != length:
            raise ValueError("Handshake message length mismatch")

        self.keySched.addMsg(record_content)
        self.recNum += 1

        return handshake_type, content
