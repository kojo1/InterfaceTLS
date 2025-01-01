from TLSrecord import TLSrecord
from KeySchedule import KeySchedule

class HandShakeMsg:
    def __init__(self, socket):
        """
        コンストラクタ
        :param socket: ソケットオブジェクト
        """
        self.socket = socket
        self.tls_record = TLSrecord(socket)

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

    def recv(self):
        """
        ハンドシェークメッセージを受信する
        :return: (handshake_type, content) タプル
        """
        # TLS Recordから受信を委譲
        record_type, record_content = self.tls_record.recv()

        if record_type != 22:  # 22はHandshakeのレコードタイプ
            raise ValueError("Unexpected record type: {}".format(record_type))

        # ハンドシェークメッセージを解析
        handshake_type = record_content[0]
        length = int.from_bytes(record_content[1:4], 'big')
        content = record_content[4:4 + length]

        if len(content) != length:
            raise ValueError("Handshake message length mismatch")

        return handshake_type, content
