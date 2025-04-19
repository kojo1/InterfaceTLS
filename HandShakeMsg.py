from wolfcrypt.ciphers import AesGcmStream

from KeySchedule import KeySchedule
from TLSrecord import TLSrecord, tls_header, separate_tls_msg

def hs_header(hs_type: int, hs_payload_len: int):
    return hs_type.to_bytes(1, 'big') + hs_payload_len.to_bytes(3, 'big')

def separate_hs_msg(hs_msg: bytes):
    hs_type = hs_msg[0]
    hs_payload_len = hs_msg[1:4]
    hs_payload = hs_msg[4:]
    
    return hs_type, hs_payload_len, hs_payload

class PlainMsg:
    def __init__(self, socket, key_sched):
        self.tls_record = TLSrecord(socket)
        self.key_sched = key_sched

    def send(self, content_type: int, tls_payload: bytes):
        self.tls_record.send(tls_header(content_type, len(tls_payload)) + tls_payload)
        self.key_sched.addMsg(tls_payload)

    def recv(self, expected_content_type: int):
        content_type, version, tls_payload_len, tls_payload = separate_tls_msg(self.tls_record.recv())
        if content_type != expected_content_type:
            raise ValueError("Unexpected content type: {}".format(content_type)) 
        self.key_sched.addMsg(tls_payload)
        
        return tls_payload

class HandShakeMsg:
    def __init__(self, socket, key_sched):
        self.plain = PlainMsg(socket, key_sched)

    def send(self, hs_type: int, hs_payload: bytes):
        tls_payload = hs_header(hs_type, len(hs_payload)) + hs_payload
        self.plain.send(22, tls_payload)

    def recv(self, expected_hs_type: int):
        tls_payload = self.plain.recv(22)
        hs_type, hs_payload_len, hs_payload = separate_hs_msg(tls_payload)
        if hs_type != expected_hs_type:
            raise ValueError("Unexpected handshake type: {}".format(hs_type))
        return hs_payload

def encrypt(key, iv, record_header, record_content):
        aes_gcm = AesGcmStream(key, iv, 16)
        aes_gcm.set_aad(record_header)
        ciphertext = aes_gcm.encrypt(record_content)
        auth_tag = aes_gcm.final()

        return ciphertext, auth_tag

def decrypt(key, iv, record_header, record_content):
    auth_tag = record_content[-16:]  # 最後の16バイトがauth_tag
    ciphertext = record_content[:-16]  # 残りが暗号化されたペイロード
    aes_gcm = AesGcmStream(key, iv, 16)
    aes_gcm.set_aad(record_header)
    plainText = aes_gcm.decrypt(ciphertext)

    return plainText

class CryptoMsg:
    def __init__(self, socket, key_sched):
        self.tls_record = TLSrecord(socket)
        self.key_sched = key_sched
        self.recNum = 0
        self.sendNum = 0
        self.c_key_iv = None
        self.s_key_iv = None

    def set_keys_and_ivs(self, c_key_iv, s_key_iv):
        self.c_key_iv = c_key_iv
        self.s_key_iv = s_key_iv

    def send(self, content_type1:int, content_type2: int, payload: bytes):
        tls_h = tls_header(content_type1, len(payload) + 1 + 16)
        c_key, c_iv = self.c_key_iv
        cipher_text, auth_tag = encrypt(
            c_key,
            self.key_sched.record_iv(c_iv, self.sendNum), # record_iv() doesn't have to be in KeySchedule class.
            tls_h,
            payload + content_type2.to_bytes(1, 'big')
        )
        self.tls_record.send(tls_h + cipher_text + auth_tag)
        self.key_sched.addMsg(payload)
        self.sendNum += 1

    def recv(self, expected_content_type1: int, expected_content_type2:int):
        content_type1, version, tls_payload_len, tls_payload = separate_tls_msg(self.tls_record.recv())
        if content_type1 != expected_content_type1:
            raise ValueError("Unexpected content_type1: {}".format(content_type1))

        tls_header = content_type1.to_bytes(1, 'big') + version + tls_payload_len # This is redundant
        s_key, s_iv = self.s_key_iv
        plain_text = decrypt(
            s_key,
            self.key_sched.record_iv(s_iv, self.recNum),
            tls_header,
            tls_payload
        )

        content = plain_text[:-1]
        content_type2 = int.from_bytes(plain_text[-1:], 'big')
        if content_type2 != expected_content_type2:
            raise ValueError("Unexpected content_type2: {}".format(content_type2))

        self.key_sched.addMsg(content)
        self.recNum += 1
        
        return content

class CryptoHandShakeMsg:
    def __init__(self, socket, key_sched: KeySchedule):
        self.key_sched = key_sched
        self.crypto = CryptoMsg(socket, key_sched)

    def calc_keys_and_ivs(self):
        self.key_sched.set_early_secret()
        self.key_sched.set_derived_secret()
        self.key_sched.set_hs_secret()
        self.key_sched.set_s_hs_traffic()
        self.key_sched.set_c_hs_traffic()
        self.key_sched.set_s_hs_key_iv()
        self.key_sched.set_c_hs_key_iv()
        self.key_sched.set_s_finished()
        self.key_sched.set_c_finished()

        self.crypto.set_keys_and_ivs(self.key_sched.get_c_hs_key_iv(), self.key_sched.get_s_hs_key_iv())

    def send(self, hs_type: int, hs_payload: bytes):
        tls_payload = hs_header(hs_type, len(hs_payload)) + hs_payload
        self.crypto.send(23, 22, tls_payload)

    def recv(self, expected_hs_type: int):
        tls_payload = self.crypto.recv(23, 22)
        hs_type, hs_payload_len, hs_payload = separate_hs_msg(tls_payload)
        if hs_type != expected_hs_type:
            raise ValueError("Unexpected hs_type: {}".format(hs_type))
        return hs_payload
    
class AppMsg:
    def __init__(self, socket, key_sched):
        self.key_sched = key_sched
        self.crypto = CryptoMsg(socket, key_sched)

    def calc_keys_and_ivs(self):
        self.key_sched.set_master_secret()
        self.key_sched.set_c_app_traffic()
        self.key_sched.set_s_app_traffic()
        self.key_sched.set_c_app_key_iv()
        self.key_sched.set_s_app_key_iv()

        self.crypto.set_keys_and_ivs(self.key_sched.get_c_app_key_iv(), self.key_sched.get_s_app_key_iv())

    def send(self, app_type: int, app_payload: bytes): # from here
        self.crypto.send(23, app_type, app_payload)

    def recv(self, expected_app_type: int):
        app_payload = self.crypto.recv(23, expected_app_type)
        return app_payload
