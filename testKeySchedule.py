import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from KeySchedule import KeySchedule

logger = logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ClientHello = bytes.fromhex(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef"
    "6283024dece7000006130113031302010000910000000b000900000673657276"
    "6572ff01000100000a00140012001d0017001800190100010101020103010400"
    "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e"
    "51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603"
    "020308040805080604010501060102010402050206020202002d00020101001c"
    "00024001"
)
ServerHello = bytes.fromhex(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155"
    "772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb"
    "f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
)

EncryptedExtensions = bytes.fromhex(
    "080000240022000a001400"
    "12001d00170018001901000101010201030104001c"
    "0002400100000000"
)

# クライアント秘密鍵（RFC 8448 の値）
client_private_bytes = bytes.fromhex(
    "49af42ba7f7994852d713ef2784bcbca"\
    "a7911de26adc5642cb634540e7ea5005"
)

# サーバー公開鍵（RFC 8448 の値）
server_public_bytes = bytes.fromhex(
    "c9828876112095fe66762bdbf7c672e1"\
    "56d6cc253b833df1dd69b1b04e751f0f"
)

keySched  = KeySchedule()
early_secret   = keySched.get_early_secret() # No PSK
logger.debug(f"early_secret : {''.join(f'{byte:02x}' for byte in early_secret )}")

derived_secret = keySched.get_derived_secret()
logger.debug(f"derived_secret : {''.join(f'{byte:02x}' for byte in derived_secret )}")

msg     = keySched.addMsg(ClientHello)
logger.debug(f"Transcrypt : {''.join(f'{byte:02x}' for byte in msg )}")

# クライアント秘密鍵オブジェクト
client_private_key = x25519.X25519PrivateKey.from_private_bytes(client_private_bytes)

# サーバー公開鍵オブジェクト
server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)

# 共有秘密値を計算
shared_secret = client_private_key.exchange(server_public_key)
keySched.set_shared_secret(shared_secret)
logger.debug(f"Shared Secret : {''.join(f'{byte:02x}' for byte in shared_secret )}")

msg     = keySched.addMsg(ServerHello)
logger.debug(f"Transcrypt : {''.join(f'{byte:02x}' for byte in msg )}")

handshake_secret = keySched.get_hs_secret()
logger.debug(f"handshake_secret : {''.join(f'{byte:02x}' for byte in handshake_secret )}")

s_hs_traffic = keySched.get_s_hs_traffic()
logger.debug(f"Server Handshake Traffic Secret : {''.join(f'{byte:02x}' for byte in s_hs_traffic )}")

c_hs_traffic = keySched.get_c_hs_traffic()
logger.debug(f"Client Handshake Traffic Secret : {''.join(f'{byte:02x}' for byte in c_hs_traffic )}")

s_hs_key = keySched.get_s_hs_key()
logger.debug(f"Server Handshake Key : {''.join(f'{byte:02x}' for byte in s_hs_key )}")

s_hs_iv = keySched.get_s_hs_iv()
logger.debug(f"Server Handshake IV : {''.join(f'{byte:02x}' for byte in s_hs_iv )}")
