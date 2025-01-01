import logging
import socket

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#from TLSrecord import TLSrecord
from HandShakeMsg import HandShakeMsg
from ClientHello import ClientHello
from ServerHello import ServerHello

logger = logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


sock = socket.create_connection(("localhost", 11111))

#tls_record = TLSrecord(sock)
#tls_record.send(23, b"Hello, TLS!")
#content_type, data = tls_record.recv()
#print(f"Received content type: {content_type}, data: {data}")

#handshake_msg = HandShakeMsg(sock)
#handshake_msg.send(0x01, b'example_payload')  # Send a ClientHello message
#handshake_type, payload = handshake_msg.recv()

CLIENT_HELLO = 1
SERVER_HELLO = 2

client_hello = ClientHello()
server_hello = ServerHello()

handshake = HandShakeMsg(sock)
handshake.send(CLIENT_HELLO, client_hello.make())
ecdh_Priv = client_hello.getPriv()
type, msg = handshake.recv()

if type != SERVER_HELLO:
    logger.info("Invalid message type")
    exit

server_hello.do(msg)
pub = server_hello.getPub()
logger.debug(f"Server Public: {''.join(f'{byte:02x}' for byte in pub)}")

#key_length = int.from_bytes(pub[:2], byteorder='big')

#logger.debug(f"Key Length: {pub[:2]},{key_length}, {len(pub[2:])}")

#if len(pub[2:]) != key_length:
#    raise ValueError("Mismatch between length field and actual public key data.")
priv_key = serialization.load_der_private_key(
    ecdh_Priv, password=None, backend=default_backend()
)
pub_key = ec.EllipticCurvePublicKey.from_encoded_point(priv_key.curve, pub)

# Perform ECDH to derive the shared secret
shared_secret = priv_key.exchange(ec.ECDH(), pub_key)
logger.debug(f"Shared Secret : {''.join(f'{byte:02x}' for byte in shared_secret )}")
