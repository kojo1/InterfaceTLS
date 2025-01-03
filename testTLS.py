import logging
import socket

#from TLSrecord import TLSrecord
from HandShakeMsg import HandShakeMsg
from ClientHello import ClientHello
from ServerHello import ServerHello
from KeySchedule import KeySchedule
from KeyExchange import KeyExchange

logger = logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

sock = socket.create_connection(("localhost", 11111))

CLIENT_HELLO = 1
SERVER_HELLO = 2

cl_hello = ClientHello()
sv_hello = ServerHello()
keySched   = KeySchedule()
keyEx    = KeyExchange(keySched)
hsMsg    = HandShakeMsg(sock, keySched)

keySched.get_early_secret() # No PSK
keySched.get_derived_secret()

# Start hadnshake for a TLS connection

hsMsg.send(CLIENT_HELLO, cl_hello.make())   # Send ClientHello
type, msg = hsMsg.recv()                    # Receive ServerHello
if type != SERVER_HELLO:
    logger.info("Invalid message type")
    exit
sv_hello.do(msg)                            # Parse ServerHello
keyEx.doExchange(cl_hello.getPriv(), sv_hello.getPub())
                                            # Key Exchange
# Derive key, IV for Server Handshake
key = keySched.get_s_hs_key()
iv  = keySched.get_s_hs_iv()
hsMsg.set_s_hs_key(key, iv)

type, msg = hsMsg.recvDec()                 # Encrypted Server Hello
print("Message: " + msg.hex())

type, msg = hsMsg.recvDec()                 # Certificate
print("Message: " + msg[:32].hex())

type, msg = hsMsg.recvDec()                 # Verify Certificate
print("Message: " + msg[:32].hex())

type, msg = hsMsg.recvDec()                 # Server Hello Done
print("Message: " + msg[:32].hex())

