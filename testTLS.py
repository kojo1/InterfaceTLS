#!python3

import logging
import socket
from HandShakeMsg import dump_hex

#from TLSrecord import TLSrecord
from HandShakeMsg import HandShakeMsg, CryptoHandShakeMsg, AppMsg
from ClientHello import ClientHello
from ServerHello import ServerHello
from Finished import Finished
from KeySchedule import KeySchedule
from KeyExchange import KeyExchange

logger = logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

sock = socket.create_connection(("localhost", 11111))

transcript = b""

# Content Types
ALERT = 21
APPLICATION_DATA = 23

# Handshake Types
CLIENT_HELLO = 1
SERVER_HELLO = 2
ENCRYPTED_EXTENTIONS = 8
CERTIFICATE = 11
CERTIFICATE_VERIFY = 15
FINISHED = 20

keySched = KeySchedule()
cl_hello = ClientHello()
sv_hello = ServerHello()
finished = Finished(keySched)
keyEx    = KeyExchange(keySched)
hsMsg    = HandShakeMsg(sock, keySched)
chsMsg   = CryptoHandShakeMsg(sock, keySched)
appMsg   = AppMsg(sock, keySched)

# Start hadnshake for a TLS connection
hsMsg.send(CLIENT_HELLO, cl_hello.make())               # Send ClientHello

sv_hello_msg = hsMsg.recv(SERVER_HELLO)                 # Receive ServerHello
sv_hello.do(sv_hello_msg)                               # Parse ServerHello

keyEx.doExchange(cl_hello.getPriv(), sv_hello.getPub()) # Key Exchange

chsMsg.calc_keys_and_ivs()

enc_exts_msg = chsMsg.recv(ENCRYPTED_EXTENTIONS)        # Receive Encrypted Server Hello
cert_msg = chsMsg.recv(CERTIFICATE)                     # Receive Certificate
cert_verify_msg = chsMsg.recv(CERTIFICATE_VERIFY)       # Verify Certificate

finished.set_expected_verify_data()
finished_msg = chsMsg.recv(FINISHED)                    # Server Finished
finished.do(finished_msg)

appMsg.calc_keys_and_ivs()

chsMsg.send(FINISHED, finished.make()) # Client Finished

appMsg.send(APPLICATION_DATA, b"Hello")
dump_hex("App Data from Server", appMsg.recv(APPLICATION_DATA))

dump_hex("App Data from Server", appMsg.recv(ALERT))
appMsg.send(ALERT, bytes.fromhex("01 00"))