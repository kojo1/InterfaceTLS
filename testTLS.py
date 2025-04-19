#!python3

import logging
import socket
from debug import dump_hex

from SslKeyLog import SslKeyLog #keyLog for Wireshark
from HandShakeMsg import HandShakeMsg, CryptoHandShakeMsg, AppMsg
from ClientHello import ClientHello
from ServerHello import ServerHello
from Finished import Finished
from KeySchedule import KeySchedule
from KeyExchange import KeyExchange

logger = logging.getLogger()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

keylog = SslKeyLog("sslkeylog.log")  # keyLog for Wireshark

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

keySched = KeySchedule(keylog)

cl_hello = ClientHello(keylog)
sv_hello = ServerHello()
finished = Finished(keySched)

keyEx    = KeyExchange(keySched)
hsMsg    = HandShakeMsg(sock, keySched)
chsMsg   = CryptoHandShakeMsg(sock, keySched)
appMsg   = AppMsg(sock, keySched)

# Start hadnshake for a TLS connection
hsMsg.send(CLIENT_HELLO, cl_hello.make())               # Send ClientHello
sv_hello.do(hsMsg.recv(SERVER_HELLO))                   # Receive and Parse ServerHello

keyEx.doExchange(cl_hello.getPriv(), sv_hello.getPub()) # Key Exchange
chsMsg.calc_keys_and_ivs()                              # set key, IV for crypted handshake message 

enc_exts_msg = chsMsg.recv(ENCRYPTED_EXTENTIONS)        # Receive Encrypted Server Hello
cert_msg = chsMsg.recv(CERTIFICATE)                     # Receive Certificate
cert_verify_msg = chsMsg.recv(CERTIFICATE_VERIFY)       # Verify Certificate

finished.set_expected_verify_data()
finished.do(chsMsg.recv(FINISHED))                      # Server Finished

appMsg.calc_keys_and_ivs()
chsMsg.send(FINISHED, finished.make())                  # Client Finished

appMsg.send(APPLICATION_DATA, b"Hello")
print("App Data from Server", appMsg.recv(APPLICATION_DATA))

print("Alert from Server", appMsg.recv(ALERT))
appMsg.send(ALERT, bytes.fromhex("01 00"))
