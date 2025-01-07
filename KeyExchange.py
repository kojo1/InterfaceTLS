import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from KeySchedule import KeySchedule

class KeyExchange:
    def __init__(self, keySched):
        logger = logging.getLogger()
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.keySched = keySched

    def doExchange(self, priv, pub):

        logging.debug(f"Server Public: {''.join(f'{byte:02x}' for byte in pub)}")

        priv_key = serialization.load_der_private_key(
            priv, password=None, backend=default_backend()
        )
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(priv_key.curve, pub)

        # Perform ECDH to derive the shared secret
        shared_sec = priv_key.exchange(ec.ECDH(), pub_key)
        print(shared_sec.hex())
        self.keySched.set_shared_secret(shared_sec)
        self.keySched.get_hs_secret()
        s_hs = self.keySched.get_s_hs_traffic()
        c_hs = self.keySched.get_c_hs_traffic()
        logging.debug(f"s hs traffic Secret : {''.join(f'{byte:02x}' for byte in s_hs )}")
        logging.debug(f"c hs traffic Secret : {''.join(f'{byte:02x}' for byte in c_hs )}")