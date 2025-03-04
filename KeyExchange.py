import logging

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
        shared_sec = priv.shared_secret(pub)
        self.keySched.set_shared_secret(shared_sec)
