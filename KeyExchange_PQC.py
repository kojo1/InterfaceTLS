import logging
from struct import pack, unpack
from abc import ABCMeta, abstractmethod

from KeySchedule import KeySchedule
from wolfcrypt.ciphers import EccPrivate, EccPublic, ECC_SECP256R1
from wolfcrypt.ciphers import MlKemType, MlKemPrivate

class KeyExAlgo(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self):
        pass

    @property
    @abstractmethod
    def supported_group(self):
        pass

    @abstractmethod
    def make_key_exchange(self):
        pass

    @abstractmethod
    def extract_key_exchange(self, key_exchange_entry):
        pass

    @abstractmethod
    def get_shared_secret(self):
        pass


class KeyExAlgoP256(KeyExAlgo):
    def __init__(self):
        self._priv = None
        self._pub = None

    @property
    def supported_group(self):
        return b"\x00\x17"  # ECC_SECP256R1

    def make_key_exchange(self):
        self._priv = EccPrivate.make_key(32)  # 32 bytes key length for ECC_SECP256R1
        qx, qy, _ = self._priv.encode_key_raw()  # qx and qy are the public key, _ is the private key
        legacy_form = pack('!B', 4)
        return legacy_form + qx + qy

    def extract_key_exchange(self, key_exchange):
        legacy_form = key_exchange[0]
        assert(legacy_form == 4)
        qx = key_exchange[1:1+32]
        qy = key_exchange[1+32:]
        self._pub = EccPublic()
        self._pub.decode_key_raw(qx, qy, ECC_SECP256R1)

    def get_shared_secret(self):
        assert(self._priv is not None and self._pub is not None)
        return self._priv.shared_secret(self._pub)

class KeyExAlgoMlKem768(KeyExAlgo):
    def __init__(self):
        self._priv = None
        self._ciphertext = None  # ciphertext

    @property
    def supported_group(self):
        return b"\x02\x01"  # ML-KEM 768

    def make_key_exchange(self):
        self.priv = MlKemPrivate.make_key(MlKemType.ML_KEM_768)
        return self.priv.encode_pub_key()

    def extract_key_exchange(self, key_exchange):
        self._ciphertext = key_exchange

    def get_shared_secret(self):
        assert(self.priv is not None and self._ciphertext is not None)
        return self.priv.decapsulate(self._ciphertext)

class KeyExAlgoP256MlKem768(KeyExAlgo):
    def __init__(self):
        self._p256 = KeyExAlgoP256()
        self._mlkem768 = KeyExAlgoMlKem768()

    @property
    def supported_group(self):
        return b"\x11\xeb"

    def make_key_exchange(self):
        return self._p256.make_key_exchange() + self._mlkem768.make_key_exchange()

    def extract_key_exchange(self, key_exchange):
        key_exchange_p256 = key_exchange[:65]
        key_exchange_mlkem768 = key_exchange[65:]

        self._p256.extract_key_exchange(key_exchange_p256)
        self._mlkem768.extract_key_exchange(key_exchange_mlkem768)

    def get_shared_secret(self):
        return self._p256.get_shared_secret() + self._mlkem768.get_shared_secret()

class KeyExchange():
    def __init__(self, key_sched, algo=KeyExAlgoP256()):
        logger = logging.getLogger()
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self._algo = algo
        self._key_sched = key_sched

    def make_supported_groups(self):
        return pack('!H', 2) + self._algo.supported_group

    def make_key_share(self):
        key_exchange = self._algo.make_key_exchange()
        key_share_entry = self._algo.supported_group + pack('!H', len(key_exchange)) + key_exchange
        return pack('!H', len(key_share_entry)) + key_share_entry

    def extract_key_share(self, key_share_entry):
        try:
            supported_group = key_share_entry[:2]
            assert(supported_group == self._algo.supported_group)
            (key_exchange_len, ) = unpack('!H', key_share_entry[2:4])
            key_exchange = key_share_entry[4:4+key_exchange_len]
            self._algo.extract_key_exchange(key_exchange)

        except Exception as e:
            logging.error(f"Failed to extract key share: {e}")
            raise

    def doExchange(self):
        ss = self._algo.get_shared_secret()
        self._key_sched.set_shared_secret(ss)

