import logging

from KeySchedule import KeySchedule

class Finished:
    def __init__(self, key_sched: KeySchedule):
        logging.basicConfig(level=logging.INFO)
        self.key_sched = key_sched
        self.expected_verify_data = None

    def set_expected_verify_data(self):
        # Calc the expected HMAC at client to validate server one
        expected_verify_data = self.key_sched.hmacAlgo(
            self.key_sched.get_s_finished(),
            self.key_sched.hashAlgo(self.key_sched.transcript).digest()
        ).digest()
        self.expected_verify_data = expected_verify_data

    def do(self, msg):
        """
        Parses the Finished message and extracts relevant fields.
        """
        if self.expected_verify_data != msg:
            raise ValueError("veryfy_data doesn't match with expected value: {}".format(msg))
        return msg

    def make(self):
        verify_data = self.key_sched.hmacAlgo(
            self.key_sched.get_c_finished(),
            self.key_sched.hashAlgo(self.key_sched.transcript).digest(),
        ).digest()

        return verify_data
