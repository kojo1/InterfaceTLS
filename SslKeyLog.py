class SslKeyLog:
    def __init__(self, log_file):
        self.log_file = log_file
        self.client_rnd = None

    def setClientRnd(self, rnd: bytes):
        if not isinstance(rnd, bytes):
            raise ValueError("rnd must be of type 'bytes'")
        if len(rnd) != 32:
            raise ValueError("rnd must be exactly 32 bytes (256 bits)")
        self.client_rnd = rnd.hex()

    def writeSecret(self, label: str, secret: bytes):
        if self.client_rnd is None:
            raise ValueError("Client Random is not set. Call setClientRnd() first.")
        if not isinstance(secret, bytes):
            raise ValueError("secret must be of type 'bytes'")

        line = f"{label} {self.client_rnd} {secret.hex()}\n"

        with open(self.log_file, "a") as f:
            f.write(line)