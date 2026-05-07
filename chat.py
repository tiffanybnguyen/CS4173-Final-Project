import os

import cipher
from chatui import run

MY_PRIV = "private_key.pem"
MY_PUB = "public_key.pem"


def ensure_keys():
    if not os.path.exists(MY_PRIV):
        priv, pub = cipher.make_rsa_keypair()
        cipher.save_rsa_priv(MY_PRIV, priv)
        cipher.save_rsa_pub(MY_PUB, pub)
        print(f"first run: generated {MY_PRIV} and {MY_PUB}")
        print(f"  → send {MY_PUB} to your partner before connecting")


if __name__ == "__main__":
    ensure_keys()
    run()
