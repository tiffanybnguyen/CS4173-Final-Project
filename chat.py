import os

import cipher
from chatui import run

MY_PRIV = "my_priv.pem"
MY_PUB = "my_pub.pem"


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
