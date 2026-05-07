import hmac
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SALT_LEN  = 16
IV_LEN    = 16
NONCE_LEN = 16
MAC_LEN   = 32

AES_KEY_LEN = 32
MAC_KEY_LEN = 32
CHA_KEY_LEN = 32
TOTAL_KEY_LEN = AES_KEY_LEN + MAC_KEY_LEN + CHA_KEY_LEN


def _split_keys(raw):
    return (
        raw[:AES_KEY_LEN],
        raw[AES_KEY_LEN:AES_KEY_LEN + MAC_KEY_LEN],
        raw[AES_KEY_LEN + MAC_KEY_LEN:],
    )


def derive_dh_keys(shared_secret):
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=TOTAL_KEY_LEN,
        salt=None,
        info=b"p2p-chat session keys",
    ).derive(shared_secret)
    return _split_keys(raw)


def rotate_keys(aes, mac, cha, fresh_salt):
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=TOTAL_KEY_LEN,
        salt=fresh_salt,
        info=b"p2p-chat rotate",
    ).derive(aes + mac + cha)
    return _split_keys(raw)


# Cascade: AES-CBC ciphertext XORed with a ChaCha20 keystream under an
# independent key. Recovering plaintext requires breaking both ciphers.
def encrypt_cascade(aes_key, mac_key, cha_key, plaintext):
    iv = secrets.token_bytes(IV_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    p = padding.PKCS7(128).padder()
    padded = p.update(plaintext) + p.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    aes_ct = enc.update(padded) + enc.finalize()
    keystream = (Cipher(algorithms.ChaCha20(cha_key, nonce), mode=None)
                 .encryptor()
                 .update(b"\x00" * len(aes_ct)))
    mixed = bytes(a ^ b for a, b in zip(aes_ct, keystream))
    body = iv + nonce + mixed
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()


def decrypt_cascade(aes_key, mac_key, cha_key, blob):
    if len(blob) < IV_LEN + NONCE_LEN + MAC_LEN + 16:
        raise ValueError("cascade blob too short")
    body, tag = blob[:-MAC_LEN], blob[-MAC_LEN:]
    if not hmac.compare_digest(tag, hmac.new(mac_key, body, hashlib.sha256).digest()):
        raise ValueError("HMAC verification failed")
    iv = body[:IV_LEN]
    nonce = body[IV_LEN:IV_LEN + NONCE_LEN]
    mixed = body[IV_LEN + NONCE_LEN:]
    keystream = (Cipher(algorithms.ChaCha20(cha_key, nonce), mode=None)
                 .decryptor()
                 .update(b"\x00" * len(mixed)))
    aes_ct = bytes(a ^ b for a, b in zip(mixed, keystream))
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = dec.update(aes_ct) + dec.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(padded) + u.finalize()


def make_dh_keypair():
    sk = X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pub


def dh_shared(sk, peer_pub_bytes):
    return sk.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))


def short_auth_string(shared_secret):
    digest = HKDF(
        algorithm=hashes.SHA256(),
        length=4,
        salt=None,
        info=b"sas-display",
    ).derive(shared_secret)
    n = int.from_bytes(digest, "big") % 1_000_000
    return f"{n:06d}"
