# CS4173 Final Project — Secure P2P Messenger

Tkinter chat between two peers. The first time you launch the app it
generates a long-term **RSA-2048 keypair** for you (`my_priv.pem` and
`my_pub.pem`). You send your `my_pub.pem` to your partner once, over a
trusted channel. Every chat session does an ephemeral **X25519
Diffie-Hellman** exchange and **signs the ephemeral public keys**
(RSA-PKCS#1 v1.5 over a SHA-256 hash). The other side verifies against
the partner's RSA public key it has on disk. A bad signature drops the
connection — no human comparison step.

Messages use a **cascade**: AES-256-CBC ciphertext XORed with a ChaCha20
keystream under an independent key, authenticated with HMAC-SHA256.
Fresh IV/nonce per message, sequence numbers prevent replay, HKDF
rotates the keys every 100 messages or 5 minutes.

## Setup

```
conda activate cs4173
pip install -r requirements.txt
```

## Run

```
python chat.py
```

The first run on a given machine prints something like:

```
first run: generated my_priv.pem and my_pub.pem
  → send my_pub.pem to your partner before connecting
```

Send your `my_pub.pem` to your partner (email, AirDrop, USB, whatever).
They send theirs back to you. Save the file they sent — call it
`peer_pub.pem` if you want to keep things tidy.

After that, the startup dialog asks for:
- **Role** — Listen or Connect
- **Host** — IP to bind (Listen) or dial (Connect)
- **Port**
- **Peer public key** — path to your partner's public key file

Run on two machines, one Listen + one Connect, both pointing at the
listener's host/port.

## Files

- `cipher.py` — primitives: HKDF, AES-CBC ⊕ ChaCha20 cascade, X25519 DH, RSA sign/verify, key serialization
- `peer.py` — TCP framing, signed DH handshake, session keys, send/receive loop, key rotation
- `chatui.py` — Tkinter startup dialog and chat window
- `chat.py` — entry point; auto-generates RSA keypair on first run
