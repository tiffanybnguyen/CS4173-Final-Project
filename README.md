# CS4173 Final Project — Secure P2P Messenger

Tkinter chat between two peers. Each session establishes shared keys via
**X25519 Diffie-Hellman** and protects messages with a **cascade cipher**:
AES-256-CBC ciphertext is XORed with a ChaCha20 keystream under an
independent key, and the result is authenticated with HMAC-SHA256.
Every message uses a fresh IV/nonce, sequence numbers prevent replays,
and HKDF rotates the keys every 100 messages or 5 minutes.

After the handshake a 6-digit **short authentication string (SAS)**
appears on each side; users compare it out-of-band to defeat MITM.

## Setup (conda)

```
conda create -n cs4173 python=3.12 -y
conda activate cs4173
pip install -r requirements.txt
```

## Run

```
conda activate cs4173
python chat.py
```

A small dialog asks for **role** (Listen / Connect), **host**, and **port**.
Run the program twice — one in Listen mode, the other in Connect mode,
both pointing at the same host/port.

## Files

- `cipher.py` — primitives: HKDF, AES-CBC ⊕ ChaCha20 cascade, X25519, SAS
- `peer.py` — TCP framing, DH handshake, session keys, send/receive loop, key rotation
- `chatui.py` — Tkinter startup dialog and chat window
- `chat.py` — entry point
