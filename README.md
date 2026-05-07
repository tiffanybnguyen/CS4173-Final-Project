# Secure P2P Messenger

This final project program is a secure chat between two peers with GUI utilizing methods learned in Computer Security (CS4173/5173).

## Setup

First, set up the corresponding Python environment:
```
conda create -n final_project python=3.12
conda activate final_project
pip install -r requirements.txt
```

## How to Run

```
python chat.py
```

The first run on a given machine prints something like:

```
first run: generated private_key.pem and public_key.pem
  → send public_key.pem to your partner before connecting
```

1. Send your `public_key.pem` to your partner.
2. They send theirs back to you, and save that file.
3. After that, the startup dialog asks for:
- **Role** — Listen or Connect
- **Host** — IP to Listen or Connect
- **Port**
- **Peer public key** — path to your partner's public key file

Run on two machines, one server (listen) + one client (connect), both pointing at the listener's host and port.

## Files

- `cipher.py` — HKDF, AES-CBC ⊕ AES-CTR cascade, X25519 DH, RSA sign/verify, key serialization
- `peer.py` — TCP framing, signed DH handshake, session keys, send/receive loop, key rotation
- `chatui.py` — Tkinter startup chat window
- `chat.py` — entry point; auto-generates RSA keypair
