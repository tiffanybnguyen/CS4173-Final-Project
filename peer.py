import os
import socket
import struct
import threading
import time

import cipher

T_HELLO_DH = 0x02
T_DATA     = 0x10
T_ROTATE   = 0x20
T_BYE      = 0x30

ROTATE_EVERY_MSGS = 100
ROTATE_EVERY_SECS = 5 * 60


def _send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer disconnected")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(sock):
    n, = struct.unpack(">I", _recv_exact(sock, 4))
    return _recv_exact(sock, n)


class Session:
    def __init__(self):
        self.aes = self.mac = self.cha = None
        self.send_seq = 0
        self.recv_seq = 0
        self.epoch = 0
        self.msgs_in_epoch = 0
        self.epoch_started = time.time()
        self.lock = threading.Lock()

    def install(self, aes, mac, cha):
        self.aes, self.mac, self.cha = aes, mac, cha
        self.epoch += 1
        self.msgs_in_epoch = 0
        self.send_seq = 0
        self.recv_seq = 0
        self.epoch_started = time.time()

    def encrypt_message(self, text):
        with self.lock:
            self.send_seq += 1
            payload = struct.pack(">Q", self.send_seq) + text.encode("utf-8")
            blob = cipher.encrypt_cascade(self.aes, self.mac, self.cha, payload)
            self.msgs_in_epoch += 1
            return blob

    def decrypt_message(self, blob):
        payload = cipher.decrypt_cascade(self.aes, self.mac, self.cha, blob)
        seq, = struct.unpack(">Q", payload[:8])
        with self.lock:
            if seq <= self.recv_seq:
                raise ValueError(f"replay/out-of-order seq {seq} (last seen {self.recv_seq})")
            self.recv_seq = seq
        return payload[8:].decode("utf-8")

    def needs_rotation(self):
        return (self.msgs_in_epoch >= ROTATE_EVERY_MSGS
                or time.time() - self.epoch_started >= ROTATE_EVERY_SECS)


EPHEMERAL_PUB_LEN = 32


class Peer:
    def __init__(self, on_event, my_rsa_priv, peer_rsa_pub):
        self.on_event = on_event
        self.session = Session()
        self.my_rsa_priv = my_rsa_priv
        self.peer_rsa_pub = peer_rsa_pub
        self.sock = None
        self.alive = False
        self.is_initiator = False
        self._reader = None
        self._send_lock = threading.Lock()

    def listen(self, host, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        self.sock, addr = srv.accept()
        srv.close()
        self.is_initiator = False
        self.on_event("connected", peer=f"{addr[0]}:{addr[1]}")

    def connect(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.is_initiator = True
        self.on_event("connected", peer=f"{host}:{port}")

    def handshake(self):
        sk, pub = cipher.make_dh_keypair()
        sig = cipher.rsa_sign(self.my_rsa_priv, pub)
        my_msg = bytes([T_HELLO_DH]) + pub + sig

        if self.is_initiator:
            _send_frame(self.sock, my_msg)
            f = _recv_frame(self.sock)
        else:
            f = _recv_frame(self.sock)
            _send_frame(self.sock, my_msg)

        if not f or f[0] != T_HELLO_DH:
            raise RuntimeError("expected HELLO_DH")
        if len(f) != 1 + EPHEMERAL_PUB_LEN + cipher.RSA_SIG_LEN:
            raise RuntimeError(f"bad HELLO_DH length {len(f)}")
        peer_pub = f[1:1 + EPHEMERAL_PUB_LEN]
        peer_sig = f[1 + EPHEMERAL_PUB_LEN:]

        if not cipher.rsa_verify(self.peer_rsa_pub, peer_pub, peer_sig):
            raise RuntimeError("peer RSA signature did not verify — possible MITM")

        shared = cipher.dh_shared(sk, peer_pub)
        aes, mac, cha = cipher.derive_dh_keys(shared)
        self.session.install(aes, mac, cha)
        self.on_event("ready")

    def start(self):
        self.alive = True
        self._reader = threading.Thread(target=self._recv_loop, daemon=True)
        self._reader.start()

    def send_text(self, text):
        with self._send_lock:
            blob = self.session.encrypt_message(text)
            _send_frame(self.sock, bytes([T_DATA]) + blob)
            self.on_event("sent", plaintext=text, ciphertext=blob)
            if self.is_initiator and self.session.needs_rotation():
                self._rotate()

    def _rotate(self):
        new_salt = os.urandom(cipher.SALT_LEN)
        wrapped = cipher.encrypt_cascade(self.session.aes, self.session.mac,
                                         self.session.cha, new_salt)
        _send_frame(self.sock, bytes([T_ROTATE]) + wrapped)
        new_keys = cipher.rotate_keys(self.session.aes, self.session.mac,
                                      self.session.cha, new_salt)
        self.session.install(*new_keys)
        self.on_event("rotated", epoch=self.session.epoch)

    def _recv_loop(self):
        try:
            while self.alive:
                frame = _recv_frame(self.sock)
                if not frame:
                    continue
                kind, body = frame[0], frame[1:]
                if kind == T_DATA:
                    text = self.session.decrypt_message(body)
                    self.on_event("received", plaintext=text, ciphertext=body)
                elif kind == T_ROTATE:
                    new_salt = cipher.decrypt_cascade(self.session.aes,
                                                     self.session.mac,
                                                     self.session.cha, body)
                    new_keys = cipher.rotate_keys(self.session.aes, self.session.mac,
                                                  self.session.cha, new_salt)
                    self.session.install(*new_keys)
                    self.on_event("rotated", epoch=self.session.epoch)
                elif kind == T_BYE:
                    break
                else:
                    self.on_event("error", msg=f"unknown frame type {kind:#x}")
        except (ConnectionError, OSError) as e:
            if self.alive:
                self.on_event("error", msg=str(e))
        except Exception as e:
            self.on_event("error", msg=f"recv: {e}")
        finally:
            self.alive = False
            self.on_event("disconnected")

    def close(self):
        if self.alive and self.sock:
            try:
                _send_frame(self.sock, bytes([T_BYE]))
            except Exception:
                pass
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
