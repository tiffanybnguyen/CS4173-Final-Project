import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

import cipher
import peer


class StartupFrame(ttk.Frame):
    def __init__(self, parent, on_start):
        super().__init__(parent, padding=24)
        self.on_start = on_start

        ttk.Label(self, text="Start P2P Chat", font=("Helvetica", 14, "bold")
                  ).grid(row=0, column=0, columnspan=3, pady=(0, 12))

        ttk.Label(self, text="Role").grid(row=1, column=0, sticky="w")
        self.role = tk.StringVar(value="listen")
        ttk.Radiobutton(self, text="Listen", variable=self.role,
                        value="listen").grid(row=1, column=1, sticky="w")
        ttk.Radiobutton(self, text="Connect", variable=self.role,
                        value="connect").grid(row=1, column=2, sticky="w")

        ttk.Label(self, text="Host").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.host = ttk.Entry(self, width=24)
        self.host.insert(0, "127.0.0.1")
        self.host.grid(row=2, column=1, columnspan=2, sticky="w", pady=(10, 0))

        ttk.Label(self, text="Port").grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.port = ttk.Entry(self, width=10)
        self.port.insert(0, "9001")
        self.port.grid(row=3, column=1, sticky="w", pady=(6, 0))

        ttk.Label(self, text="Peer public key").grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.peer_key = ttk.Entry(self, width=24)
        self.peer_key.insert(0, "peer_pub.pem")
        self.peer_key.grid(row=4, column=1, sticky="w", pady=(10, 0))
        ttk.Button(self, text="Browse",
                   command=lambda: self._pick(self.peer_key)).grid(
            row=4, column=2, sticky="w", padx=(6, 0), pady=(10, 0))

        ttk.Label(self, text="(your own keypair is auto-generated as my_priv.pem / my_pub.pem)",
                  foreground="#888888").grid(row=5, column=0, columnspan=3,
                                              sticky="w", pady=(8, 0))

        ttk.Button(self, text="Start", command=self._submit).grid(
            row=6, column=0, columnspan=3, pady=(16, 0))

        self.bind_all("<Return>", lambda _e: self._submit())
        self.host.focus_set()

    def _pick(self, entry):
        path = filedialog.askopenfilename(title="Select key file")
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _submit(self):
        host = self.host.get().strip()
        if not host:
            messagebox.showerror("Missing host", "Please enter a host/IP")
            return
        try:
            port = int(self.port.get())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number")
            return
        peer_key = self.peer_key.get().strip()
        if not peer_key:
            messagebox.showerror("Missing key", "Peer public key path is required")
            return
        self.unbind_all("<Return>")
        self.on_start({
            "role": self.role.get(),
            "host": host,
            "port": port,
            "peer_key": peer_key,
        })


class ChatWindow:
    def __init__(self, root, cfg):
        self.root = root
        self.cfg = cfg
        self.events = queue.Queue()
        self.peer = None

        root.title(f"P2P Chat — {cfg['role']}")
        root.geometry("780x640")

        header = ttk.Frame(root, padding=8)
        header.pack(fill="x")
        info = f"{cfg['role']}  •  {cfg['host']}:{cfg['port']}  •  X25519 + RSA + cascade"
        ttk.Label(header, text=info).pack(side="left")
        self.status = ttk.Label(header, text="status: starting…")
        self.status.pack(side="right")

        self.log = scrolledtext.ScrolledText(root, wrap="word",
                                             font=("Menlo", 10), state="disabled")
        self.log.pack(fill="both", expand=True, padx=8, pady=4)

        self.log.tag_config("sys",  foreground="#888888")
        self.log.tag_config("you",  foreground="#1f6feb")
        self.log.tag_config("them", foreground="#177245")
        self.log.tag_config("ct",   foreground="#999999", font=("Menlo", 9))
        self.log.tag_config("err",  foreground="#cc2a36")

        bar = ttk.Frame(root, padding=8)
        bar.pack(fill="x")
        self.entry = ttk.Entry(bar, font=("Menlo", 11))
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda _e: self._send())
        ttk.Button(bar, text="Send", command=self._send).pack(side="left", padx=(6, 0))

        root.protocol("WM_DELETE_WINDOW", self._quit)

        self._poll()
        root.after(50, self._kickoff)

    def _post(self, kind, **data):
        self.events.put((kind, data))

    def _poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                self._handle(kind, data)
        except queue.Empty:
            pass
        self.root.after(40, self._poll)

    def _handle(self, kind, data):
        if kind == "connected":
            self._line(f"-- connected to {data['peer']} --", "sys")
            self.status.config(text="status: handshaking")
        elif kind == "ready":
            self._line("-- peer RSA signature verified, session key established --", "sys")
            self.status.config(text=f"status: ready (epoch {self.peer.session.epoch})")
        elif kind == "sent":
            self._line(f"you: {data['plaintext']}", "you")
            self._line(f"  ↑ ct: {data['ciphertext'].hex()}", "ct")
        elif kind == "received":
            self._line(f"  ↓ ct: {data['ciphertext'].hex()}", "ct")
            self._line(f"peer: {data['plaintext']}", "them")
        elif kind == "rotated":
            self._line(f"-- key rotated, now epoch {data['epoch']} --", "sys")
            self.status.config(text=f"status: ready (epoch {data['epoch']})")
        elif kind == "disconnected":
            self._line("-- peer disconnected --", "sys")
            self.status.config(text="status: closed")
        elif kind == "error":
            self._line(f"!! {data['msg']}", "err")

    def _line(self, text, tag):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _send(self):
        text = self.entry.get().strip()
        if not text or not self.peer or not self.peer.alive:
            return
        try:
            self.peer.send_text(text)
        except Exception as e:
            self._line(f"send failed: {e}", "err")
            return
        self.entry.delete(0, "end")

    def _kickoff(self):
        threading.Thread(target=self._setup, daemon=True).start()

    def _setup(self):
        try:
            my_priv = cipher.load_rsa_priv("my_priv.pem")
            peer_pub = cipher.load_rsa_pub(self.cfg["peer_key"])
        except Exception as e:
            self._post("error", msg=f"could not load key files: {e}")
            return

        self.peer = peer.Peer(self._post, my_priv, peer_pub)
        try:
            if self.cfg["role"] == "listen":
                self._post("error", msg=f"listening on {self.cfg['host']}:{self.cfg['port']}…")
                self.peer.listen(self.cfg["host"], self.cfg["port"])
            else:
                self.peer.connect(self.cfg["host"], self.cfg["port"])
            self.peer.handshake()
            self.peer.start()
        except Exception as e:
            self._post("error", msg=f"setup failed: {e}")

    def _quit(self):
        if self.peer:
            self.peer.close()
        self.root.destroy()


def run():
    root = tk.Tk()
    root.title("P2P Chat")
    root.geometry("520x340")

    def proceed(cfg):
        for w in root.winfo_children():
            w.destroy()
        ChatWindow(root, cfg)

    StartupFrame(root, proceed).pack(fill="both", expand=True)
    root.mainloop()
