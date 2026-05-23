#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════╗
║   NodeTalk v1.0 - LAN内チャットアプリ（単一ファイル）  ║
║   同一LAN内でインターネット不要のリアルタイム通信       ║
╚══════════════════════════════════════════════════╝

【必要ライブラリ】
  標準ライブラリのみで動作（暗号化を使う場合は任意）
  暗号化 (任意): pip install cryptography

【起動方法】
  python nodetalk.py
  ※ 同一Wi-Fi/LAN内の複数端末で起動するだけで自動接続
"""

import socket, threading, json, time, uuid, base64, secrets, hashlib
import queue, os, struct
from collections import defaultdict
from datetime import datetime

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, font as tkfont

# ── 暗号化（オプション）──────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 定数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APP_NAME         = "NodeTalk"
APP_VERSION      = "1.0.0"
DISCOVERY_PORT   = 55000        # UDP ブロードキャスト
CHAT_PORT        = 55001        # TCP チャット
DISCOVERY_INTERVAL = 6          # 秒ごとにブロードキャスト
PEER_TIMEOUT     = 30           # 秒以上無応答でオフライン判定
BUFFER_SIZE      = 65536

TYPE_DISCOVER    = "discover"
TYPE_GOODBYE     = "goodbye"
TYPE_CHAT        = "chat"
TYPE_GROUP_MSG   = "group_msg"
TYPE_GROUP_INV   = "group_invite"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 暗号化マネージャー（AES-256-GCM + RSA鍵交換）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CryptoManager:
    """RSA-2048 で AES-256-GCM セッション鍵を交換し E2EE を実現"""

    def __init__(self):
        self.enabled        = CRYPTO_OK
        self._priv          = None
        self.pub_pem        = None
        self._peer_pubs     = {}   # peer_id -> RSA public key obj
        self._session_keys  = {}   # peer_id -> bytes (32)

        if self.enabled:
            self._gen_keys()

    def _gen_keys(self):
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # ─ 公開鍵の管理 ──────────────────────────────────
    def store_peer_pub(self, peer_id, pem: str):
        if not self.enabled:
            return
        try:
            self._peer_pubs[peer_id] = serialization.load_pem_public_key(pem.encode())
        except Exception:
            pass

    def has_peer_pub(self, peer_id):
        return peer_id in self._peer_pubs

    # ─ セッション鍵の生成・配布 ────────────────────────
    def make_session_key_for(self, peer_id) -> "str | None":
        """新しい AES-256 鍵を生成し、相手の RSA 公開鍵で暗号化して b64 文字列で返す"""
        if not self.enabled or peer_id not in self._peer_pubs:
            return None
        aes_key = secrets.token_bytes(32)
        self._session_keys[peer_id] = aes_key
        encrypted = self._peer_pubs[peer_id].encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def load_session_key(self, peer_id, encrypted_b64: str) -> bool:
        """相手から受け取った暗号化セッション鍵を自分の秘密鍵で復号して保存"""
        if not self.enabled or not self._priv:
            return False
        try:
            ct = base64.b64decode(encrypted_b64)
            aes_key = self._priv.decrypt(
                ct,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None
                )
            )
            self._session_keys[peer_id] = aes_key
            return True
        except Exception:
            return False

    def has_session(self, peer_id):
        return peer_id in self._session_keys

    # ─ 暗号化 / 復号 ────────────────────────────────
    def encrypt(self, peer_id, plaintext: str) -> "tuple[str, bool]":
        """(暗号化後テキスト, 暗号化したか)"""
        if not self.enabled or peer_id not in self._session_keys:
            return plaintext, False
        try:
            nonce = secrets.token_bytes(12)
            ct = AESGCM(self._session_keys[peer_id]).encrypt(nonce, plaintext.encode(), None)
            return base64.b64encode(nonce + ct).decode(), True
        except Exception:
            return plaintext, False

    def decrypt(self, peer_id, ciphertext: str) -> str:
        if not self.enabled or peer_id not in self._session_keys:
            return ciphertext
        try:
            data  = base64.b64decode(ciphertext)
            nonce, ct = data[:12], data[12:]
            return AESGCM(self._session_keys[peer_id]).decrypt(nonce, ct, None).decode()
        except Exception:
            return "[復号失敗]"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Peer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Peer:
    def __init__(self, peer_id, username, ip):
        self.id        = peer_id
        self.username  = username
        self.ip        = ip
        self.last_seen = time.time()
        self.online    = True

    def touch(self, username=None):
        self.last_seen = time.time()
        self.online    = True
        if username:
            self.username = username

    def alive(self):
        return (time.time() - self.last_seen) < PEER_TIMEOUT


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NetworkManager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NetworkManager:

    def __init__(self, username, peer_id, crypto: CryptoManager):
        self.username   = username
        self.peer_id    = peer_id
        self.crypto     = crypto
        self.peers      = {}   # peer_id -> Peer
        self._conns     = {}   # peer_id -> socket (アウトバウンド)
        self._lock      = threading.Lock()
        self._running   = False

        self.my_ip = self._local_ip()

        # コールバック（GUIから設定）
        self.on_peer_found = None
        self.on_peer_lost  = None
        self.on_message    = None

    # ─ 起動 / 停止 ───────────────────────────────────
    def start(self):
        self._running = True
        for target in (self._udp_recv, self._udp_cast, self._tcp_srv, self._watchdog):
            threading.Thread(target=target, daemon=True).start()

    def stop(self):
        self._broadcast(TYPE_GOODBYE, {})
        self._running = False

    # ─ ユーティリティ ────────────────────────────────
    def _local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close(); return ip
        except Exception:
            return "127.0.0.1"

    def _pack(self, msg_type, payload: dict) -> bytes:
        payload.update({
            "type": msg_type,
            "from_id":   self.peer_id,
            "from_name": self.username,
            "ts":        time.time(),
        })
        return json.dumps(payload, ensure_ascii=False).encode()

    # ─ UDP ────────────────────────────────────────────
    def _udp_send(self, data: bytes, ip="<broadcast>"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(data, (ip, DISCOVERY_PORT))
            s.close()
        except Exception:
            pass

    def _broadcast(self, msg_type, payload):
        extra = {}
        if self.crypto.enabled:
            extra["pub_key"] = self.crypto.pub_pem
        self._udp_send(self._pack(msg_type, {**payload, **extra}))

    def _udp_cast(self):
        """定期的にブロードキャスト送信"""
        while self._running:
            self._broadcast(TYPE_DISCOVER, {})
            time.sleep(DISCOVERY_INTERVAL)

    def _udp_recv(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(1.0)
        while self._running:
            try:
                data, (ip, _) = sock.recvfrom(BUFFER_SIZE)
                msg = json.loads(data.decode())
                if msg.get("from_id") == self.peer_id:
                    continue
                self._handle_udp(msg, ip)
            except (socket.timeout, json.JSONDecodeError):
                pass
            except Exception:
                pass
        sock.close()

    def _handle_udp(self, msg, ip):
        t       = msg.get("type")
        pid     = msg.get("from_id")
        uname   = msg.get("from_name", "Unknown")
        pub_key = msg.get("pub_key")

        if t in (TYPE_DISCOVER,):
            is_new = pid not in self.peers
            with self._lock:
                if is_new:
                    peer = Peer(pid, uname, ip)
                    self.peers[pid] = peer
                else:
                    self.peers[pid].touch(uname)

            # 公開鍵の保存
            if pub_key and self.crypto.enabled:
                self.crypto.store_peer_pub(pid, pub_key)

            if is_new:
                # 自分の存在を返す
                self._udp_send(self._pack(TYPE_DISCOVER, {
                    "pub_key": self.crypto.pub_pem if self.crypto.enabled else None
                }), ip)
                if self.on_peer_found:
                    self.on_peer_found(self.peers[pid])

        elif t == TYPE_GOODBYE:
            with self._lock:
                if pid in self.peers:
                    self.peers[pid].online = False
            if self.on_peer_lost and pid in self.peers:
                self.on_peer_lost(self.peers[pid])

    # ─ TCP サーバー ────────────────────────────────────
    def _tcp_srv(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("", CHAT_PORT))
        except OSError as e:
            print(f"[エラー] ポート {CHAT_PORT} を使用できません: {e}")
            print("  別のポートで再試行するか、他のプロセスを終了してください。")
            return
        srv.listen(20)
        srv.settimeout(1.0)
        while self._running:
            try:
                conn, (ip, _) = srv.accept()
                threading.Thread(target=self._tcp_recv, args=(conn, ip), daemon=True).start()
            except socket.timeout:
                pass
            except Exception:
                pass
        srv.close()

    def _tcp_recv(self, conn, ip):
        conn.settimeout(120)
        buf = b""
        try:
            while self._running:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode())
                        self._handle_tcp(msg, ip)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
        finally:
            conn.close()

    def _handle_tcp(self, msg, ip):
        t       = msg.get("type")
        pid     = msg.get("from_id")
        uname   = msg.get("from_name", ip)
        is_enc  = msg.get("encrypted", False)

        # セッション鍵の受取（送信者が初回に添付）
        if sk := msg.get("session_key"):
            self.crypto.load_session_key(pid, sk)

        if t == TYPE_CHAT:
            text = msg.get("text", "")
            if is_enc and pid:
                text = self.crypto.decrypt(pid, text)
            self._emit_msg(t, pid, uname, text, msg.get("ts", time.time()))

        elif t == TYPE_GROUP_MSG:
            room = msg.get("room", "")
            text = msg.get("text", "")
            if is_enc and pid:
                text = self.crypto.decrypt(pid, text)
            self._emit_msg(t, pid, uname, text, msg.get("ts", time.time()), room=room)

        elif t == TYPE_GROUP_INV:
            room    = msg.get("room", "")
            members = msg.get("members", [])
            if self.on_message:
                self.on_message({
                    "type": TYPE_GROUP_INV,
                    "from_id": pid, "from_name": uname,
                    "room": room, "members": members,
                    "ts": msg.get("ts", time.time()),
                })

    def _emit_msg(self, t, pid, uname, text, ts, room=""):
        if self.on_message:
            self.on_message({
                "type": t, "from_id": pid, "from_name": uname,
                "text": text, "ts": ts, "room": room,
            })

    # ─ TCP 送信 ────────────────────────────────────────
    def _connect(self, peer_id) -> "socket.socket | None":
        with self._lock:
            if peer_id in self._conns:
                return self._conns[peer_id]
        peer = self.peers.get(peer_id)
        if not peer:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((peer.ip, CHAT_PORT))
            s.settimeout(None)
            with self._lock:
                self._conns[peer_id] = s
            return s
        except Exception as e:
            print(f"[接続失敗] {peer.ip}: {e}")
            return None

    def _tcp_send(self, peer_id, payload: dict) -> bool:
        conn = self._connect(peer_id)
        if not conn:
            return False

        # 初回送信時にセッション鍵を添付
        if (self.crypto.enabled
                and self.crypto.has_peer_pub(peer_id)
                and not self.crypto.has_session(peer_id)):
            payload["session_key"] = self.crypto.make_session_key_for(peer_id)

        try:
            data = json.dumps(payload, ensure_ascii=False).encode() + b"\n"
            conn.sendall(data)
            return True
        except Exception:
            with self._lock:
                self._conns.pop(peer_id, None)
            return False

    def send_chat(self, peer_id, text) -> bool:
        enc_text, is_enc = self.crypto.encrypt(peer_id, text)
        payload = self._pack_dict(TYPE_CHAT, {"text": enc_text, "encrypted": is_enc})
        return self._tcp_send(peer_id, payload)

    def send_group(self, room, text, members) -> int:
        sent = 0
        for pid in members:
            if pid == self.peer_id:
                continue
            enc_text, is_enc = self.crypto.encrypt(pid, text)
            payload = self._pack_dict(TYPE_GROUP_MSG, {
                "room": room, "text": enc_text, "encrypted": is_enc
            })
            if self._tcp_send(pid, payload):
                sent += 1
        return sent

    def send_group_invite(self, peer_id, room, members):
        payload = self._pack_dict(TYPE_GROUP_INV, {"room": room, "members": members})
        self._tcp_send(peer_id, payload)

    def _pack_dict(self, msg_type, payload: dict) -> dict:
        payload.update({
            "type":      msg_type,
            "from_id":   self.peer_id,
            "from_name": self.username,
            "ts":        time.time(),
        })
        return payload

    # ─ 生存確認 ────────────────────────────────────────
    def _watchdog(self):
        while self._running:
            time.sleep(10)
            dead = []
            with self._lock:
                for pid, p in self.peers.items():
                    if p.online and not p.alive():
                        p.online = False
                        dead.append(p)
                        sock = self._conns.pop(pid, None)
                        if sock:
                            try: sock.close()
                            except Exception: pass
            for p in dead:
                if self.on_peer_lost:
                    self.on_peer_lost(p)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# カラーテーマ
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
C = {
    "bg":       "#1e1e2e",
    "sidebar":  "#181825",
    "panel":    "#313244",
    "border":   "#585b70",
    "text":     "#cdd6f4",
    "subtext":  "#6c7086",
    "accent":   "#89b4fa",
    "accent2":  "#cba6f7",
    "success":  "#a6e3a1",
    "warning":  "#f9e2af",
    "error":    "#f38ba8",
    "input_bg": "#313244",
    "me_clr":   "#89dceb",
    "other_clr":"#cba6f7",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# メインアプリ（Tkinter）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NodeTalkApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME}  v{APP_VERSION}")
        self.root.geometry("1060x700")
        self.root.minsize(800, 520)
        self.root.configure(bg=C["bg"])

        self.username     = ""
        self.peer_id      = str(uuid.uuid4())[:8]
        self.crypto       = CryptoManager()
        self.net          = None
        self.chat_logs    = defaultdict(list)   # chat_id -> [{from,text,time,is_me}]
        self.groups       = {}                  # room -> {name, members:[peer_id,...]}
        self.current      = None               # peer_id | "group:<room>"
        self.unread       = defaultdict(int)

        self._peer_ids    = []   # peer_listbox の順番管理
        self._group_names = []   # group_listbox の順番管理

        self._build_login()

    # ════════════════════════════════════
    # ログイン画面
    # ════════════════════════════════════
    def _build_login(self):
        frm = tk.Frame(self.root, bg=C["bg"])
        frm.pack(expand=True, fill="both")
        self._login_frm = frm

        card = tk.Frame(frm, bg=C["sidebar"], padx=56, pady=48)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="🔗", font=("Arial", 52),
                 bg=C["sidebar"], fg=C["accent"]).pack()
        tk.Label(card, text=APP_NAME, font=("Helvetica", 30, "bold"),
                 bg=C["sidebar"], fg=C["accent"]).pack(pady=(0, 4))
        tk.Label(card, text="LAN内リアルタイムチャット — インターネット不要",
                 font=("Helvetica", 11), bg=C["sidebar"], fg=C["subtext"]).pack(pady=(0, 28))

        tk.Label(card, text="ユーザー名", font=("Helvetica", 12),
                 bg=C["sidebar"], fg=C["text"]).pack(anchor="w")

        self._uname_var = tk.StringVar()
        ent = tk.Entry(card, textvariable=self._uname_var,
                       font=("Helvetica", 14), bg=C["input_bg"], fg=C["text"],
                       insertbackground=C["text"], relief="flat", width=22)
        ent.pack(ipady=9, pady=(4, 22), fill="x")
        ent.focus_set()
        ent.bind("<Return>", lambda _: self._launch())

        btn = tk.Button(card, text="参加する →",
                        font=("Helvetica", 13, "bold"),
                        bg=C["accent"], fg=C["sidebar"],
                        relief="flat", cursor="hand2",
                        padx=20, pady=10, command=self._launch)
        btn.pack(fill="x")

        info_txt = " 暗号化有効 (AES-256-GCM + RSA)" if CRYPTO_OK \
                   else "⚠ 暗号化無効  →  pip install cryptography"
        info_clr = C["success"] if CRYPTO_OK else C["warning"]
        tk.Label(card, text=info_txt, font=("Helvetica", 10),
                 bg=C["sidebar"], fg=info_clr).pack(pady=(18, 0))

    def _launch(self):
        name = self._uname_var.get().strip()
        if not name:
            messagebox.showwarning("入力エラー", "ユーザー名を入力してください")
            return
        self.username = name
        self._login_frm.destroy()

        self.net = NetworkManager(self.username, self.peer_id, self.crypto)
        self.net.on_peer_found = self._cb_peer_found
        self.net.on_peer_lost  = self._cb_peer_lost
        self.net.on_message    = self._cb_message
        self.net.start()

        self._build_main()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # ════════════════════════════════════
    # メイン UI
    # ════════════════════════════════════
    def _build_main(self):
        # ── サイドバー ───────────────────────────────
        sb = tk.Frame(self.root, bg=C["sidebar"], width=248)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        # ヘッダー
        hdr = tk.Frame(sb, bg=C["sidebar"])
        hdr.pack(fill="x", padx=14, pady=12)
        tk.Label(hdr, text="🔗  " + APP_NAME,
                 font=("Helvetica", 14, "bold"),
                 bg=C["sidebar"], fg=C["accent"]).pack(side="left")

        # 自分の情報カード
        me = tk.Frame(sb, bg=C["panel"], padx=12, pady=8)
        me.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(me, text=f"🟢  {self.username}",
                 font=("Helvetica", 11, "bold"),
                 bg=C["panel"], fg=C["success"]).pack(anchor="w")
        self._ip_lbl = tk.Label(me, text=f"IP: {self.net.my_ip}",
                                font=("Helvetica", 9),
                                bg=C["panel"], fg=C["subtext"])
        self._ip_lbl.pack(anchor="w")

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=10)

        # ── ユーザーリスト ────────────────────────────
        sec_lbl = tk.Frame(sb, bg=C["sidebar"])
        sec_lbl.pack(fill="x", padx=14, pady=(8, 3))
        tk.Label(sec_lbl, text="オンラインユーザー",
                 font=("Helvetica", 9), bg=C["sidebar"], fg=C["subtext"]).pack(side="left")
        self._online_cnt = tk.Label(sec_lbl, text="0",
                                    font=("Helvetica", 9, "bold"),
                                    bg=C["sidebar"], fg=C["accent"])
        self._online_cnt.pack(side="right")

        self._peer_lb = tk.Listbox(sb, bg=C["sidebar"], fg=C["text"],
                                   selectbackground=C["accent"], selectforeground=C["sidebar"],
                                   font=("Helvetica", 11), relief="flat", borderwidth=0,
                                   activestyle="none", cursor="hand2")
        self._peer_lb.pack(fill="both", expand=True, padx=6)
        self._peer_lb.bind("<<ListboxSelect>>", self._sel_peer)

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=10, pady=4)

        # ── グループリスト ────────────────────────────
        grp_hdr = tk.Frame(sb, bg=C["sidebar"])
        grp_hdr.pack(fill="x", padx=14, pady=(0, 3))
        tk.Label(grp_hdr, text="グループルーム",
                 font=("Helvetica", 9), bg=C["sidebar"], fg=C["subtext"]).pack(side="left")
        tk.Button(grp_hdr, text="＋", font=("Helvetica", 12),
                  bg=C["sidebar"], fg=C["accent2"],
                  relief="flat", cursor="hand2",
                  command=self._create_group).pack(side="right")

        self._grp_lb = tk.Listbox(sb, bg=C["sidebar"], fg=C["text"],
                                  selectbackground=C["accent2"], selectforeground=C["sidebar"],
                                  font=("Helvetica", 11), relief="flat", borderwidth=0,
                                  activestyle="none", cursor="hand2", height=5)
        self._grp_lb.pack(fill="x", padx=6, pady=(0, 8))
        self._grp_lb.bind("<<ListboxSelect>>", self._sel_group)

        # ── メインチャットエリア ───────────────────────
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(side="right", fill="both", expand=True)

        # チャットヘッダー
        chat_hdr = tk.Frame(main, bg=C["sidebar"], height=52)
        chat_hdr.pack(fill="x")
        chat_hdr.pack_propagate(False)

        self._chat_title = tk.StringVar(value="← チャット相手を選択")
        tk.Label(chat_hdr, textvariable=self._chat_title,
                 font=("Helvetica", 13, "bold"),
                 bg=C["sidebar"], fg=C["text"], padx=18).pack(side="left", pady=14)

        self._enc_lbl = tk.Label(chat_hdr, text="",
                                 font=("Helvetica", 9),
                                 bg=C["sidebar"], fg=C["success"], padx=12)
        self._enc_lbl.pack(side="right", pady=14)

        # チャット表示
        self._disp = scrolledtext.ScrolledText(
            main, bg=C["bg"], fg=C["text"],
            font=("Helvetica", 11), relief="flat", borderwidth=0,
            state="disabled", wrap="word", padx=18, pady=14,
        )
        self._disp.pack(fill="both", expand=True)

        self._disp.tag_configure("me_name",    foreground=C["me_clr"],    font=("Helvetica", 10, "bold"))
        self._disp.tag_configure("me_text",    foreground=C["text"])
        self._disp.tag_configure("peer_name",  foreground=C["other_clr"], font=("Helvetica", 10, "bold"))
        self._disp.tag_configure("peer_text",  foreground=C["text"])
        self._disp.tag_configure("sys_msg",    foreground=C["subtext"],   font=("Helvetica", 9, "italic"))
        self._disp.tag_configure("timestamp",  foreground=C["border"],    font=("Helvetica", 8))

        # 入力エリア
        inp_frm = tk.Frame(main, bg=C["sidebar"], pady=14)
        inp_frm.pack(fill="x")

        inner = tk.Frame(inp_frm, bg=C["panel"], padx=10, pady=4)
        inner.pack(fill="x", padx=14)

        self._inp = tk.Entry(inner, font=("Helvetica", 12),
                             bg=C["panel"], fg=C["text"],
                             insertbackground=C["text"], relief="flat")
        self._inp.pack(side="left", fill="x", expand=True, ipady=7)
        self._inp.bind("<Return>",    self._send)
        self._inp.bind("<KP_Enter>",  self._send)

        send_btn = tk.Button(inner, text="送信 ▶",
                             font=("Helvetica", 11, "bold"),
                             bg=C["accent"], fg=C["sidebar"],
                             relief="flat", cursor="hand2",
                             padx=14, command=self._send)
        send_btn.pack(side="right", padx=(10, 0))

        # ステータスバー
        self._status_var = tk.StringVar(value="🟢 起動完了")
        tk.Label(self.root, textvariable=self._status_var,
                 font=("Helvetica", 9), bg=C["sidebar"],
                 fg=C["subtext"], anchor="w", padx=14).pack(side="bottom", fill="x")

        self._tick()

    # ════════════════════════════════════
    # 定期更新（ステータスバー等）
    # ════════════════════════════════════
    def _tick(self):
        if self.net:
            online = sum(1 for p in self.net.peers.values() if p.online and p.alive())
            self._online_cnt.config(text=str(online))
            enc = "🔒 E2EE 有効" if CRYPTO_OK else "🔓 暗号化なし"
            self._status_var.set(
                f"🟢 {self.username}  |  IP: {self.net.my_ip}  |  接続: {online} 名  |  {enc}"
            )
        self.root.after(5000, self._tick)

    # ════════════════════════════════════
    # ピア管理コールバック
    # ════════════════════════════════════
    def _cb_peer_found(self, peer: Peer):
        self.root.after(0, lambda: self._refresh_peers())
        self.root.after(0, lambda: self._sys(f"🟢 {peer.username}（{peer.ip}）が参加しました"))

    def _cb_peer_lost(self, peer: Peer):
        self.root.after(0, lambda: self._refresh_peers())
        self.root.after(0, lambda: self._sys(f"🔴 {peer.username} がオフラインになりました"))

    def _refresh_peers(self):
        self._peer_lb.delete(0, tk.END)
        self._peer_ids = []
        for pid, peer in self.net.peers.items():
            st  = "🟢" if peer.online and peer.alive() else "🔴"
            unr = f"  ({self.unread[pid]})" if self.unread.get(pid, 0) > 0 else ""
            self._peer_lb.insert(tk.END, f"  {st}  {peer.username}{unr}")
            self._peer_ids.append(pid)

    def _sel_peer(self, _event=None):
        sel = self._peer_lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._peer_ids):
            return
        pid  = self._peer_ids[idx]
        peer = self.net.peers.get(pid)
        if not peer:
            return

        self.current = pid
        self._grp_lb.selection_clear(0, tk.END)
        self.unread[pid] = 0
        self._refresh_peers()

        self._chat_title.set(f"💬  {peer.username}   ({peer.ip})")
        if CRYPTO_OK and self.crypto.has_session(pid):
            self._enc_lbl.config(text="🔒 E2EE", fg=C["success"])
        elif CRYPTO_OK:
            self._enc_lbl.config(text="🔑 鍵交換中…", fg=C["warning"])
        else:
            self._enc_lbl.config(text="🔓 暗号化なし", fg=C["error"])

        self._load_history(pid)

    # ════════════════════════════════════
    # グループ管理
    # ════════════════════════════════════
    def _create_group(self):
        online_peers = [(pid, p) for pid, p in self.net.peers.items()
                        if p.online and p.alive()]
        if not online_peers:
            messagebox.showinfo("情報", "オンラインのユーザーがいません")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("グループ作成")
        dlg.geometry("340x430")
        dlg.configure(bg=C["bg"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        tk.Label(dlg, text="グループ名", bg=C["bg"], fg=C["text"],
                 font=("Helvetica", 12)).pack(padx=22, pady=(22, 4), anchor="w")
        nv = tk.StringVar()
        ne = tk.Entry(dlg, textvariable=nv, bg=C["input_bg"], fg=C["text"],
                      font=("Helvetica", 12), relief="flat")
        ne.pack(fill="x", padx=22, ipady=7)
        ne.focus_set()

        tk.Label(dlg, text="メンバーを選択", bg=C["bg"], fg=C["text"],
                 font=("Helvetica", 12)).pack(padx=22, pady=(14, 4), anchor="w")

        member_vars = {}
        scroll_frm = tk.Frame(dlg, bg=C["bg"])
        scroll_frm.pack(fill="both", expand=True, padx=22)
        for pid, peer in online_peers:
            v = tk.BooleanVar(value=True)
            member_vars[pid] = v
            tk.Checkbutton(scroll_frm, text=peer.username, variable=v,
                           bg=C["bg"], fg=C["text"], activebackground=C["bg"],
                           selectcolor=C["panel"], font=("Helvetica", 11),
                           cursor="hand2").pack(anchor="w")

        def do_create():
            room = nv.get().strip()
            if not room:
                messagebox.showwarning("エラー", "グループ名を入力してください", parent=dlg)
                return
            if room in self.groups:
                messagebox.showwarning("エラー", "同名のグループが既にあります", parent=dlg)
                return
            chosen = [pid for pid, v in member_vars.items() if v.get()]
            if not chosen:
                messagebox.showwarning("エラー", "メンバーを選択してください", parent=dlg)
                return
            members = [self.peer_id] + chosen
            self.groups[room] = {"name": room, "members": members}
            self._group_names.append(room)
            self._grp_lb.insert(tk.END, f"  👥  {room}")

            # 招待を送信
            for pid in chosen:
                self.net.send_group_invite(pid, room, members)

            dlg.destroy()
            self._open_group(room)

        tk.Button(dlg, text="グループを作成",
                  font=("Helvetica", 12, "bold"),
                  bg=C["accent2"], fg=C["sidebar"],
                  relief="flat", cursor="hand2",
                  padx=20, pady=10, command=do_create).pack(pady=18)

    def _open_group(self, room):
        self.current = f"group:{room}"
        self._peer_lb.selection_clear(0, tk.END)
        self.unread[self.current] = 0
        self._chat_title.set(f"👥  {room}")
        self._enc_lbl.config(text="")
        self._load_history(self.current)

    def _sel_group(self, _event=None):
        sel = self._grp_lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._group_names):
            return
        self._open_group(self._group_names[idx])

    # ════════════════════════════════════
    # メッセージ送受信
    # ════════════════════════════════════
    def _send(self, _event=None):
        text = self._inp.get().strip()
        if not text or not self.current:
            return
        self._inp.delete(0, tk.END)
        now = datetime.now().strftime("%H:%M")

        if self.current.startswith("group:"):
            room  = self.current[6:]
            group = self.groups.get(room)
            if not group:
                return
            self.net.send_group(room, text, group["members"])
            self._append(self.current, self.username, text, now, is_me=True)
            self.chat_logs[self.current].append(
                {"from": self.username, "text": text, "time": now, "is_me": True})
        else:
            peer = self.net.peers.get(self.current)
            if not peer or not (peer.online and peer.alive()):
                self._sys("⚠ このユーザーはオフラインです")
                return
            ok = self.net.send_chat(self.current, text)
            if ok:
                self._append(self.current, self.username, text, now, is_me=True)
                self.chat_logs[self.current].append(
                    {"from": self.username, "text": text, "time": now, "is_me": True})
                # 暗号化ラベル更新
                if CRYPTO_OK and self.crypto.has_session(self.current):
                    self._enc_lbl.config(text="🔒 E2EE", fg=C["success"])
            else:
                self._sys("⚠ 送信できませんでした（オフライン？）")

    def _cb_message(self, msg: dict):
        self.root.after(0, lambda: self._process(msg))

    def _process(self, msg: dict):
        t       = msg["type"]
        pid     = msg["from_id"]
        uname   = msg["from_name"]
        text    = msg.get("text", "")
        now     = datetime.fromtimestamp(msg["ts"]).strftime("%H:%M")

        if t == TYPE_GROUP_INV:
            room    = msg["room"]
            members = msg["members"]
            if room not in self.groups:
                self.groups[room] = {"name": room, "members": members}
                self._group_names.append(room)
                self._grp_lb.insert(tk.END, f"  👥  {room}")
            self._sys(f"📩 {uname} からグループ「{room}」に招待されました")
            return

        if t == TYPE_CHAT:
            chat_id = pid
        elif t == TYPE_GROUP_MSG:
            chat_id = f"group:{msg['room']}"
        else:
            return

        entry = {"from": uname, "text": text, "time": now, "is_me": False}
        self.chat_logs[chat_id].append(entry)

        if self.current == chat_id:
            self._append(chat_id, uname, text, now, is_me=False)
            if t == TYPE_CHAT and CRYPTO_OK and self.crypto.has_session(pid):
                self._enc_lbl.config(text="🔒 E2EE", fg=C["success"])
        else:
            self.unread[chat_id] += 1
            self._refresh_peers()
            short = text[:36] + ("…" if len(text) > 36 else "")
            self._status_var.set(f"💬 {uname}: {short}")

    # ════════════════════════════════════
    # チャット表示
    # ════════════════════════════════════
    def _load_history(self, chat_id):
        self._disp.config(state="normal")
        self._disp.delete("1.0", tk.END)
        for e in self.chat_logs.get(chat_id, []):
            self._append(chat_id, e["from"], e["text"], e["time"],
                         is_me=e["is_me"], scroll=False)
        self._disp.config(state="disabled")
        self._disp.see(tk.END)

    def _append(self, chat_id, sender, text, ts,
                is_me=False, scroll=True):
        self._disp.config(state="normal")
        if is_me:
            self._disp.insert(tk.END, f"  {ts}  ", "timestamp")
            self._disp.insert(tk.END, f"あなた\n", "me_name")
            self._disp.insert(tk.END, f"  {text}\n\n", "me_text")
        else:
            self._disp.insert(tk.END, f"  {ts}  ", "timestamp")
            self._disp.insert(tk.END, f"{sender}\n", "peer_name")
            self._disp.insert(tk.END, f"  {text}\n\n", "peer_text")
        self._disp.config(state="disabled")
        if scroll:
            self._disp.see(tk.END)

    def _sys(self, text):
        self._disp.config(state="normal")
        self._disp.insert(tk.END, f"\n  ── {text} ──\n\n", "sys_msg")
        self._disp.config(state="disabled")
        self._disp.see(tk.END)

    # ════════════════════════════════════
    # 終了
    # ════════════════════════════════════
    def _quit(self):
        if self.net:
            self.net.stop()
        self.root.destroy()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# エントリーポイント
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════╗
║  {APP_NAME} v{APP_VERSION}  —  LAN チャットアプリ    ║
╠══════════════════════════════════════════╣
║  暗号化: {"✅ AES-256-GCM + RSA" if CRYPTO_OK else "❌ 無効 (pip install cryptography)"}
║  UDPポート: {DISCOVERY_PORT}   TCPポート: {CHAT_PORT}
╚══════════════════════════════════════════╝
""")
    root = tk.Tk()
    app  = NodeTalkApp(root)
    root.mainloop()
