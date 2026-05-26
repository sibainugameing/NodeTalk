#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════╗
║  NodeTalk v4.0  ―  LAN チャット完全版（1ファイル）                ║
║  修正: macOSボタン白枠/フォント崩れ → Label製ボタン+OS別フォント  ║
╚═══════════════════════════════════════════════════════════════════╝
pip install cryptography   (暗号化 任意)
python nodetalk.py
"""

import socket, threading, json, time, uuid, base64, secrets
import struct, os, hashlib, platform
from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OS 別フォント
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_SYS = platform.system()
if _SYS == "Darwin":
    _FF = "Helvetica Neue"
elif _SYS == "Windows":
    _FF = "Segoe UI"
else:
    _FF = "Ubuntu"

def F(size, bold=False, italic=False):
    s = ("bold italic" if bold and italic
         else "bold" if bold
         else "italic" if italic else "")
    return (_FF, size, s) if s else (_FF, size)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 定数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APP_NAME      = "NodeTalk"
APP_VER       = "4.0.0"
DISC_PORT     = 55000
CHAT_PORT     = 55001
DISC_INTERVAL = 5
PEER_TIMEOUT  = 28
MAX_FILE      = 52_428_800
CHUNK_SZ      = 32_768

T_DISCOVER="discover"; T_GOODBYE="goodbye"
T_CHAT="chat";         T_GROUP="group_msg"
T_INVITE="group_invite"
T_READ="read";         T_TYPING="typing"
T_REACT="reaction"
T_FMETA="file_meta";   T_FCHUNK="file_chunk"

AVATAR_COLORS = [
    "#6366f1","#8b5cf6","#ec4899","#f43f5e",
    "#f97316","#eab308","#22c55e","#14b8a6",
    "#0ea5e9","#3b82f6","#a855f7","#10b981",
]
REACT_EMOJIS  = ["👍","❤️","😂","😮","😢","🎉","🔥","👀"]
COMMON_EMOJIS = [
    "😀","😂","🥰","😎","😅","🤔","😭","😤","🥺","😇",
    "👍","👎","❤️","🔥","🎉","✨","💯","🙏","👋","🤝",
    "😴","🤣","😊","😍","🤩","😬","😈","💀","🙄","😏",
    "🍕","🍜","🍣","🍺","☕","🎮","🎵","📱","💻","🔒",
]

def peer_color(pid):
    return AVATAR_COLORS[int(hashlib.md5(pid.encode()).hexdigest(),16) % len(AVATAR_COLORS)]

def fmt_size(n):
    for u in ("B","KB","MB","GB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} GB"

def ts_now(): return datetime.now().strftime("%H:%M")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# カラー
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
C = {
    "bg":        "#0f0f1a",
    "sidebar":   "#13131f",
    "panel":     "#1c1c2e",
    "panel2":    "#242438",
    "border":    "#2e2e4a",
    "text":      "#e8e8f0",
    "subtext":   "#a0a0c0",
    "muted":     "#54547a",
    "accent":    "#6366f1",
    "accent_h":  "#818cf8",
    "accent2":   "#a855f7",
    "success":   "#22c55e",
    "warning":   "#f59e0b",
    "error":     "#ef4444",
    "me_bub":    "#2e2b6e",
    "peer_bub":  "#1e1e32",
    "sky":       "#38bdf8",
    "peach":     "#fb923c",
    "inp":       "#191927",
    "sel":       "#252550",
    "item_h":    "#1e1e38",
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FlatBtn  ―  Label ベースのクロスプラットフォームボタン
#   tk.Button は macOS で bg が無視されて白くなるため
#   Label + イベントバインドで代替する
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FlatBtn(tk.Label):
    def __init__(self, master, text="", command=None,
                 bg=None, fg=None, hover=None,
                 font=None, padx=12, pady=7, **kw):
        self._nbg = bg    or C["panel2"]
        self._hbg = hover or C["item_h"]
        self._cmd = command
        super().__init__(master, text=text,
                         bg=self._nbg, fg=fg or C["text"],
                         font=font or F(11),
                         cursor="hand2", padx=padx, pady=pady, **kw)
        self.bind("<Enter>",    lambda _: self.config(bg=self._hbg))
        self.bind("<Leave>",    lambda _: self.config(bg=self._nbg))
        self.bind("<Button-1>", lambda _: self._cmd() if self._cmd else None)

    def set_colors(self, bg, hover=None):
        self._nbg = bg; self._hbg = hover or bg; self.config(bg=bg)

    def set_cmd(self, cmd): self._cmd = cmd


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ScrollableFrame  ―  スクロール可能コンテナ
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ScrollableFrame(tk.Frame):
    def __init__(self, master, bg=None, **kw):
        _bg = bg or C["sidebar"]
        super().__init__(master, bg=_bg, **kw)
        self._cv  = tk.Canvas(self, bg=_bg, highlightthickness=0, bd=0)
        self._sb  = tk.Scrollbar(self, orient="vertical",
                                  command=self._cv.yview,
                                  bg=_bg, troughcolor=_bg, width=4,
                                  relief="flat", bd=0)
        self.inner = tk.Frame(self._cv, bg=_bg)
        self._win  = self._cv.create_window((0,0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", lambda e:
            self._cv.configure(scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>", lambda e:
            self._cv.itemconfig(self._win, width=e.width))
        self._cv.configure(yscrollcommand=self._sb.set)

        self._sb.pack(side="right", fill="y")
        self._cv.pack(side="left",  fill="both", expand=True)

        for w in (self._cv, self.inner):
            w.bind("<MouseWheel>", self._wheel)
            w.bind("<Button-4>",   self._wheel)
            w.bind("<Button-5>",   self._wheel)

    def _wheel(self, e):
        d = -1 if (e.delta > 0 or e.num == 4) else 1
        self._cv.yview_scroll(d*2, "units")

    def scroll_top(self): self._cv.yview_moveto(0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CryptoManager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CryptoManager:
    def __init__(self):
        self.enabled    = CRYPTO_OK
        self._priv      = None
        self.pub_pem    = None
        self._pub_keys  = {}
        self._send_keys = {}
        self._recv_keys = {}
        if self.enabled:
            self._priv   = rsa.generate_private_key(65537, 2048)
            self.pub_pem = self._priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def store_pub(self, pid, pem):
        if not self.enabled: return
        try: self._pub_keys[pid] = serialization.load_pem_public_key(pem.encode())
        except: pass

    def has_pub(self, pid): return pid in self._pub_keys

    def make_send_key(self, pid):
        if not self.enabled or pid not in self._pub_keys: return None
        k = secrets.token_bytes(32); self._send_keys[pid] = k
        enc = self._pub_keys[pid].encrypt(k, ap.OAEP(
            mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(enc).decode()

    def has_send_key(self, pid): return pid in self._send_keys

    def load_recv_key(self, pid, b64):
        if not self.enabled or not self._priv: return False
        try:
            raw = self._priv.decrypt(base64.b64decode(b64), ap.OAEP(
                mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self._recv_keys[pid] = raw; return True
        except: return False

    def has_recv_key(self, pid): return pid in self._recv_keys

    def encrypt(self, pid, text):
        if not self.enabled or pid not in self._send_keys: return text, False
        try:
            n = secrets.token_bytes(12)
            ct = AESGCM(self._send_keys[pid]).encrypt(n, text.encode(), None)
            return base64.b64encode(n+ct).decode(), True
        except: return text, False

    def decrypt(self, pid, ct):
        if not self.enabled or pid not in self._recv_keys: return ct
        try:
            d = base64.b64decode(ct)
            return AESGCM(self._recv_keys[pid]).decrypt(d[:12], d[12:], None).decode()
        except: return "[復号失敗]"

    def encrypt_bytes(self, pid, data):
        if not self.enabled or pid not in self._send_keys: return data, False
        try:
            n = secrets.token_bytes(12)
            return n + AESGCM(self._send_keys[pid]).encrypt(n, data, None), True
        except: return data, False

    def decrypt_bytes(self, pid, data):
        if not self.enabled or pid not in self._recv_keys: return data
        try: return AESGCM(self._recv_keys[pid]).decrypt(data[:12], data[12:], None)
        except: return data

    def can_enc(self, pid): return self.enabled and pid in self._pub_keys


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Peer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Peer:
    def __init__(self, pid, name, ip):
        self.id = pid; self.name = name; self.ip = ip
        self.last_seen = time.time(); self.online = True
    def touch(self, name=None):
        self.last_seen = time.time(); self.online = True
        if name: self.name = name
    def alive(self): return (time.time() - self.last_seen) < PEER_TIMEOUT


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NetworkManager  (1接続=1メッセージ TCP)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NetworkManager:
    def __init__(self, username, peer_id, crypto):
        self.username = username; self.peer_id = peer_id; self.crypto = crypto
        self.peers = {}; self._lock = threading.Lock(); self._running = False
        self.my_ip = self._local_ip()
        self.on_peer_found = None
        self.on_peer_lost  = None
        self.on_message    = None

    @staticmethod
    def _local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
        except: return "127.0.0.1"

    def start(self):
        self._running = True
        for fn in (self._udp_recv, self._udp_cast, self._tcp_srv, self._watchdog):
            threading.Thread(target=fn, daemon=True).start()

    def stop(self): self._bcast(T_GOODBYE,{}); self._running = False

    # ── UDP ─────────────────────────────────────
    def _pkt(self, t, extra=None):
        d = {"type":t,"from_id":self.peer_id,"from_name":self.username,"ts":time.time()}
        if self.crypto.enabled and self.crypto.pub_pem: d["pub_key"] = self.crypto.pub_pem
        if extra: d.update(extra)
        return json.dumps(d, ensure_ascii=False).encode()

    def _bcast(self, t, extra=None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(self._pkt(t,extra), ("<broadcast>",DISC_PORT)); s.close()
        except: pass

    def _uni(self, ip, t, extra=None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(self._pkt(t,extra), (ip,DISC_PORT)); s.close()
        except: pass

    def _udp_cast(self):
        while self._running: self._bcast(T_DISCOVER); time.sleep(DISC_INTERVAL)

    def _udp_recv(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
        except AttributeError: pass
        s.bind(("",DISC_PORT)); s.settimeout(1.0)
        while self._running:
            try:
                data,(ip,_) = s.recvfrom(65536)
                msg = json.loads(data.decode())
                if msg.get("from_id") != self.peer_id: self._on_udp(msg, ip)
            except (socket.timeout, json.JSONDecodeError): pass
            except: pass
        s.close()

    def _on_udp(self, msg, ip):
        t=msg.get("type"); pid=msg.get("from_id",""); name=msg.get("from_name","?")
        if not pid: return
        if t == T_DISCOVER:
            with self._lock:
                is_new = pid not in self.peers
                if is_new: self.peers[pid] = Peer(pid,name,ip)
                else: self.peers[pid].touch(name)
            if pub := msg.get("pub_key"): self.crypto.store_pub(pid,pub)
            if is_new:
                self._uni(ip, T_DISCOVER)
                if self.on_peer_found: self.on_peer_found(self.peers[pid])
        elif t == T_GOODBYE:
            with self._lock:
                if pid in self.peers: self.peers[pid].online = False
            if self.on_peer_lost and pid in self.peers: self.on_peer_lost(self.peers[pid])

    # ── TCP サーバー ─────────────────────────────
    def _tcp_srv(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        try: srv.bind(("",CHAT_PORT))
        except OSError as e: print(f"[エラー] TCP:{CHAT_PORT} {e}"); return
        srv.listen(32); srv.settimeout(1.0)
        while self._running:
            try:
                conn,(ip,_) = srv.accept()
                threading.Thread(target=self._tcp_recv,args=(conn,ip),daemon=True).start()
            except socket.timeout: pass
            except: pass
        srv.close()

    def _read_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            try: c = conn.recv(min(n-len(buf),65536))
            except: return None
            if not c: return None
            buf += c
        return buf

    def _tcp_recv(self, conn, peer_ip):
        conn.settimeout(30)
        try:
            hdr = self._read_exact(conn,4)
            if not hdr: return
            ln = struct.unpack(">I",hdr)[0]
            if not ln or ln > MAX_FILE+4096: return
            body = self._read_exact(conn, ln)
            if not body: return
            self._on_tcp(json.loads(body.decode("utf-8")), peer_ip)
        except: pass
        finally:
            try: conn.close()
            except: pass

    def _on_tcp(self, msg, peer_ip):
        t=msg.get("type",""); pid=msg.get("from_id",""); name=msg.get("from_name",peer_ip)
        if not pid or not t: return
        with self._lock:
            is_new = pid not in self.peers
            if is_new: self.peers[pid] = Peer(pid,name,peer_ip)
            else: self.peers[pid].touch(name)
        if is_new and self.on_peer_found: self.on_peer_found(self.peers[pid])
        if pub := msg.get("pub_key"): self.crypto.store_pub(pid,pub)
        if sk  := msg.get("session_key"): self.crypto.load_recv_key(pid,sk)

        om = self.on_message
        if not om: return

        if t in (T_CHAT, T_GROUP):
            text=msg.get("text",""); ie=msg.get("encrypted",False)
            if ie: text=self.crypto.decrypt(pid,text)
            om({"type":t,"msg_id":msg.get("msg_id",""),"from_id":pid,"from_name":name,
                "text":text,"encrypted":ie,"ts":msg.get("ts",time.time()),"room":msg.get("room","")})
        elif t == T_INVITE:
            om({"type":t,"from_id":pid,"from_name":name,
                "room":msg.get("room",""),"members":msg.get("members",[])})
        elif t == T_READ:
            om({"type":t,"from_id":pid,"msg_ids":msg.get("msg_ids",[])})
        elif t == T_TYPING:
            om({"type":t,"from_id":pid,"from_name":name})
        elif t == T_REACT:
            om({"type":t,"from_id":pid,"msg_id":msg.get("msg_id",""),"emoji":msg.get("emoji","")})
        elif t == T_FMETA:
            om({"type":t,"msg_id":msg.get("msg_id",""),"from_id":pid,"from_name":name,
                "file_id":msg.get("file_id",""),"filename":msg.get("filename","file"),
                "file_size":msg.get("file_size",0),"total_chunks":msg.get("total_chunks",1),
                "encrypted":msg.get("encrypted",False),"ts":msg.get("ts",time.time()),
                "room":msg.get("room","")})
        elif t == T_FCHUNK:
            om({"type":t,"from_id":pid,"file_id":msg.get("file_id",""),
                "chunk_idx":msg.get("chunk_idx",0),"data_b64":msg.get("data_b64",""),
                "encrypted":msg.get("encrypted",False)})

    # ── TCP 送信 ─────────────────────────────────
    def _tcp_send(self, pid, payload):
        peer = self.peers.get(pid)
        if not peer: return False
        if self.crypto.enabled and self.crypto.has_pub(pid) and not self.crypto.has_send_key(pid):
            sk = self.crypto.make_send_key(pid)
            if sk: payload["session_key"] = sk
        if self.crypto.enabled and self.crypto.pub_pem: payload["pub_key"] = self.crypto.pub_pem
        payload.setdefault("from_id",   self.peer_id)
        payload.setdefault("from_name", self.username)
        payload.setdefault("ts",        time.time())
        try:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8); s.connect((peer.ip, CHAT_PORT))
            s.sendall(struct.pack(">I", len(body)) + body); s.close(); return True
        except Exception as e: print(f"[送信失敗→{peer.ip}] {e}"); return False

    def send_chat(self, pid, mid, text):
        enc,ie = self.crypto.encrypt(pid,text)
        return self._tcp_send(pid,{"type":T_CHAT,"msg_id":mid,"text":enc,"encrypted":ie})

    def send_group(self, room, mid, text, members):
        ok=0
        for pid in members:
            if pid == self.peer_id: continue
            enc,ie = self.crypto.encrypt(pid,text)
            if self._tcp_send(pid,{"type":T_GROUP,"msg_id":mid,"room":room,"text":enc,"encrypted":ie}): ok+=1
        return ok

    def send_invite(self, pid, room, members):
        self._tcp_send(pid,{"type":T_INVITE,"room":room,"members":members})

    def send_read(self, pid, ids):
        if ids: self._tcp_send(pid,{"type":T_READ,"msg_ids":ids})

    def send_typing(self, pid):
        self._tcp_send(pid,{"type":T_TYPING})

    def send_reaction(self, pid, mid, emoji):
        self._tcp_send(pid,{"type":T_REACT,"msg_id":mid,"emoji":emoji})

    def send_file(self, pid, path, prog=None):
        try:
            with open(path,"rb") as f: raw=f.read()
        except Exception as e: print(f"[ファイル] {e}"); return False, ""
        fn=os.path.basename(path); fid=str(uuid.uuid4())[:12]
        mid=str(uuid.uuid4())[:8]; sz=len(raw)
        chunks=[raw[i:i+CHUNK_SZ] for i in range(0,len(raw),CHUNK_SZ)]; total=len(chunks)
        ec=[]
        for ch in chunks:
            b,ie=self.crypto.encrypt_bytes(pid,ch); ec.append((base64.b64encode(b).decode(),ie))
        ie_f = ec[0][1] if ec else False
        ok = self._tcp_send(pid,{"type":T_FMETA,"msg_id":mid,"file_id":fid,"filename":fn,
                                  "file_size":sz,"total_chunks":total,"encrypted":ie_f})
        if not ok: return False, mid
        for i,(b64,_) in enumerate(ec):
            self._tcp_send(pid,{"type":T_FCHUNK,"file_id":fid,"chunk_idx":i,
                                 "data_b64":b64,"encrypted":ie_f})
            if prog: prog(i+1,total)
        return True, mid

    def _watchdog(self):
        while self._running:
            time.sleep(8); dead=[]
            with self._lock:
                for pid,p in list(self.peers.items()):
                    if p.online and not p.alive(): p.online=False; dead.append(p)
            for p in dead:
                if self.on_peer_lost: self.on_peer_lost(p)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NodeTalkApp
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NodeTalkApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME}  v{APP_VER}")
        self.root.geometry("1160x780")
        self.root.minsize(900,580)
        self.root.configure(bg=C["bg"])

        self.username  = ""
        self.peer_id   = str(uuid.uuid4())[:8]
        self.crypto    = CryptoManager()
        self.net: NetworkManager = None

        self.chat_logs  = defaultdict(list)
        self.groups     = {}
        self.rcv_files  = {}
        self.unread     = defaultdict(int)
        self.current    = None

        self._peer_items    = {}   # pid → {"frame","all_bg","set_bg"}
        self._selected_pid  = None
        self._selected_gid  = None
        self._grp_items     = {}   # room → {"frame","set_bg"}

        self._typing_peers  = {}
        self._typing_timers = {}
        self._typing_send_t = 0

        self._search_visible = False
        self._search_results = []
        self._search_idx     = 0

        self._msg_outer = None   # reference for search bar placement

        self._build_login()

    # ══════════════════════════════════════════
    # ログイン画面
    # ══════════════════════════════════════════
    def _build_login(self):
        self._login_frm = tk.Frame(self.root, bg=C["bg"])
        self._login_frm.pack(expand=True, fill="both")

        # カード
        card = tk.Frame(self._login_frm, bg=C["panel"], padx=64, pady=60)
        card.place(relx=0.5, rely=0.5, anchor="center")

        # ロゴ
        cv = tk.Canvas(card, width=80, height=80, bg=C["panel"], highlightthickness=0)
        cv.pack(pady=(0,14))
        cv.create_oval(4,4,76,76, fill=C["accent"], outline="")
        cv.create_text(40,41, text="🔗", font=("Arial",30))

        tk.Label(card, text=APP_NAME, font=F(30,bold=True),
                 bg=C["panel"], fg=C["accent"]).pack()
        tk.Label(card, text="LAN 内リアルタイムチャット  ·  インターネット不要",
                 font=F(11), bg=C["panel"], fg=C["muted"]).pack(pady=(4,36))

        tk.Label(card, text="ユーザー名", font=F(11),
                 bg=C["panel"], fg=C["subtext"]).pack(anchor="w")
        self._uname_var = tk.StringVar()
        ent = tk.Entry(card, textvariable=self._uname_var,
                       font=F(14), bg=C["panel2"], fg=C["text"],
                       insertbackground=C["text"], relief="flat",
                       highlightthickness=1, highlightcolor=C["accent"],
                       highlightbackground=C["border"], width=26)
        ent.pack(ipady=12, pady=(6,28), fill="x")
        ent.focus_set(); ent.bind("<Return>", lambda _: self._launch())

        # 送信ボタン (FlatBtn)
        FlatBtn(card, text="参加する  →",
                command=self._launch,
                bg=C["accent"], fg="white", hover=C["accent_h"],
                font=F(13,bold=True), padx=24, pady=13).pack(fill="x")

        inf = ("✅ 暗号化有効  (AES-256-GCM + RSA-2048)" if CRYPTO_OK
               else "⚠  暗号化無効  →  pip install cryptography")
        tk.Label(card, text=inf, font=F(10),
                 bg=C["panel"], fg=C["success"] if CRYPTO_OK else C["warning"]).pack(pady=(22,0))

    def _launch(self):
        name = self._uname_var.get().strip()
        if not name: messagebox.showwarning("入力エラー","ユーザー名を入力してください"); return
        self.username = name
        self._login_frm.destroy()
        self.net = NetworkManager(self.username, self.peer_id, self.crypto)
        self.net.on_peer_found = lambda p: self.root.after(0, lambda pp=p: self._cb_peer_found(pp))
        self.net.on_peer_lost  = lambda p: self.root.after(0, lambda pp=p: self._cb_peer_lost(pp))
        self.net.on_message    = lambda m: self.root.after(0, lambda mm=m: self._cb_msg(mm))
        self.net.start()
        self._build_main()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # ══════════════════════════════════════════
    # メインUI
    # ══════════════════════════════════════════
    def _build_main(self):
        # ── サイドバー ───────────────────────
        self._sb = tk.Frame(self.root, bg=C["sidebar"], width=280)
        self._sb.pack(side="left", fill="y")
        self._sb.pack_propagate(False)

        # ロゴ行
        logo_row = tk.Frame(self._sb, bg=C["sidebar"])
        logo_row.pack(fill="x", padx=14, pady=(16,12))

        logo_cv = tk.Canvas(logo_row, width=30, height=30,
                             bg=C["sidebar"], highlightthickness=0)
        logo_cv.pack(side="left", padx=(0,8))
        logo_cv.create_oval(2,2,28,28, fill=C["accent"], outline="")
        logo_cv.create_text(15,16, text="🔗", font=("Arial",13))

        tk.Label(logo_row, text=APP_NAME, font=F(16,bold=True),
                 bg=C["sidebar"], fg=C["accent"]).pack(side="left")

        FlatBtn(logo_row, text="⚙", command=self._open_settings,
                bg=C["sidebar"], fg=C["subtext"], hover=C["item_h"],
                font=F(15), padx=8, pady=4).pack(side="right")

        # 自分カード
        me = tk.Frame(self._sb, bg=C["panel2"], padx=12, pady=10)
        me.pack(fill="x", padx=10, pady=(0,12))
        av = tk.Canvas(me, width=38, height=38, bg=C["panel2"], highlightthickness=0)
        av.pack(side="left", padx=(0,10))
        av.create_oval(2,2,36,36, fill=C["accent"], outline="")
        av.create_text(19,19, text=(self.username[0].upper() if self.username else "?"),
                       fill="white", font=F(14,bold=True))
        inf = tk.Frame(me, bg=C["panel2"]); inf.pack(side="left")
        tk.Label(inf, text=self.username, font=F(12,bold=True),
                 bg=C["panel2"], fg=C["text"]).pack(anchor="w")
        self._ip_lbl = tk.Label(inf, text=self.net.my_ip, font=F(9),
                                 bg=C["panel2"], fg=C["muted"])
        self._ip_lbl.pack(anchor="w")

        # 区切り
        tk.Frame(self._sb, bg=C["border"], height=1).pack(fill="x", padx=10)

        # フィルタ行
        filt = tk.Frame(self._sb, bg=C["panel2"], padx=10, pady=7)
        filt.pack(fill="x", padx=10, pady=10)
        tk.Label(filt, text="🔍", font=("Arial",11),
                 bg=C["panel2"], fg=C["muted"]).pack(side="left", padx=(0,6))
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *a: self._refresh_peer_list())
        tk.Entry(filt, textvariable=self._filter_var,
                 font=F(10), bg=C["panel2"], fg=C["text"],
                 insertbackground=C["text"], relief="flat").pack(
                 side="left", fill="x", expand=True, ipady=3)

        # オンライン数
        cnt_row = tk.Frame(self._sb, bg=C["sidebar"])
        cnt_row.pack(fill="x", padx=14, pady=(0,4))
        tk.Label(cnt_row, text="オンライン", font=F(9),
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left")
        self._cnt_lbl = tk.Label(cnt_row, text="0", font=F(9,bold=True),
                                  bg=C["sidebar"], fg=C["accent"])
        self._cnt_lbl.pack(side="right")

        # ピアスクロールエリア
        self._peer_scroll = ScrollableFrame(self._sb, bg=C["sidebar"])
        self._peer_scroll.pack(fill="both", expand=True, padx=4)

        # 区切り
        tk.Frame(self._sb, bg=C["border"], height=1).pack(fill="x", padx=10, pady=4)

        # グループヘッダー
        g_hdr = tk.Frame(self._sb, bg=C["sidebar"])
        g_hdr.pack(fill="x", padx=14, pady=(0,4))
        tk.Label(g_hdr, text="グループ", font=F(9),
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left")
        FlatBtn(g_hdr, text="＋", command=self._open_create_group,
                bg=C["sidebar"], fg=C["accent2"], hover=C["item_h"],
                font=F(14), padx=6, pady=2).pack(side="right")

        # グループスクロールエリア
        self._grp_scroll = ScrollableFrame(self._sb, bg=C["sidebar"])
        self._grp_scroll.pack(fill="x", padx=4, pady=(0,10))
        # 高さ制限（グループが少ない間は小さく）
        self._grp_scroll.configure(height=130)
        self._grp_scroll.pack_propagate(False)

        # ── メインエリア ────────────────────
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)

        # チャットヘッダー
        self._chat_hdr = tk.Frame(main, bg=C["sidebar"], height=60)
        self._chat_hdr.pack(fill="x")
        self._chat_hdr.pack_propagate(False)

        self._title_var = tk.StringVar(value="← ユーザーを選択してください")
        tk.Label(self._chat_hdr, textvariable=self._title_var,
                 font=F(13,bold=True), bg=C["sidebar"], fg=C["text"], padx=20).pack(
                 side="left", pady=18)

        # ヘッダー右ボタン群
        h_btns = tk.Frame(self._chat_hdr, bg=C["sidebar"])
        h_btns.pack(side="right", padx=10, pady=12)

        self._enc_badge = tk.Label(h_btns, text="", font=F(9),
                                    bg=C["sidebar"], fg=C["success"], padx=8)
        self._enc_badge.pack(side="left", padx=4)

        for txt, cmd in [("👥", self._show_members),
                         ("💾", self._export_chat),
                         ("🔍", self._toggle_search)]:
            FlatBtn(h_btns, text=txt, command=cmd,
                    bg=C["sidebar"], fg=C["subtext"], hover=C["panel2"],
                    font=("Arial",14), padx=10, pady=6).pack(side="left", padx=2)

        # 検索バー (hidden 初期)
        self._search_bar = tk.Frame(main, bg=C["panel2"])
        # ← pack しない

        s_row = tk.Frame(self._search_bar, bg=C["panel2"])
        s_row.pack(fill="x", padx=14, pady=8)
        tk.Label(s_row, text="検索:", font=F(10),
                 bg=C["panel2"], fg=C["subtext"]).pack(side="left", padx=(0,8))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *a: self._do_search())
        self._search_entry = tk.Entry(s_row, textvariable=self._search_var,
                                       font=F(11), bg=C["panel"], fg=C["text"],
                                       insertbackground=C["text"],
                                       relief="flat", highlightthickness=0)
        self._search_entry.pack(side="left", fill="x", expand=True, ipady=5)
        self._search_entry.bind("<Return>",  lambda _: self._search_next())
        self._search_entry.bind("<Escape>",  lambda _: self._toggle_search())
        self._search_cnt = tk.Label(s_row, text="", font=F(9),
                                     bg=C["panel2"], fg=C["subtext"])
        self._search_cnt.pack(side="left", padx=8)
        for txt, cmd in [("↑", self._search_prev), ("↓", self._search_next)]:
            FlatBtn(s_row, text=txt, command=cmd,
                    bg=C["panel"], fg=C["text"], hover=C["item_h"],
                    font=F(10), padx=8, pady=4).pack(side="left", padx=2)
        FlatBtn(s_row, text="✕", command=self._toggle_search,
                bg=C["panel"], fg=C["error"], hover=C["item_h"],
                font=F(10), padx=8, pady=4).pack(side="left", padx=(6,0))

        # メッセージエリア
        self._msg_outer = tk.Frame(main, bg=C["bg"])
        self._msg_outer.pack(fill="both", expand=True)

        msg_sb = tk.Scrollbar(self._msg_outer, orient="vertical",
                               bg=C["sidebar"], troughcolor=C["bg"],
                               relief="flat", width=6)
        msg_sb.pack(side="right", fill="y")
        self._canvas = tk.Canvas(self._msg_outer, bg=C["bg"],
                                  yscrollcommand=msg_sb.set, highlightthickness=0)
        self._canvas.pack(side="left", fill="both", expand=True)
        msg_sb.config(command=self._canvas.yview)

        self._msg_frame = tk.Frame(self._canvas, bg=C["bg"])
        self._frame_id  = self._canvas.create_window((0,0), window=self._msg_frame, anchor="nw")
        self._msg_frame.bind("<Configure>", lambda e:
            self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e:
            self._canvas.itemconfig(self._frame_id, width=e.width))

        for w in (self._canvas, self._msg_frame):
            w.bind("<MouseWheel>", self._wheel)
            w.bind("<Button-4>",   self._wheel)
            w.bind("<Button-5>",   self._wheel)

        # タイピングインジケーター
        typing_frm = tk.Frame(main, bg=C["bg"], height=22)
        typing_frm.pack(fill="x")
        typing_frm.pack_propagate(False)
        self._typing_var = tk.StringVar()
        tk.Label(typing_frm, textvariable=self._typing_var,
                 font=F(9,italic=True), bg=C["bg"], fg=C["muted"], padx=22).pack(side="left")

        # 入力エリア
        inp_outer = tk.Frame(main, bg=C["sidebar"])
        inp_outer.pack(fill="x")
        inp_row = tk.Frame(inp_outer, bg=C["inp"], padx=12, pady=8)
        inp_row.pack(fill="x", padx=12, pady=10)

        for txt, cmd, title in [("📎", self._pick_file, "ファイル添付"),
                                 ("😊", self._open_emoji, "絵文字")]:
            FlatBtn(inp_row, text=txt, command=cmd,
                    bg=C["inp"], fg=C["subtext"], hover=C["panel2"],
                    font=("Arial",15), padx=6, pady=6).pack(side="left", padx=(0,4))

        self._inp = tk.Entry(inp_row, font=F(12), bg=C["inp"], fg=C["text"],
                             insertbackground=C["text"],
                             relief="flat", highlightthickness=0)
        self._inp.pack(side="left", fill="x", expand=True, ipady=10)
        self._inp.bind("<Return>",    self._send_text)
        self._inp.bind("<KP_Enter>",  self._send_text)
        self._inp.bind("<KeyRelease>",self._on_typing)

        FlatBtn(inp_row, text="送信  ▶", command=self._send_text,
                bg=C["accent"], fg="white", hover=C["accent_h"],
                font=F(11,bold=True), padx=18, pady=9).pack(side="right", padx=(10,0))

        # ステータスバー
        self._status = tk.StringVar(value="🟢 起動完了")
        tk.Label(self.root, textvariable=self._status, font=F(9),
                 bg=C["sidebar"], fg=C["muted"],
                 anchor="w", padx=16).pack(side="bottom", fill="x")

        self._tick()

    # ══════════════════════════════════════════
    # ホイール
    # ══════════════════════════════════════════
    def _wheel(self, e):
        d = -1 if (e.delta > 0 or e.num == 4) else 1
        self._canvas.yview_scroll(d*3, "units")

    # ══════════════════════════════════════════
    # 定期更新
    # ══════════════════════════════════════════
    def _tick(self):
        if self.net:
            n = sum(1 for p in self.net.peers.values() if p.online and p.alive())
            self._cnt_lbl.config(text=str(n))
            enc = "🔒 E2EE" if CRYPTO_OK else "🔓 暗号化なし"
            self._status.set(
                f"🟢 {self.username}  ·  {self.net.my_ip}  ·  接続: {n}名  ·  {enc}"
                f"  ·  UDP:{DISC_PORT} / TCP:{CHAT_PORT}")
        if self._typing_peers:
            names = ", ".join(self._typing_peers.values())
            dots  = ["·", "··", "···"][int(time.time()*2)%3]
            self._typing_var.set(f"  {names} が入力中  {dots}")
        self.root.after(800, self._tick)

    # ══════════════════════════════════════════
    # ピアアイテム生成
    # ══════════════════════════════════════════
    def _make_peer_item(self, pid, peer, unread):
        """ピア1件分のウィジェットを作成して _peer_scroll.inner に追加"""
        col   = peer_color(pid)
        alive = peer.online and peer.alive()
        bg    = C["sidebar"]

        row = tk.Frame(self._peer_scroll.inner, bg=bg,
                        padx=10, pady=8, cursor="hand2")
        row.pack(fill="x", pady=1)

        # アバター
        av = tk.Canvas(row, width=36, height=36, bg=bg, highlightthickness=0)
        av.pack(side="left", padx=(0,10))
        av.create_oval(2,2,34,34, fill=col, outline="")
        av.create_text(18,18, text=(peer.name[0].upper() if peer.name else "?"),
                        fill="white", font=F(12,bold=True))

        # 名前 + IP
        info = tk.Frame(row, bg=bg); info.pack(side="left", fill="x", expand=True)
        nl = tk.Label(info, text=peer.name, font=F(11,bold=True), bg=bg, fg=C["text"])
        nl.pack(anchor="w")
        il = tk.Label(info, text=peer.ip, font=F(8), bg=bg, fg=C["muted"])
        il.pack(anchor="w")

        # 右側: オンドット + 未読バッジ
        right = tk.Frame(row, bg=bg); right.pack(side="right")
        dot_col = C["success"] if alive else C["muted"]
        dl = tk.Label(right, text="●", font=F(9), bg=bg, fg=dot_col)
        dl.pack(anchor="e")
        unread_lbl = None
        if unread > 0:
            unread_lbl = tk.Label(right, text=str(unread),
                                   font=F(8,bold=True),
                                   bg=C["accent"], fg="white",
                                   padx=5, pady=1)
            unread_lbl.pack(anchor="e", pady=(2,0))

        # set_bg コールバック (bg 一括変更用)
        all_bg = [row, info, nl, il, right, dl, av]
        if unread_lbl: all_bg.append(unread_lbl)

        def set_bg(new_bg, is_sel=False):
            for w in all_bg:
                try: w.config(bg=new_bg)
                except: pass
            av.config(bg=new_bg)
            if is_sel:
                nl.config(fg=C["text"]); il.config(fg=C["subtext"])
            else:
                nl.config(fg=C["text"]); il.config(fg=C["muted"])

        def on_enter(_): set_bg(C["item_h"])
        def on_leave(_):
            if self._selected_pid == pid: set_bg(C["sel"], is_sel=True)
            else: set_bg(C["sidebar"])

        def on_click(_): self._on_peer_click(pid)

        for w in all_bg + [av]:
            w.bind("<Enter>",    on_enter)
            w.bind("<Leave>",    on_leave)
            w.bind("<Button-1>", on_click)

        self._peer_items[pid] = {"frame": row, "set_bg": set_bg}

    def _make_grp_item(self, room):
        bg = C["sidebar"]
        row = tk.Frame(self._grp_scroll.inner, bg=bg, padx=12, pady=8, cursor="hand2")
        row.pack(fill="x", pady=1)

        av = tk.Canvas(row, width=32, height=32, bg=bg, highlightthickness=0)
        av.pack(side="left", padx=(0,10))
        av.create_oval(2,2,30,30, fill=C["accent2"], outline="")
        av.create_text(16,16, text="👥", font=("Arial",13))

        nl = tk.Label(row, text=room, font=F(11), bg=bg, fg=C["text"])
        nl.pack(side="left")

        unr = self.unread.get(f"group:{room}", 0)
        badge = None
        if unr > 0:
            badge = tk.Label(row, text=str(unr), font=F(8,bold=True),
                              bg=C["accent2"], fg="white", padx=5, pady=1)
            badge.pack(side="right", padx=4)

        all_bg = [row, av, nl]
        if badge: all_bg.append(badge)

        def set_bg(new_bg):
            for w in all_bg:
                try: w.config(bg=new_bg)
                except: pass
            av.config(bg=new_bg)

        def on_enter(_): set_bg(C["item_h"])
        def on_leave(_):
            cid = f"group:{room}"
            if self._selected_gid == cid: set_bg(C["sel"])
            else: set_bg(C["sidebar"])

        def on_click(_): self._switch_grp(room)

        for w in all_bg + [av]:
            w.bind("<Enter>",    on_enter)
            w.bind("<Leave>",    on_leave)
            w.bind("<Button-1>", on_click)

        self._grp_items[room] = {"frame": row, "set_bg": set_bg}

    # ══════════════════════════════════════════
    # ピアリスト更新
    # ══════════════════════════════════════════
    def _refresh_peer_list(self):
        # 既存ウィジェットを全削除
        for w in self._peer_scroll.inner.winfo_children(): w.destroy()
        self._peer_items.clear()

        filt = self._filter_var.get().lower() if hasattr(self,"_filter_var") else ""
        for pid, peer in self.net.peers.items():
            if filt and filt not in peer.name.lower(): continue
            unr = self.unread.get(pid, 0)
            self._make_peer_item(pid, peer, unr)
            # 選択状態を復元
            if pid == self._selected_pid and pid in self._peer_items:
                self._peer_items[pid]["set_bg"](C["sel"], is_sel=True)

        n = sum(1 for p in self.net.peers.values() if p.online and p.alive())
        self._cnt_lbl.config(text=str(n))

    # ══════════════════════════════════════════
    # ピア選択
    # ══════════════════════════════════════════
    def _on_peer_click(self, pid):
        # 旧選択を解除
        if self._selected_pid and self._selected_pid in self._peer_items:
            self._peer_items[self._selected_pid]["set_bg"](C["sidebar"])
        if self._selected_gid and self._selected_gid in self._grp_items:
            self._grp_items[self._selected_gid]["set_bg"](C["sidebar"])

        self._selected_pid = pid
        self._selected_gid = None

        if pid in self._peer_items:
            self._peer_items[pid]["set_bg"](C["sel"], is_sel=True)

        peer = self.net.peers.get(pid)
        if not peer: return

        self.current = pid
        self.unread[pid] = 0
        self._refresh_peer_list()
        self._title_var.set(f"💬  {peer.name}   ·   {peer.ip}")
        self._update_enc_badge(pid)
        self._render_chat(pid)

        # 既読通知
        pending = []
        for e in self.chat_logs.get(pid, []):
            if not e["is_me"] and not e.get("read_sent") and e.get("msg_id"):
                e["read_sent"] = True; pending.append(e["msg_id"])
        if pending:
            threading.Thread(target=self.net.send_read, args=(pid,pending), daemon=True).start()

    def _update_enc_badge(self, pid=None):
        if pid is None: pid = self.current
        if not pid or pid.startswith("group:"):
            self._enc_badge.config(text=""); return
        if CRYPTO_OK and self.crypto.has_send_key(pid) and self.crypto.has_recv_key(pid):
            self._enc_badge.config(text="🔒 E2EE 確立", fg=C["success"])
        elif CRYPTO_OK and self.crypto.can_enc(pid):
            self._enc_badge.config(text="🔑 鍵交換中…", fg=C["warning"])
        else:
            self._enc_badge.config(text="🔓 暗号化なし", fg=C["muted"])

    # ══════════════════════════════════════════
    # グループ
    # ══════════════════════════════════════════
    def _switch_grp(self, room):
        if self._selected_pid and self._selected_pid in self._peer_items:
            self._peer_items[self._selected_pid]["set_bg"](C["sidebar"])
        cid = f"group:{room}"
        if self._selected_gid and self._selected_gid in self._grp_items:
            self._grp_items[self._selected_gid]["set_bg"](C["sidebar"])
        self._selected_pid = None
        self._selected_gid = cid
        if room in self._grp_items:
            self._grp_items[room]["set_bg"](C["sel"])

        self.current = cid
        self.unread[cid] = 0
        self._title_var.set(f"👥  {room}")
        self._enc_badge.config(text="")
        self._render_chat(cid)

    def _open_create_group(self):
        online = [(pid,p) for pid,p in self.net.peers.items() if p.online and p.alive()]
        if not online: messagebox.showinfo("情報","オンラインユーザーがいません"); return

        dlg = tk.Toplevel(self.root); dlg.title("グループ作成")
        dlg.geometry("360x500"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set(); dlg.resizable(False,False)

        tk.Label(dlg, text="グループ名", font=F(12), bg=C["bg"], fg=C["text"]).pack(
            padx=24, pady=(24,4), anchor="w")
        nv = tk.StringVar()
        ne = tk.Entry(dlg, textvariable=nv, font=F(12), bg=C["panel"], fg=C["text"],
                       insertbackground=C["text"], relief="flat")
        ne.pack(fill="x", padx=24, ipady=8); ne.focus_set()

        tk.Label(dlg, text="メンバーを選択", font=F(12), bg=C["bg"], fg=C["text"]).pack(
            padx=24, pady=(16,6), anchor="w")
        mv = {}
        for pid,peer in online:
            v = tk.BooleanVar(value=True); mv[pid] = v
            cf = tk.Frame(dlg, bg=C["bg"])
            cf.pack(fill="x", padx=24, pady=2)
            av2 = tk.Canvas(cf, width=26, height=26, bg=C["bg"], highlightthickness=0)
            av2.pack(side="left", padx=(0,8))
            av2.create_oval(1,1,25,25, fill=peer_color(pid), outline="")
            av2.create_text(13,13, text=peer.name[0].upper(), fill="white", font=F(9,bold=True))
            tk.Checkbutton(cf, text=peer.name, variable=v, bg=C["bg"], fg=C["text"],
                            activebackground=C["bg"], selectcolor=C["panel"],
                            font=F(11), cursor="hand2").pack(side="left")

        def do_create():
            room = nv.get().strip()
            if not room: messagebox.showwarning("エラー","グループ名を入力してください",parent=dlg); return
            if room in self.groups: messagebox.showwarning("エラー","同名のグループがあります",parent=dlg); return
            chosen = [pid for pid,v in mv.items() if v.get()]
            if not chosen: messagebox.showwarning("エラー","メンバーを選択してください",parent=dlg); return
            members = [self.peer_id] + chosen
            self.groups[room] = {"name":room,"members":members}
            self._make_grp_item(room)
            for p in chosen:
                threading.Thread(target=self.net.send_invite, args=(p,room,members), daemon=True).start()
            dlg.destroy(); self._switch_grp(room)

        FlatBtn(dlg, text="グループを作成", command=do_create,
                bg=C["accent2"], fg="white", hover="#9333ea",
                font=F(12,bold=True), padx=20, pady=10).pack(pady=22)

    # ══════════════════════════════════════════
    # ネットワークコールバック
    # ══════════════════════════════════════════
    def _cb_peer_found(self, peer):
        self._refresh_peer_list()
        self._sys(f"🟢  {peer.name}（{peer.ip}）が参加しました")

    def _cb_peer_lost(self, peer):
        self._refresh_peer_list()
        self._sys(f"⚫  {peer.name} がオフラインになりました")

    def _cb_msg(self, msg):
        t = msg["type"]

        if t == T_INVITE:
            room=msg["room"]; members=msg["members"]
            if room not in self.groups:
                self.groups[room]={"name":room,"members":members}
                self._make_grp_item(room)
            self._sys(f"📩  {msg['from_name']} からグループ「{room}」に招待されました")
            return

        if t == T_READ:
            pid=msg["from_id"]; ids=set(msg.get("msg_ids",[]))
            for logs in self.chat_logs.values():
                for e in logs:
                    if e.get("is_me") and e.get("msg_id") in ids and not e.get("read"):
                        e["read"] = True
                        lbl = e.get("_meta_lbl")
                        if lbl:
                            try:
                                if lbl.winfo_exists(): lbl.config(text=self._meta_text(e))
                            except: pass
            return

        if t == T_TYPING:
            pid=msg["from_id"]; name=msg["from_name"]
            if self.current == pid:
                if pid in self._typing_timers:
                    try: self.root.after_cancel(self._typing_timers[pid])
                    except: pass
                self._typing_peers[pid] = name
                self._typing_timers[pid] = self.root.after(3000, lambda p=pid: self._hide_typing(p))
            return

        if t == T_REACT:
            pid=msg["from_id"]; mid=msg["msg_id"]; em=msg["emoji"]
            for logs in self.chat_logs.values():
                for e in logs:
                    if e.get("msg_id") == mid:
                        r = e.setdefault("reactions",{})
                        if em not in r: r[em]=[]
                        if pid not in r[em]: r[em].append(pid)
                        self._refresh_react_widget(e)
            return

        if t == T_FMETA:
            fid=msg["file_id"]; pid=msg["from_id"]
            self.rcv_files[fid]={"meta":msg,"chunks":{},"data":None,"done":False}
            ts=datetime.fromtimestamp(msg["ts"]).strftime("%H:%M")
            e=self._mk_e(msg["msg_id"],msg["from_name"],pid,ts,is_me=False,
                          enc=msg["encrypted"],etype="file")
            e.update({"filename":msg["filename"],"file_size":msg["file_size"],
                       "file_id":fid,"file_ready":False})
            self.chat_logs[pid].append(e)
            if self.current == pid: self._add_bubble(e)
            else: self.unread[pid]+=1; self._refresh_peer_list()
            return

        if t == T_FCHUNK:
            fid=msg["file_id"]; pid=msg["from_id"]
            if fid not in self.rcv_files: return
            idx=msg["chunk_idx"]; raw=base64.b64decode(msg["data_b64"])
            if msg["encrypted"]: raw=self.crypto.decrypt_bytes(pid,raw)
            self.rcv_files[fid]["chunks"][idx]=raw
            meta=self.rcv_files[fid]["meta"]
            if len(self.rcv_files[fid]["chunks"]) >= meta["total_chunks"]:
                assembled=b"".join(self.rcv_files[fid]["chunks"][i] for i in range(meta["total_chunks"]))
                self.rcv_files[fid].update({"data":assembled,"done":True})
                cid=meta["from_id"]
                for e in self.chat_logs.get(cid,[]):
                    if e.get("file_id")==fid:
                        e["file_ready"]=True
                        btn=e.get("_dl_btn")
                        if btn:
                            try:
                                if btn.winfo_exists():
                                    btn.set_colors(C["accent"], hover=C["accent_h"])
                                    btn.config(text="📥  保存する")
                                    btn.set_cmd(lambda fid_=fid, fn_=e["filename"]: self._save_file(fid_,fn_))
                            except: pass
                        break
                self.root.bell()
            return

        # テキスト
        if t in (T_CHAT, T_GROUP):
            pid=msg["from_id"]; name=msg["from_name"]
            text=msg["text"]; ie=msg.get("encrypted",False)
            ts=datetime.fromtimestamp(msg["ts"]).strftime("%H:%M")
            cid = pid if t==T_CHAT else f"group:{msg['room']}"
            e=self._mk_e(msg["msg_id"],name,pid,ts,is_me=False,enc=ie)
            e["text"]=text
            self.chat_logs[cid].append(e)
            if self.current == cid:
                self._add_bubble(e)
                if t==T_CHAT and msg.get("msg_id"):
                    e["read_sent"]=True
                    threading.Thread(target=self.net.send_read,
                                     args=(pid,[msg["msg_id"]]),daemon=True).start()
                if t==T_CHAT: self._update_enc_badge(pid)
            else:
                self.unread[cid]+=1; self._refresh_peer_list()
                self._status.set(f"💬  新着  {name}: {text[:50]}")
            self.root.bell()

    def _hide_typing(self, pid):
        self._typing_peers.pop(pid,None); self._typing_timers.pop(pid,None)
        if not self._typing_peers: self._typing_var.set("")

    # ══════════════════════════════════════════
    # 送信
    # ══════════════════════════════════════════
    def _send_text(self, _=None):
        text=self._inp.get().strip()
        if not text or not self.current: return
        self._inp.delete(0,tk.END)
        mid=str(uuid.uuid4())[:8]; ts=ts_now()

        if self.current.startswith("group:"):
            room=self.current[6:]; grp=self.groups.get(room)
            if not grp: return
            ie=CRYPTO_OK and all(self.crypto.can_enc(p) for p in grp["members"] if p!=self.peer_id)
            e=self._mk_e(mid,self.username,self.peer_id,ts,is_me=True,enc=ie)
            e["text"]=text; self.chat_logs[self.current].append(e); self._add_bubble(e)
            threading.Thread(target=self.net.send_group,
                             args=(room,mid,text,grp["members"]),daemon=True).start()
        else:
            peer=self.net.peers.get(self.current)
            if not peer or not(peer.online and peer.alive()):
                self._sys("⚠  オフラインのため送信できません"); return
            pid=self.current; ie=CRYPTO_OK and self.crypto.can_enc(pid)
            e=self._mk_e(mid,self.username,self.peer_id,ts,is_me=True,enc=ie)
            e["text"]=text; self.chat_logs[pid].append(e); self._add_bubble(e)
            def do():
                ok=self.net.send_chat(pid,mid,text)
                if not ok: self.root.after(0,lambda:self._sys("⚠  送信失敗（オフライン？）"))
                else:       self.root.after(0,lambda:self._update_enc_badge(pid))
            threading.Thread(target=do,daemon=True).start()

    def _on_typing(self, _=None):
        if not self.current or self.current.startswith("group:"): return
        now=time.time()
        if now-self._typing_send_t > 2.0:
            self._typing_send_t=now
            threading.Thread(target=self.net.send_typing,args=(self.current,),daemon=True).start()

    def _pick_file(self):
        if not self.current: messagebox.showinfo("情報","送信先を選択してください"); return
        if self.current.startswith("group:"): messagebox.showinfo("情報","ファイル送信は1対1専用です"); return
        peer=self.net.peers.get(self.current)
        if not peer or not(peer.online and peer.alive()):
            messagebox.showinfo("情報","オフラインの相手には送れません"); return
        path=filedialog.askopenfilename(title="送信するファイルを選択")
        if not path: return
        sz=os.path.getsize(path)
        if sz>MAX_FILE: messagebox.showerror("エラー",f"ファイル上限は {fmt_size(MAX_FILE)} です"); return
        pid=self.current; fn=os.path.basename(path); ie=CRYPTO_OK and self.crypto.can_enc(pid)
        mid=str(uuid.uuid4())[:8]; ts=ts_now()
        e=self._mk_e(mid,self.username,self.peer_id,ts,is_me=True,enc=ie,etype="file")
        e.update({"filename":fn,"file_size":sz,"file_id":None,"file_ready":True})
        self.chat_logs[pid].append(e); self._add_bubble(e)
        self._sys(f"📤  {fn}（{fmt_size(sz)}）送信中…")
        def do():
            ok,_ = self.net.send_file(pid,path)
            msg=f"✅  {fn} 送信完了" if ok else f"❌  {fn} 送信失敗"
            self.root.after(0,lambda:self._sys(msg))
        threading.Thread(target=do,daemon=True).start()

    # ══════════════════════════════════════════
    # バブル描画
    # ══════════════════════════════════════════
    @staticmethod
    def _mk_e(mid,sender,sid,ts,*,is_me,enc,etype="text"):
        return {"msg_id":mid,"from":sender,"from_id":sid,"text":"","time":ts,
                "is_me":is_me,"encrypted":enc,"read":False,"read_sent":False,
                "type":etype,"filename":None,"file_size":None,"file_id":None,
                "file_ready":False,"reactions":{},
                "_meta_lbl":None,"_react_frm":None,"_dl_btn":None,"_row":None}

    def _meta_text(self, e):
        parts = ["🔒 暗号化済み" if e["encrypted"] else "🔓 暗号化なし"]
        if e["is_me"]: parts.append("✓✓ 既読" if e["read"] else "✓ 送信済み")
        return "    ".join(parts)

    def _add_bubble(self, entry, scroll=True):
        is_me  = entry["is_me"]
        pid    = entry["from_id"]
        bub_bg = C["me_bub"] if is_me else C["peer_bub"]
        av_col = C["accent"] if is_me else peer_color(pid)
        name   = "あなた" if is_me else entry["from"]

        row = tk.Frame(self._msg_frame, bg=C["bg"])
        row.pack(fill="x", padx=10, pady=4)
        entry["_row"] = row

        # アバター
        av = tk.Canvas(row, width=34, height=34, bg=C["bg"], highlightthickness=0)
        av.create_oval(2,2,32,32, fill=av_col, outline="")
        av.create_text(17,17, text=(name[0].upper() if name else "?"),
                        fill="white", font=F(11,bold=True))

        # バブル
        bub = tk.Frame(row, bg=bub_bg, padx=14, pady=10)

        # 名前（他者のみ）
        if not is_me:
            tk.Label(bub, text=name, font=F(9,bold=True),
                     bg=bub_bg, fg=av_col).pack(anchor="w", pady=(0,3))

        # 本文 or ファイル
        if entry["type"] == "file":
            fn=entry.get("filename","file"); sz=entry.get("file_size",0)
            fid=entry.get("file_id"); fr=entry.get("file_ready",False)

            frow = tk.Frame(bub, bg=bub_bg); frow.pack(anchor="w")
            fc = tk.Canvas(frow, width=36, height=36, bg=bub_bg, highlightthickness=0)
            fc.pack(side="left", padx=(0,10))
            fc.create_oval(2,2,34,34, fill=C["peach"], outline="")
            fc.create_text(18,18, text="📎", font=("Arial",14))
            fi = tk.Frame(frow, bg=bub_bg); fi.pack(side="left")
            tk.Label(fi, text=fn, font=F(11,bold=True), bg=bub_bg, fg=C["text"],
                     wraplength=280).pack(anchor="w")
            tk.Label(fi, text=fmt_size(sz), font=F(9), bg=bub_bg, fg=C["subtext"]).pack(anchor="w")

            if not is_me and fid:
                dl_text = "📥  保存する" if fr else "受信中…"
                dl_bg   = C["accent"] if fr else C["muted"]
                dl_btn  = FlatBtn(bub, text=dl_text,
                                   command=(lambda fid_=fid, fn_=fn: self._save_file(fid_,fn_)) if fr else None,
                                   bg=dl_bg, fg="white", hover=C["accent_h"],
                                   font=F(10,bold=True), padx=12, pady=6)
                dl_btn.pack(anchor="w", pady=(8,0))
                entry["_dl_btn"] = dl_btn
        else:
            tk.Label(bub, text=entry["text"],
                     font=F(11), bg=bub_bg, fg=C["text"],
                     wraplength=420, justify="left").pack(anchor="w")

        # リアクション
        r_frm = tk.Frame(bub, bg=bub_bg); r_frm.pack(anchor="w", pady=(4,0))
        entry["_react_frm"] = r_frm
        self._refresh_react_widget(entry, r_frm)

        # メタ行
        meta_row = tk.Frame(bub, bg=bub_bg); meta_row.pack(fill="x", pady=(3,0))
        tk.Label(meta_row, text=entry["time"], font=F(8),
                 bg=bub_bg, fg=C["muted"]).pack(side="left", padx=(0,6))
        meta_lbl = tk.Label(meta_row, text=self._meta_text(entry),
                             font=F(8), bg=bub_bg, fg=C["muted"])
        meta_lbl.pack(side="left")
        entry["_meta_lbl"] = meta_lbl

        # 右クリックでリアクションメニュー
        def on_right(ev, e=entry): self._show_react_menu(e, ev)
        for w in (bub, meta_row, meta_lbl):
            w.bind("<Button-3>", on_right)
            w.bind("<Button-2>", on_right)

        if is_me:
            av.pack(side="right", anchor="n", padx=(4,2), pady=2)
            bub.pack(side="right", anchor="n", padx=(0,6), pady=2)
        else:
            av.pack(side="left", anchor="n", padx=(2,4), pady=2)
            bub.pack(side="left", anchor="n", padx=(6,0), pady=2)

        if scroll:
            self.root.after(50, self._scroll_bottom)

    def _refresh_react_widget(self, entry, frm=None):
        if frm is None: frm = entry.get("_react_frm")
        if not frm: return
        try:
            if not frm.winfo_exists(): return
        except: return
        for w in frm.winfo_children(): w.destroy()
        bub_bg = C["me_bub"] if entry["is_me"] else C["peer_bub"]
        for em, pids in (entry.get("reactions") or {}).items():
            if not pids: continue
            cnt = len(pids); is_mine = self.peer_id in pids
            chip_bg = C["accent"] if is_mine else C["panel2"]
            chip = tk.Label(frm, text=f"{em} {cnt}", font=F(9),
                             bg=chip_bg, fg=C["text"], padx=7, pady=3, cursor="hand2")
            chip.pack(side="left", padx=(0,4))
            chip.bind("<Button-1>", lambda ev, e=entry, emoji=em: self._toggle_react(e, emoji))

    def _show_react_menu(self, entry, event):
        menu = tk.Toplevel(self.root)
        menu.overrideredirect(True)
        menu.configure(bg=C["panel2"])
        menu.geometry(f"+{event.x_root}+{event.y_root}")
        frm = tk.Frame(menu, bg=C["panel2"], padx=10, pady=8); frm.pack()
        tk.Label(frm, text="リアクション", font=F(9), bg=C["panel2"], fg=C["muted"]).pack(pady=(0,6))
        row = tk.Frame(frm, bg=C["panel2"]); row.pack()
        def pick(em):
            self._toggle_react(entry, em); menu.destroy()
        for em in REACT_EMOJIS:
            b = FlatBtn(row, text=em, command=lambda e=em: pick(e),
                         bg=C["panel2"], fg=C["text"], hover=C["item_h"],
                         font=("Arial",16), padx=6, pady=4)
            b.pack(side="left", padx=1)
        menu.bind("<FocusOut>", lambda _: menu.destroy())
        menu.focus_set()

    def _toggle_react(self, entry, emoji):
        r = entry.setdefault("reactions", {})
        if emoji not in r: r[emoji] = []
        if self.peer_id in r[emoji]: r[emoji].remove(self.peer_id)
        else: r[emoji].append(self.peer_id)
        if not r[emoji]: del r[emoji]
        self._refresh_react_widget(entry)
        pid = self.current
        if pid and not pid.startswith("group:") and entry.get("msg_id"):
            threading.Thread(target=self.net.send_reaction,
                             args=(pid,entry["msg_id"],emoji),daemon=True).start()

    # ══════════════════════════════════════════
    # チャット描画
    # ══════════════════════════════════════════
    def _render_chat(self, cid):
        self._clear_messages()
        for e in self.chat_logs.get(cid, []):
            self._add_bubble(e, scroll=False)
        self.root.after(80, self._scroll_bottom)

    def _clear_messages(self):
        for w in self._msg_frame.winfo_children(): w.destroy()

    def _scroll_bottom(self):
        self._canvas.update_idletasks()
        self._canvas.yview_moveto(1.0)

    def _sys(self, text):
        row = tk.Frame(self._msg_frame, bg=C["bg"]); row.pack(fill="x", pady=3)
        tk.Label(row, text=text, font=F(9,italic=True), bg=C["bg"], fg=C["muted"]).pack()
        self.root.after(50, self._scroll_bottom)

    # ══════════════════════════════════════════
    # 絵文字ピッカー
    # ══════════════════════════════════════════
    def _open_emoji(self):
        if not self.current: return
        popup = tk.Toplevel(self.root); popup.overrideredirect(True)
        popup.configure(bg=C["panel2"])
        x=self._inp.winfo_rootx(); y=self._inp.winfo_rooty()-240
        popup.geometry(f"330x230+{x}+{y}")
        tk.Label(popup, text="絵文字", font=F(10), bg=C["panel2"], fg=C["muted"]).pack(pady=(8,4))
        frm = tk.Frame(popup, bg=C["panel2"]); frm.pack(padx=8, pady=4)
        row_f = None
        def ins(em): self._inp.insert(tk.END, em); popup.destroy(); self._inp.focus_set()
        for i, em in enumerate(COMMON_EMOJIS):
            if i%10 == 0: row_f = tk.Frame(frm, bg=C["panel2"]); row_f.pack(fill="x")
            FlatBtn(row_f, text=em, command=lambda e=em: ins(e),
                     bg=C["panel2"], fg=C["text"], hover=C["item_h"],
                     font=("Arial",15), padx=3, pady=3).pack(side="left")
        popup.bind("<FocusOut>", lambda _: popup.destroy())
        popup.focus_set()

    # ══════════════════════════════════════════
    # 検索
    # ══════════════════════════════════════════
    def _toggle_search(self):
        self._search_visible = not self._search_visible
        if self._search_visible:
            self._search_bar.pack(fill="x", before=self._msg_outer)
            self._search_entry.focus_set()
        else:
            self._search_bar.pack_forget()
            self._search_var.set("")
            self._clear_search_hl()
            self._search_results=[]; self._search_cnt.config(text="")

    def _do_search(self):
        self._clear_search_hl()
        q = self._search_var.get().strip()
        if not q or not self.current:
            self._search_results=[]; self._search_cnt.config(text=""); return
        self._search_results=[]
        for e in self.chat_logs.get(self.current,[]):
            txt = e.get("text","") or e.get("filename","")
            if q.lower() in txt.lower():
                self._search_results.append(e)
                row = e.get("_row")
                if row:
                    try:
                        if row.winfo_exists(): row.config(highlightbackground=C["warning"],highlightthickness=2)
                    except: pass
        n = len(self._search_results)
        self._search_idx = 0
        self._search_cnt.config(text=f"{n} 件" if n else "見つかりません")
        if n: self._scroll_to(self._search_results[0])

    def _clear_search_hl(self):
        if not self.current: return
        for e in self.chat_logs.get(self.current,[]):
            row = e.get("_row")
            if row:
                try:
                    if row.winfo_exists(): row.config(highlightthickness=0)
                except: pass

    def _search_next(self):
        if not self._search_results: return
        self._search_idx=(self._search_idx+1)%len(self._search_results)
        self._scroll_to(self._search_results[self._search_idx])

    def _search_prev(self):
        if not self._search_results: return
        self._search_idx=(self._search_idx-1)%len(self._search_results)
        self._scroll_to(self._search_results[self._search_idx])

    def _scroll_to(self, entry):
        row = entry.get("_row")
        if not row: return
        try:
            if not row.winfo_exists(): return
            self._canvas.update_idletasks()
            total = self._msg_frame.winfo_height()
            y     = row.winfo_y()
            if total > 0:
                self._canvas.yview_moveto(max(0,min(1,(y-40)/total)))
        except: pass

    # ══════════════════════════════════════════
    # エクスポート
    # ══════════════════════════════════════════
    def _export_chat(self):
        if not self.current: messagebox.showinfo("情報","チャットを選択してください"); return
        entries=self.chat_logs.get(self.current,[])
        if not entries: messagebox.showinfo("情報","履歴がありません"); return
        if self.current.startswith("group:"):
            fname=f"nodetalk_{self.current[6:]}.txt"
        else:
            peer=self.net.peers.get(self.current)
            fname=f"nodetalk_{peer.name if peer else self.current}.txt"
        path=filedialog.asksaveasfilename(
            initialfile=fname, defaultextension=".txt",
            filetypes=[("テキスト","*.txt"),("全て","*.*")], title="履歴を保存")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                f.write(f"NodeTalk チャット履歴\nエクスポート: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n\n")
                for e in entries:
                    sender="あなた" if e["is_me"] else e["from"]
                    enc="[暗号化]" if e["encrypted"] else "[平文]"
                    if e["type"]=="file":
                        f.write(f"[{e['time']}] {sender} {enc}: 📎 {e.get('filename','')} ({fmt_size(e.get('file_size',0))})\n")
                    else:
                        f.write(f"[{e['time']}] {sender} {enc}: {e.get('text','')}\n")
                    if e.get("reactions"):
                        f.write("  リアクション: "+" ".join(f"{em}×{len(p)}" for em,p in e["reactions"].items())+"\n")
            messagebox.showinfo("完了",f"保存しました:\n{path}")
        except Exception as ex:
            messagebox.showerror("エラー",str(ex))

    # ══════════════════════════════════════════
    # 設定
    # ══════════════════════════════════════════
    def _open_settings(self):
        dlg=tk.Toplevel(self.root); dlg.title("設定")
        dlg.geometry("400x340"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set(); dlg.resizable(False,False)

        tk.Label(dlg, text="⚙  設定", font=F(16,bold=True),
                 bg=C["bg"], fg=C["accent"]).pack(pady=(28,20))

        tk.Frame(dlg, bg=C["border"], height=1).pack(fill="x", padx=24)

        frm1=tk.Frame(dlg,bg=C["bg"]); frm1.pack(fill="x",padx=24,pady=16)
        tk.Label(frm1,text="ユーザー名",font=F(11),bg=C["bg"],fg=C["subtext"]).pack(anchor="w")
        nv=tk.StringVar(value=self.username)
        ne=tk.Entry(frm1,textvariable=nv,font=F(12),bg=C["panel"],fg=C["text"],
                    insertbackground=C["text"],relief="flat",
                    highlightthickness=1, highlightcolor=C["accent"],
                    highlightbackground=C["border"])
        ne.pack(fill="x",ipady=9,pady=(4,0)); ne.focus_set()

        tk.Frame(dlg,bg=C["border"],height=1).pack(fill="x",padx=24)

        frm2=tk.Frame(dlg,bg=C["bg"]); frm2.pack(fill="x",padx=24,pady=12)
        enc_s=("✅  AES-256-GCM + RSA-2048  有効" if CRYPTO_OK
               else "❌  暗号化ライブラリ未インストール\n    pip install cryptography")
        tk.Label(frm2,text=enc_s,font=F(10),bg=C["bg"],
                 fg=C["success"] if CRYPTO_OK else C["warning"],justify="left").pack(anchor="w")
        tk.Label(frm2,text=f"\nIP: {self.net.my_ip}  ·  UDP:{DISC_PORT}  ·  TCP:{CHAT_PORT}",
                 font=F(10),bg=C["bg"],fg=C["muted"]).pack(anchor="w")

        def apply():
            new=nv.get().strip()
            if not new: messagebox.showwarning("エラー","ユーザー名を入力してください",parent=dlg); return
            self.username=new; self.net.username=new; dlg.destroy()
            messagebox.showinfo("完了","ユーザー名を変更しました")

        FlatBtn(dlg, text="変更を適用", command=apply,
                bg=C["accent"], fg="white", hover=C["accent_h"],
                font=F(11,bold=True), padx=22, pady=10).pack(pady=18)

    # ══════════════════════════════════════════
    # メンバー表示
    # ══════════════════════════════════════════
    def _show_members(self):
        if not self.current: return
        if self.current.startswith("group:"):
            room=self.current[6:]; grp=self.groups.get(room)
            if not grp: messagebox.showinfo("情報","グループ情報がありません"); return
            dlg=tk.Toplevel(self.root); dlg.title(f"グループ「{room}」")
            dlg.geometry("300x380"); dlg.configure(bg=C["bg"])
            dlg.transient(self.root); dlg.grab_set()
            tk.Label(dlg,text=f"👥  {room}",font=F(14,bold=True),
                     bg=C["bg"],fg=C["accent2"]).pack(pady=(20,14))
            for pid in grp.get("members",[]):
                row=tk.Frame(dlg,bg=C["panel2"],padx=12,pady=8)
                row.pack(fill="x",padx=20,pady=2)
                col=C["accent"] if pid==self.peer_id else peer_color(pid)
                av=tk.Canvas(row,width=30,height=30,bg=C["panel2"],highlightthickness=0)
                av.pack(side="left",padx=(0,10))
                av.create_oval(1,1,29,29,fill=col,outline="")
                n=self.username if pid==self.peer_id else (self.net.peers[pid].name if pid in self.net.peers else pid)
                av.create_text(15,15,text=n[0].upper(),fill="white",font=F(10,bold=True))
                suffix=" (あなた)" if pid==self.peer_id else ""
                tk.Label(row,text=n+suffix,font=F(11),bg=C["panel2"],fg=C["text"]).pack(side="left")
        else:
            peer=self.net.peers.get(self.current)
            if not peer: return
            dlg=tk.Toplevel(self.root); dlg.title("ユーザー情報")
            dlg.geometry("300x260"); dlg.configure(bg=C["bg"])
            dlg.transient(self.root); dlg.grab_set()
            col=peer_color(self.current)
            cv=tk.Canvas(dlg,width=64,height=64,bg=C["bg"],highlightthickness=0)
            cv.pack(pady=(26,8))
            cv.create_oval(3,3,61,61,fill=col,outline="")
            cv.create_text(32,32,text=peer.name[0].upper(),fill="white",font=F(22,bold=True))
            tk.Label(dlg,text=peer.name,font=F(16,bold=True),bg=C["bg"],fg=C["text"]).pack()
            tk.Label(dlg,text=peer.ip,font=F(11),bg=C["bg"],fg=C["muted"]).pack(pady=2)
            alive=peer.online and peer.alive()
            tk.Label(dlg,text="🟢 オンライン" if alive else "⚫ オフライン",
                     font=F(11),bg=C["bg"],fg=C["success"] if alive else C["muted"]).pack()
            ek=CRYPTO_OK and self.crypto.has_send_key(self.current) and self.crypto.has_recv_key(self.current)
            tk.Label(dlg,text="🔒 E2EE 確立" if ek else ("🔑 鍵交換中" if CRYPTO_OK else "🔓 暗号化なし"),
                     font=F(10),bg=C["bg"],fg=C["success"] if ek else C["warning"]).pack(pady=4)

    # ══════════════════════════════════════════
    # ファイル保存
    # ══════════════════════════════════════════
    def _save_file(self, fid, filename):
        info=self.rcv_files.get(fid)
        if not info or not info.get("done"): messagebox.showwarning("情報","受信中です"); return
        path=filedialog.asksaveasfilename(initialfile=filename, title="保存先を選択")
        if not path: return
        try:
            with open(path,"wb") as f: f.write(info["data"])
            messagebox.showinfo("保存完了",f"保存しました:\n{path}")
        except Exception as e: messagebox.showerror("保存エラー",str(e))

    # ══════════════════════════════════════════
    # 終了
    # ══════════════════════════════════════════
    def _quit(self):
        if self.net: self.net.stop()
        self.root.destroy()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# エントリーポイント
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════════╗
║  {APP_NAME} v{APP_VER}  ―  LAN チャット完全版                    ║
╠══════════════════════════════════════════════════════════╣
║  OS      : {_SYS} / フォント: {_FF}
║  暗号化  : {"✅ AES-256-GCM + RSA-2048" if CRYPTO_OK else "❌ 無効  →  pip install cryptography"}
║  UDP     : {DISC_PORT}  /  TCP : {CHAT_PORT}
╚══════════════════════════════════════════════════════════╝
""")
    root = tk.Tk()
    app  = NodeTalkApp(root)
    root.mainloop()
