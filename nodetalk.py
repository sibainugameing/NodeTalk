#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════╗
║   NodeTalk v2.0  ―  LAN 内チャットv2（1ファイル）         ║
║   自動検出 / E2EE暗号化 / 既読通知 / ファイル送信 / グループ  ║
╚═══════════════════════════════════════════════════════════════╝

【依存ライブラリ】
  標準ライブラリのみで動作します。
  暗号化を有効にするには: pip install cryptography

【起動方法】
  python nodetalk.py
  ※ 同一 Wi-Fi / LAN 内の複数端末で起動するだけで自動接続

【修正点 v2.0】
  - TCP 双方向通信バグ修正（1接続=1メッセージ, 長さプレフィックス方式）
  - 送信方向 / 受信方向で鍵を分離（E2EE の正確な実装）
  - ファイル送受信（チャンク分割・Base64・暗号化対応）
  - 既読通知プロトコル（TYPE_READ）と per-message 表示
  - 暗号化状態をメッセージ本文の下に薄く表示
  - グループルーム招待・グループチャット
  - TCP 経由でもピア登録（UDP 未検出のフォールバック）
"""

import socket, threading, json, time, uuid, base64, secrets, struct, os
from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

# ── 暗号化ライブラリ (オプション) ──────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 定数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APP_NAME       = "NodeTalk"
APP_VER        = "2.0.0"
DISC_PORT      = 55000        # UDP ブロードキャスト
CHAT_PORT      = 55001        # TCP メッセージ
DISC_INTERVAL  = 5            # ブロードキャスト間隔(秒)
PEER_TIMEOUT   = 28           # ピアタイムアウト(秒)
MAX_MSG_BYTES  = 52_428_800   # 50 MB 上限
FILE_CHUNK_SZ  = 32_768       # ファイルチャンクサイズ(bytes)

T_DISCOVER  = "discover"
T_GOODBYE   = "goodbye"
T_CHAT      = "chat"
T_GROUP_MSG = "group_msg"
T_GROUP_INV = "group_invite"
T_READ      = "read"
T_FILE_META = "file_meta"
T_FILE_CHUNK= "file_chunk"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# カラーパレット（Catppuccin Mocha ベース）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
C = {
    "bg":       "#1e1e2e",  # 背景
    "sidebar":  "#181825",  # サイドバー
    "panel":    "#313244",  # カード / 入力
    "border":   "#45475a",  # 区切り線
    "text":     "#cdd6f4",  # 主テキスト
    "subtext":  "#a6adc8",  # 副テキスト
    "muted":    "#6c7086",  # 薄テキスト（メタ行）
    "accent":   "#89b4fa",  # 青（リンク・アクセント）
    "accent2":  "#cba6f7",  # 紫（グループ）
    "success":  "#a6e3a1",  # 緑（成功・暗号化済み）
    "warning":  "#f9e2af",  # 黄（警告）
    "error":    "#f38ba8",  # 赤（エラー）
    "sky":      "#89dceb",  # 水色（自分の名前）
    "peach":    "#fab387",  # オレンジ（ファイル）
}


def fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def ts_now() -> str:
    return datetime.now().strftime("%H:%M")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CryptoManager  ―  RSA-2048 + AES-256-GCM E2EE
#
# 【鍵設計】
#   _send_keys[peer_id] : 自分が生成し、送信に使うAES鍵
#   _recv_keys[peer_id] : 相手が生成し、受信に使うAES鍵
#   → 送信方向と受信方向で独立した鍵を持つ
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CryptoManager:
    def __init__(self):
        self.enabled   = CRYPTO_OK
        self._priv     = None
        self.pub_pem   = None
        self._pub_keys = {}        # peer_id → RSA PublicKey (相手の公開鍵)
        self._send_keys= {}        # peer_id → bytes(32) 送信用 AES 鍵
        self._recv_keys= {}        # peer_id → bytes(32) 受信用 AES 鍵

        if self.enabled:
            self._priv = rsa.generate_private_key(65537, 2048)
            self.pub_pem = self._priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

    # ── 公開鍵管理 ────────────────────────────────
    def store_pub(self, pid: str, pem: str):
        if not self.enabled:
            return
        try:
            self._pub_keys[pid] = serialization.load_pem_public_key(pem.encode())
        except Exception:
            pass

    def has_pub(self, pid: str) -> bool:
        return pid in self._pub_keys

    # ── 送信用鍵の生成（自分が生成して相手公開鍵で暗号化） ──
    def make_send_key(self, pid: str) -> "str | None":
        """新しいAES鍵を生成 → _send_keys[pid] に保存 → RSA暗号化して返す(b64)"""
        if not self.enabled or pid not in self._pub_keys:
            return None
        k   = secrets.token_bytes(32)
        self._send_keys[pid] = k
        enc = self._pub_keys[pid].encrypt(
            k, ap.OAEP(mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return base64.b64encode(enc).decode()

    def has_send_key(self, pid: str) -> bool:
        return pid in self._send_keys

    # ── 受信用鍵の読込（相手が生成した鍵を自分の秘密鍵で復号） ──
    def load_recv_key(self, pid: str, enc_b64: str) -> bool:
        """相手から受け取った暗号化AES鍵を復号 → _recv_keys[pid] に保存"""
        if not self.enabled or not self._priv:
            return False
        try:
            raw = self._priv.decrypt(
                base64.b64decode(enc_b64),
                ap.OAEP(mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
            self._recv_keys[pid] = raw
            return True
        except Exception:
            return False

    def has_recv_key(self, pid: str) -> bool:
        return pid in self._recv_keys

    # ── テキスト暗号化 / 復号 ─────────────────────
    def encrypt(self, pid: str, text: str) -> "tuple[str, bool]":
        """送信用鍵でテキストを暗号化"""
        if not self.enabled or pid not in self._send_keys:
            return text, False
        try:
            nonce = secrets.token_bytes(12)
            ct    = AESGCM(self._send_keys[pid]).encrypt(nonce, text.encode(), None)
            return base64.b64encode(nonce + ct).decode(), True
        except Exception:
            return text, False

    def decrypt(self, pid: str, ct_b64: str) -> str:
        """受信用鍵でテキストを復号"""
        if not self.enabled or pid not in self._recv_keys:
            return ct_b64
        try:
            d = base64.b64decode(ct_b64)
            return AESGCM(self._recv_keys[pid]).decrypt(d[:12], d[12:], None).decode()
        except Exception:
            return "[復号失敗]"

    # ── バイナリ暗号化 / 復号（ファイル転送用） ───
    def encrypt_bytes(self, pid: str, data: bytes) -> "tuple[bytes, bool]":
        if not self.enabled or pid not in self._send_keys:
            return data, False
        try:
            nonce = secrets.token_bytes(12)
            ct    = AESGCM(self._send_keys[pid]).encrypt(nonce, data, None)
            return nonce + ct, True
        except Exception:
            return data, False

    def decrypt_bytes(self, pid: str, data: bytes) -> bytes:
        if not self.enabled or pid not in self._recv_keys:
            return data
        try:
            return AESGCM(self._recv_keys[pid]).decrypt(data[:12], data[12:], None)
        except Exception:
            return data

    # ── 接続状態確認 ──────────────────────────────
    def can_encrypt_to(self, pid: str) -> bool:
        """送信暗号化の可否（公開鍵あり ＝ 鍵交換可能）"""
        return self.enabled and pid in self._pub_keys


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Peer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Peer:
    def __init__(self, pid: str, name: str, ip: str):
        self.id        = pid
        self.name      = name
        self.ip        = ip
        self.last_seen = time.time()
        self.online    = True

    def touch(self, name: str = None):
        self.last_seen = time.time()
        self.online    = True
        if name:
            self.name = name

    def alive(self) -> bool:
        return (time.time() - self.last_seen) < PEER_TIMEOUT


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NetworkManager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NetworkManager:
    """
    【TCP 設計】
      1 接続 = 1 メッセージ方式
      フォーマット: [4バイト 長さ ビッグエンディアン][UTF-8 JSON]
      → 接続の使い回しによる競合・デッドロックを根本排除
      → 双方向メッセージの対称性が保証される
    """

    def __init__(self, username: str, peer_id: str, crypto: CryptoManager):
        self.username = username
        self.peer_id  = peer_id
        self.crypto   = crypto
        self.peers    = {}        # peer_id → Peer
        self._lock    = threading.Lock()
        self._running = False
        self.my_ip    = self._local_ip()

        # コールバック（NodeTalkApp から設定）
        self.on_peer_found: callable = None
        self.on_peer_lost:  callable = None
        self.on_message:    callable = None

    # ── IP 取得 ─────────────────────────────────
    @staticmethod
    def _local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ── 起動 / 停止 ─────────────────────────────
    def start(self):
        self._running = True
        for fn in (self._udp_recv_loop, self._udp_cast_loop,
                   self._tcp_server_loop, self._watchdog_loop):
            threading.Thread(target=fn, daemon=True, name=fn.__name__).start()

    def stop(self):
        self._bcast_udp(T_GOODBYE, {})
        self._running = False

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # UDP ― ピア検出
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def _make_udp_pkt(self, t: str, extra: dict = None) -> bytes:
        d = {"type": t, "from_id": self.peer_id, "from_name": self.username, "ts": time.time()}
        if self.crypto.enabled and self.crypto.pub_pem:
            d["pub_key"] = self.crypto.pub_pem
        if extra:
            d.update(extra)
        return json.dumps(d, ensure_ascii=False).encode()

    def _bcast_udp(self, t: str, extra: dict = None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(self._make_udp_pkt(t, extra), ("<broadcast>", DISC_PORT))
            s.close()
        except Exception:
            pass

    def _unicast_udp(self, ip: str, t: str, extra: dict = None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(self._make_udp_pkt(t, extra), (ip, DISC_PORT))
            s.close()
        except Exception:
            pass

    def _udp_cast_loop(self):
        while self._running:
            self._bcast_udp(T_DISCOVER)
            time.sleep(DISC_INTERVAL)

    def _udp_recv_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        s.bind(("", DISC_PORT))
        s.settimeout(1.0)
        while self._running:
            try:
                data, (ip, _) = s.recvfrom(65536)
                msg = json.loads(data.decode())
                if msg.get("from_id") != self.peer_id:
                    self._handle_udp(msg, ip)
            except (socket.timeout, json.JSONDecodeError):
                pass
            except Exception:
                pass
        s.close()

    def _handle_udp(self, msg: dict, ip: str):
        t    = msg.get("type")
        pid  = msg.get("from_id", "")
        name = msg.get("from_name", "?")
        pub  = msg.get("pub_key")

        if not pid:
            return

        if t == T_DISCOVER:
            with self._lock:
                is_new = pid not in self.peers
                if is_new:
                    self.peers[pid] = Peer(pid, name, ip)
                else:
                    self.peers[pid].touch(name)

            if pub:
                self.crypto.store_pub(pid, pub)

            if is_new:
                # 相手に自分の存在を返す
                self._unicast_udp(ip, T_DISCOVER)
                if self.on_peer_found:
                    peer = self.peers[pid]
                    self.on_peer_found(peer)

        elif t == T_GOODBYE:
            with self._lock:
                if pid in self.peers:
                    self.peers[pid].online = False
            if self.on_peer_lost:
                p = self.peers.get(pid)
                if p:
                    self.on_peer_lost(p)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TCP サーバー ― 受信
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def _tcp_server_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("", CHAT_PORT))
        except OSError as e:
            print(f"[NodeTalk エラー] TCP ポート {CHAT_PORT} を使用できません: {e}")
            print("  解決策: 別のポートで実行中の NodeTalk を終了してください。")
            return
        srv.listen(32)
        srv.settimeout(1.0)
        while self._running:
            try:
                conn, (peer_ip, _) = srv.accept()
                threading.Thread(
                    target=self._tcp_recv_one,
                    args=(conn, peer_ip),
                    daemon=True,
                ).start()
            except socket.timeout:
                pass
            except Exception:
                pass
        srv.close()

    def _recv_exact(self, conn: socket.socket, n: int) -> "bytes | None":
        """正確に n バイト読む（ブロッキング）"""
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(min(n - len(buf), 65536))
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _tcp_recv_one(self, conn: socket.socket, peer_ip: str):
        """1 接続 = 1 メッセージ: ヘッダー(4B) + JSON ボディを読んで処理"""
        conn.settimeout(30)
        try:
            hdr = self._recv_exact(conn, 4)
            if not hdr:
                return
            length = struct.unpack(">I", hdr)[0]
            if length == 0 or length > MAX_MSG_BYTES:
                return
            body = self._recv_exact(conn, length)
            if not body:
                return
            msg = json.loads(body.decode("utf-8"))
            self._handle_tcp(msg, peer_ip)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_tcp(self, msg: dict, peer_ip: str):
        t    = msg.get("type", "")
        pid  = msg.get("from_id", "")
        name = msg.get("from_name", peer_ip)

        if not pid or not t:
            return

        # TCP 経由でも未登録ピアを自動登録（UDP 未検出のフォールバック）
        with self._lock:
            is_new = pid not in self.peers
            if is_new:
                self.peers[pid] = Peer(pid, name, peer_ip)
            else:
                self.peers[pid].touch(name)

        if is_new and self.on_peer_found:
            self.on_peer_found(self.peers[pid])

        # 相手の公開鍵を UDP で未受信なら TCP ペイロードから受取
        if pub := msg.get("pub_key"):
            self.crypto.store_pub(pid, pub)

        # 相手が生成した AES 鍵（暗号化済み）を受取 → recv_key に保存
        if sk := msg.get("session_key"):
            self.crypto.load_recv_key(pid, sk)

        # ── メッセージ種別ごとの処理 ──────────────
        if t in (T_CHAT, T_GROUP_MSG):
            text   = msg.get("text", "")
            is_enc = msg.get("encrypted", False)
            if is_enc:
                text = self.crypto.decrypt(pid, text)
            if self.on_message:
                self.on_message({
                    "type":      t,
                    "msg_id":    msg.get("msg_id", ""),
                    "from_id":   pid,
                    "from_name": name,
                    "text":      text,
                    "encrypted": is_enc,
                    "ts":        msg.get("ts", time.time()),
                    "room":      msg.get("room", ""),
                })

        elif t == T_GROUP_INV:
            if self.on_message:
                self.on_message({
                    "type":    t,
                    "from_id": pid, "from_name": name,
                    "room":    msg.get("room", ""),
                    "members": msg.get("members", []),
                })

        elif t == T_READ:
            if self.on_message:
                self.on_message({
                    "type":    t,
                    "from_id": pid,
                    "msg_ids": msg.get("msg_ids", []),
                })

        elif t == T_FILE_META:
            if self.on_message:
                self.on_message({
                    "type":         t,
                    "msg_id":       msg.get("msg_id", ""),
                    "from_id":      pid,
                    "from_name":    name,
                    "file_id":      msg.get("file_id", ""),
                    "filename":     msg.get("filename", "file"),
                    "file_size":    msg.get("file_size", 0),
                    "total_chunks": msg.get("total_chunks", 1),
                    "encrypted":    msg.get("encrypted", False),
                    "ts":           msg.get("ts", time.time()),
                    "room":         msg.get("room", ""),
                })

        elif t == T_FILE_CHUNK:
            if self.on_message:
                self.on_message({
                    "type":      t,
                    "from_id":   pid,
                    "file_id":   msg.get("file_id", ""),
                    "chunk_idx": msg.get("chunk_idx", 0),
                    "data_b64":  msg.get("data_b64", ""),
                    "encrypted": msg.get("encrypted", False),
                })

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TCP クライアント ― 送信
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def _tcp_send(self, peer_id: str, payload: dict) -> bool:
        """新規 TCP 接続でメッセージを 1 件送信"""
        peer = self.peers.get(peer_id)
        if not peer:
            return False

        # 送信用 AES 鍵が未生成かつ公開鍵あり → 今回のペイロードに鍵を添付
        if self.crypto.enabled and self.crypto.has_pub(peer_id) and not self.crypto.has_send_key(peer_id):
            sk = self.crypto.make_send_key(peer_id)
            if sk:
                payload["session_key"] = sk

        # 自分の公開鍵も添付（相手が未取得の場合のフォールバック）
        if self.crypto.enabled and self.crypto.pub_pem:
            payload["pub_key"] = self.crypto.pub_pem

        payload.setdefault("from_id",   self.peer_id)
        payload.setdefault("from_name", self.username)
        payload.setdefault("ts",        time.time())

        try:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            s    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((peer.ip, CHAT_PORT))
            s.sendall(struct.pack(">I", len(body)) + body)
            s.close()
            return True
        except Exception as e:
            print(f"[送信失敗 → {peer.ip}:{CHAT_PORT}] {e}")
            return False

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 公開 API
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def send_chat(self, peer_id: str, msg_id: str, text: str) -> bool:
        enc, is_enc = self.crypto.encrypt(peer_id, text)
        return self._tcp_send(peer_id, {
            "type": T_CHAT, "msg_id": msg_id,
            "text": enc, "encrypted": is_enc,
        })

    def send_group(self, room: str, msg_id: str, text: str, members: list) -> int:
        ok = 0
        for pid in members:
            if pid == self.peer_id:
                continue
            enc, is_enc = self.crypto.encrypt(pid, text)
            if self._tcp_send(pid, {
                "type": T_GROUP_MSG, "msg_id": msg_id,
                "room": room, "text": enc, "encrypted": is_enc,
            }):
                ok += 1
        return ok

    def send_group_invite(self, peer_id: str, room: str, members: list):
        self._tcp_send(peer_id, {"type": T_GROUP_INV, "room": room, "members": members})

    def send_read(self, peer_id: str, msg_ids: list):
        if msg_ids:
            self._tcp_send(peer_id, {"type": T_READ, "msg_ids": msg_ids})

    def send_file(self, peer_id: str, filepath: str,
                  progress_cb: callable = None) -> bool:
        """ファイルを読み込み、チャンク分割して送信"""
        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()
        except Exception as e:
            print(f"[ファイル読込エラー] {e}")
            return False

        filename    = os.path.basename(filepath)
        file_id     = str(uuid.uuid4())[:12]
        msg_id      = str(uuid.uuid4())[:8]
        file_size   = len(raw_data)
        chunks      = [raw_data[i: i + FILE_CHUNK_SZ] for i in range(0, len(raw_data), FILE_CHUNK_SZ)]
        total       = len(chunks)

        # チャンクを暗号化してBase64に
        enc_chunks  = []
        for ch in chunks:
            enc_ch, is_enc = self.crypto.encrypt_bytes(peer_id, ch)
            enc_chunks.append((base64.b64encode(enc_ch).decode(), is_enc))

        is_enc_flag = enc_chunks[0][1] if enc_chunks else False

        # メタデータ送信
        ok = self._tcp_send(peer_id, {
            "type": T_FILE_META, "msg_id": msg_id, "file_id": file_id,
            "filename": filename, "file_size": file_size,
            "total_chunks": total, "encrypted": is_enc_flag,
        })
        if not ok:
            return False

        # チャンク送信
        for idx, (chunk_b64, _) in enumerate(enc_chunks):
            self._tcp_send(peer_id, {
                "type": T_FILE_CHUNK, "file_id": file_id,
                "chunk_idx": idx, "data_b64": chunk_b64,
                "encrypted": is_enc_flag,
            })
            if progress_cb:
                progress_cb(idx + 1, total)

        return True

    # ── 生存確認 ────────────────────────────────
    def _watchdog_loop(self):
        while self._running:
            time.sleep(8)
            dead = []
            with self._lock:
                for pid, p in list(self.peers.items()):
                    if p.online and not p.alive():
                        p.online = False
                        dead.append(p)
            for p in dead:
                if self.on_peer_lost:
                    self.on_peer_lost(p)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NodeTalkApp  ―  Tkinter GUI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NodeTalkApp:
    def __init__(self, root: tk.Tk):
        self.root     = root
        self.root.title(f"{APP_NAME}  v{APP_VER}")
        self.root.geometry("1100x730")
        self.root.minsize(860, 560)
        self.root.configure(bg=C["bg"])

        self.username  = ""
        self.peer_id   = str(uuid.uuid4())[:8]
        self.crypto    = CryptoManager()
        self.net: NetworkManager = None

        # ─ データ ──────────────────────────────────
        # chat_id → [entry_dict, ...]
        # chat_id: peer_id (1対1) or "group:<room>" (グループ)
        self.chat_logs  = defaultdict(list)
        # room → {"name": str, "members": [peer_id, ...]}
        self.groups     = {}
        # file_id → {"meta": dict, "chunks": {idx: bytes}, "data": bytes|None, "done": bool}
        self.rcv_files  = {}
        # 未読数
        self.unread     = defaultdict(int)
        # 現在表示中の chat_id
        self.current: str = None
        # サイドバー順序
        self._peer_ids  = []
        self._grp_names = []

        self._build_login()

    # ════════════════════════════════════════════
    # ログイン画面
    # ════════════════════════════════════════════
    def _build_login(self):
        frm = tk.Frame(self.root, bg=C["bg"])
        frm.pack(expand=True, fill="both")
        self._login_frm = frm

        card = tk.Frame(frm, bg=C["sidebar"], padx=64, pady=56)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="🔗", font=("Arial", 56),
                 bg=C["sidebar"], fg=C["accent"]).pack()
        tk.Label(card, text=APP_NAME,
                 font=("Helvetica", 32, "bold"),
                 bg=C["sidebar"], fg=C["accent"]).pack(pady=(0, 4))
        tk.Label(card, text="LAN 内リアルタイムチャット  ·  インターネット不要",
                 font=("Helvetica", 11),
                 bg=C["sidebar"], fg=C["muted"]).pack(pady=(0, 36))

        tk.Label(card, text="ユーザー名",
                 font=("Helvetica", 12),
                 bg=C["sidebar"], fg=C["text"]).pack(anchor="w")
        self._uname_var = tk.StringVar()
        ent = tk.Entry(card, textvariable=self._uname_var,
                       font=("Helvetica", 14),
                       bg=C["panel"], fg=C["text"],
                       insertbackground=C["text"],
                       relief="flat", width=26)
        ent.pack(ipady=11, pady=(4, 26), fill="x")
        ent.focus_set()
        ent.bind("<Return>", lambda _: self._launch())

        tk.Button(card, text="参加する  →",
                  font=("Helvetica", 13, "bold"),
                  bg=C["accent"], fg=C["sidebar"],
                  relief="flat", cursor="hand2",
                  padx=24, pady=12,
                  command=self._launch).pack(fill="x")

        info = ("✅ 暗号化有効  (AES-256-GCM + RSA-2048)"
                if CRYPTO_OK else
                "⚠  暗号化無効  →  pip install cryptography")
        tk.Label(card, text=info,
                 font=("Helvetica", 10),
                 bg=C["sidebar"],
                 fg=C["success"] if CRYPTO_OK else C["warning"]).pack(pady=(22, 0))

    def _launch(self):
        name = self._uname_var.get().strip()
        if not name:
            messagebox.showwarning("入力エラー", "ユーザー名を入力してください")
            return
        self.username = name
        self._login_frm.destroy()

        self.net = NetworkManager(self.username, self.peer_id, self.crypto)
        self.net.on_peer_found = lambda p: self.root.after(0, lambda pp=p: self._cb_peer_found(pp))
        self.net.on_peer_lost  = lambda p: self.root.after(0, lambda pp=p: self._cb_peer_lost(pp))
        self.net.on_message    = lambda m: self.root.after(0, lambda mm=m: self._cb_message(mm))
        self.net.start()

        self._build_main()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # ════════════════════════════════════════════
    # メイン UI
    # ════════════════════════════════════════════
    def _build_main(self):
        # ── サイドバー ────────────────────────────
        self._sb = tk.Frame(self.root, bg=C["sidebar"], width=264)
        self._sb.pack(side="left", fill="y")
        self._sb.pack_propagate(False)

        tk.Label(self._sb, text=f"🔗  {APP_NAME}",
                 font=("Helvetica", 14, "bold"),
                 bg=C["sidebar"], fg=C["accent"],
                 padx=16, pady=12).pack(anchor="w")

        # 自分カード
        me = tk.Frame(self._sb, bg=C["panel"], padx=12, pady=8)
        me.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(me, text=f"🟢  {self.username}",
                 font=("Helvetica", 11, "bold"),
                 bg=C["panel"], fg=C["success"]).pack(anchor="w")
        self._ip_lbl = tk.Label(me, text=f"IP: {self.net.my_ip}",
                                font=("Helvetica", 9),
                                bg=C["panel"], fg=C["muted"])
        self._ip_lbl.pack(anchor="w")

        tk.Frame(self._sb, bg=C["border"], height=1).pack(fill="x", padx=10)

        # オンラインユーザーラベル行
        row = tk.Frame(self._sb, bg=C["sidebar"])
        row.pack(fill="x", padx=14, pady=(8, 2))
        tk.Label(row, text="オンラインユーザー",
                 font=("Helvetica", 9),
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left")
        self._cnt_lbl = tk.Label(row, text="0",
                                 font=("Helvetica", 9, "bold"),
                                 bg=C["sidebar"], fg=C["accent"])
        self._cnt_lbl.pack(side="right")

        self._peer_lb = tk.Listbox(self._sb,
                                   bg=C["sidebar"], fg=C["text"],
                                   selectbackground=C["accent"],
                                   selectforeground=C["sidebar"],
                                   font=("Helvetica", 11),
                                   relief="flat", borderwidth=0,
                                   activestyle="none", cursor="hand2")
        self._peer_lb.pack(fill="both", expand=True, padx=6)
        self._peer_lb.bind("<<ListboxSelect>>", self._on_peer_select)

        tk.Frame(self._sb, bg=C["border"], height=1).pack(fill="x", padx=10, pady=4)

        # グループラベル行
        row2 = tk.Frame(self._sb, bg=C["sidebar"])
        row2.pack(fill="x", padx=14, pady=(0, 2))
        tk.Label(row2, text="グループルーム",
                 font=("Helvetica", 9),
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left")
        tk.Button(row2, text="＋",
                  font=("Helvetica", 12),
                  bg=C["sidebar"], fg=C["accent2"],
                  relief="flat", cursor="hand2",
                  command=self._open_create_group).pack(side="right")

        self._grp_lb = tk.Listbox(self._sb,
                                  bg=C["sidebar"], fg=C["text"],
                                  selectbackground=C["accent2"],
                                  selectforeground=C["sidebar"],
                                  font=("Helvetica", 11),
                                  relief="flat", borderwidth=0,
                                  activestyle="none", cursor="hand2",
                                  height=5)
        self._grp_lb.pack(fill="x", padx=6, pady=(0, 10))
        self._grp_lb.bind("<<ListboxSelect>>", self._on_group_select)

        # ── メインエリア ──────────────────────────
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(side="right", fill="both", expand=True)

        # ヘッダー
        self._hdr = tk.Frame(main, bg=C["sidebar"], height=56)
        self._hdr.pack(fill="x")
        self._hdr.pack_propagate(False)

        self._title_var = tk.StringVar(value="← チャット相手を選択してください")
        tk.Label(self._hdr, textvariable=self._title_var,
                 font=("Helvetica", 13, "bold"),
                 bg=C["sidebar"], fg=C["text"],
                 padx=18).pack(side="left", pady=16)

        self._enc_badge = tk.Label(self._hdr, text="",
                                   font=("Helvetica", 9),
                                   bg=C["sidebar"], fg=C["success"],
                                   padx=14)
        self._enc_badge.pack(side="right", pady=16)

        # チャット表示 (Text widget + Scrollbar)
        disp_frame = tk.Frame(main, bg=C["bg"])
        disp_frame.pack(fill="both", expand=True)

        sb_y = tk.Scrollbar(disp_frame, orient="vertical",
                            bg=C["sidebar"], troughcolor=C["sidebar"],
                            relief="flat")
        sb_y.pack(side="right", fill="y")

        self._disp = tk.Text(disp_frame,
                             yscrollcommand=sb_y.set,
                             bg=C["bg"], fg=C["text"],
                             font=("Helvetica", 11),
                             relief="flat", borderwidth=0,
                             state="disabled", wrap="word",
                             padx=20, pady=16,
                             spacing2=2, spacing3=0,
                             cursor="arrow")
        sb_y.configure(command=self._disp.yview)
        self._disp.pack(side="left", fill="both", expand=True)

        # テキストタグ設定
        self._disp.tag_configure("ts",
            foreground=C["muted"], font=("Helvetica", 8))
        self._disp.tag_configure("me_name",
            foreground=C["sky"],  font=("Helvetica", 10, "bold"))
        self._disp.tag_configure("peer_name",
            foreground=C["accent2"], font=("Helvetica", 10, "bold"))
        self._disp.tag_configure("body",
            foreground=C["text"], font=("Helvetica", 11))
        self._disp.tag_configure("file_label",
            foreground=C["peach"], font=("Helvetica", 11))
        self._disp.tag_configure("dl_btn",
            foreground=C["accent"],
            font=("Helvetica", 9, "underline"),
            spacing1=0)
        self._disp.tag_configure("meta_enc_on",
            foreground=C["success"], font=("Helvetica", 8))
        self._disp.tag_configure("meta_enc_off",
            foreground=C["muted"], font=("Helvetica", 8))
        self._disp.tag_configure("meta_read",
            foreground=C["sky"], font=("Helvetica", 8))
        self._disp.tag_configure("meta_sent",
            foreground=C["muted"], font=("Helvetica", 8))
        self._disp.tag_configure("meta_sep",
            foreground=C["border"], font=("Helvetica", 8))
        self._disp.tag_configure("sys",
            foreground=C["muted"], font=("Helvetica", 9, "italic"))

        # ── 入力エリア ──────────────────────────
        inp_outer = tk.Frame(main, bg=C["sidebar"])
        inp_outer.pack(fill="x")
        inp_row = tk.Frame(inp_outer, bg=C["panel"], padx=10, pady=6)
        inp_row.pack(fill="x", padx=14, pady=10)

        # ファイル添付ボタン
        tk.Button(inp_row, text="📎",
                  font=("Arial", 15),
                  bg=C["panel"], fg=C["subtext"],
                  activebackground=C["panel"],
                  relief="flat", cursor="hand2",
                  padx=4, command=self._pick_file).pack(side="left")

        self._inp = tk.Entry(inp_row,
                             font=("Helvetica", 12),
                             bg=C["panel"], fg=C["text"],
                             insertbackground=C["text"],
                             relief="flat")
        self._inp.pack(side="left", fill="x", expand=True, ipady=8, padx=(8, 0))
        self._inp.bind("<Return>",   self._send_text)
        self._inp.bind("<KP_Enter>", self._send_text)

        tk.Button(inp_row, text="送信 ▶",
                  font=("Helvetica", 11, "bold"),
                  bg=C["accent"], fg=C["sidebar"],
                  activebackground="#6ba3e8",
                  relief="flat", cursor="hand2",
                  padx=16, command=self._send_text).pack(side="right", padx=(10, 0))

        # ステータスバー
        self._status_var = tk.StringVar(value="🟢 起動完了")
        tk.Label(self.root, textvariable=self._status_var,
                 font=("Helvetica", 9),
                 bg=C["sidebar"], fg=C["muted"],
                 anchor="w", padx=16).pack(side="bottom", fill="x")

        self._tick()

    # ════════════════════════════════════════════
    # 定期更新
    # ════════════════════════════════════════════
    def _tick(self):
        if self.net:
            n  = sum(1 for p in self.net.peers.values() if p.online and p.alive())
            self._cnt_lbl.config(text=str(n))
            enc = "🔒 E2EE 有効" if CRYPTO_OK else "🔓 暗号化なし"
            self._status_var.set(
                f"🟢 {self.username}  ·  {self.net.my_ip}  ·  接続中: {n} 名  ·  {enc}"
                f"  ·  UDP:{DISC_PORT} / TCP:{CHAT_PORT}"
            )
        self.root.after(4000, self._tick)

    # ════════════════════════════════════════════
    # ピア管理コールバック
    # ════════════════════════════════════════════
    def _cb_peer_found(self, peer: Peer):
        self._refresh_peer_list()
        self._sys(f"🟢 {peer.name}（{peer.ip}）が参加しました")

    def _cb_peer_lost(self, peer: Peer):
        self._refresh_peer_list()
        self._sys(f"🔴 {peer.name} がオフラインになりました")

    def _refresh_peer_list(self):
        self._peer_lb.delete(0, tk.END)
        self._peer_ids = []
        for pid, peer in self.net.peers.items():
            dot = "🟢" if peer.online and peer.alive() else "🔴"
            unr = f"  ● {self.unread[pid]}" if self.unread.get(pid, 0) > 0 else ""
            self._peer_lb.insert(tk.END, f"  {dot}  {peer.name}{unr}")
            self._peer_ids.append(pid)
        n = sum(1 for p in self.net.peers.values() if p.online and p.alive())
        self._cnt_lbl.config(text=str(n))

    # ════════════════════════════════════════════
    # ピア選択
    # ════════════════════════════════════════════
    def _on_peer_select(self, _event=None):
        sel = self._peer_lb.curselection()
        if not sel or sel[0] >= len(self._peer_ids):
            return
        pid  = self._peer_ids[sel[0]]
        peer = self.net.peers.get(pid)
        if not peer:
            return

        self._grp_lb.selection_clear(0, tk.END)
        self.current = pid
        self.unread[pid] = 0
        self._refresh_peer_list()
        self._title_var.set(f"💬  {peer.name}   ({peer.ip})")
        self._update_enc_badge(pid)
        self._render_chat(pid)

        # 未既読メッセージに既読通知を送る
        pending = []
        for m in self.chat_logs.get(pid, []):
            if not m["is_me"] and not m.get("read_sent") and m.get("msg_id"):
                m["read_sent"] = True
                pending.append(m["msg_id"])
        if pending:
            threading.Thread(
                target=self.net.send_read,
                args=(pid, pending), daemon=True
            ).start()

    def _update_enc_badge(self, pid: str = None):
        if pid is None:
            pid = self.current
        if pid is None or pid.startswith("group:"):
            self._enc_badge.config(text="")
            return
        if CRYPTO_OK and self.crypto.has_send_key(pid) and self.crypto.has_recv_key(pid):
            self._enc_badge.config(text="🔒 E2EE 確立", fg=C["success"])
        elif CRYPTO_OK and self.crypto.can_encrypt_to(pid):
            self._enc_badge.config(text="🔑 鍵交換中…", fg=C["warning"])
        else:
            self._enc_badge.config(text="🔓 暗号化なし", fg=C["muted"])

    # ════════════════════════════════════════════
    # グループ
    # ════════════════════════════════════════════
    def _open_create_group(self):
        online = [(pid, p) for pid, p in self.net.peers.items()
                  if p.online and p.alive()]
        if not online:
            messagebox.showinfo("情報", "オンラインユーザーがいません")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("グループ作成")
        dlg.geometry("360x460")
        dlg.configure(bg=C["bg"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        tk.Label(dlg, text="グループ名",
                 bg=C["bg"], fg=C["text"],
                 font=("Helvetica", 12)).pack(padx=24, pady=(24, 4), anchor="w")
        nv = tk.StringVar()
        ne = tk.Entry(dlg, textvariable=nv,
                      bg=C["panel"], fg=C["text"],
                      font=("Helvetica", 12), relief="flat")
        ne.pack(fill="x", padx=24, ipady=8)
        ne.focus_set()

        tk.Label(dlg, text="メンバーを選択",
                 bg=C["bg"], fg=C["text"],
                 font=("Helvetica", 12)).pack(padx=24, pady=(16, 4), anchor="w")

        mv = {}
        for pid, peer in online:
            v = tk.BooleanVar(value=True)
            mv[pid] = v
            tk.Checkbutton(dlg, text=peer.name, variable=v,
                           bg=C["bg"], fg=C["text"],
                           activebackground=C["bg"],
                           selectcolor=C["panel"],
                           font=("Helvetica", 11),
                           cursor="hand2").pack(padx=24, anchor="w")

        def do_create():
            room = nv.get().strip()
            if not room:
                messagebox.showwarning("エラー", "グループ名を入力してください", parent=dlg); return
            if room in self.groups:
                messagebox.showwarning("エラー", "同名のグループが既にあります", parent=dlg); return
            chosen = [pid for pid, v in mv.items() if v.get()]
            if not chosen:
                messagebox.showwarning("エラー", "メンバーを選択してください", parent=dlg); return
            members = [self.peer_id] + chosen
            self.groups[room] = {"name": room, "members": members}
            self._grp_names.append(room)
            self._grp_lb.insert(tk.END, f"  👥  {room}")
            for pid in chosen:
                threading.Thread(target=self.net.send_group_invite,
                                 args=(pid, room, members), daemon=True).start()
            dlg.destroy()
            self._switch_to_group(room)

        tk.Button(dlg, text="グループを作成",
                  font=("Helvetica", 12, "bold"),
                  bg=C["accent2"], fg=C["sidebar"],
                  relief="flat", cursor="hand2",
                  padx=20, pady=10, command=do_create).pack(pady=22)

    def _switch_to_group(self, room: str):
        self.current = f"group:{room}"
        self._peer_lb.selection_clear(0, tk.END)
        self.unread[self.current] = 0
        self._title_var.set(f"👥  {room}")
        self._enc_badge.config(text="")
        self._render_chat(self.current)

    def _on_group_select(self, _event=None):
        sel = self._grp_lb.curselection()
        if not sel or sel[0] >= len(self._grp_names):
            return
        self._switch_to_group(self._grp_names[sel[0]])

    # ════════════════════════════════════════════
    # 送信
    # ════════════════════════════════════════════
    def _send_text(self, _event=None):
        text = self._inp.get().strip()
        if not text or not self.current:
            return
        self._inp.delete(0, tk.END)

        msg_id = str(uuid.uuid4())[:8]
        ts     = ts_now()

        if self.current.startswith("group:"):
            room = self.current[6:]
            grp  = self.groups.get(room)
            if not grp:
                return
            # グループの暗号化は全メンバーが鍵を持っている場合 True
            is_enc = CRYPTO_OK and all(
                self.crypto.can_encrypt_to(pid)
                for pid in grp["members"] if pid != self.peer_id
            )
            entry = self._make_entry(msg_id, self.username, self.peer_id,
                                     ts, is_me=True, encrypted=is_enc)
            entry["text"] = text
            self.chat_logs[self.current].append(entry)
            self._append_entry(entry)
            members = grp["members"]
            threading.Thread(
                target=self.net.send_group,
                args=(room, msg_id, text, members),
                daemon=True,
            ).start()

        else:
            peer = self.net.peers.get(self.current)
            if not peer or not (peer.online and peer.alive()):
                self._sys("⚠ このユーザーはオフラインです")
                return
            pid    = self.current
            is_enc = CRYPTO_OK and self.crypto.can_encrypt_to(pid)
            entry  = self._make_entry(msg_id, self.username, self.peer_id,
                                      ts, is_me=True, encrypted=is_enc)
            entry["text"] = text
            self.chat_logs[pid].append(entry)
            self._append_entry(entry)

            def do_send():
                ok = self.net.send_chat(pid, msg_id, text)
                if not ok:
                    self.root.after(0, lambda: self._sys("⚠ 送信失敗（相手がオフラインの可能性）"))
                else:
                    self.root.after(0, lambda: self._update_enc_badge(pid))
            threading.Thread(target=do_send, daemon=True).start()

    def _pick_file(self):
        if not self.current:
            messagebox.showinfo("情報", "送信先を選択してください"); return
        if self.current.startswith("group:"):
            messagebox.showinfo("情報", "ファイル送信は 1対1 チャット専用です"); return
        peer = self.net.peers.get(self.current)
        if not peer or not (peer.online and peer.alive()):
            messagebox.showinfo("情報", "オフラインの相手にはファイルを送れません"); return

        path = filedialog.askopenfilename(title="送信するファイルを選択")
        if not path:
            return
        size = os.path.getsize(path)
        if size > MAX_MSG_BYTES:
            messagebox.showerror("エラー",
                f"ファイルが大きすぎます（上限 {fmt_size(MAX_MSG_BYTES)}）")
            return

        pid      = self.current
        filename = os.path.basename(path)
        is_enc   = CRYPTO_OK and self.crypto.can_encrypt_to(pid)
        msg_id   = str(uuid.uuid4())[:8]
        ts       = ts_now()

        entry = self._make_entry(msg_id, self.username, self.peer_id,
                                 ts, is_me=True, encrypted=is_enc,
                                 etype="file")
        entry.update({"filename": filename, "file_size": size,
                      "file_id": None, "file_ready": True})
        self.chat_logs[pid].append(entry)
        self._append_entry(entry)
        self._sys(f"📤 {filename}（{fmt_size(size)}）を送信中…")

        def do_send():
            ok = self.net.send_file(pid, path)
            msg = f"✅ {filename} を送信しました" if ok else f"❌ {filename} の送信に失敗しました"
            self.root.after(0, lambda: self._sys(msg))
        threading.Thread(target=do_send, daemon=True).start()

    # ════════════════════════════════════════════
    # 受信コールバック
    # ════════════════════════════════════════════
    def _cb_message(self, msg: dict):
        t = msg["type"]

        # ── グループ招待 ──────────────────────
        if t == T_GROUP_INV:
            room    = msg["room"]
            members = msg["members"]
            if room not in self.groups:
                self.groups[room] = {"name": room, "members": members}
                self._grp_names.append(room)
                self._grp_lb.insert(tk.END, f"  👥  {room}")
            self._sys(f"📩 {msg['from_name']} からグループ「{room}」に招待されました")
            return

        # ── 既読通知 ──────────────────────────
        if t == T_READ:
            pid     = msg["from_id"]
            ids_set = set(msg.get("msg_ids", []))
            changed = False
            for chat_id, logs in self.chat_logs.items():
                for e in logs:
                    if e.get("is_me") and e.get("msg_id") in ids_set and not e.get("read"):
                        e["read"] = True
                        changed   = True
            if changed and self.current and self.current in self.chat_logs:
                self._rerender_current()
            return

        # ── ファイルメタデータ ─────────────────
        if t == T_FILE_META:
            fid     = msg["file_id"]
            pid     = msg["from_id"]
            chat_id = pid  # 1対1想定
            ts      = datetime.fromtimestamp(msg["ts"]).strftime("%H:%M")

            self.rcv_files[fid] = {
                "meta": msg, "chunks": {}, "data": None, "done": False
            }
            entry = self._make_entry(
                msg["msg_id"], msg["from_name"], pid, ts,
                is_me=False, encrypted=msg["encrypted"], etype="file"
            )
            entry.update({
                "filename":  msg["filename"], "file_size": msg["file_size"],
                "file_id":   fid,             "file_ready": False,
            })
            self.chat_logs[chat_id].append(entry)
            if self.current == chat_id:
                self._append_entry(entry)
            else:
                self.unread[chat_id] += 1
                self._refresh_peer_list()
            return

        # ── ファイルチャンク ───────────────────
        if t == T_FILE_CHUNK:
            fid     = msg["file_id"]
            pid     = msg["from_id"]
            if fid not in self.rcv_files:
                return

            idx  = msg["chunk_idx"]
            raw  = base64.b64decode(msg["data_b64"])
            if msg["encrypted"]:
                raw = self.crypto.decrypt_bytes(pid, raw)

            self.rcv_files[fid]["chunks"][idx] = raw
            meta  = self.rcv_files[fid]["meta"]
            total = meta["total_chunks"]

            if len(self.rcv_files[fid]["chunks"]) >= total:
                # 全チャンク揃った → 結合
                assembled = b"".join(
                    self.rcv_files[fid]["chunks"][i] for i in range(total)
                )
                self.rcv_files[fid]["data"] = assembled
                self.rcv_files[fid]["done"] = True

                # chat_log の file_ready を更新
                chat_id = meta["from_id"]
                for e in self.chat_logs.get(chat_id, []):
                    if e.get("file_id") == fid:
                        e["file_ready"] = True
                        break
                if self.current == chat_id:
                    self._rerender_current()
                else:
                    self._refresh_peer_list()
            return

        # ── テキストメッセージ ─────────────────
        if t in (T_CHAT, T_GROUP_MSG):
            pid     = msg["from_id"]
            name    = msg["from_name"]
            text    = msg["text"]
            ts      = datetime.fromtimestamp(msg["ts"]).strftime("%H:%M")
            is_enc  = msg.get("encrypted", False)
            chat_id = pid if t == T_CHAT else f"group:{msg['room']}"

            entry = self._make_entry(
                msg["msg_id"], name, pid, ts,
                is_me=False, encrypted=is_enc
            )
            entry["text"] = text
            self.chat_logs[chat_id].append(entry)

            if self.current == chat_id:
                self._append_entry(entry)
                # 即時既読通知（1対1のみ）
                if t == T_CHAT and msg.get("msg_id"):
                    entry["read_sent"] = True
                    threading.Thread(
                        target=self.net.send_read,
                        args=(pid, [msg["msg_id"]]),
                        daemon=True,
                    ).start()
                # 暗号化バッジ更新
                if t == T_CHAT:
                    self._update_enc_badge(pid)
            else:
                self.unread[chat_id] += 1
                self._refresh_peer_list()
                preview = text[:45] + ("…" if len(text) > 45 else "")
                self._status_var.set(f"💬 新着  {name}: {preview}")

    # ════════════════════════════════════════════
    # メッセージ描画
    # ════════════════════════════════════════════
    @staticmethod
    def _make_entry(msg_id: str, sender: str, sender_id: str,
                    ts: str, *, is_me: bool, encrypted: bool,
                    etype: str = "text") -> dict:
        return {
            "msg_id":    msg_id,
            "from":      sender,
            "from_id":   sender_id,
            "text":      "",
            "time":      ts,
            "is_me":     is_me,
            "encrypted": encrypted,
            "read":      False,    # 相手が既読にしたか（送信側）
            "read_sent": False,    # 自分が既読通知を送ったか（受信側）
            "type":      etype,    # "text" or "file"
            "filename":  None,
            "file_size": None,
            "file_id":   None,
            "file_ready":False,
        }

    def _render_entry(self, entry: dict):
        """1 メッセージを Text ウィジェットに描画"""
        is_me  = entry["is_me"]
        enc    = entry["encrypted"]
        read   = entry["read"]
        etype  = entry["type"]
        ts     = entry["time"]
        name   = "あなた" if is_me else entry["from"]
        msg_id = entry.get("msg_id", "")

        name_tag = "me_name" if is_me else "peer_name"

        # ─ タイムスタンプ + 名前 ─
        self._disp.insert(tk.END, f"  {ts}  ", "ts")
        self._disp.insert(tk.END, f"{name}\n", name_tag)

        # ─ 本文 or ファイル ─
        if etype == "file":
            fname  = entry.get("filename", "file")
            fsize  = entry.get("file_size", 0)
            fid    = entry.get("file_id")
            fready = entry.get("file_ready", False)

            self._disp.insert(tk.END, f"  📎 {fname}  ({fmt_size(fsize)})", "file_label")

            if not is_me and fid:
                if fready:
                    tag = f"dl_{fid}"
                    self._disp.insert(tk.END, "  [保存する ▼]", ("dl_btn", tag))
                    self._disp.tag_bind(
                        tag, "<Button-1>",
                        lambda e, fid=fid, fn=fname: self._save_file(fid, fn)
                    )
                    self._disp.tag_configure(tag, foreground=C["accent"],
                                             font=("Helvetica", 9, "underline"))
                else:
                    self._disp.insert(tk.END, "  受信中…", "meta_sent")
            self._disp.insert(tk.END, "\n", "body")

        else:
            self._disp.insert(tk.END, f"  {entry['text']}\n", "body")

        # ─ メタ行（暗号化 + 既読） ─────────────
        #   送信側: 🔒/🔓 + ✓✓既読 or ✓送信済み
        #   受信側: 🔒/🔓 のみ
        self._disp.insert(tk.END, "  ", "ts")

        # 暗号化アイコン
        if enc:
            self._disp.insert(tk.END, "🔒 暗号化済み", "meta_enc_on")
        else:
            self._disp.insert(tk.END, "🔓 暗号化なし", "meta_enc_off")

        # 既読ステータス（送信側のみ）
        if is_me:
            self._disp.insert(tk.END, "  ·  ", "meta_sep")
            if read:
                self._disp.insert(tk.END, "✓✓ 既読", "meta_read")
            else:
                self._disp.insert(tk.END, "✓ 送信済み", "meta_sent")

        self._disp.insert(tk.END, "\n\n", "ts")

    def _append_entry(self, entry: dict):
        """末尾に 1 件追加してスクロール"""
        self._disp.config(state="normal")
        self._render_entry(entry)
        self._disp.config(state="disabled")
        self._disp.see(tk.END)

    def _render_chat(self, chat_id: str):
        """チャット履歴を全再描画"""
        y   = self._disp.yview()
        end = y[1] >= 0.98

        self._disp.config(state="normal")
        self._disp.delete("1.0", tk.END)
        for entry in self.chat_logs.get(chat_id, []):
            self._render_entry(entry)
        self._disp.config(state="disabled")

        if end:
            self._disp.see(tk.END)
        else:
            self._disp.yview_moveto(y[0])

    def _rerender_current(self):
        """現在のチャットを再描画（既読・ファイル受信完了時）"""
        if self.current:
            self._render_chat(self.current)

    def _sys(self, text: str):
        """システムメッセージ"""
        self._disp.config(state="normal")
        self._disp.insert(tk.END, f"  ── {text} ──\n\n", "sys")
        self._disp.config(state="disabled")
        self._disp.see(tk.END)

    # ════════════════════════════════════════════
    # ファイル保存
    # ════════════════════════════════════════════
    def _save_file(self, file_id: str, filename: str):
        info = self.rcv_files.get(file_id)
        if not info or not info.get("done"):
            messagebox.showwarning("情報", "ファイルの受信がまだ完了していません")
            return
        path = filedialog.asksaveasfilename(
            initialfile=filename, title="保存先を選択"
        )
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(info["data"])
            messagebox.showinfo("保存完了", f"保存しました:\n{path}")
        except Exception as e:
            messagebox.showerror("保存エラー", f"保存に失敗しました:\n{e}")

    # ════════════════════════════════════════════
    # 終了
    # ════════════════════════════════════════════
    def _quit(self):
        if self.net:
            self.net.stop()
        self.root.destroy()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# エントリーポイント
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║  {APP_NAME} v{APP_VER}  ―  LAN v2                ║
╠══════════════════════════════════════════════════════╣
║  暗号化 : {"✅ AES-256-GCM + RSA-2048 (E2EE)" if CRYPTO_OK else "❌ 無効  →  pip install cryptography"}
║  UDP    : {DISC_PORT}  /  TCP : {CHAT_PORT}
║  ファイル: 最大 {fmt_size(MAX_MSG_BYTES)} まで送受信可
╚══════════════════════════════════════════════════════╝
""")
    root = tk.Tk()
    app  = NodeTalkApp(root)
    root.mainloop()
