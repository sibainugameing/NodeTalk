# NodeTalk

**Secure Local Network Communication**  
Fast. Offline. Peer-to-Peer.

NodeTalk is a local network communication application built with Python, designed for fast and secure communication between devices on the same LAN without requiring internet access.

---

## Features

- **LAN Discovery**  
  Automatically detects devices on the same local network.

- **Real-time Chat**  
  Low-latency messaging using WebSocket communication.

- **P2P Connection**  
  Direct device-to-device communication without central servers.

- **End-to-End Encryption**  
  AES-256 + RSA key exchange for secure messaging.

- **File Sharing**  
  Send files securely over the local network.

---

## Built With

- **Backend:** Python (`asyncio`, `FastAPI`, `websockets`)
- **GUI:** Tkinter (tk)
- **Protocol:** UDP Discovery + TCP + WebSocket + P2P Socket
- **Security:** AES-256 / RSA / E2EE
- **Packaging:** `PyInstaller`
- **Platforms:** Windows / macOS / Linux

---

## Installation

```bash
git clone <your-repo-url>
cd NodeTalk
pip install -r requirements.txt
python main.py
```

---

## Usage

1. Launch NodeTalk on multiple devices connected to the same LAN.
2. Devices are automatically discovered.
3. Select a device or create a room.
4. Start chatting securely.

---

## Security

NodeTalk prioritizes privacy and security:

- End-to-End Encryption (E2EE)
- Local-only communication by default
- No external servers required
- No account registration required

---

## Terms of Use

- NodeTalk is provided **"as is"**, without warranty of any kind.
- Users must comply with applicable laws and network policies.
- Illegal or malicious use is prohibited.
- Users are responsible for securing their own devices and networks.
- Developers are not liable for data loss or damages.
- Distributed under the **MIT License** (see `LICENSE`).

---

## License

MIT License

See `LICENSE` for details.
