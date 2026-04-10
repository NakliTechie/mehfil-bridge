# mehfil-bridge

LAN bridge for [Mehfil](https://github.com/NakliTechie/Mehfil). Lets devices on the same network sync messages even when they're not simultaneously online — no cloud required.

## What it does

- **Announces itself via mDNS** (`_mehfil._tcp.local` on port 8765) so Mehfil finds it automatically on your LAN
- **Store-and-forward relay** — buffers the last 24h of messages in memory; devices fetch what they missed
- **WebRTC signaling hub** — relays WebRTC offer/answer/ICE between peers on the LAN so they can establish direct connections
- **Signed with a keypair** — every response includes `X-Bridge-Fp` (your bridge fingerprint); Mehfil pins this on first connect so you know you're always talking to the same bridge

---

## Install

### macOS (Homebrew tap — coming soon)
```bash
brew install naklitechie/tap/mehfil-bridge
mehfil-bridge
```

### macOS / Linux (manual)
Download the binary for your platform from [Releases](https://github.com/NakliTechie/mehfil-bridge/releases):

```bash
# macOS Apple Silicon
curl -L https://github.com/NakliTechie/mehfil-bridge/releases/latest/download/mehfil-bridge-darwin-arm64 -o /usr/local/bin/mehfil-bridge
chmod +x /usr/local/bin/mehfil-bridge
mehfil-bridge
```

### Windows
Download `mehfil-bridge-windows-amd64.exe` from Releases, place it anywhere, double-click to run.

> **Windows note:** mDNS auto-discovery may not work on Windows 10/11 if the `dnscache` service intercepts multicast queries. The bridge is still reachable at `http://localhost:8765` and can be added manually in Mehfil → Settings → Transports.

### Build from source
```bash
git clone https://github.com/NakliTechie/mehfil-bridge
cd mehfil-bridge
go build -o mehfil-bridge .
./mehfil-bridge
```

---

## Usage

Just run it:
```
./mehfil-bridge
```

Output:
```
Generated new keypair → /Users/you/.mehfil-bridge/key
Bridge fingerprint: a3f2b1e4c9d07812
mDNS: announced _mehfil._tcp.local on port 8765
Mehfil Bridge listening on :8765 (fp: a3f2b1e4c9d07812)
```

The bridge keeps running in the background. Your keypair is saved to `~/.mehfil-bridge/key` — the same fingerprint appears on every run so Mehfil can verify it.

---

## Add to Mehfil

In Mehfil: **⚙ Settings → Workspace → Transports → Add bridge**

Mehfil will auto-detect the bridge if it's running on the same LAN. If auto-detect fails, enter `http://mehfil.local:8765` manually.

On first connect, Mehfil shows your bridge fingerprint and asks you to confirm it matches what was printed in the terminal. After that, the fingerprint is pinned — you'll be warned if it ever changes.

---

## Auto-start on macOS (launchd)

Create `~/Library/LaunchAgents/com.mehfil.bridge.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>com.mehfil.bridge</string>
  <key>ProgramArguments</key> <array><string>/usr/local/bin/mehfil-bridge</string></array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>/tmp/mehfil-bridge.log</string>
  <key>StandardErrorPath</key><string>/tmp/mehfil-bridge.log</string>
</dict>
</plist>
```

Then:
```bash
launchctl load ~/Library/LaunchAgents/com.mehfil.bridge.plist
```

## Auto-start on Linux (systemd)

```ini
# ~/.config/systemd/user/mehfil-bridge.service
[Unit]
Description=Mehfil LAN Bridge

[Service]
ExecStart=/usr/local/bin/mehfil-bridge
Restart=always

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now mehfil-bridge
```

---

## API reference

All responses include `X-Bridge-Fp: <fingerprint>` and `Access-Control-Allow-Origin: *`.

### `GET /health`
```json
{ "ok": true, "fp": "a3f2b1e4c9d07812", "ts": 1712345678000 }
```

### `GET /peers`
```json
{ "peers": ["<pubkey1>", "<pubkey2>"], "fp": "a3f2b1e4c9d07812" }
```

### `PUT /ws/:ws_id/envelopes`
Store one envelope. Body: raw msgpack bytes. Returns `204`.

### `GET /ws/:ws_id/envelopes?since=<cursor>&limit=<n>`
Returns `[{ "seq": "...", "data": "<base64>" }, ...]`. Max 500 results.

### `GET /ws/:ws_id/cursor`
Returns `{ "cursor": "..." }`.

### `WebSocket /signal?pubkey=<b64url_pubkey>`
WebRTC signaling channel. Send:
```json
{ "type": "offer", "to": "<target_pubkey>", "payload": "<sdp>" }
```
Receive:
```json
{ "type": "offer", "from": "<sender_pubkey>", "payload": "<sdp>" }
{ "type": "peer_joined", "pubkey": "<pubkey>" }
{ "type": "peer_left",   "pubkey": "<pubkey>" }
```

---

## Security

- **No auth required** for LAN use — physical network presence is the implicit trust boundary.
- **Fingerprint pinning** in Mehfil ensures you're always talking to your bridge.
- Envelope contents are **end-to-end encrypted** by Mehfil; the bridge sees only ciphertext.
- Keypair is stored at `~/.mehfil-bridge/key` (mode 0600). Back it up if you want the fingerprint to survive a machine reinstall.
- The bridge holds up to **2000 envelopes per workspace** in RAM for 24 hours. Data is lost on restart — that's fine, since the cloud relay is the durable store.
