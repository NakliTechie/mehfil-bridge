// mehfil-bridge — LAN bridge for Mehfil workspaces
//
// Announces itself via mDNS (_mehfil._tcp.local) and serves:
//   GET  /health                         — liveness + fingerprint
//   GET  /peers                          — currently-connected signaling peers
//   PUT  /ws/{id}/envelopes              — store envelope (24h in-memory)
//   GET  /ws/{id}/envelopes?since&limit  — fetch envelopes since cursor
//   GET  /ws/{id}/cursor                 — latest cursor
//   WS   /signal?pubkey={b64url}         — WebRTC offer/answer/ICE relay
//
// Auth: none — the bridge fingerprint is the trust anchor.
// All responses carry X-Bridge-Fp and CORS headers.
//
// Keypair stored at ~/.mehfil-bridge/key (never in the repo).
// All envelope data is in-memory; restarts lose the buffer.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	randmath "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/gorilla/websocket"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// storedEnv is one envelope in the LAN relay buffer.
type storedEnv struct {
	seq      string // "{ts16}_{rand4}" — lexicographically sortable
	data     string // base64-encoded msgpack bytes (as sent by client)
	storedAt int64  // Unix ms — for 24h eviction
}

// wsBuffer is the per-workspace in-memory envelope ring (max 2000 entries).
type wsBuffer struct {
	mu   sync.RWMutex
	envs []storedEnv
	cur  string // latest seq
}

// sigMsg is the JSON shape for /signal WebSocket messages.
type sigMsg struct {
	Type    string `json:"type"`              // "offer"|"answer"|"ice"|"peer_joined"|"peer_left"
	To      string `json:"to,omitempty"`      // target pubkey (sender fills)
	From    string `json:"from,omitempty"`    // source pubkey (bridge fills)
	Pubkey  string `json:"pubkey,omitempty"`  // used in peer_joined/peer_left
	Payload string `json:"payload,omitempty"` // SDP or ICE candidate
}

// sigPeer is one connected WebSocket peer in the signaling hub.
type sigPeer struct {
	pubkey string
	send   chan []byte
}

// relaySyncState tracks per-workspace relay sync cursors and loop-prevention hashes.
type relaySyncState struct {
	mu           sync.Mutex
	pushedCursor string          // last local seq pushed to relay
	relayCursor  string          // last relay seq pulled from relay
	pulledHashes map[string]bool // hex(sha256(data)[:8]) of envelopes received FROM relay
}

// ─── Global state ─────────────────────────────────────────────────────────────

var (
	bridgeFP   string // hex fingerprint (first 16 bytes of SHA-256(pubkey))
	bridgeName string // human-readable display name for this bridge (BRIDGE_NAME env)
	signPriv   ed25519.PrivateKey

	bufMu   sync.RWMutex
	buffers = map[string]*wsBuffer{} // wsId → *wsBuffer

	peerMu sync.RWMutex
	peers  = map[string]*sigPeer{} // pubkey → *sigPeer

	upgrader = websocket.Upgrader{
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
		CheckOrigin:     func(r *http.Request) bool { return true }, // allow all origins (LAN)
	}

	rng = randmath.New(randmath.NewSource(time.Now().UnixNano()))

	// Relay federation config (optional — set via RELAY_URL / RELAY_TOKEN env vars).
	relayURL   string // e.g. https://relay.example.workers.dev (no trailing slash)
	relayToken string // Bearer token for the relay Worker

	relaySyncMu     sync.Mutex
	relaySyncStates = map[string]*relaySyncState{} // wsId → state

	relayClient = &http.Client{Timeout: 15 * time.Second}
)

// ─── Keypair ──────────────────────────────────────────────────────────────────

func loadOrCreateKeypair() {
	dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("cannot find home dir:", err)
	}
	keyDir := filepath.Join(dir, ".mehfil-bridge")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		log.Fatal("cannot create key dir:", err)
	}
	keyPath := filepath.Join(keyDir, "key")

	raw, err := os.ReadFile(keyPath)
	if err == nil && len(raw) == ed25519.PrivateKeySize {
		signPriv = ed25519.PrivateKey(raw)
	} else {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal("keygen:", err)
		}
		if err := os.WriteFile(keyPath, []byte(priv), 0600); err != nil {
			log.Fatal("write key:", err)
		}
		signPriv = priv
		log.Println("Generated new keypair →", keyPath)
	}

	pub := signPriv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	bridgeFP = hex.EncodeToString(sum[:16])
	log.Printf("Bridge fingerprint: %s", bridgeFP)
}

// ─── Envelope buffer ──────────────────────────────────────────────────────────

const (
	maxEnvsPerWS = 2000
	envTTL       = 24 * time.Hour
)

func getOrCreateBuffer(wsId string) *wsBuffer {
	bufMu.RLock()
	b := buffers[wsId]
	bufMu.RUnlock()
	if b != nil {
		return b
	}
	bufMu.Lock()
	defer bufMu.Unlock()
	if buffers[wsId] == nil {
		buffers[wsId] = &wsBuffer{}
	}
	return buffers[wsId]
}

func newSeq() string {
	ts := time.Now().UnixMilli()
	chars := "0123456789abcdefghijklmnopqrstuvwxyz"
	rand4 := make([]byte, 4)
	for i := range rand4 {
		rand4[i] = chars[rng.Intn(len(chars))]
	}
	return fmt.Sprintf("%016d_%s", ts, rand4)
}

func (b *wsBuffer) put(data string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	seq := newSeq()
	now := time.Now().UnixMilli()
	// Evict expired entries (lazy — runs on every put).
	cutoff := now - envTTL.Milliseconds()
	i := 0
	for i < len(b.envs) && b.envs[i].storedAt < cutoff {
		i++
	}
	b.envs = b.envs[i:]
	// Cap at maxEnvsPerWS by dropping oldest.
	if len(b.envs) >= maxEnvsPerWS {
		b.envs = b.envs[len(b.envs)-maxEnvsPerWS+1:]
	}
	b.envs = append(b.envs, storedEnv{seq: seq, data: data, storedAt: now})
	b.cur = seq
	return seq
}

func (b *wsBuffer) getAfter(since string, limit int) []storedEnv {
	b.mu.RLock()
	defer b.mu.RUnlock()
	// Find the first entry with seq > since.
	start := 0
	if since != "" {
		for start < len(b.envs) && b.envs[start].seq <= since {
			start++
		}
	}
	end := start + limit
	if end > len(b.envs) {
		end = len(b.envs)
	}
	return b.envs[start:end]
}

func (b *wsBuffer) cursor() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cur
}

// ─── Relay federation sync ────────────────────────────────────────────────────

func getOrCreateSyncState(wsId string) *relaySyncState {
	relaySyncMu.Lock()
	defer relaySyncMu.Unlock()
	if s, ok := relaySyncStates[wsId]; ok {
		return s
	}
	s := &relaySyncState{pulledHashes: map[string]bool{}}
	relaySyncStates[wsId] = s
	return s
}

// pullWorkspaceFromRelay fetches new envelopes from the relay since our last cursor
// and stores them in the local buffer. Each pulled envelope's data hash is recorded
// in pulledHashes so we never re-push it back to the relay (loop prevention).
func pullWorkspaceFromRelay(wsId string) error {
	state := getOrCreateSyncState(wsId)

	state.mu.Lock()
	since := state.relayCursor
	state.mu.Unlock()

	u := relayURL + "/ws/" + wsId + "/envelopes?limit=100"
	if since != "" {
		u += "&since=" + since
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if relayToken != "" {
		req.Header.Set("Authorization", "Bearer "+relayToken)
	}

	resp, err := relayClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay GET %d", resp.StatusCode)
	}

	var items []struct {
		Seq  string `json:"seq"`
		Data string `json:"data"` // base64-encoded msgpack bytes
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	buf := getOrCreateBuffer(wsId)
	for _, item := range items {
		// Compute loop-prevention hash BEFORE storing.
		sum := sha256.Sum256([]byte(item.Data))
		hashKey := hex.EncodeToString(sum[:8])

		// Store in local LAN buffer so offline-LAN devices can pick it up.
		buf.put(item.Data)

		// Record that this envelope came from the relay.
		state.mu.Lock()
		state.pulledHashes[hashKey] = true
		state.relayCursor = item.Seq
		state.mu.Unlock()
	}
	log.Printf("[relay-sync] pull %s: %d envelopes", wsId[:8], len(items))
	return nil
}

// pushWorkspaceToRelay pushes new local envelopes to the relay.
// Envelopes that originated from the relay (in pulledHashes) are skipped.
func pushWorkspaceToRelay(wsId string) error {
	state := getOrCreateSyncState(wsId)

	state.mu.Lock()
	since := state.pushedCursor
	state.mu.Unlock()

	buf := getOrCreateBuffer(wsId)
	envs := buf.getAfter(since, 100)
	if len(envs) == 0 {
		return nil
	}

	pushed := 0
	for _, env := range envs {
		sum := sha256.Sum256([]byte(env.data))
		hashKey := hex.EncodeToString(sum[:8])

		state.mu.Lock()
		isPulled := state.pulledHashes[hashKey]
		state.mu.Unlock()

		if isPulled {
			// Came from relay — skip to avoid echo loop.
			state.mu.Lock()
			state.pushedCursor = env.seq
			state.mu.Unlock()
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(env.data)
		if err != nil {
			// Corrupt entry — skip.
			state.mu.Lock()
			state.pushedCursor = env.seq
			state.mu.Unlock()
			continue
		}

		req, err := http.NewRequest(http.MethodPut,
			relayURL+"/ws/"+wsId+"/envelopes",
			bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		if relayToken != "" {
			req.Header.Set("Authorization", "Bearer "+relayToken)
		}

		putResp, err := relayClient.Do(req)
		if err != nil {
			return err
		}
		putResp.Body.Close()
		if putResp.StatusCode >= 400 {
			return fmt.Errorf("relay PUT %d", putResp.StatusCode)
		}

		pushed++
		state.mu.Lock()
		state.pushedCursor = env.seq
		state.mu.Unlock()
	}

	if pushed > 0 {
		log.Printf("[relay-sync] push %s: %d envelopes", wsId[:8], pushed)
	}
	return nil
}

// startRelaySync launches the background goroutine that syncs every known
// workspace buffer with the configured relay every 5 seconds.
// No-op if RELAY_URL is not set.
func startRelaySync() {
	if relayURL == "" {
		return
	}
	log.Printf("[relay-sync] enabled → %s (bridge name: %q)", relayURL, bridgeName)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// Snapshot workspace IDs from the live buffer map.
			bufMu.RLock()
			wsIds := make([]string, 0, len(buffers))
			for id := range buffers {
				wsIds = append(wsIds, id)
			}
			bufMu.RUnlock()

			for _, wsId := range wsIds {
				if err := pullWorkspaceFromRelay(wsId); err != nil {
					log.Printf("[relay-sync] pull %s: %v", wsId[:8], err)
				}
				if err := pushWorkspaceToRelay(wsId); err != nil {
					log.Printf("[relay-sync] push %s: %v", wsId[:8], err)
				}
			}
		}
	}()
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

// cors adds required headers to every response; also handles OPTIONS preflight.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("X-Bridge-Fp", bridgeFP)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func jsonWrite(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonWrite(w, map[string]any{
		"ok":   true,
		"fp":   bridgeFP,
		"name": bridgeName,
		"ts":   time.Now().UnixMilli(),
	})
}

func handlePeers(w http.ResponseWriter, r *http.Request) {
	peerMu.RLock()
	list := make([]string, 0, len(peers))
	for pk := range peers {
		list = append(list, pk)
	}
	peerMu.RUnlock()
	jsonWrite(w, map[string]any{"peers": list, "fp": bridgeFP})
}

// handleEnvelopes handles both PUT (store) and GET (fetch) for /ws/{id}/envelopes.
func handleEnvelopes(w http.ResponseWriter, r *http.Request) {
	// Extract workspace ID from path: /ws/{id}/envelopes
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	wsId := parts[1]

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || len(body) == 0 {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		data := base64.StdEncoding.EncodeToString(body)
		getOrCreateBuffer(wsId).put(data)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		since := r.URL.Query().Get("since")
		limit := 100
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
			if l > 500 {
				l = 500
			}
			limit = l
		}
		envs := getOrCreateBuffer(wsId).getAfter(since, limit)
		out := make([]map[string]string, len(envs))
		for i, e := range envs {
			out[i] = map[string]string{"seq": e.seq, "data": e.data}
		}
		jsonWrite(w, out)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleCursor(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	wsId := parts[1]
	cur := getOrCreateBuffer(wsId).cursor()
	jsonWrite(w, map[string]string{"cursor": cur})
}

// ─── WebSocket signaling hub ──────────────────────────────────────────────────

func handleSignal(w http.ResponseWriter, r *http.Request) {
	pubkey := r.URL.Query().Get("pubkey")
	if pubkey == "" {
		http.Error(w, "pubkey required", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, http.Header{"X-Bridge-Fp": {bridgeFP}})
	if err != nil {
		log.Println("ws upgrade:", err)
		return
	}

	peer := &sigPeer{pubkey: pubkey, send: make(chan []byte, 64)}

	// Register peer and announce to existing peers.
	peerMu.Lock()
	if old, ok := peers[pubkey]; ok {
		close(old.send) // evict stale connection
	}
	peers[pubkey] = peer
	// Collect existing peer list before releasing the lock.
	existing := make([]string, 0, len(peers)-1)
	for pk := range peers {
		if pk != pubkey {
			existing = append(existing, pk)
		}
	}
	peerMu.Unlock()

	broadcast(pubkey, sigMsg{Type: "peer_joined", Pubkey: pubkey})

	// Tell the new peer about everyone already online.
	for _, pk := range existing {
		send(peer, sigMsg{Type: "peer_joined", Pubkey: pk})
	}

	// Write pump — flushes the send channel to the WebSocket.
	go func() {
		for msg := range peer.send {
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				break
			}
		}
		conn.Close()
	}()

	// Read pump — routes incoming messages to the target peer.
	defer func() {
		peerMu.Lock()
		if peers[pubkey] == peer {
			delete(peers, pubkey)
		}
		peerMu.Unlock()
		close(peer.send)
		broadcast(pubkey, sigMsg{Type: "peer_left", Pubkey: pubkey})
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var msg sigMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		msg.From = pubkey
		if msg.To == "" {
			continue
		}
		peerMu.RLock()
		target := peers[msg.To]
		peerMu.RUnlock()
		if target != nil {
			send(target, msg)
		}
	}
}

func send(p *sigPeer, msg sigMsg) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case p.send <- raw:
	default: // drop if send buffer is full
	}
}

func broadcast(exceptPubkey string, msg sigMsg) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	peerMu.RLock()
	defer peerMu.RUnlock()
	for pk, p := range peers {
		if pk == exceptPubkey {
			continue
		}
		select {
		case p.send <- raw:
		default:
		}
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	loadOrCreateKeypair()

	// Optional relay federation config.
	relayURL   = strings.TrimRight(os.Getenv("RELAY_URL"), "/")
	relayToken = os.Getenv("RELAY_TOKEN")
	bridgeName = os.Getenv("BRIDGE_NAME")
	if bridgeName == "" {
		bridgeName = "Bridge"
	}
	startRelaySync()

	// mDNS registration — announces _mehfil._tcp.local on port 8765.
	// TXT record carries the fingerprint so clients can verify before connecting.
	zcServer, err := zeroconf.Register(
		"Mehfil Bridge",
		"_mehfil._tcp",
		"local.",
		8765,
		[]string{"fp=" + bridgeFP, "v=1"},
		nil,
	)
	if err != nil {
		log.Println("mDNS registration failed (bridge still reachable at mehfil.local:8765):", err)
	} else {
		defer zcServer.Shutdown()
		log.Println("mDNS: announced _mehfil._tcp.local on port 8765")
	}

	// HTTP routes.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", cors(handleHealth))
	mux.HandleFunc("/peers", cors(handlePeers))
	mux.HandleFunc("/signal", cors(handleSignal)) // WebSocket
	mux.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) {
		// Route /ws/{id}/envelopes and /ws/{id}/cursor
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("X-Bridge-Fp", bridgeFP)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/cursor") {
			handleCursor(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/envelopes") {
			handleEnvelopes(w, r)
		} else {
			http.NotFound(w, r)
		}
	})

	addr := ":8765"
	log.Printf("Mehfil Bridge listening on %s (fp: %s)", addr, bridgeFP)
	log.Fatal(http.ListenAndServe(addr, mux))
}
