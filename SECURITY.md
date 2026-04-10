# Security

## Threat model

The Mehfil bridge is a LAN-only store-and-forward buffer. It never holds encryption keys or decrypts envelopes — all cryptographic operations happen client-side. The bridge sees only padded ciphertext addressed to a workspace ID.

The bridge is designed to be run on a trusted local network. It does **not** protect against:

- **LAN-local attackers** — any device on the same network can push envelopes to the bridge. They cannot decrypt them (no keys), but they could attempt to flood the in-memory buffer. The 4 KB per-envelope cap and 200-workspace limit bound the damage.
- **Traffic analysis** — a bridge operator can observe message timing, frequency, and approximate size (envelopes are padded to 1 KB).
- **Relay trust** — if `RELAY_URL` is configured, the bridge syncs with that relay. A compromised relay could serve garbage envelopes; recipients will drop them on signature verification failure.

## Trust anchor

The bridge has no bearer-token auth. Trust is established by **fingerprint pinning**: on first connect, Mehfil fetches the bridge's Ed25519 fingerprint via `/health` and asks the user to confirm it matches the value printed in the bridge terminal. The fingerprint is then stored and verified on every subsequent connection — a mismatch blocks the connection.

Never run the bridge on an untrusted network. The fingerprint only protects against a rogue device impersonating the bridge; it does not authenticate clients pushing envelopes.

## Key storage

The bridge keypair is stored at `~/.mehfil-bridge/key` with mode `0600`. It is never transmitted and never committed to the repository (enforced by `.gitignore`).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities. Reach out on Twitter at [@chirag](https://twitter.com/chirag). Include a description of the vulnerability, steps to reproduce, and your assessment of severity. I aim to respond within 72 hours.
