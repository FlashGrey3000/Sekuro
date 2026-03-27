# HexChat — P2P Secure Messaging Application

A fully end-to-end encrypted peer-to-peer chat application built as a computer security assignment demo.

---

## Architecture

```
┌──────────────┐   WebSocket (encrypted payloads only)   ┌──────────────┐
│  Browser A   │ ◄────────────────────────────────────► │  FastAPI     │
│  (React)     │                                         │  Server      │
│              │ ◄────────────────────────────────────► │  (Relay)     │
│  Browser B   │                                         └──────────────┘
└──────────────┘
```

**The server is a dumb relay.** It routes opaque byte blobs between clients and never sees plaintext. All cryptographic operations run in the browser via the **Web Crypto API**.

---

## Cryptographic Protocol

### 1. Identity Keypair (ECDSA P-256)
Each client generates a long-term identity keypair on first connect:
- Used to **sign** every DH handshake to prove identity.
- The SHA-256 fingerprint of your public key is your **identity fingerprint** (shown as emojis).

### 2. Key Exchange — ECDH + HKDF (per session)

```
Alice                              Bob
  |                                 |
  | ── dh_init ──────────────────► |
  |   { ephemPub_A, identPub_A,    |
  |     sig_A(ephemPub_A, Bob, ts) }|
  |                                 |
  | ◄──────────────── dh_response ─|
  |   { ephemPub_B, identPub_B,    |
  |     sig_B(ephemPub_B, Alice, ts) }
  |                                 |
  Both: ECDH(ephemPriv, peerEphemPub)
        → HKDF-SHA256 → AES-256-GCM key
```

- **Ephemeral keypairs** per session → perfect forward secrecy
- Signatures prevent MITM substitution of ephemeral keys

### 3. Message Encryption — AES-256-GCM
- Every message gets a **fresh random 96-bit IV**
- GCM provides **confidentiality + integrity + authenticity** (no separate HMAC needed)
- Ciphertext includes the GCM auth tag — any tampering causes decryption failure

### 4. MITM Protection — Fingerprint Verification
- Both peers display the SHA-256 fingerprint of the **other party's identity public key** as emoji
- Users compare fingerprints **out-of-band** (phone call, in-person) to confirm no MITM
- A warning banner is shown until the user clicks "Verify"

### 5. Session Management
| Feature | Implementation |
|---|---|
| Session IDs | UUID per connection assigned by server |
| Inactivity timeout | Server disconnects after 300s idle |
| Key rotation trigger | Server signals after 50 messages OR 120s |
| Manual re-key | "Re-key" button in UI |
| Re-key flow | Full new ECDH exchange with fresh ephemeral keys |
| Replay protection | Timestamps in handshake, reject if >30s old |

---

## Security Properties

| Property | How |
|---|---|
| **Confidentiality** | AES-256-GCM encryption |
| **Integrity** | GCM authentication tag |
| **Authenticity** | ECDSA signatures on handshake |
| **Forward Secrecy** | Ephemeral ECDH keys per session |
| **MITM Protection** | Fingerprint verification + signed ephemeral keys |
| **Replay Prevention** | Timestamps in signed handshake payloads |
| **Session Expiry** | Server-side idle timeout + periodic rekey |

---

## Setup & Run

### Backend
```bash
cd backend
pip install fastapi uvicorn
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open two browser tabs/windows at `http://localhost:5173`, use different usernames.

---

## File Structure

```
backend/
  main.py           — FastAPI WebSocket relay server

frontend/src/
  crypto.js         — All Web Crypto API primitives
  useCrypto.js      — React hook managing session/key state  
  App.jsx           — UI + WebSocket + message handling
  App.css           — Dark terminal-style UI
```

---

## Message Flow (Wire Format)

All payloads sent over WebSocket are JSON. The server only reads `type`, `to`, `from` — never `payload`.

```json
// Encrypted message
{
  "type": "message",
  "to": "alice",
  "payload": {
    "iv": "<base64 96-bit IV>",
    "ciphertext": "<base64 AES-GCM ciphertext + tag>"
  }
}

// DH init
{
  "type": "dh_init",
  "to": "bob",
  "payload": {
    "ephemeralPub": { /* JWK */ },
    "identityPub":  { /* JWK */ },
    "signature":    "<base64 ECDSA sig>",
    "timestamp":    1712345678901
  }
}
```