/**
 * crypto.js — All cryptographic operations for the P2P secure chat.
 *
 * Protocol summary:
 *  1. Each client generates a long-term ECDSA P-256 identity keypair on startup.
 *     The public key acts as the identity; its fingerprint is shown for MITM verification.
 *
 *  2. Key exchange (per session/rekey):
 *     a. Initiator generates an ephemeral ECDH P-256 keypair.
 *     b. Initiator signs (ephemeral_pub_jwk + peer_id + timestamp) with identity key.
 *     c. Sends { ephemeralPub, identityPub, signature, timestamp } → server → peer.
 *     d. Responder verifies signature, sends back its own signed ephemeral key.
 *     e. Both sides derive shared secret via ECDH → HKDF-SHA-256 → 256-bit AES-GCM key.
 *
 *  3. Encryption: AES-256-GCM (provides confidentiality + integrity + authentication).
 *     Each message gets a fresh 96-bit random IV. Ciphertext includes GCM auth tag.
 *
 *  4. MITM protection: Both sides display the SHA-256 fingerprint of the peer's
 *     identity public key. Users compare out-of-band (emoji fingerprint shown).
 *
 *  5. Session management: Server signals rekey after N messages or T seconds.
 *     Client re-runs steps 2a-2e with a fresh ephemeral keypair; old key is discarded.
 */

// ─── Identity keypair (ECDSA P-256) ──────────────────────────────────────────

export async function generateIdentityKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

export async function exportPublicKeyJwk(key) {
  return crypto.subtle.exportKey("jwk", key);
}

export async function importPublicKeyECDSA(jwk) {
  return crypto.subtle.importKey(
    "jwk", jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

// ─── Ephemeral ECDH keypair (P-256) ──────────────────────────────────────────

export async function generateEphemeralKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
}

export async function importPublicKeyECDH(jwk) {
  return crypto.subtle.importKey(
    "jwk", jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

// ─── Shared secret derivation (ECDH + HKDF) ──────────────────────────────────

export async function deriveSharedKey(myEphemeralPrivate, theirEphemeralPublic, salt) {
  // ECDH raw secret
  const ecdhSecret = await crypto.subtle.deriveKey(
    { name: "ECDH", public: theirEphemeralPublic },
    myEphemeralPrivate,
    { name: "HKDF" },  // intermediate, not usable directly
    false,
    ["deriveKey"]
  );

  // We can't do 2-step HKDF cleanly via subtle.deriveKey chaining,
  // so we use deriveBits for ECDH then HKDF separately.
  const rawBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: theirEphemeralPublic },
    myEphemeralPrivate,
    256
  );

  // HKDF to derive final AES key
  const hkdfKey = await crypto.subtle.importKey(
    "raw", rawBits,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  const enc = new TextEncoder();
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt || enc.encode("p2p-secure-chat-v1"),
      info: enc.encode("aes-gcm-session-key"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return aesKey;
}

// ─── AES-256-GCM encrypt / decrypt ───────────────────────────────────────────

export async function encryptMessage(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(plaintext)
  );
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ciphertext),
  };
}

export async function decryptMessage(aesKey, iv_b64, ciphertext_b64) {
  const iv = base64ToBuf(iv_b64);
  const ciphertext = base64ToBuf(ciphertext_b64);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    ciphertext
  );
  return new TextDecoder().decode(plainBuf);
}

// ─── ECDSA sign / verify ──────────────────────────────────────────────────────

export async function signHandshake(identityPrivKey, ephemeralPubJwk, peerId, timestamp) {
  const enc = new TextEncoder();
  const msg = enc.encode(JSON.stringify({ ephemeralPubJwk, peerId, timestamp }));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identityPrivKey,
    msg
  );
  return bufToBase64(sig);
}

export async function verifyHandshake(identityPubKey, ephemeralPubJwk, peerId, timestamp, signature_b64) {
  const enc = new TextEncoder();
  const msg = enc.encode(JSON.stringify({ ephemeralPubJwk, peerId, timestamp }));
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    identityPubKey,
    base64ToBuf(signature_b64),
    msg
  );
}

// ─── Fingerprint (for MITM verification) ─────────────────────────────────────

export async function computeFingerprint(pubKeyJwk) {
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(pubKeyJwk));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bufToHex(hash);
}

/** Convert a hex fingerprint to an emoji sequence for easy visual comparison */
export function fingerprintToEmoji(hex) {
  const EMOJI_PALETTE = [
    "🔴","🟠","🟡","🟢","🔵","🟣","⚫","⚪","🔶","🔷",
    "❤️","🧡","💛","💚","💙","💜","🖤","🤍","💔","💯",
    "🌟","⭐","🌙","☀️","🌈","❄️","🔥","💧","🌊","🍀",
    "🦊","🐺","🦁","🐯","🐻","🦅","🦋","🐉","🦄","🐙"
  ];
  const bytes = hex.match(/.{2}/g).map(h => parseInt(h, 16));
  // Pick 6 emojis from first 6 bytes, mod palette length
  return bytes.slice(0, 6).map(b => EMOJI_PALETTE[b % EMOJI_PALETTE.length]).join(" ");
}

// ─── Utilities ────────────────────────────────────────────────────────────────

export function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function base64ToBuf(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

export function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}