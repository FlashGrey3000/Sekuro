/**
 * useCrypto.js — React hook that manages:
 *  - Identity keypair lifecycle
 *  - Per-peer session state (ephemeral keys, AES session key, fingerprints)
 *  - DH handshake (initiator + responder roles)
 *  - Rekey flow
 *  - Encrypt / decrypt helpers bound to a peer session
 */

import { useRef, useCallback } from "react";
import {
  generateIdentityKeypair,
  generateEphemeralKeypair,
  exportPublicKeyJwk,
  importPublicKeyECDH,
  importPublicKeyECDSA,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  signHandshake,
  verifyHandshake,
  computeFingerprint,
  fingerprintToEmoji,
} from "./crypto";

export function useCrypto() {
  // Long-term identity keypair
  const identityRef = useRef(null);     // { privateKey, publicKey, pubJwk, fingerprint }

  // Per-peer session map: peerId → session
  // session = {
  //   aesKey, myEphemeralKeypair, theirEphemPubJwk,
  //   theirIdentityPubJwk, theirFingerprint, theirFingerprintEmoji,
  //   status: "pending"|"active"|"rekeying"
  // }
  const sessionsRef = useRef({});

  // ── Init identity ───────────────────────────────────────────────────────────

  const initIdentity = useCallback(async () => {
    const kp = await generateIdentityKeypair();
    const pubJwk = await exportPublicKeyJwk(kp.publicKey);
    const fingerprint = await computeFingerprint(pubJwk);
    const emoji = fingerprintToEmoji(fingerprint);
    identityRef.current = {
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      pubJwk,
      fingerprint,
      emoji,
    };
    return identityRef.current;
  }, []);

  // ── Build DH_INIT payload (initiator) ───────────────────────────────────────

  const buildDHInit = useCallback(async (peerId) => {
    const ephKp = await generateEphemeralKeypair();
    const ephPubJwk = await exportPublicKeyJwk(ephKp.publicKey);
    const timestamp = Date.now();
    const sig = await signHandshake(
      identityRef.current.privateKey,
      ephPubJwk, peerId, timestamp
    );

    sessionsRef.current[peerId] = {
      myEphemeralKeypair: ephKp,
      status: "pending",
    };

    return {
      ephemeralPub: ephPubJwk,
      identityPub: identityRef.current.pubJwk,
      signature: sig,
      timestamp,
    };
  }, []);

  // ── Process DH_INIT (responder) → returns DH_RESPONSE payload ───────────────

  const processDHInit = useCallback(async (peerId, payload, myId) => {
    const { ephemeralPub, identityPub, signature, timestamp } = payload;

    // Verify freshness (reject replays > 30s old)
    if (Math.abs(Date.now() - timestamp) > 30_000) {
      throw new Error("Handshake timestamp too old — possible replay attack");
    }

    // Verify signature
    const theirIdentityKey = await importPublicKeyECDSA(identityPub);
    const valid = await verifyHandshake(theirIdentityKey, ephemeralPub, myId, timestamp, signature);
    if (!valid) throw new Error("Invalid handshake signature — possible MITM!");

    // Build our response
    const myEphKp = await generateEphemeralKeypair();
    const myEphPubJwk = await exportPublicKeyJwk(myEphKp.publicKey);
    const myTimestamp = Date.now();
    const mySig = await signHandshake(
      identityRef.current.privateKey,
      myEphPubJwk, peerId, myTimestamp
    );

    // Derive shared AES key
    const theirEphPubKey = await importPublicKeyECDH(ephemeralPub);
    const aesKey = await deriveSharedKey(myEphKp.privateKey, theirEphPubKey);

    // Compute fingerprint
    const fp = await computeFingerprint(identityPub);
    const emoji = fingerprintToEmoji(fp);

    sessionsRef.current[peerId] = {
      myEphemeralKeypair: myEphKp,
      theirEphemPubJwk: ephemeralPub,
      theirIdentityPubJwk: identityPub,
      theirFingerprint: fp,
      theirFingerprintEmoji: emoji,
      aesKey,
      status: "active",
    };

    return {
      ephemeralPub: myEphPubJwk,
      identityPub: identityRef.current.pubJwk,
      signature: mySig,
      timestamp: myTimestamp,
    };
  }, []);

  // ── Process DH_RESPONSE (initiator finalizes) ────────────────────────────────

  const processDHResponse = useCallback(async (peerId, payload, myId) => {
    const { ephemeralPub, identityPub, signature, timestamp } = payload;
    const session = sessionsRef.current[peerId];
    if (!session) throw new Error("No pending session for peer");

    if (Math.abs(Date.now() - timestamp) > 30_000) {
      throw new Error("Response timestamp too old");
    }

    const theirIdentityKey = await importPublicKeyECDSA(identityPub);
    const valid = await verifyHandshake(theirIdentityKey, ephemeralPub, myId, timestamp, signature);
    if (!valid) throw new Error("Invalid response signature — possible MITM!");

    const theirEphPubKey = await importPublicKeyECDH(ephemeralPub);
    const aesKey = await deriveSharedKey(session.myEphemeralKeypair.privateKey, theirEphPubKey);

    const fp = await computeFingerprint(identityPub);
    const emoji = fingerprintToEmoji(fp);

    sessionsRef.current[peerId] = {
      ...session,
      theirEphemPubJwk: ephemeralPub,
      theirIdentityPubJwk: identityPub,
      theirFingerprint: fp,
      theirFingerprintEmoji: emoji,
      aesKey,
      status: "active",
    };

    return { fingerprint: fp, emoji };
  }, []);

  // ── Encrypt for peer ─────────────────────────────────────────────────────────

  const encrypt = useCallback(async (peerId, plaintext) => {
    const session = sessionsRef.current[peerId];
    if (!session?.aesKey) throw new Error("No active session with " + peerId);
    return encryptMessage(session.aesKey, plaintext);
  }, []);

  // ── Decrypt from peer ────────────────────────────────────────────────────────

  const decrypt = useCallback(async (peerId, iv, ciphertext) => {
    const session = sessionsRef.current[peerId];
    if (!session?.aesKey) throw new Error("No active session with " + peerId);
    return decryptMessage(session.aesKey, iv, ciphertext);
  }, []);

  // ── Get session info ─────────────────────────────────────────────────────────

  const getSession = useCallback((peerId) => {
    return sessionsRef.current[peerId] || null;
  }, []);

  const clearSession = useCallback((peerId) => {
    delete sessionsRef.current[peerId];
  }, []);

  // ── Start rekey (initiator role — reuses DH init flow) ───────────────────────

  const buildRekeyInit = useCallback(async (peerId) => {
    const session = sessionsRef.current[peerId];
    if (session) session.status = "rekeying";
    return buildDHInit(peerId);   // reuses same flow
  }, [buildDHInit]);

  return {
    identityRef,
    initIdentity,
    buildDHInit,
    processDHInit,
    processDHResponse,
    buildRekeyInit,
    encrypt,
    decrypt,
    getSession,
    clearSession,
  };
}