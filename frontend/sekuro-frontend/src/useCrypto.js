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
  const identityRef = useRef(null);
  const sessionsRef = useRef({});

  const SALT = new TextEncoder().encode("fixed-salt");

  // ── Init identity ─────────────────────────────────────────────

  const initIdentity = useCallback(async () => {
    try {
      console.log("🔑 Generating identity keypair");

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

      console.log("✅ Identity initialized");
      return identityRef.current;

    } catch (err) {
      console.error("❌ Identity init failed:", err);
      throw err;
    }
  }, []);

  // ── Build DH_INIT ─────────────────────────────────────────────

  const buildDHInit = useCallback(async (peerId) => {
    try {
      console.log("🚀 Initiating DH with", peerId);

      const ephKp = await generateEphemeralKeypair();
      const ephPubJwk = await exportPublicKeyJwk(ephKp.publicKey);
      const timestamp = Date.now();

      const sig = await signHandshake(
        identityRef.current.privateKey,
        ephPubJwk,
        peerId,
        timestamp
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

    } catch (err) {
      console.error("❌ buildDHInit failed:", err);
      throw err;
    }
  }, []);

  // ── Process DH_INIT ───────────────────────────────────────────

  const processDHInit = useCallback(async (peerId, payload, myId) => {
    try {
      console.log("✅ Received DH_INIT from", peerId);

      const { ephemeralPub, identityPub, signature, timestamp } = payload;

      console.log("➡️ Step 1: timestamp check");
      if (Math.abs(Date.now() - timestamp) > 30000) {
        throw new Error("Timestamp too old");
      }

      console.log("➡️ Step 2: import identity key");
      const theirIdentityKey = await importPublicKeyECDSA(identityPub);

      console.log("➡️ Step 3: verify signature");
      const valid = await verifyHandshake(
        theirIdentityKey,
        ephemeralPub,
        myId,
        timestamp,
        signature
      );
      if (!valid) throw new Error("Invalid signature");

      console.log("➡️ Step 4: generate ephemeral key");
      const myEphKp = await generateEphemeralKeypair();

      console.log("➡️ Step 5: export ephemeral pub");
      const myEphPubJwk = await exportPublicKeyJwk(myEphKp.publicKey);

      const myTimestamp = Date.now();

      console.log("➡️ Step 6: sign handshake");
      const mySig = await signHandshake(
        identityRef.current.privateKey,
        myEphPubJwk,
        peerId,
        myTimestamp
      );

      console.log("➡️ Step 7: import peer ECDH key");
      const theirEphPubKey = await importPublicKeyECDH(ephemeralPub);

      console.log("➡️ Step 8: derive shared key");
      const aesKey = await deriveSharedKey(
        myEphKp.privateKey,
        theirEphPubKey,
        SALT
      );

      console.log("➡️ Step 9: compute fingerprint");
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

      console.log("📤 Sending DH_RESPONSE to", peerId);

      return {
        ephemeralPub: myEphPubJwk,
        identityPub: identityRef.current.pubJwk,
        signature: mySig,
        timestamp: myTimestamp,
      };

    } catch (err) {
      console.error("❌ ERROR in processDHInit:", err);
      throw err;
    }
  }, []);

  // ── Process DH_RESPONSE ───────────────────────────────────────

  const processDHResponse = useCallback(async (peerId, payload, myId) => {
    try {
      console.log("✅ Received DH_RESPONSE from", peerId);

      const { ephemeralPub, identityPub, signature, timestamp } = payload;
      const session = sessionsRef.current[peerId];

      if (!session) throw new Error("No pending session");

      console.log("➡️ Step 1: timestamp check");
      if (Math.abs(Date.now() - timestamp) > 30000) {
        throw new Error("Response too old");
      }

      console.log("➡️ Step 2: import identity key");
      const theirIdentityKey = await importPublicKeyECDSA(identityPub);

      console.log("➡️ Step 3: verify signature");
      const valid = await verifyHandshake(
        theirIdentityKey,
        ephemeralPub,
        myId,
        timestamp,
        signature
      );
      if (!valid) throw new Error("Invalid response signature");

      console.log("➡️ Step 4: import peer ECDH key");
      const theirEphPubKey = await importPublicKeyECDH(ephemeralPub);

      console.log("➡️ Step 5: derive shared key");
      const aesKey = await deriveSharedKey(
        session.myEphemeralKeypair.privateKey,
        theirEphPubKey,
        SALT
      );

      console.log("➡️ Step 6: compute fingerprint");
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

      console.log("🔐 Session established with", peerId);

      return { fingerprint: fp, emoji };

    } catch (err) {
      console.error("❌ ERROR in processDHResponse:", err);
      throw err;
    }
  }, []);

  // ── Encrypt ───────────────────────────────────────────────────

  const encrypt = useCallback(async (peerId, plaintext) => {
    try {
      console.log("🔐 Encrypting message for", peerId);
      const session = sessionsRef.current[peerId];
      if (!session?.aesKey) throw new Error("No active session");
      return encryptMessage(session.aesKey, plaintext);
    } catch (err) {
      console.error("❌ Encryption failed:", err);
      throw err;
    }
  }, []);

  // ── Decrypt ───────────────────────────────────────────────────

  const decrypt = useCallback(async (peerId, iv, ciphertext) => {
    try {
      console.log("🔓 Decrypting message from", peerId);
      const session = sessionsRef.current[peerId];
      if (!session?.aesKey) throw new Error("No active session");
      return decryptMessage(session.aesKey, iv, ciphertext);
    } catch (err) {
      console.error("❌ Decryption failed:", err);
      throw err;
    }
  }, []);

  const getSession = useCallback((peerId) => {
  return sessionsRef.current[peerId] || null;
  }, []);

  return {
    identityRef,
    initIdentity,
    buildDHInit,
    processDHInit,
    processDHResponse,
    encrypt,
    decrypt,
    getSession,
  };
}