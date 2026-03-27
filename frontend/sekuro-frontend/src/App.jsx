import React, { useState, useEffect, useRef, useCallback } from "react";
import { useCrypto } from "./useCrypto";
import "./App.css";

// ─── Constants ────────────────────────────────────────────────────────────────
const WS_URL = "ws://localhost:8000/ws";

// ─── Tiny helpers ─────────────────────────────────────────────────────────────
const ts = () => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function SystemMsg({ text, color }) {
  return (
    <div className={`sys-msg ${color || ""}`}>
      <span className="sys-icon">⚙</span> {text}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [screen, setScreen] = useState("login"); // login | chat
  const [username, setUsername] = useState("");
  const [loginError, setLoginError] = useState("");

  const [users, setUsers] = useState([]);
  const [activePeer, setActivePeer] = useState(null);

  // messages: { [peerId]: [{id, from, text, time, type}] }
  const [allMessages, setAllMessages] = useState({});
  const [inputText, setInputText] = useState("");

  // session states per peer: "idle" | "handshaking" | "active" | "rekeying"
  const [sessionStates, setSessionStates] = useState({});
  const [fingerprints, setFingerprints] = useState({});  // peerId -> { fp, emoji }
  const [verifiedPeers, setVerifiedPeers] = useState({}); // peerId -> bool

  const [sessionInfo, setSessionInfo] = useState(null);

  const socketRef = useRef(null);
  const crypto = useCrypto();
  const messagesEndRef = useRef(null);
  const usernameRef = useRef("");

  // ── Derived ─────────────────────────────────────────────────────────────────
  const peerMessages = activePeer ? (allMessages[activePeer] || []) : [];
  const currentSession = activePeer ? sessionStates[activePeer] : null;
  const unreadCounts = {};  // could extend

  // ── Scroll to bottom ─────────────────────────────────────────────────────────
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [peerMessages]);

  // ── Add message to state ──────────────────────────────────────────────────────
  const addMessage = useCallback((peerId, msg) => {
    setAllMessages(prev => ({
      ...prev,
      [peerId]: [...(prev[peerId] || []), { id: Date.now() + Math.random(), ...msg }]
    }));
  }, []);

  const addSysMsg = useCallback((peerId, text, color) => {
    addMessage(peerId, { type: "system", text, color, time: ts() });
  }, [addMessage]);

  // ── WebSocket message handler ─────────────────────────────────────────────────
  const handleWSMessage = useCallback(async (event) => {
    const data = JSON.parse(event.data);
    const myId = usernameRef.current;

    switch (data.type) {

      case "session_init":
        setSessionInfo(data.payload);
        break;

      case "user_list":
        setUsers(data.payload);
        break;

      case "error":
        if (data.payload.includes("already taken")) {
          setLoginError("Username already taken. Try another.");
          socketRef.current?.close();
          setScreen("login");
        }
        break;

      case "session_expired":
        addSysMsg("__global__", "Your session expired due to inactivity.", "warn");
        socketRef.current?.close();
        setScreen("login");
        break;

      // ── DH handshake (responder receives init) ─────────────────────────────
      case "dh_init": {
        const peerId = data.from;
        setSessionStates(p => ({ ...p, [peerId]: "handshaking" }));
        addSysMsg(peerId, `🤝 Key exchange started with ${peerId}…`, "info");

        try {
          const responsePayload = await crypto.processDHInit(peerId, data.payload, myId);
          // Send back DH response
          socketRef.current.send(JSON.stringify({
            type: "dh_response",
            to: peerId,
            payload: responsePayload,
          }));
          // Confirm session active
          socketRef.current.send(JSON.stringify({
            type: "dh_confirm",
            to: peerId,
            payload: { status: "ok" },
          }));

          const session = crypto.getSession(peerId);
          setFingerprints(p => ({
            ...p,
            [peerId]: { fp: session.theirFingerprint, emoji: session.theirFingerprintEmoji }
          }));
          setSessionStates(p => ({ ...p, [peerId]: "active" }));
          addSysMsg(peerId, `🔐 Secure session established with ${peerId}`, "success");
          addSysMsg(peerId, `🔑 Their fingerprint: ${session.theirFingerprintEmoji}`, "fp");
        } catch (e) {
          addSysMsg(peerId, `❌ Handshake FAILED: ${e.message}`, "error");
          setSessionStates(p => ({ ...p, [peerId]: "idle" }));
        }
        break;
      }

      // ── DH handshake (initiator receives response) ─────────────────────────
      case "dh_response": {
        const peerId = data.from;
        try {
          const result = await crypto.processDHResponse(peerId, data.payload, myId);
          setFingerprints(p => ({
            ...p,
            [peerId]: { fp: result.fingerprint, emoji: result.emoji }
          }));
          setSessionStates(p => ({ ...p, [peerId]: "active" }));
          addSysMsg(peerId, `🔐 Secure session established with ${peerId}`, "success");
          addSysMsg(peerId, `🔑 Their fingerprint: ${result.emoji}`, "fp");
        } catch (e) {
          addSysMsg(peerId, `❌ Handshake FAILED: ${e.message}`, "error");
          setSessionStates(p => ({ ...p, [peerId]: "idle" }));
        }
        break;
      }

      case "dh_confirm":
        // Both sides are now active — no extra action needed
        break;

      // ── Encrypted message ──────────────────────────────────────────────────
      case "message": {
        const peerId = data.from;
        const { iv, ciphertext } = data.payload;
        try {
          const plain = await crypto.decrypt(peerId, iv, ciphertext);
          addMessage(peerId, { type: "recv", from: peerId, text: plain, time: ts() });
        } catch (e) {
          addMessage(peerId, {
            type: "error-msg",
            from: peerId,
            text: `[Decryption failed: ${e.message}]`,
            time: ts()
          });
        }
        break;
      }

      // ── Server-initiated rekey ─────────────────────────────────────────────
      case "rekey_request": {
        const peerId = data.payload?.with || data.from;
        addSysMsg(peerId, `🔄 Server requested key rotation with ${peerId}…`, "warn");
        // Initiate rekey
        await startHandshake(peerId, true);
        break;
      }

      case "rekey_init": {
        // Same as dh_init but mark as rekeying
        const peerId = data.from;
        setSessionStates(p => ({ ...p, [peerId]: "rekeying" }));
        addSysMsg(peerId, `🔄 Re-keying session with ${peerId}…`, "warn");
        try {
          const responsePayload = await crypto.processDHInit(peerId, data.payload, myId);
          socketRef.current.send(JSON.stringify({
            type: "rekey_response",
            to: peerId,
            payload: responsePayload,
          }));
          socketRef.current.send(JSON.stringify({
            type: "rekey_confirm",
            to: peerId,
            payload: { status: "ok" }
          }));
          const session = crypto.getSession(peerId);
          setSessionStates(p => ({ ...p, [peerId]: "active" }));
          addSysMsg(peerId, `🔐 New session key established`, "success");
        } catch (e) {
          addSysMsg(peerId, `❌ Rekey FAILED: ${e.message}`, "error");
        }
        break;
      }

      case "rekey_response": {
        const peerId = data.from;
        try {
          await crypto.processDHResponse(peerId, data.payload, myId);
          setSessionStates(p => ({ ...p, [peerId]: "active" }));
          addSysMsg(peerId, `🔐 New session key active`, "success");
        } catch (e) {
          addSysMsg(peerId, `❌ Rekey response FAILED: ${e.message}`, "error");
        }
        break;
      }

      case "rekey_confirm":
        break;

      default:
        break;
    }
  }, [crypto, addMessage, addSysMsg]);

  // ── Connect ──────────────────────────────────────────────────────────────────
  const connect = async () => {
    if (!username.trim()) return;
    setLoginError("");

    await crypto.initIdentity();
    usernameRef.current = username.trim();

    const ws = new WebSocket(`${WS_URL}/${username.trim()}`);
    socketRef.current = ws;

    ws.onopen = () => setScreen("chat");
    ws.onmessage = handleWSMessage;
    ws.onclose = () => {
      if (screen === "chat") {
        setScreen("login");
        setLoginError("Disconnected from server.");
      }
    };
  };

  // ── Start handshake (initiator) ───────────────────────────────────────────────
  const startHandshake = useCallback(async (peerId, isRekey = false) => {
    if (!socketRef.current) return;
    setSessionStates(p => ({ ...p, [peerId]: "handshaking" }));
    if (!isRekey) addSysMsg(peerId, `🤝 Initiating key exchange with ${peerId}…`, "info");

    try {
      const payload = isRekey
        ? await crypto.buildRekeyInit(peerId)
        : await crypto.buildDHInit(peerId);

      socketRef.current.send(JSON.stringify({
        type: isRekey ? "rekey_init" : "dh_init",
        to: peerId,
        payload,
      }));
    } catch (e) {
      addSysMsg(peerId, `❌ Handshake init failed: ${e.message}`, "error");
      setSessionStates(p => ({ ...p, [peerId]: "idle" }));
    }
  }, [crypto, addSysMsg]);

  // ── Select peer ───────────────────────────────────────────────────────────────
  const selectPeer = (peerId) => {
    setActivePeer(peerId);
    const state = sessionStates[peerId] || "idle";
    if (state === "idle") {
      startHandshake(peerId);
    }
  };

  // ── Send message ──────────────────────────────────────────────────────────────
  const sendMessage = async () => {
    if (!inputText.trim() || !activePeer || sessionStates[activePeer] !== "active") return;
    const text = inputText.trim();
    setInputText("");

    try {
      const encrypted = await crypto.encrypt(activePeer, text);
      socketRef.current.send(JSON.stringify({
        type: "message",
        to: activePeer,
        payload: encrypted,
      }));
      addMessage(activePeer, { type: "sent", from: usernameRef.current, text, time: ts() });
    } catch (e) {
      addSysMsg(activePeer, `❌ Encryption failed: ${e.message}`, "error");
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // ── Disconnect ────────────────────────────────────────────────────────────────
  const disconnect = () => {
    socketRef.current?.close();
    setScreen("login");
    setUsers([]);
    setActivePeer(null);
    setAllMessages({});
    setSessionStates({});
    setFingerprints({});
    setVerifiedPeers({});
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────────────────────

  if (screen === "login") {
    return (
      <div className="login-screen">
        <div className="login-card">
          <div className="login-logo">
            <div className="logo-icon">⬡</div>
            <h1 className="logo-title">HEXCHAT</h1>
            <p className="logo-sub">End-to-end encrypted P2P messaging</p>
          </div>

          <div className="login-badges">
            <span className="badge">ECDH P-256</span>
            <span className="badge">AES-256-GCM</span>
            <span className="badge">ECDSA</span>
            <span className="badge">HKDF</span>
          </div>

          <div className="login-form">
            <input
              className="login-input"
              placeholder="Enter username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === "Enter" && connect()}
              autoFocus
            />
            <button className="login-btn" onClick={connect}>
              Connect Securely →
            </button>
            {loginError && <p className="login-error">{loginError}</p>}
          </div>

          <p className="login-note">
            All crypto runs in your browser. The server never sees your messages.
          </p>
        </div>
      </div>
    );
  }

  // ── Chat screen ───────────────────────────────────────────────────────────────
  const myFingerprint = crypto.identityRef.current?.emoji || "—";
  const peerFp = activePeer ? fingerprints[activePeer] : null;
  const peerStatus = activePeer ? (sessionStates[activePeer] || "idle") : null;

  const onlineUsers = users.filter(u => u.id !== usernameRef.current);

  return (
    <div className="chat-app">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="my-identity">
            <div className="avatar me">{usernameRef.current[0]?.toUpperCase()}</div>
            <div className="identity-info">
              <span className="my-name">{usernameRef.current}</span>
              <span className="my-fp" title="Your identity fingerprint">{myFingerprint}</span>
            </div>
          </div>
          <button className="logout-btn" onClick={disconnect} title="Disconnect">⏻</button>
        </div>

        <div className="sidebar-label">ONLINE PEERS</div>

        <ul className="peer-list">
          {onlineUsers.length === 0 && (
            <li className="no-peers">Waiting for others to join…</li>
          )}
          {onlineUsers.map(u => {
            const state = sessionStates[u.id] || "idle";
            const isActive = activePeer === u.id;
            return (
              <li
                key={u.id}
                className={`peer-item ${isActive ? "active" : ""}`}
                onClick={() => selectPeer(u.id)}
              >
                <div className={`avatar peer state-${state}`}>
                  {u.id[0]?.toUpperCase()}
                </div>
                <div className="peer-meta">
                  <span className="peer-name">{u.id}</span>
                  <span className={`peer-state state-${state}`}>
                    {state === "active" ? "🔐 Secure" :
                     state === "handshaking" ? "🤝 Handshaking…" :
                     state === "rekeying" ? "🔄 Re-keying…" : "○ Click to connect"}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>

        {sessionInfo && (
          <div className="session-info">
            <div className="si-label">SESSION POLICY</div>
            <div className="si-row"><span>Timeout</span><span>{sessionInfo.session_timeout}s</span></div>
            <div className="si-row"><span>Re-key every</span><span>{sessionInfo.rekey_msg_count} msgs</span></div>
            <div className="si-row"><span>Or every</span><span>{sessionInfo.rekey_interval}s</span></div>
          </div>
        )}
      </aside>

      {/* ── Main chat pane ── */}
      <main className="chat-main">
        {!activePeer ? (
          <div className="no-chat-selected">
            <div className="ncs-icon">⬡</div>
            <h2>Select a peer to start chatting</h2>
            <p>A Diffie–Hellman key exchange will be initiated automatically.</p>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="chat-header">
              <div className="ch-peer">
                <div className={`avatar peer state-${peerStatus}`}>
                  {activePeer[0]?.toUpperCase()}
                </div>
                <div className="ch-peer-info">
                  <span className="ch-peer-name">{activePeer}</span>
                  {peerFp && (
                    <span className="ch-peer-fp" title={`SHA-256: ${peerFp.fp}`}>
                      {peerFp.emoji}
                    </span>
                  )}
                </div>
              </div>

              <div className="ch-actions">
                {peerStatus === "active" && peerFp && (
                  <button
                    className={`verify-btn ${verifiedPeers[activePeer] ? "verified" : ""}`}
                    onClick={() => setVerifiedPeers(p => ({ ...p, [activePeer]: !p[activePeer] }))}
                    title="Mark fingerprint as verified out-of-band"
                  >
                    {verifiedPeers[activePeer] ? "✓ Verified" : "⚠ Verify"}
                  </button>
                )}
                {peerStatus === "active" && (
                  <button
                    className="rekey-btn"
                    onClick={() => startHandshake(activePeer, true)}
                    title="Manually trigger key rotation"
                  >
                    🔄 Re-key
                  </button>
                )}
                <div className={`status-pill status-${peerStatus}`}>
                  {peerStatus === "active" ? "E2E Encrypted" :
                   peerStatus === "handshaking" ? "Handshaking…" :
                   peerStatus === "rekeying" ? "Re-keying…" : "Not secured"}
                </div>
              </div>
            </div>

            {/* MITM warning */}
            {peerStatus === "active" && !verifiedPeers[activePeer] && (
              <div className="mitm-banner">
                <span className="mitm-icon">⚠</span>
                <span>
                  <strong>Verify fingerprint to prevent MITM attacks.</strong>{" "}
                  Compare <em>{peerFp?.emoji}</em> with {activePeer} out-of-band (call, in person, etc.)
                  then click <strong>Verify</strong>.
                </span>
              </div>
            )}

            {/* Messages */}
            <div className="messages-area">
              {peerMessages.map(msg => {
                if (msg.type === "system") {
                  return <SystemMsg key={msg.id} text={msg.text} color={msg.color} />;
                }
                const isSent = msg.type === "sent";
                return (
                  <div key={msg.id} className={`message-row ${isSent ? "sent" : "recv"}`}>
                    <div className={`bubble ${isSent ? "bubble-sent" : "bubble-recv"} ${msg.type === "error-msg" ? "bubble-error" : ""}`}>
                      <span className="bubble-text">{msg.text}</span>
                      <span className="bubble-time">{msg.time} {isSent ? "🔐" : "🔓"}</span>
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="input-area">
              {peerStatus !== "active" ? (
                <div className="input-blocked">
                  {peerStatus === "handshaking" || peerStatus === "rekeying"
                    ? "⏳ Establishing secure channel…"
                    : "Click the peer to initiate a secure session."}
                </div>
              ) : (
                <>
                  <textarea
                    className="message-input"
                    placeholder={`Message ${activePeer} (encrypted)…`}
                    value={inputText}
                    onChange={e => setInputText(e.target.value)}
                    onKeyDown={handleKeyDown}
                    rows={1}
                  />
                  <button
                    className="send-btn"
                    onClick={sendMessage}
                    disabled={!inputText.trim()}
                  >
                    ↑
                  </button>
                </>
              )}
            </div>
          </>
        )}
      </main>
    </div>
  );
}