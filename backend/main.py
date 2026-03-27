from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import json
import asyncio
import time
import uuid

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── State ────────────────────────────────────────────────────────────────────

class Client:
    def __init__(self, ws: WebSocket, client_id: str):
        self.ws = ws
        self.client_id = client_id
        self.session_id = str(uuid.uuid4())
        self.connected_at = time.time()
        self.last_active = time.time()
        self.sessions: dict[str, str] = {}   # peer_id -> session_id for P2P sessions

clients: dict[str, Client] = {}

SESSION_TIMEOUT = 300        # 5 min inactivity → disconnect
REKEY_INTERVAL  = 120        # suggest re-key every 2 min
REKEY_MSG_COUNT = 50         # or every 50 messages

# per-pair message counters  {frozenset(a,b): count}
pair_msg_count: dict[frozenset, int] = {}
pair_last_rekey: dict[frozenset, float] = {}

# ─── Helpers ──────────────────────────────────────────────────────────────────

async def send(client: Client, data: dict):
    try:
        await client.ws.send_text(json.dumps(data))
    except Exception:
        pass

async def broadcast_user_list():
    user_list = [
        {"id": cid, "session_id": c.session_id}
        for cid, c in clients.items()
    ]
    for c in clients.values():
        await send(c, {"type": "user_list", "payload": user_list})

async def check_rekey(a: str, b: str):
    key = frozenset([a, b])
    count = pair_msg_count.get(key, 0)
    last  = pair_last_rekey.get(key, time.time())
    now   = time.time()

    if count >= REKEY_MSG_COUNT or (now - last) >= REKEY_INTERVAL:
        pair_msg_count[key]    = 0
        pair_last_rekey[key]   = now
        # notify both peers
        for cid in [a, b]:
            if cid in clients:
                await send(clients[cid], {
                    "type": "rekey_request",
                    "payload": {"with": b if cid == a else a}
                })

async def session_watchdog():
    """Disconnect idle clients."""
    while True:
        await asyncio.sleep(30)
        now = time.time()
        stale = [
            cid for cid, c in clients.items()
            if now - c.last_active > SESSION_TIMEOUT
        ]
        for cid in stale:
            c = clients.get(cid)
            if c:
                await send(c, {"type": "session_expired", "payload": "Idle timeout"})
                await c.ws.close()

# ─── WebSocket endpoint ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    asyncio.create_task(session_watchdog())


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()

    # Reject duplicate usernames
    if client_id in clients:
        await websocket.send_text(json.dumps({
            "type": "error",
            "payload": "Username already taken"
        }))
        await websocket.close()
        return

    client = Client(websocket, client_id)
    clients[client_id] = client
    print(f"[+] {client_id} connected  (session={client.session_id})")

    # Send session info back to this client
    await send(client, {
        "type": "session_init",
        "payload": {
            "session_id": client.session_id,
            "rekey_interval": REKEY_INTERVAL,
            "rekey_msg_count": REKEY_MSG_COUNT,
            "session_timeout": SESSION_TIMEOUT,
        }
    })

    await broadcast_user_list()

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)

            client.last_active = time.time()

            msg_type = data.get("type")
            target   = data.get("to")
            payload  = data.get("payload")

            # ── Routable message types ──────────────────────────────────────
            ROUTABLE = {
                "dh_init",          # ECDH public key + identity sig
                "dh_response",      # ECDH public key + identity sig
                "dh_confirm",       # Key confirmation / session open
                "message",          # Encrypted AES-GCM ciphertext
                "rekey_init",       # Trigger re-key exchange
                "rekey_response",   # Re-key ECDH response
                "rekey_confirm",    # Re-key complete ack
                "ping",             # Liveness
                "session_close",    # Graceful teardown
            }

            if msg_type in ROUTABLE:
                if target and target in clients:
                    peer = clients[target]

                    # count messages for rekey tracking
                    if msg_type == "message":
                        key = frozenset([client_id, target])
                        pair_msg_count[key] = pair_msg_count.get(key, 0) + 1
                        await check_rekey(client_id, target)

                    await send(peer, {
                        "type": msg_type,
                        "from": client_id,
                        "payload": payload
                    })
                else:
                    await send(client, {
                        "type": "error",
                        "payload": f"User '{target}' not found or offline"
                    })

            elif msg_type == "pong":
                pass  # just updates last_active, already done above

            else:
                await send(client, {
                    "type": "error",
                    "payload": f"Unknown message type: {msg_type}"
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] Error for {client_id}: {e}")
    finally:
        print(f"[-] {client_id} disconnected")
        clients.pop(client_id, None)
        await broadcast_user_list()