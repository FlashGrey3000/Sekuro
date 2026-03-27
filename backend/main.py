from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import json

app = FastAPI()

# Store active connections
clients: dict[str, WebSocket] = {}


# Helper: send user list to all clients
async def broadcast_user_list():
    user_list = list(clients.keys())

    message = json.dumps({
        "type": "user_list",
        "payload": user_list
    })

    for connection in clients.values():
        await connection.send_text(message)


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()

    # Store client
    clients[client_id] = websocket
    print(f"{client_id} connected")

    # Notify everyone of updated users
    await broadcast_user_list()

    try:
        while True:
            raw_data = await websocket.receive_text()
            data = json.loads(raw_data)

            msg_type = data.get("type")
            target = data.get("to")
            payload = data.get("payload")

            # Direct messaging
            if target in clients:
                await clients[target].send_text(json.dumps({
                    "type": msg_type,
                    "from": client_id,
                    "payload": payload
                }))

            else:
                # Optional: send error back
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "payload": f"User {target} not found"
                }))

    except WebSocketDisconnect:
        print(f"{client_id} disconnected")

        # Remove client
        if client_id in clients:
            del clients[client_id]

        # Update everyone
        await broadcast_user_list()