import React, { useState, useEffect } from "react";

function App() {
  const [username, setUsername] = useState("");
  const [connected, setConnected] = useState(false);
  const [socket, setSocket] = useState(null);

  const [users, setUsers] = useState([]);
  const [target, setTarget] = useState("");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);

  // 🔌 Connect to WebSocket
  const connect = () => {
    const ws = new WebSocket(`ws://localhost:8000/ws/${username}`);

    ws.onopen = () => {
      console.log("Connected");
      setConnected(true);
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "user_list") {
        setUsers(data.payload);
      }

      if (data.type === "message") {
        setMessages((prev) => [
          ...prev,
          `${data.from}: ${data.payload}`,
        ]);
      }

      if (data.type === "error") {
        alert(data.payload);
      }
    };

    setSocket(ws);
  };

  // 📩 Send message
  const sendMessage = () => {
    if (!socket || !target) return;

    socket.send(
      JSON.stringify({
        type: "message",
        to: target,
        payload: message,
      })
    );

    setMessages((prev) => [...prev, `Me → ${target}: ${message}`]);
    setMessage("");
  };

  // 🧱 UI

  if (!connected) {
    return (
      <div style={{ padding: 20 }}>
        <h2>Connect</h2>
        <input
          placeholder="Enter username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <button onClick={connect}>Connect</button>
      </div>
    );
  }

  return (
    <div style={{ padding: 20 }}>
      <h2>Logged in as: {username}</h2>

      <h3>Available Users</h3>
      <ul>
        {users
          .filter((u) => u !== username)
          .map((u) => (
            <li key={u} onClick={() => setTarget(u)} style={{ cursor: "pointer" }}>
              {u}
            </li>
          ))}
      </ul>

      <h3>Chatting with: {target || "None"}</h3>

      <div style={{ border: "1px solid black", height: 200, overflowY: "scroll", marginBottom: 10 }}>
        {messages.map((msg, i) => (
          <div key={i}>{msg}</div>
        ))}
      </div>

      <input
        placeholder="Type message"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
      />
      <button onClick={sendMessage}>Send</button>
    </div>
  );
}

export default App;