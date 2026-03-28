## Message formats
1) User list (server → client)
```json
{
  "type": "user_list",
  "payload": ["user1", "user2"]
}
```
2) Send message (client → server)
```json
{
  "type": "message",
  "to": "user2",
  "payload": "hello"
}
```
3) Receive message (server → client)
```json
{
  "type": "message",
  "from": "user1",
  "payload": "hello"
}
```
4) Future: key exchange
```json
{
  "type": "key_exchange",
  "to": "user2",
  "payload": {
    "public_key": "...",
    "signature": "..."
  }
}
```