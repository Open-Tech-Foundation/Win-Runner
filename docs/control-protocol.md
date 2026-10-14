# Headless control protocol (for agents)

Persistent, scriptable control of one shell over a loopback WebSocket.
This is the interface automation should use for interactive sessions; for
one-shot jobs prefer `winrun runner`, for long-lived state prefer
`winrun instance exec`.

## Start

```bash
winrun --headless --control=127.0.0.1:0 shell
# stdout, one JSON line:
{"event":"ready","protocol":1,"url":"ws://127.0.0.1:PORT/control/<token>"}
```

- Binds **loopback only** (non-loopback is refused). Port `0` picks a free port.
- `<token>` is a random 32-hex-char session secret. **Anyone holding the URL
  controls the shell — do not log it.** Token comparison is constant-time;
  wrong paths get HTTP 401.
- `--control` requires `--headless` and the `shell` target.
- Idle/partial unauthenticated handshakes expire after 2s (max 64 pending) so
  scanners can't wedge the listener.

## Events (server → client, JSON text frames)

| Event | Shape | Meaning |
|---|---|---|
| `ready` | `{"event":"ready","protocol":1,"url":"…"}` | Printed on stdout at startup (not on the socket) |
| `output` | `{"event":"output","channel":"stdout"\|"stderr","text":"…","data_base64":"…"}` | Chunk of guest output; `text` is lossy, `data_base64` is exact |
| `prompt` | `{"event":"prompt","cwd":"…"}` | Shell is ready for the next input; current guest directory |
| `exit` | `{"event":"exit","code":N}` | Session ended; socket closes after this |

`stdout` and `stderr` arrive as separate events (no interleaving guarantee
beyond arrival order). Guest stdin stays connected, so a running program can
still consume piped input.

## Requests (client → server, JSON text frames)

| `op` | Fields | Effect |
|---|---|---|
| `write` | `text: string` | Feed text to shell stdin (as if typed + Enter where applicable) |
| `write_bytes` | `data_base64: string` | Feed raw bytes to stdin |
| `key` | `key: string` | Named key: `ENTER TAB ESC/ESCAPE BACKSPACE CTRL_C CTRL_D CTRL_X CTRL_S UP DOWN RIGHT LEFT` |
| `resize` | `columns: 1–500, rows: 1–300` | Update shared console size seen by guest APIs |
| `close` | — | No-op acknowledgement path |

Unknown `op`s and malformed requests return an error and leave the session
running.

## Minimal client (Python)

```python
import json, subprocess, websocket  # pip install websocket-client

proc = subprocess.Popen(
    ["winrun", "--headless", "--control=127.0.0.1:0", "shell"],
    stdout=subprocess.PIPE, text=True,
)
ready = json.loads(proc.stdout.readline())
ws = websocket.create_connection(ready["url"])
ws.send(json.dumps({"op": "write", "text": "Write-Output '{\"ok\":true}'\n"}))
ws.send(json.dumps({"op": "write", "text": "exit\n"}))
while True:
    msg = json.loads(ws.recv())
    print(msg.get("event"), msg.get("channel", ""), msg.get("text", "")[:200])
    if msg.get("event") == "exit":
        break
print("exit code:", msg["code"])
```

## Tips

- Prefer single-quoted PowerShell literals and `ConvertTo-Json -Compress` for
  machine-readable replies (double-quoted strings interpolate `$` and backticks).
- Emit `"Write-Output \"__EXIT:$LASTEXITCODE\"\n"` after commands whose status
  you need — the protocol reports output and final exit, not per-command codes.
- `resize` before programs that query console size (editors, progress bars).
- One session per listener; for concurrent jobs use separate headless
  processes or `instance exec`.
