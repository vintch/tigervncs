"""Loopback-only regression checks for automatic, window-preserving recovery."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]


def receive(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def serve_connection(conn, mode, color, metrics):
    conn.settimeout(12)
    conn.sendall(b"RFB 003.008\n")
    receive(conn, 12)
    conn.sendall(b"\x01\x01")
    assert receive(conn, 1) == b"\x01"
    conn.sendall(struct.pack("!I", 0))
    receive(conn, 1)
    pixel_format = struct.pack("!BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    name = b"Automatic recovery fixture"
    conn.sendall(struct.pack("!HH", 64, 48) + pixel_format + struct.pack("!I", len(name)) + name)
    first = True
    partial_sent = False
    started = time.monotonic()
    while True:
        kind = receive(conn, 1)[0]
        if kind == 0:
            receive(conn, 3)
            pixel_format = receive(conn, 16)
        elif kind == 2:
            count = struct.unpack("!xH", receive(conn, 3))[0]
            receive(conn, count * 4)
        elif kind == 3:
            incremental, x, y, width, height = struct.unpack("!BHHHH", receive(conn, 9))
            if first:
                if mode == "delayed":
                    time.sleep(1.1)
            elif mode == "partial":
                if not incremental and not partial_sent:
                    conn.sendall(struct.pack("!BBHHHHHi", 0, 0, 1, 0, 0, 64, 48, 0) + bytes(64))
                    partial_sent = True
                continue
            elif mode == "stall":
                continue
            elif incremental:
                # A healthy static desktop legitimately sends no incremental update.
                continue
            bpp, _, endian, _, red, green, blue, rs, gs, bs = struct.unpack("!BBBBHHHBBBxxx", pixel_format)
            r, g, b = color
            value = ((r * red // 255) << rs) | ((g * green // 255) << gs) | ((b * blue // 255) << bs)
            pixel = value.to_bytes(bpp // 8, "big" if endian else "little")
            if first:
                x = y = 0
                width, height = 64, 48
            packet = struct.pack("!BBHHHHHi", 0, 0, 1, x, y, width, height, 0) + pixel * width * height
            if mode == "slow":
                # Total frame transfer exceeds the active deadline, but bytes keep arriving.
                for offset in range(0, len(packet), 1024):
                    conn.sendall(packet[offset:offset + 1024])
                    time.sleep(0.45)
            else:
                conn.sendall(packet)
            if first:
                metrics.append({"event": "first-frame", "time": time.monotonic()})
                first = False
            if mode == "drop":
                time.sleep(0.2)
                return
        elif kind == 4:
            receive(conn, 7)
        elif kind == 5:
            receive(conn, 5)
        elif kind == 6:
            length = struct.unpack("!xxxI", receive(conn, 7))[0]
            receive(conn, length)
        else:
            raise AssertionError(f"Unexpected message {kind}")


def run_case(executable, mode):
    directory = ROOT / "build" / "session-recovery" / mode
    directory.mkdir(parents=True, exist_ok=True)
    viewer = directory / "viewer.exe"
    shutil.copy2(executable, viewer)
    events_file = directory / "events.jsonl"
    events_file.write_text("")
    (directory / "tigervncs.json").write_text(json.dumps({
        "schemaVersion": 1, "viewer": {"AutoSelect": False, "PreferredEncoding": "Raw",
        "FullColor": True, "ScaleToWindow": True}, "connections": []
    }))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen()
    listener.settimeout(14)
    errors, metrics = [], []
    recover = mode not in ("idle", "slow")

    def worker():
        try:
            conn, _ = listener.accept()
            with conn:
                try:
                    serve_connection(conn, "stall" if mode == "retry-drop" else mode, (220, 30, 30), metrics)
                except (EOFError, OSError):
                    pass
            if recover:
                if mode == "retry-drop":
                    conn, _ = listener.accept()
                    conn.close()  # A failed recovery handshake must keep the same frozen image.
                conn, _ = listener.accept()
                with conn:
                    try:
                        serve_connection(conn, "delayed", (30, 220, 30), metrics)
                    except (EOFError, OSError):
                        pass
        except Exception as error:
            errors.append(repr(error))
        finally:
            listener.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    env = os.environ.copy()
    env["VNC_TEST_EVENTS"] = str(events_file)
    if not recover:
        env["VNC_TEST_CLOSE_IDLE"] = "1"
    result = subprocess.run([str(viewer), "-Audio=0", "-PingEnabled=1",
        "-ConnectTimeoutSeconds=4", "-SessionTimeoutSeconds=4", f"127.0.0.1::{port}"],
        env=env, cwd=ROOT, capture_output=True, timeout=24)
    (directory / "viewer.log").write_bytes(result.stdout + result.stderr)
    thread.join(timeout=2)
    assert not thread.is_alive() and not errors, (mode, errors)
    assert result.returncode == 0, (mode, result.returncode)
    events = [json.loads(line) for line in events_file.read_text().splitlines()]
    assert events[-1]["event"] == "main-window", events
    assert not any(e["event"] == "connection-error" for e in events), events
    attachments = [e for e in events if e["event"] == "attached"]
    frames = [e for e in events if e["event"] == "frame"]
    frozen = [e for e in events if e["event"] == "frozen"]
    assert sum(not e["reused"] for e in attachments) == 1, events
    assert all(e["presenceSuspended"] for e in attachments + frames + frozen), events
    if recover:
        assert len(frames) == 2 and frozen, events
        assert frames[0]["window"] == frames[1]["window"], events
        assert frames[0]["pixel"] != frames[1]["pixel"], events
        assert all(e["pixel"] == frames[0]["pixel"] for e in frozen), events
        assert all(e["pixel"] == frames[0]["pixel"] for e in attachments[1:]), events
        if mode in ("stall", "retry-drop"):
            delay = frozen[0]["elapsedMs"] - frames[0]["elapsedMs"]
            assert 4000 <= delay <= 6500, events
    else:
        assert len(frames) == 1 and not frozen, events
    return {"scenario": mode, "passed": True, "events": events}


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve()
    results = [run_case(executable, mode) for mode in ("stall", "retry-drop", "drop", "partial", "idle", "slow")]
    (ROOT / "build" / "session-recovery-results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
