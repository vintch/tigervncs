"""Exercise viewer recovery against loopback-only fake RFB servers.

Pass the explicitly built vncviewer_lifecycle_test.exe. No external servers,
credentials or GUI automation are used. Results go under build/lifecycle-tests.
"""
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


def server(listener, mode, count):
    for _ in range(count):
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(12)
            try:
                if mode == "silent":
                    while conn.recv(1024):
                        pass
                elif mode == "early-drop":
                    conn.sendall(b"RFB 003.008\n")
                    receive(conn, 12)
                else:
                    conn.sendall(b"RFB 003.008\n")
                    receive(conn, 12)
                    conn.sendall(b"\x01\x01")
                    assert receive(conn, 1) == b"\x01"
                    conn.sendall(struct.pack("!I", 0))
                    receive(conn, 1)
                    name = b"Loopback lifecycle fixture"
                    pixel_format = struct.pack("!BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
                    conn.sendall(struct.pack("!HH", 64, 48) + pixel_format + struct.pack("!I", len(name)) + name)
                    # Stay established beyond the connection deadline, proving
                    # this is not an idle-session timeout, then drop the socket.
                    time.sleep(5.2)
            except (EOFError, OSError):
                pass
    listener.close()


def run_case(executable, mode, retries):
    directory = ROOT / "build" / "lifecycle-tests" / mode
    directory.mkdir(parents=True, exist_ok=True)
    viewer = directory / "viewer.exe"
    shutil.copy2(executable, viewer)
    events_path = directory / "events.jsonl"
    events_path.write_text("", encoding="utf-8")
    (directory / "tigervncs.json").write_text(json.dumps({
        "schemaVersion": 1, "viewer": {"AutoSelect": False, "FullColor": True,
        "PreferredEncoding": "Raw", "ScaleToWindow": True}, "connections": []
    }), encoding="utf-8")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    thread = None
    if mode == "refused":
        listener.close()
    else:
        listener.listen()
        thread = threading.Thread(target=server, args=(listener, mode, retries + 1), daemon=True)
        thread.start()
    env = os.environ.copy()
    env["VNC_TEST_EVENTS"] = str(events_path)
    env["VNC_TEST_RETRIES"] = str(retries)
    result = subprocess.run([str(viewer), "-Audio=0", "-ReconnectOnError=0", "-ConnectTimeoutSeconds=4",
                             f"127.0.0.1::{port}"], env=env, cwd=ROOT,
                            capture_output=True, timeout=18)
    (directory / "viewer.log").write_bytes(result.stdout + result.stderr)
    assert result.returncode == 0, (mode, result.returncode)
    if thread:
        thread.join(timeout=2)
        assert not thread.is_alive(), mode
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    assert events[-1]["event"] == "main-window", (mode, events)
    assert events[-1]["credentialsCleared"], (mode, events)
    errors = events[:-1]
    if mode == "established-drop":
        assert errors == [], events
        assert events[-1]["elapsedMs"] >= 5000, events
    else:
        assert len(errors) == retries + 1, events
        assert [e["action"] for e in errors] == ["Retry"] * retries + ["Cancel"], events
        if mode == "silent":
            previous = 0
            for error in errors:
                assert "4 seconds" in error["message"], events
                assert 3800 <= error["elapsedMs"] - previous <= 4800, events
                previous = error["elapsedMs"]
    return {"scenario": mode, "passed": True, "events": events}


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve()
    results = [run_case(executable, mode, retries) for mode, retries in [
        ("refused", 1), ("early-drop", 1), ("silent", 1)]]
    output = ROOT / "build" / "lifecycle-results.json"
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
