"""Local-only RFB fixture: inspect clicks and change framebuffer size on demand.

Run from the checkout with Python. Logs are under build/. To request a remote
resize, write e.g. 900x1600 to build/scaling-server-size.txt. No credentials or
real desktops are involved. Only listens on 127.0.0.1:5919.
"""
import json
import socket
import struct
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG = ROOT / "build/scaling-pointer-events.jsonl"
SIZE = ROOT / "build/scaling-server-size.txt"


def receive(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise EOFError
        result.extend(part)
    return bytes(result)


def event(**value):
    with LOG.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value) + "\n")


def serve(sock):
    width, height = 1600, 900
    pf = struct.pack("!BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    sock.sendall(b"RFB 003.008\n")
    receive(sock, 12)
    sock.sendall(b"\x01\x01")
    assert receive(sock, 1) == b"\x01"
    sock.sendall(struct.pack("!I", 0))
    receive(sock, 1)
    name = b"Scaling verification (local fixture)"
    sock.sendall(struct.pack("!HH", width, height) + pf + struct.pack("!I", len(name)) + name)
    event(connected=True)
    first = True
    while True:
        kind = receive(sock, 1)[0]
        if kind == 0:
            receive(sock, 3)
            pf = receive(sock, 16)
        elif kind == 2:
            count = struct.unpack("!xH", receive(sock, 3))[0]
            receive(sock, count * 4)
        elif kind == 3:
            receive(sock, 9)
            new_size = tuple(map(int, SIZE.read_text().strip().split("x"))) if SIZE.exists() else (1600, 900)
            changed = new_size != (width, height)
            if changed:
                width, height = new_size
            bpp, _, endian, _, red, green, blue, rs, gs, bs = struct.unpack("!BBBBHHHBBBxxx", pf)

            def pixel(r, g, b):
                number = ((r * red // 255) << rs) | ((g * green // 255) << gs) | ((b * blue // 255) << bs)
                return number.to_bytes(bpp // 8, "big" if endian else "little")

            rect = lambda x, y, w, h, encoding: struct.pack("!HHHHi", x, y, w, h, encoding)
            if first or changed:
                rows = []
                for y in range(height):
                    left = pixel(210, 40 if y < height // 2 else 160, 40)
                    right = pixel(40, 80 if y < height // 2 else 200, 210)
                    rows.append(left * (width // 2) + right * (width - width // 2))
                extra = rect(0, 0, width, height, -223) if changed else b""
                sock.sendall(struct.pack("!BBH", 0, 0, 2 if changed else 1) + extra +
                             rect(0, 0, width, height, 0) + b"".join(rows))
                event(framebuffer=[width, height])
                first = False
            else:
                time.sleep(0.15)
                sock.sendall(struct.pack("!BBH", 0, 0, 1) + rect(0, 0, 1, 1, 0) + pixel(200, 40, 40))
        elif kind == 4:
            receive(sock, 7)
        elif kind == 5:
            mask, x, y = struct.unpack("!BHH", receive(sock, 5))
            if mask:
                event(button=mask, x=x, y=y, framebuffer=[width, height])
        elif kind == 6:
            length = struct.unpack("!xxxI", receive(sock, 7))[0]
            receive(sock, length)
        else:
            raise ValueError(f"Unexpected client message {kind}")


if __name__ == "__main__":
    LOG.write_text("", encoding="utf-8")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 5919))
        listener.listen()
        print("Scaling fixture ready on 127.0.0.1:5919", flush=True)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    serve(connection)
                except (EOFError, ConnectionError):
                    event(disconnected=True)
