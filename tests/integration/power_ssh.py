"""Real plink against a synthetic SSH server. Never execute a power command.

Requires Paramiko in .tools/ssh-test-python and a free loopback TCP port 22.
"""
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import winreg

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".tools" / "ssh-test-python"))
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

PASSWORD = "p@ss ' quote \\ special!"
USERNAME = 'user name"quote'


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.ready = threading.Event()
        self.authenticated = False
        self.command = None

    def check_auth_password(self, username, password):
        self.authenticated = username == USERNAME and password == PASSWORD
        return paramiko.AUTH_SUCCESSFUL if self.authenticated else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode("utf-8")
        self.ready.set()
        return True


def host_keys():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\SimonTatham\PuTTY\SshHostKeys")
    except FileNotFoundError:
        return None
    with key:
        return [winreg.EnumValue(key, i) for i in range(winreg.QueryInfoKey(key)[1])]


def main():
    directory = ROOT / "build" / "power ssh integration"
    directory.mkdir(parents=True, exist_ok=True)
    for binary in ("connection_fixture", "power_tools_probe"):
        shutil.copy2(ROOT / "build/windows-release/tests/unit" / (binary + ".exe"), directory)
    config = directory / "tigervncs.json"
    config.write_text(json.dumps({"schemaVersion": 1, "viewer": {}, "connections": []}))
    env = os.environ.copy()
    env.update(VNC_TEST_ADDRESS="127.0.0.1::5909", VNC_USERNAME=USERNAME, VNC_PASSWORD=PASSWORD)
    subprocess.run([str(directory / "connection_fixture.exe")], env=env, capture_output=True, check=True, timeout=5)
    document = json.loads(config.read_text())
    document["viewer"]["PlinkExecutable"] = r"C:\Program Files\PuTTY\plink.exe"
    computer = document["connections"][0]
    results = []
    for action, fragment, accepted in (
        ("Power Off", "/sbin/shutdown -h now", True),
        ("Reboot", "/sbin/shutdown -r now", True),
        ("Force Power Off", "/sbin/halt -q", True),
        ("Force Reboot", "/sbin/reboot -q", True),
        ("Reboot", "/sbin/shutdown -r now", False),
    ):
        # A different, uncached key on every connection must be accepted.
        key = paramiko.RSAKey.generate(2048)
        config.write_text(json.dumps(document))
        before_keys = host_keys()
        before_config = config.read_bytes()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 22))
        listener.listen(1)
        listener.settimeout(8)
        server = Server()
        errors = []
        stdin_matches = []

        def serve():
            transport = None
            try:
                # Discovery must stop at host-key verification, without ever
                # sending the saved username/password for authentication.
                connection, _ = listener.accept()
                discovery = Server()
                scan = paramiko.Transport(connection)
                scan.add_server_key(key)
                try:
                    scan.start_server(server=discovery)
                    scan.accept(5)
                except (EOFError, ConnectionResetError):
                    pass
                finally:
                    scan.close()
                assert not discovery.authenticated and discovery.command is None
                connection, _ = listener.accept()
                transport = paramiko.Transport(connection)
                transport.add_server_key(key)
                transport.start_server(server=server)
                channel = transport.accept(5)
                assert channel is not None and server.ready.wait(5)
                channel.settimeout(5)
                data = b""
                while b"\n" not in data:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                stdin_matches.append(data == (PASSWORD + "\n").encode())
                assert fragment in server.command and "sudo -S" in server.command
                # Parse syntax only. The shutdown/reboot script is NEVER run.
                parsed = subprocess.run([str(ROOT / ".tools/msys64/usr/bin/bash.exe"),
                                         "--noprofile", "--norc", "-n", "-c", server.command],
                                        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                assert parsed.returncode == 0
                if accepted:
                    marker = re.search(r"TIGERVNCS_ACCEPTED_[0-9a-f]{32}", server.command).group()
                    channel.sendall((marker + "\n").encode())
                else:
                    channel.send_stderr(b"Synthetic sudo rejection; intentionally hidden\n")
                channel.send_exit_status(0 if accepted else 1)
                channel.close()
            except (EOFError, ConnectionResetError):
                pass  # The acknowledged client can close immediately.
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                if transport:
                    transport.close()
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = subprocess.run([str(directory / "power_tools_probe.exe"), str(config), computer["id"], action],
                                capture_output=True, timeout=19)
        thread.join(2)
        assert not thread.is_alive() and not errors, (errors, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
        assert server.authenticated and stdin_matches == [True]
        assert (result.returncode == 0) == accepted, (action, result.returncode)
        assert host_keys() == before_keys, "PuTTY host keys were persisted"
        assert config.read_bytes() == before_config, "SSH modified the JSON config"
        results.append({"action": action, "expectedAccepted": accepted, "passed": True})
    print(json.dumps({"realPlink": True, "loopbackOnly": True,
                      "powerCommandsExecuted": False, "changingHostKeysAccepted": True,
                      "hostKeysNotPersisted": True, "cases": results}, indent=2))


if __name__ == "__main__":
    main()
