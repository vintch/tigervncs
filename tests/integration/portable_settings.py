"""Check portable preference migration without modifying the user's registry."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import winreg

ROOT = Path(__file__).resolve().parents[2]


def registry_snapshot(path):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    with key:
        children, values, _ = winreg.QueryInfoKey(key)
        return (
            [winreg.EnumValue(key, i) for i in range(values)],
            [(name, registry_snapshot(path + "\\" + name))
             for name in (winreg.EnumKey(key, i) for i in range(children))],
        )


def run(executable):
    directory = ROOT / "build" / "portable settings fixture"
    directory.mkdir(parents=True, exist_ok=True)
    viewer = directory / "TigerVNCs.exe"
    shutil.copy2(executable, viewer)
    config = directory / "tigervncs.json"
    before_registry = registry_snapshot(r"Software\TigerVNC\vncviewer")
    document = {
        "schemaVersion": 1,
        "viewer": {"ViewOnly": True, "ConnectTimeoutSeconds": 7,
                   "SessionTimeoutSeconds": 13, "PingEnabled": False,
                   "RdpForceWindowSize": True, "RdpWindowWidth": 1600, "RdpWindowHeight": 900,
                   "DisableLocalMouseCursor": True,
                   "PingPeriodSeconds": 11, "PingMinimumIntervalSeconds": 2,
                   "WireGuardConfigurationDirectory": r"C:\VPN test profiles",
                   "OpenVPNConnectExecutable": r"C:\VPN test client\client.exe"},
        "connections": [{"id": "fixture", "customField": "preserve"}],
        "futureSection": {"custom": True},
        "history": ["localhost::5909"],
        "lastServer": "localhost::5909",
    }
    config.write_text(json.dumps(document), encoding="utf-8")
    for attempt in range(2):
        result = subprocess.run([str(viewer), "--version"], cwd=ROOT,
                                capture_output=True, timeout=8)
        assert result.returncode == 0, result.returncode
        saved = json.loads(config.read_text(encoding="utf-8"))
        assert saved["settingsMigrated"] is True
        for name, value in document["viewer"].items():
            assert saved["viewer"][name] == value, name
        for name in ("connections", "futureSection", "history", "lastServer"):
            assert saved[name] == document[name], name
        assert len(saved["viewer"]) > 30
    assert registry_snapshot(r"Software\TigerVNC\vncviewer") == before_registry
    assert sorted(p.name for p in directory.iterdir()) == ["TigerVNCs.exe", "tigervncs.json"]
    return {"portableSettings": True, "registryUnchanged": True,
            "unknownFieldsPreserved": True, "workingDirectoryIndependent": True,
            "preferenceCount": len(saved["viewer"])}


if __name__ == "__main__":
    print(json.dumps(run(Path(sys.argv[1]).resolve()), indent=2))
