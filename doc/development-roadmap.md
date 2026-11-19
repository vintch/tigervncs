# TigerVNCs implementation status

The Windows viewer additions requested for mod 1.0 are implemented:

- Window-fit desktop scaling and matching pointer coordinates.
- Saved computers in nested folders, context-menu editing and reordering,
  persistent folder/list state and asynchronous ICMP indicators.
- AES-256-GCM saved credentials protected by the Windows account.
- macOS Current screen / User session selection and reduced-color compatibility.
- Configurable timeouts, silent session recovery and return to the main window.
- One portable `tigervncs.json` for all application settings and saved computers.
- Manual VPN associations, status and connect/disconnect controls for Wireguard
  and OpenVPN Connect, with session-long Wireguard elevation when requested.
- Hidden plink SSH shutdown/reboot commands with confirmation.
- Shelly Plug outlet cycling with encrypted credentials, configurable delay,
  confirmations, modal progress, cancellation and device-side restoration timer.
- Standalone `TigerVNCs.exe` Windows build and regression/integration checks.
- Per-computer VNC/RDP selection and external mstsc lifecycle handling.
- Configurable RDP startup dimensions, durable prompt-settings recovery and
  a manual restore button; normal-size VNC cursors with optional local hiding.

VPN control is intentionally independent of VNC connections. Selecting a
computer, starting the viewer or clicking Connect does not activate its VPN.
The earlier proposal to connect VPNs automatically has been superseded by this
manual behavior.

Future changes should preserve existing connection fields, encrypted secrets,
folder state, preferences and unknown custom JSON fields. Keep reachability
informational, perform network work away from the UI, and retain the main
window after failed operations. No further feature is scheduled here.

See [the viewer guide](tigervncs-portable.txt),
[Shelly Plug guide](shelly-power.md) and
[integration checks](../tests/integration/README.md) for current behavior.
