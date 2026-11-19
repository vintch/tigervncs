# Connection manager checks on Windows

`build-windows.ps1 -RunTests` runs the store, credential vault and actual FLTK
tree regression tests, alongside the existing viewer tests. Tree tests rebuild
from disk repeatedly with nested folders; this covers the null-root crash
after adding the first folder or restarting with saved folders.

For interactive tests without contacting a VNC server, explicitly build the
`vncviewer_manager_test` and `connection_fixture` CMake targets. Copy both exes
into an isolated directory under `build/`, never beside the user's settings.
Set process environment variables `VNC_TEST_ADDRESS`, `VNC_USERNAME` and
`VNC_PASSWORD` to synthetic test values and run `connection_fixture` there.
It creates encrypted sample entries, including nested folders. Start
`vncviewer_manager_test` with the same environment.

The test viewer uses the production dialog, including its selection, editing,
Connect and double-click handlers. It replaces the VNC main loop with a stub
that checks the active address, username and decrypted password. The result
beside the exe is `tigervncs.json.stub-result`, containing booleans only.
Require `passed: true`, then repeat for the other connection gesture.

Also check folder creation, nested folder creation, renaming both entry types,
collapse/reopen, and restart with both expansion states. Deletion, invalid
parents, cycles, password replacement/removal and metadata preservation are
covered by the automated store tests.

The stub is compiled only into the explicit test target. Production
`dist/TigerVNCs.exe` uses the normal VNC connection path. Do not distribute the
test executable or include test credentials/configurations in Git.

For connection recovery, explicitly build `vncviewer_lifecycle_test` and run
`python tests/integration/session_lifecycle.py <path-to-test-exe>`. This uses
real viewer sockets and handshake processing against loopback-only fake RFB
servers. Only error-dialog decisions and the final return-to-main-window are
stubbed. It verifies refused connections, early server drops, two four-second
handshake timeouts with Retry, and an established session lasting beyond four
seconds before dropping. No real VNC computers are contacted. JSON event logs
and the aggregate result are saved under `build/`.

Presence scheduling, hysteresis, cancellation and stale-result handling are
tested with a deterministic fake transport in the unit suite. The store/tree
tests cover mixed sibling order, both disabled boundaries and nested folder
visibility after reload.

For explicit ICMP checks, build `presence_probe`. Pass a UTF-8 JSON fixture
containing `{"targets":[{"id":"a","address":"127.0.0.1"}]}`. It runs the
production scheduler/Windows backend for 15 seconds and prints send/completion
events plus final online states. Include only the intended test targets, with
no credential fields. Verify at least 1000 ms between consecutive send events
and at least 3000 ms between sends for each ID. Interactive context-menu tests
should use a viewer/configuration copy under `build/` to preserve user data.

For explicitly authorized live Apple checks, build `apple_session_probe` and
pass a config file path, saved computer ID and current-screen or user-session.
It uses that profile's encrypted credentials and production CConnection code,
then exits after decoding one complete framebuffer update. It sends no keyboard
or pointer input and stores no image or plaintext credentials. Use a supported
reachable Mac and require sessionGranted=true and framebufferDecoded=true.

The GUI stub also accepts VNC_TEST_SESSION_MODE (current-screen/user-session)
and records sessionModeMatches. Use synthetic credentials to verify both the
saved editor preference and context-menu overrides without contacting a Mac.

For Shelly HTTP integration, build `shelly_power_probe` explicitly and run
`python tests/integration/shelly_http_test.py <path-to-probe>`. Loopback mock
plugs verify Basic and SHA-256 Digest authentication, the device-side backup
timer, cancellation, failed commands, and blocked redirects. Passwords are
supplied through standard input and saved encrypted in temporary fixtures.
No real plugs are contacted by this script.

Interactive checks use an isolated viewer and JSON under `build/`. Verify
Power On is disabled for None, and works independently of SSH availability.
For Shelly Plug, check IP/login/password fields, password retention after
editing, the Tools delay preference, both confirmations for a cached green
computer, and Cancel restoring power while the main window stays blocked.
Live outlet control requires explicit authorization. Shut down an online Mac
through SSH before cutting its outlet. Always leave the plug switched on.

The `rdpclient` unit target launches itself as a non-networking mstsc substitute
to verify the process lifetime, temporary credential handoff and restoration.
It also checks protocol defaults, port syntax, endpoint binding and restoration
of the native password/certificate prompt flags without changing other settings.
Recovery tests leave a persisted snapshot behind to simulate interruption,
then verify manual restoration and recovery before the next connection. They
use isolated native-preference files and JSON, never the user's Default.rdp.
For explicitly authorized live RDP checks, build `rdp_client_probe`. Its `seed`
operation takes a config path, host and username; supply the password through
standard input, never command-line arguments. Then `connect <config>` runs the
production launcher. Use an isolated viewer/config under `build/` to verify
Connect and double-click, hidden/restored manager state, and disabled macOS
session options. Tests must not send input or execute commands on the remote
desktop; disconnect by closing the local client or terminating its test PID.

Options / RDP exposes startup dimensions and Restore default RDP settings.
Verify Set initial RDP window size is off by default, disables both dimension
inputs when off, and retains their values while toggled. The native launcher
must omit /w and /h when off and include both when on. The unit suite checks
both argument paths; the portable-settings check covers persistence.
The restore action changes native prompt preferences immediately; test its
backend using isolated fixtures. Options / Input exposes Disable local mouse
cursor. The server-provided local cursor image and hotspot stay unscaled at
all framebuffer zoom levels; only pointer coordinates use the desktop transform.
The local cursor hiding option does not remove a cursor baked into server pixels.
