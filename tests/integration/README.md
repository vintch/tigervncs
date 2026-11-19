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
`dist/vncviewer.exe` uses the normal VNC connection path. Do not distribute the
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
