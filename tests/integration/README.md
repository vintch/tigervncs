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
