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
