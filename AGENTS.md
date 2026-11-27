# TigerVNCs fork workflow

- The fork revision is defined in VERSION_TIGERVNCS (currently 1.4).
- Increase the minor integer once for each new feature: 1.9, 1.10, 1.11, etc.
  Do not change the major integer without the user's explicit agreement.
  Rebuilding the same feature does not increment its revision.
- Final Windows releases are built with build-windows.ps1. It copies only
  TigerVNCs.exe into C:\SW\TigerVNCs, replacing the existing executable.
- Never modify, replace, migrate or copy configuration files in C:\SW\TigerVNCs.
  Keep user settings out of version control and use isolated build/ fixtures.
- Commit major changes locally. Push only when explicitly requested.
