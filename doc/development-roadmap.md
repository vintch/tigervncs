# Next change: VPN integration

Requested by the repository owner on 2026-11-18; intentionally deferred until
the connection manager is complete and verified.

- Each computer will have an optional VPN type (WireGuard or OpenVPN) and
  the name of its VPN profile.
- Detect whether the required VPN is connected.
- Allow connecting and disconnecting VPN profiles.
- Selecting a computer and connecting should activate its required VPN before
  starting the VNC connection.
- Preserve all existing connection fields, encrypted credentials, folders,
  viewer settings and unknown custom fields when extending the JSON schema.

The present implementation does not control VPNs. Determine the installed
clients and their supported interfaces when starting that work.
