# Shelly Plug Power On

Edit a saved computer and choose **Power On: Shelly Plug**, then enter the
plug's IP address, login and password. Leave the password field blank when
editing to retain the existing secret. Choosing **None** disables Power On
without deleting the saved plug settings. These settings are independent of
the computer's SSH credentials, VPN association and ping status.

**Options > Tools > Shelly Plug delay (s)** sets the pause between off and on.
The default is 15 seconds; the supported range is 1–3600 seconds. Everything
is saved in `tigervncs.json` beside the executable. The plug password uses
AES-256-GCM with the same Windows-account-protected key as VNC passwords,
but with a separate authenticated context so the two cannot be interchanged.

**Tools > Power On** always asks for confirmation. A computer currently
marked green by the existing presence monitor requires an additional warning
confirmation; the command does not trigger another ping. The modal progress
window blocks the main window while the plug is off. **Cancel**, including
closing that window, skips the remaining delay and requests power restoration.
If an off request is still in progress, it finishes before restoration is
sent, preventing a late off request from reversing the cancellation.

Commands run on a background worker with bounded HTTP timeouts. Failed off
requests also trigger restoration because a device might have applied the
command before its response was lost. Restoration is retried once on failure;
the dialog reports any command failure. Normal completion is silent.

The local `/relay/0` API supports the tested Gen1 Shelly Plug S. Basic and
SHA-256 Digest authentication are supported. The off command also sets a
one-shot device timer so the plug can restore power if the viewer closes or
loses connectivity. A response that does not confirm this timer causes an
immediate restoration attempt. The final on command clears the timer.
HTTP proxies and redirects are disabled, and credentials never appear in
URLs or external process arguments.

API references:

- [Shelly Gen1 HTTP API](https://shelly-api-docs.shelly.cloud/gen1/)
- [Shelly Gen2 authentication](https://shelly-api-docs.shelly.cloud/gen2/General/Authentication/)

The Mac must be configured to start when power returns. Shut down a running
computer before using a power cycle; the green warning is informational and
does not shut it down automatically.

## Plus Plug S v2 and hostnames

Plug addresses accept IP addresses or DNS names, optionally with a port. Plus
Plug S v2 (Gen2) uses Switch.Set RPC when legacy relay commands are rejected.
The off command includes toggle_after as a device-side restoration timer.
The on command omits the optional timer because older firmware rejects zero.
HTTP Digest SHA-256 authentication uses username admin and the device password;
whitespace in authentication challenges is accepted. Redirects remain blocked.

Reference: https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Switch/
