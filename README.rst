TigerVNCs
=========

TigerVNCs is a fork of `TigerVNC <https://github.com/TigerVNC/tigervnc>`_
focused on a portable Windows viewer for macOS Screen Sharing and everyday
remote administration. The Windows application is named **TigerVNCs.exe**.
Its interface is in English. The original TigerVNC sources, licensing and
acknowledgements are retained below.

Features added in this fork
--------------------------

* **Fit the remote desktop to the window.** Toggle "Scale desktop to window"
  in the session menu (Ctrl+Alt+M with the default shortcut modifiers) or
  Options / Display. Aspect ratio and mouse coordinates are handled together;
  the local cursor keeps its original size. Options / Input can hide the local
  cursor with "Disable local mouse cursor". Preferences survive restarts.
* **Connection manager with nested folders.** Save computer addresses,
  usernames and passwords; select an entry to fill the server field, or
  double-click to connect. The context menu provides creation, editing,
  deletion and sibling reordering. List visibility, folder expansion and
  ordering are remembered.
* **VNC and RDP connection types.** Each computer can use the built-in VNC
  viewer or Windows Remote Desktop (mstsc). RDP receives the saved server,
  username and password without putting the password in command-line arguments.
  The manager hides while mstsc runs and returns when it exits. The client
  starts without an RDP file, avoiding the unsigned-connection confirmation.
  Password and certificate prompts are suppressed using temporary native
  client settings, which are restored when it exits. Options / RDP sets the
  optional initial window dimensions with "Set initial RDP window size"
  (off by default) and provides "Restore default RDP settings".
  Recovery values are saved in JSON so native settings can be restored after
  an interrupted session.
* **Protected saved passwords.** VNC and Shelly Plug passwords use
  AES-256-GCM with a key protected by Windows DPAPI for the current account.
  Copying the configuration alone to another account or computer does not
  make those passwords usable there.
* **macOS compatibility and session selection.** Apple Screen Sharing
  connections use compatible encodings and RGB565 for reduced color depth.
  Choose "Current screen" or "User session" per computer, or override it
  for one connection through "Connect to". Saved credentials can be used
  in both modes; User session requires a saved username and password.
* **Persistent compression controls.** Save automatic/manual encoding,
  color depth, compression level and JPEG quality preferences. Apple
  connections fall back to compatible lossless encodings when necessary;
  JPEG quality only applies when the server sends JPEG-compressed images.
* **Connection recovery.** Initial failures offer Retry / Cancel. Sessions
  recover automatically from network errors or response stalls while
  retaining the desktop window and last image. Leaving a session returns
  to the connection window. Establishment and active-session response
  timeouts are separately configurable, both defaulting to four seconds.
* **Asynchronous reachability indicators.** Visible computers are monitored
  with staggered ICMP requests: green after a reply, blue after two failures.
  Ping timing and enablement are configurable; monitoring pauses during VNC
  sessions and recovery. Ping status does not gate SSH or VPN commands.
* **Manual Wireguard and OpenVPN Connect controls.** Associate a VPN profile
  with each computer and use the grey/amber/green VPN button to connect or
  disconnect. Selecting a computer never connects a VPN automatically.
  Wireguard elevation is retained by a restricted helper until TigerVNCs
  closes. OpenVPN status combines adapter state with its connection log.
* **SSH power tools for macOS.** Tools provides Power Off, Reboot, Force
  Power Off and Force Reboot through PuTTY plink, with confirmation and a
  hidden background invocation using the computer's saved credentials.
  These commands require plink, SSH access and suitable administrator rights.
* **Shelly Plug Power On.** Supports original plugs and Plus Plug S v2 (Gen2).
  Configure a plug IP address or hostname and separate login
  credentials, then cycle its outlet through Tools / Power On. The delay
  defaults to 15 seconds and is configurable in Options / Tools. A modal
  progress window includes Cancel, which requests immediate restoration.
  A cached green computer requires an additional confirmation. A device-side
  backup timer also restores power if the viewer loses connectivity.
* **One portable configuration file.** Preferences, history, saved computers,
  encrypted credentials, VPN associations and folder state live in
  ``tigervncs.json`` beside the actual executable. Legacy registry preferences
  are imported once; new preferences are saved to JSON.
* **Standalone Windows build.** A repository-local build script produces a
  single Windows x64 executable without additional non-system runtime DLLs.

Getting started
---------------

Build the viewer as described below, then run ``dist/TigerVNCs.exe`` from a
writable directory. **Computers** opens the saved connection list. Right-click
the list to add computers or folders. **Options** contains compression,
display, network, VPN and power-tool settings.

For a Windows Remote Desktop connection, choose **Connection: RDP** in the
computer editor. To specify its startup dimensions, enable **Set initial RDP
window size** under **Options / RDP**. Leaving it unchecked uses the local
display size, ignores cached small desktop dimensions and enables resizing
with content scaling. Native display preferences are restored after exit;
your saved width and height remain available for later use.

Optional tools are installed separately: PuTTY plink for SSH actions,
Wireguard and/or OpenVPN Connect for VPN control, and a compatible Shelly
Plug for outlet control. The Mac must be configured to start when power
returns for Shelly Power On to start it.

SSH power actions automatically accept the server's currently presented host
key without saving it; they do not verify its identity against a trusted key.
Shut down a running computer before cycling its outlet. See the
`viewer guide <doc/tigervncs-portable.txt>`_ and
`Shelly Plug guide <doc/shelly-power.md>`_ for behavior and requirements.

Building on Windows
-------------------

From PowerShell in a checkout, run::

    .\build-windows.ps1 -Bootstrap -RunTests

The first build downloads MSYS2 and installs the toolchain and dependencies
inside ``.tools`` in the checkout. It needs network access and a Windows short
path without spaces (the script checks this). Subsequent builds use::

    .\build-windows.ps1 -RunTests

Output: ``dist/TigerVNCs.exe`` and ``dist/build-info.json`` containing the
source revision, checksum and dependency information. The script excludes
``.tools``, ``build`` and ``dist`` from commits. Keep personal
``tigervncs.json`` files out of version control.

The Windows unit suite includes connection-type and RDP launch/cleanup tests.
Additional isolated
integration checks are documented in `tests/integration/README.md
<tests/integration/README.md>`_. General upstream build instructions remain in
`BUILDING.txt <BUILDING.txt>`_.


About upstream TigerVNC
======================

Virtual Network Computing (VNC) is a remote display system which allows you to
view and interact with a virtual desktop environment that is running on another
computer on the network.  Using VNC, you can run graphical applications on a
remote machine and send only the display from these applications to your local
machine.  VNC is platform-independent and supports a wide variety of operating
systems and architectures as both servers and clients.

TigerVNC is a high-speed version of VNC based on the RealVNC 4 and X.org code
bases.  TigerVNC started as a next-generation development effort for TightVNC
on Unix and Linux platforms, but it split from its parent project in early 2009
so that TightVNC could focus on Windows platforms.  TigerVNC supports a variant
of Tight encoding that is greatly accelerated by the use of the libjpeg-turbo
JPEG codec.


Legal
=====

Incomplete and generally out of date copyright list::

        Copyright (C) 1999 AT&T Laboratories Cambridge
        Copyright (C) 2002-2005 RealVNC Ltd.
        Copyright (C) 2000-2006 TightVNC Group
        Copyright (C) 2005-2006 Martin Koegler
        Copyright (C) 2005-2006 Sun Microsystems, Inc.
        Copyright (C) 2006 OCCAM Financial Technology
        Copyright (C) 2000-2008 Constantin Kaplinsky
        Copyright (C) 2004-2017 Peter Astrand for Cendio AB
        Copyright (C) 2010 Antoine Martin
        Copyright (C) 2010 m-privacy GmbH
        Copyright (C) 2009-2011 D. R. Commander
        Copyright (C) 2009-2011 Pierre Ossman for Cendio AB
        Copyright (C) 2004, 2009-2011 Red Hat, Inc.
        Copyright (C) 2009-2026 TigerVNC team
        All Rights Reserved.

This software is distributed under the GNU General Public Licence as published
by the Free Software Foundation.  See the file LICENCE.TXT for the conditions
under which this software is made available.  TigerVNC also contains code from
other sources.  See the Acknowledgements section below, and the individual
source files, for details of the conditions under which they are made
available.


All Platforms
=============

All versions of TigerVNC contain the following programs:

* vncviewer - the cross-platform TigerVNC Viewer, written using FLTK.
              vncviewer connects to a VNC server and allows you to interact
              with the remote desktop being displayed by the VNC server.  The
              VNC server can be running on a Windows or a Unix/Linux machine.


Windows-specific
================

The Windows version of TigerVNC contains the following programs:

* winvnc - the TigerVNC server for Windows.  winvnc allows a Windows desktop to
           be accessed remotely using a VNC viewer.

WARNING: winvnc is currently unmaintained and and may not function correctly.

winvnc may not work if the Fast user switching or Remote desktop features are
in use.


Unix/Linux-specific (not Mac)
=============================

The Unix/Linux version of TigerVNC contains the following programs:

* Xvnc - the TigerVNC server for Unix.  Xvnc is both a VNC server and an X
         server with a "virtual" framebuffer.  You should normally use the
         vncserver service to start Xvnc.

* vncpasswd - a program which allows you to change the VNC password used to
              access your VNC server sessions (assuming that VNC authentication
              is being used.) This command must be run to set a password before
              using VNC authentication with any of the servers or services.

* vncconfig - a program which is used to configure and control a running
              instance of Xvnc.

* x0vncserver - an inefficient VNC server which continuously polls any X
                display, allowing it to be controlled via VNC.  It is intended
                mainly as a demonstration of a simple VNC server.

* w0vncserver - a VNC server for Wayland compositors which gives control
                over your local Wayland session.

It also contains the following systemd service:

* vncserver@.service - a service to start a user session with Xvnc and one of
                       the desktop environments available on the system.

ACKNOWLEDGEMENTS
================

This distribution contains public domain DES software by Richard Outerbridge.
This is:

    Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
    (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.


This distribution contains software from the X Window System.  This is:

 Copyright 1987, 1988, 1998  The Open Group
 
 Permission to use, copy, modify, distribute, and sell this software and its
 documentation for any purpose is hereby granted without fee, provided that
 the above copyright notice appear in all copies and that both that
 copyright notice and this permission notice appear in supporting
 documentation.
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
 Except as contained in this notice, the name of The Open Group shall not be
 used in advertising or otherwise to promote the sale, use or other dealings
 in this Software without prior written authorization from The Open Group.
 
 
 Copyright 1987, 1988 by Digital Equipment Corporation, Maynard, Massachusetts.
 
                         All Rights Reserved
 
 Permission to use, copy, modify, and distribute this software and its 
 documentation for any purpose and without fee is hereby granted, 
 provided that the above copyright notice appear in all copies and that
 both that copyright notice and this permission notice appear in 
 supporting documentation, and that the name of Digital not be
 used in advertising or publicity pertaining to distribution of the
 software without specific, written prior permission.  
 
 DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 SOFTWARE.
