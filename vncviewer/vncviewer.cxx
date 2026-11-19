/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright 2011-2024 Pierre Ossman <ossman@cendio.se> for Cendio AB
 * Copyright (C) 2011 D. R. Commander.  All Rights Reserved.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef WIN32
#include <core/winerrno.h>
#include <direct.h>
#endif

#include <core/Exception.h>
#include <core/Logger_stdio.h>
#include <core/LogWriter.h>
#include <core/Timer.h>
#include <core/string.h>

#ifdef HAVE_GNUTLS
#include <rfb/CSecurityTLS.h>
#endif

#include <core/i18n.h>
#include <core/xdgdirs.h>

#include <network/TcpSocket.h>

#include <FL/Fl_File_Chooser.H>
#include <FL/Fl_PNG_Image.H>
#include <FL/Fl_Sys_Menu_Bar.H>
#include <FL/fl_ask.H>

#include "fltk/Fl_Password_Input.h"
#include "fltk/theme.h"
#include "fltk/util.h"
#include "parameters.h"
#include "PortableSettings.h"
#include "CConn.h"
#include "DesktopWindow.h"
#include "NetworkSettings.h"
#include "VpnProfiles.h"
#include "ServerDialog.h"
#include "touch.h"
#include "vncviewer.h"

#ifdef WIN32
#include "resource.h"
#include "win32.h"
#endif

static core::LogWriter vlog("main");

static std::string vncServerName;

static const char *argv0 = nullptr;

static bool inMainloop = false;
static bool exitMainloop = false;
static std::string exitError;
static bool fatalError = false;
static bool reconnectRequested = false;
static bool userDisconnected = false;

static const char *about_text()
{
  static char buffer[1024];

  // This is used in multiple places with potentially different
  // encodings, so we need to make sure we get a fresh string every
  // time.
  snprintf(buffer, sizeof(buffer),
           _("TigerVNCs v%s\n"
             "Skalierung und Computerliste mod, ver 1.0\n"
             "Built on: %s\n"
             "Copyright (C) 1999-%d TigerVNC team and many others (see README.rst)\n"
             "See https://www.tigervnc.org for information on TigerVNCs."),
           PACKAGE_VERSION, BUILD_TIMESTAMP, 2026);

  return buffer;
}


void abort_vncviewer(const char *error, ...)
{
  fatalError = true;

  // Prioritise the first error we get as that is probably the most
  // relevant one.
  if (exitError.empty()) {
    va_list ap;

    va_start(ap, error);
    exitError = core::vformat(error, ap);
    va_end(ap);
  }

  if (inMainloop)
    exitMainloop = true;
  else {
    // We're early in the startup. Assume we can just exit().
    if (alertOnFatalError && !exitError.empty())
      fl_alert("%s", exitError.c_str());
    exit(EXIT_FAILURE);
  }
}

void abort_connection(const char *error, ...)
{
  assert(inMainloop);

  // Prioritise the first error we get as that is probably the most
  // relevant one.
  if (exitError.empty()) {
    va_list ap;

    va_start(ap, error);
    exitError = core::vformat(error, ap);
    va_end(ap);
  }

  exitMainloop = true;
}

void abort_connection_unexpected(const std::exception &e)
{
  abort_connection(_("An unexpected error occurred when communicating "
                     "with the server:\n\n%s"), e.what());
}

void disconnect()
{
  userDisconnected = true;
  reconnectRequested = false;
  exitError.clear();
  exitMainloop = true;
}

void reconnect_connection(const char* error)
{
  if (userDisconnected) return;
  abort_connection("%s", error);
  reconnectRequested = true;
}

void about_vncviewer()
{
  fl_message_title(_("About TigerVNCs"));
  fl_message("%s", about_text());
}

static void mainloop(const char* vncserver, network::Socket* sock)
{
  DesktopWindow* retained = nullptr;
  ConnectionCredentials credentials;
  bool automatic = false;
  while (true) {
    CConn *cc = nullptr;

    exitMainloop = false;
    exitError.clear();
    fatalError = false;
    reconnectRequested = false;
    userDisconnected = false;

    try {
      cc = new CConn(retained, automatic ? &credentials : nullptr);
      retained = nullptr;
      cc->connect(vncserver, sock);
    } catch (std::exception& e) {
      abort_connection_unexpected(e);
    }

    while (!exitMainloop) {
      int next_timer;

      next_timer = core::Timer::checkTimeouts();
      if (exitMainloop) break;
      if (next_timer < 0)
        next_timer = INT_MAX;

      if (Fl::wait((double)next_timer / 1000.0) < 0.0) {
        abort_connection(_("The window event loop failed."));
        break;
      }
    }

    bool established = cc && cc->state() == rfb::CConnection::RFBSTATE_NORMAL;
    if (reconnectRequested && !userDisconnected && sock == nullptr && cc && (established || automatic)) {
      credentials = cc->credentialsForReconnect();
      retained = cc->releaseDesktopForReconnect();
      delete cc;
      vlog.info("Automatically reconnecting: %s", exitError.c_str());
      // Yield between failed attempts so Close remains responsive. Never
      // recreate the dialog or window, or ask for credentials during recovery.
      if (automatic) Fl::wait(0.25);
      if (userDisconnected) { delete retained; retained = nullptr; break; }
      automatic = true;
      continue;
    }
    delete cc;
    delete retained; retained = nullptr;

    if (automatic) break;

    if (established) {
      // A finished session returns directly to the connection manager.
      if (!exitError.empty()) vlog.info("%s", exitError.c_str());
      exitError.clear();
      break;
    }

    if (exitError.empty())
      break;

#ifdef TIGERVNCS_SESSION_TEST
    extern int connectionErrorStub(const std::string&);
    int ret = connectionErrorStub(exitError);
#else
    int ret = fl_choice("%s", _("Cancel"), _("Retry"), nullptr, exitError.c_str());
#endif
    exitError.clear();
    fatalError = false;
    // An accepted reverse socket has been destroyed with CConn. Return to
    // the server dialog rather than attempting to reuse that socket.
    if (ret == 1 && sock == nullptr) continue;
    break;
  }
}

#ifdef __APPLE__
static void about_callback(Fl_Widget* /*widget*/, void* /*data*/)
{
  about_vncviewer();
}

static void new_connection_cb(Fl_Widget* /*widget*/, void* /*data*/)
{
  const char *argv[2];
  pid_t pid;

  pid = fork();
  if (pid == -1) {
    vlog.error(_("Error starting new connection: %s"), strerror(errno));
    return;
  }

  if (pid != 0)
    return;

  argv[0] = argv0;
  argv[1] = nullptr;

  execvp(argv[0], (char * const *)argv);

  vlog.error(_("Error starting new connection: %s"), strerror(errno));
  _exit(1);
}
#endif

static void CleanupSignalHandler(int sig)
{
  // CleanupSignalHandler allows C++ object cleanup to happen because it calls
  // exit() rather than the default which is to abort.
  vlog.info(_("Termination signal %d has been received. TigerVNCs will now exit."), sig);
  exit(1);
}

static void init_fltk()
{
  // Adjust look of FLTK
  init_theme();

  // Proper Gnome Shell integration requires that we set a sensible
  // WM_CLASS for the window.
  Fl_Window::default_xclass("vncviewer");

  // Set the default icon for all windows.
#ifdef WIN32
  HICON lg, sm;

  lg = (HICON)LoadImage(GetModuleHandle(nullptr),
                        MAKEINTRESOURCE(IDI_ICON),
                        IMAGE_ICON, GetSystemMetrics(SM_CXICON),
                        GetSystemMetrics(SM_CYICON),
                        LR_DEFAULTCOLOR | LR_SHARED);
  sm = (HICON)LoadImage(GetModuleHandle(nullptr),
                        MAKEINTRESOURCE(IDI_ICON),
                        IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                        GetSystemMetrics(SM_CYSMICON),
                        LR_DEFAULTCOLOR | LR_SHARED);

  Fl_Window::default_icons(lg, sm);
#elif ! defined(__APPLE__)
  const int icon_sizes[] = {128, 64, 48, 32, 24, 22, 16};

  Fl_PNG_Image *icons[sizeof(icon_sizes)/sizeof(icon_sizes[0])];
  int count;

  count = 0;

  // FIXME: Follow icon theme specification
  for (int icon_size : icon_sizes) {
      char icon_path[PATH_MAX];
      bool exists;

      sprintf(icon_path, "%s/icons/hicolor/%dx%d/apps/tigervnc.png",
              CMAKE_INSTALL_FULL_DATADIR, icon_size, icon_size);

      struct stat st;
      if (stat(icon_path, &st) != 0)
        exists = false;
      else
        exists = true;

      if (exists) {
          icons[count] = new Fl_PNG_Image(icon_path);
          if (icons[count]->w() == 0 ||
              icons[count]->h() == 0 ||
              icons[count]->d() != 4) {
              delete icons[count];
              continue;
          }

          count++;
      }
  }

  Fl_Window::default_icons((const Fl_RGB_Image**)icons, count);

  for (int i = 0;i < count;i++)
      delete icons[i];
#endif

  // Turn off the annoying behaviour where popups track the mouse.
  fl_message_hotspot(false);

  // Avoid empty titles for popups
  fl_message_title_default("TigerVNCs");

  // FLTK exposes these so that we can translate them.
  fl_no     = _("No");
  fl_yes    = _("Yes");
  fl_ok     = _("OK");
  fl_cancel = _("Cancel");
  fl_close  = _("Close");

  Fl_Password_Input::caps_warning_tooltip = _("Caps lock is active");

  Fl_File_Chooser::add_favorites_label = _("Add to Favorites");
  Fl_File_Chooser::all_files_label = _("All Files (*)");
  Fl_File_Chooser::custom_filter_label = _("Custom Filter");
  Fl_File_Chooser::existing_file_label = _("Please choose an existing file!");
  Fl_File_Chooser::favorites_label = _("Favorites");
  Fl_File_Chooser::filename_label = _("Filename:");
#ifdef WIN32
  Fl_File_Chooser::filesystems_label = _("My Computer");
#else
  Fl_File_Chooser::filesystems_label = _("File Systems");
#endif // WIN32
  Fl_File_Chooser::manage_favorites_label = _("Manage Favorites");
  Fl_File_Chooser::new_directory_label = _("New Directory?");
  Fl_File_Chooser::new_directory_tooltip = _("Create a new directory.");
  Fl_File_Chooser::preview_label = _("Preview");
  Fl_File_Chooser::save_label = _("Save");
  Fl_File_Chooser::show_label = _("Show:");
  Fl_File_Chooser::hidden_label = _("Show hidden files");

#ifdef __APPLE__
  Fl_Mac_App_Menu::about = _("About TigerVNCs");
  Fl_Mac_App_Menu::print = ""; // Don't want the print item
  Fl_Mac_App_Menu::services = _("Services");
  Fl_Mac_App_Menu::hide = _("Hide TigerVNCs");
  Fl_Mac_App_Menu::hide_others = _("Hide others");
  Fl_Mac_App_Menu::show = _("Show all");
  Fl_Mac_App_Menu::quit = _("Quit TigerVNCs");

  fl_mac_set_about(about_callback, nullptr);

  Fl_Sys_Menu_Bar *menubar;
  menubar = new Fl_Sys_Menu_Bar(0, 0, 500, 25);
  // Fl_Sys_Menu_Bar overrides methods without them being virtual,
  // which means we cannot use our generic Fl_Menu_ helpers.
  menubar->add(
    fltk_menu_escape(C_("SysMenu|", "&File")).c_str(),
    0, nullptr, nullptr, FL_SUBMENU);
  menubar->insert(
    1, fltk_menu_escape(C_("SysMenu|File|", "&New connection")).c_str(),
    FL_COMMAND | 'n', new_connection_cb);
#endif
}

static void usage(const char *programName)
{
#ifdef WIN32
  // If we don't have a console then we need to create one for output
  if (GetConsoleWindow() == nullptr) {
    HANDLE handle;
    int fd;

    AllocConsole();

    handle = GetStdHandle(STD_ERROR_HANDLE);
    fd = _open_osfhandle((intptr_t)handle, O_TEXT);
    *stderr = *fdopen(fd, "w");
  }
#endif

#ifdef WIN32
  fprintf(stderr, _(
          "\n"
          "Usage: %s [parameters] [host][:displayNum]\n"
          "       %s [parameters] [host][::port]\n"
          "       %s [parameters] -listen [port]\n"
          "       %s [parameters] [.tigervnc file]\n"),
          programName, programName, programName, programName);
#else
  fprintf(stderr, _(
          "\n"
          "Usage: %s [parameters] [host][:displayNum]\n"
          "       %s [parameters] [host][::port]\n"
          "       %s [parameters] [unix socket]\n"
          "       %s [parameters] -listen [port]\n"
          "       %s [parameters] [.tigervnc file]\n"),
          programName, programName, programName, programName, programName);
#endif

#if !defined(WIN32) && !defined(__APPLE__)
  fprintf(stderr, _("\n"
          "Options:\n\n"
          "  -display Xdisplay  - Specifies the X display for the viewer window\n"
          "  -geometry geometry - Initial position of the main TigerVNCs window. See the\n"
          "                       man page for details.\n"));
#endif

  fprintf(stderr, _("\n"
          "Parameters can be turned on with -<param> or off with -<param>=0\n"
          "Parameters which take a value can be specified as "
          "-<param> <value>\n"
          "Other valid forms are <param>=<value> -<param>=<value> "
          "--<param>=<value>\n"
          "Parameter names are case-insensitive.  The parameters are:\n\n"));
  core::Configuration::listParams(79, 14);

#ifdef WIN32
  // Just wait for the user to kill the console window
  Sleep(INFINITE);
#endif

  exit(1);
}

static void
potentiallyLoadConfigurationFile(const char *filename)
{
  const bool hasPathSeparator = (strchr(filename, '/') != nullptr ||
                                 (strchr(filename, '\\')) != nullptr);

  if (hasPathSeparator) {
#ifndef WIN32
    struct stat sb;

    // This might be a UNIX socket, we need to check
    if (stat(filename, &sb) == -1) {
      // Some access problem; let loadViewerParameters() deal with it...
    } else {
      if ((sb.st_mode & S_IFMT) == S_IFSOCK)
        return;
    }
#endif

    try {
      // The server name might be empty, but we still need to clear it
      // so we don't try to connect to the filename
      vncServerName = loadViewerParameters(filename);
    } catch (std::exception& e) {
      vlog.error("%s", e.what());
      abort_vncviewer(_("Unable to load the specified configuration "
                        "file:\n\n%s"), e.what());
    }
  }
}

static void
create_base_dirs()
{
  const char *dir;

  dir = core::getvncconfigdir();
  if (dir == nullptr) {
    vlog.error(_("Could not determine VNC config directory path"));
    return;
  }

#ifndef WIN32
  const char *dotdir = strrchr(dir, '.');
  if (dotdir != nullptr && strcmp(dotdir, ".vnc") == 0)
    vlog.info(_("~/.vnc is deprecated, please consult 'man vncviewer' for paths to migrate to."));
#else
  const char *vncdir = strrchr(dir, '\\');
  if (vncdir != nullptr && strcmp(vncdir, "vnc") == 0)
    vlog.info(_("%%APPDATA%%\\vnc is deprecated, please switch to the %%APPDATA%%\\TigerVNCs location."));
#endif

  if (core::mkdir_p(dir, 0755) == -1) {
    if (errno != EEXIST)
      vlog.error(_("Could not create VNC config directory \"%s\": %s"),
                 dir, strerror(errno));
  }

  dir = core::getvncdatadir();
  if (dir == nullptr) {
    vlog.error(_("Could not determine VNC data directory path"));
    return;
  }

  if (core::mkdir_p(dir, 0755) == -1) {
    if (errno != EEXIST)
      vlog.error(_("Could not create VNC data directory \"%s\": %s"),
                 dir, strerror(errno));
  }

  dir = core::getvncstatedir();
  if (dir == nullptr) {
    vlog.error(_("Could not determine VNC state directory path"));
    return;
  }

  if (core::mkdir_p(dir, 0755) == -1) {
    if (errno != EEXIST)
      vlog.error(_("Could not create VNC state directory \"%s\": %s"),
                 dir, strerror(errno));
  }
}

#ifndef WIN32
static void
createTunnel(const char *gatewayHost, const char *remoteHost,
             int remotePort, int localPort)
{
  const char *cmd = getenv("VNC_VIA_CMD");
  char *cmd2, *percent;
  char lport[10], rport[10];
  sprintf(lport, "%d", localPort);
  sprintf(rport, "%d", remotePort);
  setenv("G", gatewayHost, 1);
  setenv("H", remoteHost, 1);
  setenv("R", rport, 1);
  setenv("L", lport, 1);
  if (!cmd)
    cmd = "/usr/bin/ssh -f -L \"$L\":\"$H\":\"$R\" -- \"$G\" sleep 20";
  /* Compatibility with TigerVNCs's method. */
  cmd2 = strdup(cmd);
  while ((percent = strchr(cmd2, '%')) != nullptr)
    *percent = '$';
  int res = system(cmd2);
  if (res != 0)
    vlog.error(_("Failed to create tunnel: '%s' returned %d"),
               cmd2, res);
  free(cmd2);
}

static void mktunnel()
{
  const char *gatewayHost;
  std::string remoteHost;
  int localPort = network::findFreeTcpPort();
  int remotePort;

  network::getHostAndPort(vncServerName.c_str(), &remoteHost, &remotePort);
  vncServerName = core::format("localhost::%d", localPort);
  gatewayHost = (const char*)via;
  createTunnel(gatewayHost, remoteHost.c_str(), remotePort, localPort);
}
#endif /* !WIN32 */

int main(int argc, char** argv)
{
  argv0 = argv[0];

  setlocale(LC_ALL, "");

  fprintf(stderr,"\n%s\n", about_text());

  core::initStdIOLoggers();
  // Portable mode does not create persistent logs.
  core::LogWriter::setLogParams("*:stderr:30");

#ifdef SIGHUP
  signal(SIGHUP, CleanupSignalHandler);
#endif
  signal(SIGINT, CleanupSignalHandler);
  signal(SIGTERM, CleanupSignalHandler);

  /* Load the default parameter settings */
  std::string defaultServerName;
  try {
    defaultServerName = loadViewerParameters(nullptr);
  } catch (std::exception& e) {
    vlog.error("%s", e.what());
  }

  try {
    loadPortableViewerParameters();
  } catch (const std::exception& e) {
    vlog.error("%s", e.what());
    fl_alert("Unable to load portable settings:\n%s", e.what());
  }


  for (int i = 1; i < argc;) {
    int ret;

    ret = core::Configuration::handleParamArg(argc, argv, i);
    if (ret > 0) {
      i += ret;
      continue;
    }

    if (strcmp(argv[i], "-h") == 0 ||
        strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
    }

    if (strcmp(argv[i], "-v") == 0 ||
        strcmp(argv[i], "--version") == 0) {
      /* We already print version on every start */
      return 0;
    }

    if (argv[i][0] == '-') {
      fprintf(stderr, "\n");
      fprintf(stderr, _("%s: Unrecognized option '%s'\n"),
              argv[0], argv[i]);
      fprintf(stderr, _("See '%s --help' for more information.\n"),
              argv[0]);
      exit(1);
    }

    if (vncServerName[0] != '\0') {
      fprintf(stderr, "\n");
      fprintf(stderr, _("%s: Extra argument '%s'\n"), argv[0], argv[i]);
      fprintf(stderr, _("See '%s --help' for more information.\n"),
              argv[0]);
      exit(0);
    }

    vncServerName = argv[i];
    i++;
  }

  // Handle any old settings specified on the command line
  migrateDeprecatedOptions();

#if !defined(WIN32) && !defined(__APPLE__)
  if (strcmp(display, "") != 0) {
    Fl::display(display);
  }
  fl_open_display();
#endif

  vpnProfiles::refresh();

  init_fltk();
  enable_touch();
#ifdef TIGERVNCS_SESSION_TEST
  extern bool optionsUiStub();
  if (optionsUiStub()) return 0;
#endif

  // Check if the server name in reality is a configuration file
  potentiallyLoadConfigurationFile(vncServerName.c_str());

#ifndef WIN32
  create_base_dirs();
#endif

  network::Socket* sock = nullptr;

#ifndef WIN32
  /* Specifying -via and -listen together is nonsense */
  if (listenMode && strlen(via) > 0) {
    // TRANSLATORS: "Parameters" are command line arguments, or settings
    // from a file or the Windows registry.
    vlog.error(_("Parameters -listen and -via are incompatible"));
    abort_vncviewer(_("Parameters -listen and -via are incompatible"));
    return 1; /* Not reached */
  }
#endif

  if (listenMode) {
    std::list<network::SocketListener*> listeners;
    try {
      int port = 5500;
      if (!vncServerName.empty() && isdigit(vncServerName[0]))
        port = atoi(vncServerName.c_str());

      createTcpListeners(&listeners, nullptr, port);
      if (listeners.empty())
        throw std::runtime_error(_("Unable to listen for incoming connections"));

      vlog.info(_("Listening on port %d"), port);

      /* Wait for a connection */
      while (sock == nullptr) {
        fd_set rfds;
        FD_ZERO(&rfds);
        for (network::SocketListener* listener : listeners)
          FD_SET(listener->getFd(), &rfds);

        int n = select(FD_SETSIZE, &rfds, nullptr, nullptr, nullptr);
        if (n < 0) {
          if (errno == EINTR) {
            vlog.debug("Interrupted select() system call");
            continue;
          } else {
            throw core::socket_error("select", errno);
          }
        }

        for (network::SocketListener* listener : listeners)
          if (FD_ISSET(listener->getFd(), &rfds)) {
            sock = listener->accept();
            if (sock)
              /* Got a connection */
              break;
          }
      }
    } catch (std::exception& e) {
      vlog.error("%s", e.what());
      abort_vncviewer(_("Failure waiting for incoming VNC connection:\n\n%s"), e.what());
      return 1; /* Not reached */
    }

    while (!listeners.empty()) {
      delete listeners.back();
      listeners.pop_back();
    }
  } else {
    if (vncServerName.empty()) {
      vncServerName = ServerDialog::run(defaultServerName.c_str());
      if (vncServerName.empty())
        return 1;
    }

#ifndef WIN32
    if (strlen(via) > 0) {
      try {
        mktunnel();
      } catch (std::exception& e) {
        vlog.error("%s", e.what());
        abort_vncviewer(_("Failure setting up encrypted tunnel:\n\n%s"), e.what());
      }
    }
#endif
  }

#ifdef TIGERVNCS_CONNECTION_STUB
  extern int runConnectionStub(const std::string&);
  return runConnectionStub(vncServerName);
#endif
  while (true) {
    inMainloop = true;
    mainloop(vncServerName.c_str(), sock);
    inMainloop = false;
    sock = nullptr;
    exitMainloop = false;
    exitError.clear();
    fatalError = false;
    // End the session, not the application. Discard its credential binding
    // and construct the same initial dialog used on a fresh launch.
    CConn::clearSavedCredentials();
    vncServerName = ServerDialog::run(defaultServerName.c_str());
    if (vncServerName.empty()) break;
  }

  return 0;
}
