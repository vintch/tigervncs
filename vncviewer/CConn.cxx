/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright (C) 2011 D. R. Commander.  All Rights Reserved.
 * Copyright 2009-2014 Pierre Ossman for Cendio AB
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
#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_GNUTLS
#include <gnutls/x509.h>
#endif

#include <core/Exception.h>
#include <core/LogWriter.h>
#include <core/Timer.h>
#include <core/i18n.h>
#include <core/string.h>
#include <core/time.h>
#include <core/xdgdirs.h>

#include <rdr/FdInStream.h>
#include <rdr/FdOutStream.h>
#include <rdr/TLSException.h>

#include <rfb/CMsgWriter.h>
#include <rfb/ClientCompatibility.h>
#include <rfb/CSecurity.h>
#include <rfb/Exception.h>
#include <rfb/Security.h>
#include <rfb/fenceTypes.h>
#include <rfb/obfuscate.h>
#include <rfb/screenTypes.h>

#include <network/TcpSocket.h>
#ifndef WIN32
#include <network/UnixSocket.h>
#endif

#include <FL/Fl.H>
#include <FL/fl_ask.H>

#include "fltk/layout.h"
#include "fltk/util.h"
#include "AudioOutput.h"
#include "AuthDialog.h"
#include "ConnectionStore.h"
#include "ConnectionTimeout.h"
#include "PresenceMonitor.h"
#include "NetworkSettings.h"
#ifdef HAVE_GNUTLS
#include <gnutls/crypto.h>
#endif
#include <atomic>
#include <thread>
#include "CConn.h"
#include "OptionsDialog.h"
#include "DesktopWindow.h"
#include "PlatformPixelBuffer.h"
#include "parameters.h"
#include "vncviewer.h"

std::string CConn::savedUsername;
std::string CConn::savedPassword;

static core::LogWriter vlog("CConn");

// 8 colours (1 bit per component)
static const rfb::PixelFormat verylowColourPF(8, 3,false, true,
                                              1, 1, 1, 2, 1, 0);
// 64 colours (2 bits per component)
static const rfb::PixelFormat lowColourPF(8, 6, false, true,
                                          3, 3, 3, 4, 2, 0);
// 256 colours (2-3 bits per component)
static const rfb::PixelFormat mediumColourPF(8, 8, false, true,
                                             7, 7, 3, 5, 2, 0);
static const rfb::PixelFormat reducedColourPF(16, 16, false, true,
                                              31, 63, 31, 11, 5, 0);

// Time new bandwidth estimates are weighted against (in ms)
static const unsigned bpsEstimateWindow = 1000;

struct CConn::PendingConnect {
  std::atomic<bool> done{false};
  std::unique_ptr<network::Socket> socket;
  std::string error;
};
static std::atomic<unsigned> connectionWorkers{0};

CConn::CConn(DesktopWindow* retained, const ConnectionCredentials* credentials)
  : serverPort(0), sock(nullptr),
    msgTimer(this, &CConn::processNextMsg),
    connectionTimer(this, &CConn::connectionTimedOut),
    sessionTimer(this, &CConn::checkSession), connectPollTimer(this, &CConn::checkConnect), desktop(retained),
    audioOutput(nullptr),
    updateCount(0), pixelCount(0),
    lastServerEncoding((unsigned int)-1), bpsEstimate(20000000)
{
  recovering = retained != nullptr;
  if (credentials) recoveryCredentials = *credentials;
  if (desktop) desktop->setConnection(this);
  setShared(::shared);

  supportsLocalCursor = true;
  supportsCursorPosition = true;
  supportsDesktopResize = true;
  supportsLEDState = true;

#ifdef HAVE_AUDIO
  // Only ask the server to send audio if there is a device that can
  // play it. Opening that device is deferred until the server actually
  // has something for us.
  if (playAudio) {
    audioOutput = AudioOutput::create();
    supportsAudio = audioOutput != nullptr;
  }
#endif

  if (customCompressLevel)
    setCompressLevel(::compressLevel);

  setQualityLevel(::qualityLevel);

  OptionsDialog::addCallback(handleOptions, this);
}

CConn::~CConn()
{
  connectionTimer.stop();
  sessionTimer.stop();
  connectPollTimer.stop(); pendingConnect.reset();
  if (!fastClose) {
    OptionsDialog::hideDialogs();
    OptionsDialog::setServerProfile(false, -1);
  }
  close();

  OptionsDialog::removeCallback(handleOptions);
  Fl::remove_timeout(handleUpdateTimeout, this);

  if (desktop)
    delete desktop;

  delete audioOutput;

  if (fastClose && sock) {
    Fl::remove_fd(sock->getFd()); delete sock; sock = nullptr;
  }

  if (sock) {
    struct timeval now;

    sock->shutdownWrite();

    // Do a graceful close by waiting for the peer (up to 250 ms)
    // FIXME: should do this asynchronously
    gettimeofday(&now, nullptr);
    while (core::msSince(&now) < 250) {
      bool done;

      done = false;
      while (true) {
        try {
          sock->inStream().skip(sock->inStream().avail());
          if (!sock->inStream().hasData(1))
            break;
        } catch (std::exception&) {
          done = true;
          break;
        }
      }

      if (done)
        break;

  #ifdef WIN32
      Sleep(10);
  #else
      usleep(10000);
  #endif
    }

    Fl::remove_fd(sock->getFd());

    delete sock;
  }
}

void CConn::connect(const char* vncServerName, network::Socket* socket)
{
  suspendPresence();
  connectionTimer.start(networkSettings::connectTimeoutMs());
  sock = socket;
  if(sock == nullptr) {
    try {
#ifndef WIN32
      if (strchr(vncServerName, '/') != nullptr) {
        sock = new network::UnixSocket(vncServerName);
        serverHost = sock->getPeerAddress();
        vlog.info(_("Connected to socket %s"), serverHost.c_str());
      } else
#endif
      {
        network::getHostAndPort(vncServerName, &serverHost, &serverPort);
        ConnectionCredentials profile;
        if (recovering) profile.sessionMode = recoveryCredentials.sessionMode;
        else ConnectionStore::activeCredentials(serverHost, serverPort, profile);
        recoveryCredentials.sessionMode = profile.sessionMode;
        setAppleSessionMode(profile.sessionMode == "user-session" ? 2 : 1);

        // DNS and TCP establishment cannot freeze an existing window while
        // recovering, even if the user chose a long connection timeout.
        network::initSockets();
        auto pending = std::make_shared<PendingConnect>();
        auto host = serverHost; auto port = serverPort;
        int timeout = networkSettings::connectTimeoutMs();
        if (connectionWorkers.fetch_add(1) >= 2) {
          connectionWorkers.fetch_sub(1);
          throw std::runtime_error("Previous network connection attempts are still finishing");
        }
        try {
          std::thread([pending, host, port, timeout] {
            try { pending->socket.reset(new network::TcpSocket(host.c_str(), port, timeout)); }
            catch (std::exception& e) { pending->error = e.what(); }
            catch (...) { pending->error = "Network connection failed"; }
            connectionWorkers.fetch_sub(1);
            pending->done.store(true, std::memory_order_release);
          }).detach();
        } catch (...) { connectionWorkers.fetch_sub(1); throw; }
        pendingConnect = pending;
        connectPollTimer.start(20);
        return;
      }
    } catch (std::exception& e) {
      vlog.error("%s", e.what());
      if (recovering) { reconnect_connection(e.what()); return; }
      abort_connection(_("Failed to connect to \"%s\":\n\n%s"),
                       vncServerName, e.what());
      return;
    }
  }

  finishConnect();
}

void CConn::checkConnect(core::Timer*)
{
  if (!pendingConnect) return;
  if (!pendingConnect->done.load(std::memory_order_acquire)) { connectPollTimer.repeat(20); return; }
  auto pending = pendingConnect; pendingConnect.reset();
  if (!pending->error.empty()) {
    if (recovering) reconnect_connection(pending->error.c_str());
    else abort_connection(_("Failed to connect to %s:\n\n%s"), serverHost.c_str(), pending->error.c_str());
    return;
  }
  sock = pending->socket.release();
  try {
    vlog.info(_("Connected to host %s port %d"), serverHost.c_str(), serverPort);
    finishConnect();
  } catch (std::exception& e) {
    if (recovering) reconnect_connection(e.what());
    else abort_connection_unexpected(e);
  }
}

void CConn::finishConnect()
{
  Fl::add_fd(sock->getFd(), FL_READ | FL_EXCEPT, socketEvent, this);

  setServerName(serverHost.c_str());
  setStreams(&sock->inStream(), &sock->outStream());

  initialiseProtocol();
}

std::string CConn::connectionInfo()
{
  std::string infoText;

  char pfStr[100];

  infoText += core::format(_("Desktop name: %.80s"), server.name());
  infoText += "\n";

  infoText += core::format(_("Host: %.80s port: %d"),
                           serverHost.c_str(), serverPort);
  infoText += "\n";

  infoText += core::format(_("Size: %d x %d"),
                           server.width(), server.height());
  infoText += "\n";

  // TRANSLATORS: Will be filled in with a string describing the
  // protocol pixel format in a fairly language neutral way
  server.pf().print(pfStr, 100);
  infoText += core::format(_("Pixel format: %s"), pfStr);
  infoText += "\n";

  infoText += core::format(_("Requested encoding: %s"),
                           rfb::encodingName(getPreferredEncoding()));
  infoText += "\n";

  infoText += core::format(_("Last used encoding: %s"),
                           rfb::encodingName(lastServerEncoding));
  infoText += "\n";

  infoText += core::format(_("Line speed estimate: %d kbit/s"),
                           (int)(bpsEstimate / 1000));
  infoText += "\n";

  infoText += core::format(_("Protocol version: %d.%d"),
                           server.majorVersion, server.minorVersion);
  infoText += "\n";

  infoText += core::format(_("Security method: %s"),
                           rfb::secTypeName(csecurity->getType()));
  infoText += "\n";

  return infoText;
}

unsigned CConn::getUpdateCount()
{
  return updateCount;
}

unsigned CConn::getPixelCount()
{
  return pixelCount;
}

unsigned CConn::getPosition()
{
  return sock->inStream().pos();
}

void CConn::socketEvent(FL_SOCKET fd, void *data)
{
  CConn *cc;

  assert(data);
  cc = (CConn*)data;

  // Stop monitoring the socket for now and start processing incoming
  // data asynchronously
  Fl::remove_fd(fd);
  cc->msgTimer.start(0);

  // Coalesce data until we're fully done processing things
  cc->getOutStream()->cork(true);
}

void CConn::processNextMsg(core::Timer*)
{
  static bool recursing = false;
  bool again;
  int when;

  // I don't think processMsg() is recursion safe, so add this check
  assert(!recursing);

  recursing = true;

  again = false;
  try {
    // We might have been called to flush unwritten socket data
    sock->outStream().flush();

    again = processMsg();
  } catch (rdr::end_of_stream& e) {
    vlog.info("%s", e.what());
    if (desktop) {
      reconnect_connection(_("The server closed the connection unexpectedly."));
    } else {
      vlog.error(_("The connection was dropped by the server before "
                   "the session could be established."));
      abort_connection(_("The connection was dropped by the server "
                       "before the session could be established."));
    }
  } catch (core::socket_error& e) {
    if (desktop) reconnect_connection(e.what());
    else abort_connection_unexpected(e);
  } catch (rfb::auth_cancelled& e) {
    vlog.info("%s", e.what());
    disconnect();
  } catch (rfb::auth_error& e) {
    ConnectionStore::rejectActivePassword();
    clearSavedCredentials();
    vlog.error(_("Authentication failed: %s"), e.what());
    abort_connection(_("Failed to authenticate with the server. Reason "
                       "given by the server:\n\n%s"), e.what());
  } catch (std::exception& e) {
    vlog.error("%s", e.what());
    abort_connection_unexpected(e);
  }

  recursing = false;

  if (again) {
    msgTimer.repeat();
    return;
  }

  // Out of data, go back to waiting

  getOutStream()->cork(false);

  when = FL_READ | FL_EXCEPT;
  if (sock->outStream().hasBufferedData())
    when |= FL_WRITE;

  Fl::add_fd(sock->getFd(), when, socketEvent, this);
}

////////////////////// CConnection callback methods //////////////////////

void CConn::clearSavedCredentials()
{
  savedUsername.clear();
  CredentialVault::erase(savedPassword);
}

void CConn::connectionTimedOut(core::Timer*)
{
  auto error = core::format(_("The connection timed out after %d seconds."), int(networkSettings::connectTimeout));
  if (recovering) reconnect_connection(error.c_str());
  else abort_connection("%s", error.c_str());
}

DesktopWindow* CConn::releaseDesktopForReconnect()
{
  connectionTimer.stop(); sessionTimer.stop(); msgTimer.stop(); connectPollTimer.stop(); pendingConnect.reset();
  Fl::remove_timeout(handleUpdateTimeout, this);
  if (sock) Fl::remove_fd(sock->getFd());
  fastClose = true;
  auto window = desktop;
  if (window) window->freezeFramebuffer(releaseFramebuffer());
#ifdef TIGERVNCS_SESSION_TEST
  extern void sessionWindowStub(const char*, const void*, uint32_t, bool);
  if (window) sessionWindowStub("frozen", window, window->displayedPixel(), true);
#endif
  desktop = nullptr;
  return window;
}

void CConn::checkSession(core::Timer*)
{
  if (!sock || state() != RFBSTATE_NORMAL) return;
  try {
    auto now = pingClockMs();
    if (startupRefreshAt && now >= startupRefreshAt) {
      startupRefreshAt = 0;
      // Apple Screen Sharing can acknowledge the initial request before its
      // screen capture is ready. Ask for a complete image once it has settled.
      vlog.info("Requesting a complete startup framebuffer refresh");
      refreshFramebuffer();
      getOutStream()->cork(false);
    }
    liveness.progress(now, sock->inStream().pos() + sock->inStream().avail());
    auto action = liveness.check(now);
    if (action == SessionLiveness::Reconnect) {
      auto error = core::format(_("The active session stopped responding for %d seconds."), int(networkSettings::sessionTimeout));
      reconnect_connection(error.c_str());
      return;
    }
    if (action == SessionLiveness::Probe) {
      // An incremental request may legitimately wait on an unchanged desktop.
      // A non-incremental one-pixel RFB request always has an answer; no ICMP.
      if (!reportedFirstFrame) refreshFramebuffer();
      else writer()->writeFramebufferUpdateRequest({0, 0, 1, 1}, false);
      getOutStream()->cork(false);
    }
    sessionTimer.repeat(250);
  } catch (std::exception& e) { reconnect_connection(e.what()); }
}

void CConn::rememberCredentials(const std::string* user, const std::string* password)
{
  recoveryCredentials.username = user ? *user : "";
  CredentialVault::erase(recoveryCredentials.password);
  recoveryCredentials.password = *password; recoveryCredentials.hasPassword = true;
}

void CConn::getUserPasswd(std::string *user, std::string *password)
{
  PauseConnectionTimeout pause(connectionTimer);
  const char *passwordFileName(passwordFile);
  int ret_val;

  assert(password);
  if (recovering) {
    if (!recoveryCredentials.hasPassword || (user && recoveryCredentials.username.empty()))
      throw rfb::auth_cancelled();
    if (user) *user = recoveryCredentials.username;
    *password = recoveryCredentials.password;
    return;
  }
  ConnectionCredentials credentials;
  bool savedProfile = ConnectionStore::activeCredentials(serverHost, serverPort, credentials);
  if (credentials.sessionMode == "user-session" && (!savedProfile || !credentials.hasPassword))
    throw rfb::protocol_error(_("User session requires valid saved credentials. Return to the initial window and edit this computer."));
  if (savedProfile && credentials.hasPassword) {
    if (user) *user = credentials.username;
    *password = credentials.password;
    rememberCredentials(user, password);
    return;
  }
  char *envUsername = getenv("VNC_USERNAME");
  char *envPassword = getenv("VNC_PASSWORD");

  if(!savedProfile && user && envUsername && envPassword) {
    *user = envUsername;
    *password = envPassword;
    rememberCredentials(user, password);
    return;
  }

  if (!savedProfile && !user && envPassword) {
    *password = envPassword;
    rememberCredentials(user, password);
    return;
  }

  if (!savedProfile && user && !savedUsername.empty() && !savedPassword.empty()) {
    *user = savedUsername;
    *password = savedPassword;
    rememberCredentials(user, password);
    return;
  }

  if (!savedProfile && !user && !savedPassword.empty()) {
    *password = savedPassword;
    rememberCredentials(user, password);
    return;
  }

  if (!savedProfile && !user && passwordFileName[0]) {
    std::vector<uint8_t> obfPwd(8);
    FILE* fp;

    fp = fopen(passwordFileName, "rb");
    if (!fp)
      throw core::posix_error(
        core::format(_("Failed to open \"%s\""), passwordFileName),
        errno);

    obfPwd.resize(fread(obfPwd.data(), 1, obfPwd.size(), fp));
    fclose(fp);

    *password = rfb::deobfuscate(obfPwd.data(), obfPwd.size());

    rememberCredentials(user, password);
    return;
  }

  AuthDialog d(isSecure(), user != nullptr, password != nullptr);
  if (savedProfile) d.setUser(credentials.username);
  d.show();
  while (d.shown())
    Fl::wait();
  ret_val = d.result();

  if (ret_val == 1) {
    bool keepPasswd;

    if (reconnectOnError)
      keepPasswd = d.getKeepPassword();
    else
      keepPasswd = false;

    if (user) {
      *user = d.getUser();
      if (keepPasswd)
        savedUsername = d.getUser();
    }
    *password = d.getPassword();
    if (keepPasswd)
      savedPassword = d.getPassword();
  }

  if (ret_val != 1)
    throw rfb::auth_cancelled();
  rememberCredentials(user, password);
}

// initDone() is called when the serverInit message has been received.  At
// this point we create the desktop window and display it.  We also tell the
// server the pixel format and encodings to use and request the first update.
void CConn::initDone()
{
  connectionTimer.stop();
  OptionsDialog::setServerProfile(isAppleServer(), -1);
#ifdef TIGERVNCS_SESSION_TEST
  bool reused = desktop != nullptr;
#endif
  if (desktop) desktop->attachFramebuffer(server.width(), server.height());
  else desktop = new DesktopWindow(server.width(), server.height(), this);
#ifdef TIGERVNCS_SESSION_TEST
  extern void sessionWindowStub(const char*, const void*, uint32_t, bool);
  sessionWindowStub("attached", desktop, desktop->displayedPixel(), reused);
#endif
  liveness.start(pingClockMs(), sock->inStream().pos() + sock->inStream().avail());
  liveness.configure(networkSettings::sessionTimeoutMs());
  sessionTimer.start(250);
  startupRefreshAt = pingClockMs() + 1000;

  // Force a switch to the format and encoding we'd like
  updateEncoding();
  updatePixelFormat();
}

bool CConn::verifyCertificate(unsigned int status,
                              const uint8_t* certificate, size_t length)
{
  PauseConnectionTimeout pause(connectionTimer);
#ifndef HAVE_GNUTLS
  (void)status;
  (void)certificate;
  (void)length;
  throw std::logic_error("TLS support not enabled");
#else
  const unsigned allowed_errors =
    GNUTLS_CERT_INVALID |
    GNUTLS_CERT_SIGNER_NOT_FOUND |
    GNUTLS_CERT_SIGNER_NOT_CA |
    GNUTLS_CERT_NOT_ACTIVATED |
    GNUTLS_CERT_EXPIRED |
    GNUTLS_CERT_INSECURE_ALGORITHM |
    GNUTLS_CERT_UNEXPECTED_OWNER;
  gnutls_datum_t status_str;
  unsigned int fatal_status;

  gnutls_datum_t cert_datum;
  gnutls_x509_crt_t crt;
  int err, known;

  const char *hostsDir;
  gnutls_datum_t info_datum;
  std::string info;
  size_t len;

  assert(status != 0);

  fatal_status = status & (~allowed_errors);

  if (fatal_status != 0) {
    err = gnutls_certificate_verification_status_print(fatal_status,
                                                       GNUTLS_CRT_X509,
                                                       &status_str,
                                                       0);
    if (err != GNUTLS_E_SUCCESS)
      throw rdr::tls_error(_("Failed to get certificate problem "
                             "description"), err);

    abort_connection(_("Invalid server certificate: %s"),
                     status_str.data);

    gnutls_free(status_str.data);

    return false;
  }

  err = gnutls_certificate_verification_status_print(status,
                                                     GNUTLS_CRT_X509,
                                                     &status_str,
                                                     0);
  if (err != GNUTLS_E_SUCCESS)
    throw rdr::tls_error(_("Failed to get certificate problem "
                           "description"), err);

  vlog.info(_("Server certificate problems: %s"), status_str.data);

  gnutls_free(status_str.data);

  /* Certificate has some user overridable problems, so TOFU time */

  hostsDir = core::getvncstatedir();
  if (hostsDir == nullptr) {
    throw std::runtime_error(_("Could not determine VNC state "
                               "directory path"));
  }

  std::string dbPath;
  dbPath = (std::string)hostsDir + "/x509_known_hosts";

  cert_datum.data = (uint8_t*)certificate;
  cert_datum.size = length;

  unsigned char digest[32];
  if (gnutls_hash_fast(GNUTLS_DIG_SHA256, certificate, length, digest) < 0)
    throw std::runtime_error("Cannot fingerprint server certificate");
  std::string fingerprint;
  const char hex[] = "0123456789abcdef";
  for (auto octet : digest) { fingerprint += hex[octet >> 4]; fingerprint += hex[octet & 15]; }
  PortableConfig trustFile(PortableConfig::executablePath());
  auto trustDocument = trustFile.read();
  const auto& saved = trustDocument["certificateExceptions"][getServerName()];
  if (saved.isString()) known = saved.asString() == fingerprint ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
  else known = gnutls_verify_stored_pubkey(dbPath.c_str(), nullptr,
                                         getServerName(), nullptr, GNUTLS_CRT_X509, &cert_datum, 0);

  /* Previously known? */
  if (known == GNUTLS_E_SUCCESS) {
    if (saved.isNull()) {
      trustDocument["certificateExceptions"][getServerName()] = fingerprint;
      trustFile.write(trustDocument);
    }
    vlog.info(_("Server has an existing security exception"));
    return true;
  }

  if ((known != GNUTLS_E_NO_CERTIFICATE_FOUND) &&
      (known != GNUTLS_E_CERTIFICATE_KEY_MISMATCH))
    throw rdr::tls_error(_("Failed to load list of servers with a "
                           "security exception"), known);

  gnutls_x509_crt_init(&crt);
  err = gnutls_x509_crt_import(crt, &cert_datum, GNUTLS_X509_FMT_DER);
  if (err != GNUTLS_E_SUCCESS)
    throw rdr::tls_error(_("Failed to decode server certificate"), err);

  err = gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_ONELINE,
                              &info_datum);
  gnutls_x509_crt_deinit(crt);
  if (err != GNUTLS_E_SUCCESS)
    throw rdr::tls_error(_("Failed to format server certificate for "
                           "display"), err);

  len = strlen((char*)info_datum.data);
  for (size_t i = 0; i < len - 1; i++) {
    if (info_datum.data[i] == ',' && info_datum.data[i + 1] == ' ')
      info_datum.data[i] = '\n';
  }

  info = (const char*)info_datum.data;

  gnutls_free(info_datum.data);

  /* New host */
  if (known == GNUTLS_E_NO_CERTIFICATE_FOUND) {
    std::string text;

    vlog.info(_("Server host is not previously known"));
    vlog.info("%s", info.c_str());

    if (status & (GNUTLS_CERT_INVALID |
                  GNUTLS_CERT_SIGNER_NOT_FOUND |
                  GNUTLS_CERT_SIGNER_NOT_CA)) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This certificate has been signed by an unknown authority:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unknown certificate issuer"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~(GNUTLS_CERT_INVALID |
                  GNUTLS_CERT_SIGNER_NOT_FOUND |
                  GNUTLS_CERT_SIGNER_NOT_CA);
    }

    if (status & GNUTLS_CERT_NOT_ACTIVATED) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This certificate is not yet valid:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Certificate is not yet valid"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_NOT_ACTIVATED;
    }

    if (status & GNUTLS_CERT_EXPIRED) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This certificate has expired:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Expired certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_EXPIRED;
    }

    if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This certificate uses an insecure algorithm:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Insecure certificate algorithm"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_INSECURE_ALGORITHM;
    }

    if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        core::format(
          _("The specified hostname \"%s\" does not match the "
            "certificate provided by the server:"),
          getServerName()).c_str(),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Certificate hostname mismatch"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_UNEXPECTED_OWNER;
    }

    if (status != 0) {
      vlog.error("Unhandled server certificate problems: 0x%x",
                 status);
      throw std::logic_error("Unhandled server certificate problems");
    }
  } else if (known == GNUTLS_E_CERTIFICATE_KEY_MISMATCH) {
    std::string text;

    vlog.info(_("Server host certificate has changed"));
    vlog.info("%s", info.c_str());

    if (status & (GNUTLS_CERT_INVALID |
                  GNUTLS_CERT_SIGNER_NOT_FOUND |
                  GNUTLS_CERT_SIGNER_NOT_CA)) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This host is previously known with a different certificate, "
          "and the new certificate has been signed by an unknown "
          "authority:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unexpected server certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~(GNUTLS_CERT_INVALID |
                  GNUTLS_CERT_SIGNER_NOT_FOUND |
                  GNUTLS_CERT_SIGNER_NOT_CA);
    }

    if (status & GNUTLS_CERT_NOT_ACTIVATED) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This host is previously known with a different certificate, "
          "and the new certificate is not yet valid:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unexpected server certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_NOT_ACTIVATED;
    }

    if (status & GNUTLS_CERT_EXPIRED) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This host is previously known with a different certificate, "
          "and the new certificate has expired:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unexpected server certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_EXPIRED;
    }

    if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        _("This host is previously known with a different certificate, "
          "and the new certificate uses an insecure algorithm:"),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unexpected server certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_INSECURE_ALGORITHM;
    }

    if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
      text = core::format(
        "%s\n\n%s\n\n%s\n\n%s",
        core::format(
          _("This host is previously known with a different "
            "certificate, and the specified hostname \"%s\" does not "
            "match the new certificate provided by the server:"),
          getServerName()).c_str(),
        info.c_str(),
        _("Someone could be trying to impersonate the site and you "
          "should not continue."),
        _("Do you want to make an exception for this server?"));

      fl_message_title(_("Unexpected server certificate"));
      if (fl_choice("%s", nullptr, fl_cancel, _("Add exception"),
                    fltk_escape(text).c_str()) != 2)
        return false;

      status &= ~GNUTLS_CERT_UNEXPECTED_OWNER;
    }

    if (status != 0) {
      vlog.error("Unhandled server certificate problems: 0x%x",
                 status);
      throw std::logic_error("Unhandled server certificate problems");
    }
  }

  // Re-read so other settings saved while the certificate prompt was open survive.
  trustDocument = trustFile.read();
  trustDocument["certificateExceptions"][getServerName()] = fingerprint;
  trustFile.write(trustDocument);

  vlog.info(_("Security exception added for server host"));

  return true;
#endif
}

bool CConn::verifyHostKey(const uint8_t* key, size_t length,
                          const char* fingerprint)
{
  PauseConnectionTimeout pause(connectionTimer);
  std::string text = core::format(
    _("The server has provided the following identifying information:\n"
      "\n"
      "Fingerprint: %s\n"
      "\n"
      "Do you want to continue connecting to this server?"),
    fingerprint);
  fl_message_title(_("Verify server key"));
  if (fl_choice("%s", nullptr, fl_cancel, _("Continue"),
                fltk_escape(text).c_str()) != 2)
    return false;

  // FIXME: Should save this for TOFU
  (void)key;
  (void)length;

  return true;
}

void CConn::setExtendedDesktopSize(unsigned reason, unsigned result,
                                   int w, int h,
                                   const rfb::ScreenSet& layout)
{
  CConnection::setExtendedDesktopSize(reason, result, w, h, layout);

  if (reason == rfb::reasonClient)
    desktop->setDesktopSizeDone(result);
}

// setName() is called when the desktop name changes
void CConn::setName(const char* name)
{
  CConnection::setName(name);
  desktop->updateCaption();
}

// framebufferUpdateStart() is called at the beginning of an update.
// Here we try to send out a new framebuffer update request so that the
// next update can be sent out in parallel with us decoding the current
// one.
void CConn::framebufferUpdateStart()
{
  liveness.frameStarted();
  CConnection::framebufferUpdateStart();

  // For bandwidth estimate
  gettimeofday(&updateStartTime, nullptr);
  updateStartPos = sock->inStream().pos();

  // Update the screen prematurely for very slow updates
  Fl::add_timeout(1.0, handleUpdateTimeout, this);
}

// framebufferUpdateEnd() is called at the end of an update.
// For each rectangle, the FdInStream will have timed the speed
// of the connection, allowing us to select format and encoding
// appropriately, and then request another incremental update.
void CConn::framebufferUpdateEnd()
{
  unsigned long long elapsed, bps, weight;
  struct timeval now;

  CConnection::framebufferUpdateEnd();
  liveness.frameCompleted(pingClockMs());
  bool wasRecovering = recovering;
  if (recovering && freshPixels) {
    desktop->commitFramebuffer(); recovering = false;
    vlog.info("Automatic reconnection completed with a fresh framebuffer");
  }
#ifdef TIGERVNCS_SESSION_TEST
  if (freshPixels && !reportedFirstFrame) {
    extern void sessionWindowStub(const char*, const void*, uint32_t, bool);
    sessionWindowStub("frame", desktop, desktop->displayedPixel(), wasRecovering);
  }
#else
  (void)wasRecovering;
#endif
  if (freshPixels) reportedFirstFrame = true;

  updateCount++;

  // Calculate bandwidth everything managed to maintain during this update
  gettimeofday(&now, nullptr);
  elapsed = (now.tv_sec - updateStartTime.tv_sec) * 1000000;
  elapsed += now.tv_usec - updateStartTime.tv_usec;
  if (elapsed == 0)
    elapsed = 1;
  bps = (unsigned long long)(sock->inStream().pos() -
                             updateStartPos) * 8 *
                            1000000 / elapsed;
  // Allow this update to influence things more the longer it took, to a
  // maximum of 20% of the new value.
  weight = elapsed * 1000 / bpsEstimateWindow;
  if (weight > 200000)
    weight = 200000;
  bpsEstimate = ((bpsEstimate * (1000000 - weight)) +
                 (bps * weight)) / 1000000;

  Fl::remove_timeout(handleUpdateTimeout, this);
  desktop->updateWindow();

  // Compute new settings based on updated bandwidth values
  if (autoSelect) {
    updateEncoding();
    updateQualityLevel();
    updatePixelFormat();
  }
}

// The rest of the callbacks are fairly self-explanatory...

void CConn::bell()
{
  fl_beep();
}

bool CConn::dataRect(const core::Rect& r, int encoding)
{
  bool ret;

  if (encoding != rfb::encodingCopyRect) {
    if (lastServerEncoding != (unsigned)encoding) {
      vlog.info("Server is using %s encoding", rfb::encodingName(encoding));
      OptionsDialog::setServerProfile(isAppleServer(), encoding);
    }
    lastServerEncoding = encoding;
  }

  ret = CConnection::dataRect(r, encoding);

  if (ret) {
    pixelCount += r.area();
    if (r.area() && encoding >= 0) freshPixels = true;
  }

  return ret;
}

void CConn::setCursor(int width, int height, const core::Point& hotspot,
                      const uint8_t* data)
{
  CConnection::setCursor(width, height, hotspot, data);

  desktop->setCursor();
}

void CConn::setCursorPos(const core::Point& pos)
{
  desktop->setCursorPos(pos);
}

void CConn::setLEDState(unsigned int state)
{
  CConnection::setLEDState(state);

  desktop->setLEDState(state);
}

void CConn::handleClipboardRequest()
{
  desktop->handleClipboardRequest();
}

void CConn::handleClipboardAnnounce(bool available)
{
  desktop->handleClipboardAnnounce(available);
}

void CConn::handleClipboardData(const char* data)
{
  desktop->handleClipboardData(data);
}

void CConn::handleAudioBegin()
{
  if (audioOutput == nullptr)
    return;

  audioOutput->start();
}

void CConn::handleAudioEnd()
{
  if (audioOutput == nullptr)
    return;

  audioOutput->stop();
}

void CConn::handleAudioData(const uint8_t* data, size_t length)
{
  if (audioOutput == nullptr)
    return;

  audioOutput->play(data, length);
}


////////////////////// Internal methods //////////////////////

void CConn::resizeFramebuffer()
{
  desktop->resizeFramebuffer(server.width(), server.height());
}

void CConn::updateEncoding()
{
  int encNum;

  if (autoSelect)
    encNum = rfb::encodingTight;
  else
    encNum = rfb::encodingNum(::preferredEncoding.getValueStr().c_str());

  if (encNum != -1)
    setPreferredEncoding(rfb::compatibleEncoding(isAppleServer(), encNum));
}

void CConn::updateCompressLevel()
{
  if (customCompressLevel)
    setCompressLevel(::compressLevel);
  else
    setCompressLevel(-1);
}

void CConn::updateQualityLevel()
{
  int newQualityLevel;

  if (!autoSelect)
    newQualityLevel = ::qualityLevel;
  else {
    // Above 16Mbps (i.e. LAN), we choose the second highest JPEG
    // quality, which should be perceptually lossless. If the bandwidth
    // is below that, we choose a more lossy JPEG quality.

    if (bpsEstimate > 16000000)
      newQualityLevel = 8;
    else
      newQualityLevel = 6;

    if (newQualityLevel != getQualityLevel()) {
      vlog.info(_("Throughput %d kbit/s - changing to quality %d"),
                (int)(bpsEstimate/1000), newQualityLevel);
    }
  }

  setQualityLevel(newQualityLevel);
}

void CConn::updatePixelFormat()
{
  bool useFullColour;
  rfb::PixelFormat pf, fullColourPF;

  useFullColour = fullColour;

  fullColourPF = getFramebuffer()->getPF();

  // If the bandwidth drops below 256 Kbps, we switch to palette mode.
  if (autoSelect) {
    useFullColour = (bpsEstimate > 256000);
    if (useFullColour != (server.pf() == fullColourPF)) {
      if (useFullColour)
        vlog.info(_("Throughput %d kbit/s - full color is now enabled"),
                  (int)(bpsEstimate/1000));
      else
        vlog.info(_("Throughput %d kbit/s - full color is now disabled"),
                  (int)(bpsEstimate/1000));
    }
  }

  if (useFullColour) {
    pf = fullColourPF;
  } else {
    if (lowColourLevel == 0)
      pf = verylowColourPF;
    else if (lowColourLevel == 1)
      pf = lowColourPF;
    else
      pf = lowColourLevel == 3 ? reducedColourPF : mediumColourPF;
  }

  pf = rfb::compatiblePixelFormat(isAppleServer(), pf);

  if (pf != server.pf()) {
    char str[256];
    pf.print(str, 256);
    vlog.info(_("Using pixel format %s"),str);
    setPF(pf);
  }
}

void CConn::handleOptions(void *data)
{
  CConn *self = (CConn*)data;
  self->liveness.configure(networkSettings::sessionTimeoutMs());
  if (self->state() != RFBSTATE_NORMAL) return;

  self->updateEncoding();
  self->updateCompressLevel();
  self->updateQualityLevel();
  self->updatePixelFormat();
}

void CConn::handleUpdateTimeout(void *data)
{
  CConn *self = (CConn *)data;

  assert(self);

  self->desktop->updateWindow();

  Fl::repeat_timeout(1.0, handleUpdateTimeout, data);
}
