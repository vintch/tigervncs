// SPDX-License-Identifier: GPL-2.0-or-later
// Test-only fixture: run beside an isolated viewer copy. Secrets are read from
// the process environment and are never printed or accepted on the command line.
#include "ConnectionStore.h"
#include <network/TcpSocket.h>
#include <cstdlib>
#include <iostream>

int main() {
  try {
    const char* address = std::getenv("VNC_TEST_ADDRESS");
    const char* user = std::getenv("VNC_USERNAME");
    const char* password = std::getenv("VNC_PASSWORD");
    if (!address || !user || !password) return 2;
    ConnectionStore store;
    auto folder = store.saveFolder("", "Integration tests", "");
    auto sub = store.saveFolder("", "Macs", folder);
    auto id = store.saveConnection("", "Mac saved credentials", address, user, sub,
      ConnectionStore::SetPassword, password);
    store.setExpanded(true);
    std::string host; int port;
    network::getHostAndPort(address, &host, &port);
    // Verify the authentication path, including rejecting a failed saved password.
    ConnectionStore::activate(id, address);
    auto entry = store.connection(id);
    auto doc = store.read();
    if (CredentialVault::decrypt(doc, id, entry["password"]) != password) return 3;
    ConnectionCredentials credentials;
    if (!ConnectionStore::activeCredentials(host, port, credentials) ||
        !credentials.hasPassword || credentials.username != user || credentials.password != password) return 4;
    ConnectionCredentials other;
    if (ConnectionStore::activeCredentials("unrelated.example", port, other)) return 5;
    ConnectionStore::rejectActivePassword();
    ConnectionCredentials retry;
    if (!ConnectionStore::activeCredentials(host, port, retry) || retry.hasPassword) return 6;
    ConnectionStore::clearActive();
    std::cout << "Encrypted connection fixture ready\n";
    return 0;
  } catch (std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
