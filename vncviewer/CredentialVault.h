// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_CREDENTIAL_VAULT_H
#define TIGERVNCS_CREDENTIAL_VAULT_H
#include <json/json.h>
#include <string>

class CredentialVault {
public:
  static Json::Value encrypt(Json::Value& document, const std::string& profileId,
                              const std::string& password);
  static std::string decrypt(const Json::Value& document, const std::string& profileId,
                              const Json::Value& encrypted);
  static std::string newId();
  static void erase(std::string& secret);
};
#endif
