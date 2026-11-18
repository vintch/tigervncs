// SPDX-License-Identifier: GPL-2.0-or-later
#include "CredentialVault.h"
#include <stdexcept>
#include <vector>
#include <cstring>
#ifdef WIN32
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#endif

namespace {
using Bytes = std::vector<unsigned char>;
void wipe(Bytes& bytes) {
  volatile unsigned char* p = bytes.data();
  for (size_t i = 0; i < bytes.size(); ++i) p[i] = 0;
}
struct Secret : Bytes {
  explicit Secret(size_t length) : Bytes(length) {}
  ~Secret() { wipe(*this); }
};
#ifdef WIN32
void check(NTSTATUS result) {
  if (result < 0) throw std::runtime_error("Windows credential encryption failed");
}
Bytes randomBytes(size_t size) {
  Bytes result(size);
  check(BCryptGenRandom(nullptr, result.data(), ULONG(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
  return result;
}
std::string encode(const Bytes& bytes) {
  if (bytes.empty()) return "";
  DWORD size = 0;
  const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
  if (!CryptBinaryToStringA(bytes.data(), DWORD(bytes.size()), flags, nullptr, &size))
    throw std::runtime_error("Cannot encode encrypted credentials");
  std::string result(size, '\0');
  if (!CryptBinaryToStringA(bytes.data(), DWORD(bytes.size()), flags, &result[0], &size))
    throw std::runtime_error("Cannot encode encrypted credentials");
  result.resize(size);
  while (!result.empty() && result.back() == '\0') result.pop_back();
  return result;
}
Bytes decode(const Json::Value& value) {
  if (!value.isString() || value.asString().size() > 1024 * 1024)
    throw std::runtime_error("Invalid encrypted credential data");
  std::string text = value.asString();
  if (text.empty()) return {};
  DWORD size = 0;
  if (!CryptStringToBinaryA(text.data(), DWORD(text.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                            nullptr, &size, nullptr, nullptr))
    throw std::runtime_error("Invalid encrypted credential encoding");
  Bytes result(size);
  if (!CryptStringToBinaryA(text.data(), DWORD(text.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                            result.data(), &size, nullptr, nullptr))
    throw std::runtime_error("Invalid encrypted credential encoding");
  result.resize(size);
  return result;
}
void masterKey(Json::Value& document, Secret& key, bool create) {
  const char purpose[] = "TigerVNCs credential key v1";
  DATA_BLOB entropy{DWORD(sizeof(purpose)), (BYTE*)purpose};
  Json::Value& metadata = document["credentialKey"];
  if (metadata.isNull()) {
    if (!create) throw std::runtime_error("The saved credential key is missing");
    for (const auto& connection : document["connections"])
      if (!connection["password"].isNull())
        throw std::runtime_error("The credential key is missing; existing passwords were not changed");
    check(BCryptGenRandom(nullptr, key.data(), ULONG(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    DATA_BLOB input{DWORD(key.size()), key.data()}, output{};
    if (!CryptProtectData(&input, L"TigerVNCs AES-256 key", &entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output))
      throw std::runtime_error("Windows could not protect the credential key for this account");
    Bytes protectedKey(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    metadata["version"] = 1;
    metadata["protection"] = "DPAPI-CurrentUser";
    metadata["wrappedKey"] = encode(protectedKey);
    return;
  }
  if (!metadata.isObject() || metadata["version"] != 1 ||
      metadata["protection"] != "DPAPI-CurrentUser")
    throw std::runtime_error("Unsupported credential key format");
  Bytes protectedKey = decode(metadata["wrappedKey"]);
  DATA_BLOB input{DWORD(protectedKey.size()), protectedKey.data()}, output{};
  if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output))
    throw std::runtime_error("Saved passwords cannot be unlocked by this Windows account on this computer");
  bool correctSize = output.cbData == key.size();
  if (correctSize) std::memcpy(key.data(), output.pbData, key.size());
  SecureZeroMemory(output.pbData, output.cbData);
  LocalFree(output.pbData);
  if (!correctSize) throw std::runtime_error("Invalid saved credential key");
}
struct Cipher {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  Secret object{0};
  explicit Cipher(const Secret& material) {
    try {
      check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0));
      check(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
      DWORD length = 0, returned = 0;
      check(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&length,
                             sizeof(length), &returned, 0));
      object.resize(length);
      check(BCryptGenerateSymmetricKey(algorithm, &key, object.data(), length,
                                       const_cast<PUCHAR>(material.data()), ULONG(material.size()), 0));
    } catch (...) { close(); throw; }
  }
  void close() {
    if (key) { BCryptDestroyKey(key); key = nullptr; }
    if (algorithm) { BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr; }
  }
  ~Cipher() { close(); }
};
#endif
}

void CredentialVault::erase(std::string& secret) {
  volatile char* p = secret.empty() ? nullptr : &secret[0];
  for (size_t i = 0; i < secret.size(); ++i) p[i] = 0;
  secret.clear();
}

std::string CredentialVault::newId() {
#ifdef WIN32
  Bytes bytes = randomBytes(16);
  static const char hex[] = "0123456789abcdef";
  std::string result;
  for (auto value : bytes) { result += hex[value >> 4]; result += hex[value & 15]; }
  return result;
#else
  throw std::runtime_error("Windows is required for the connection manager credential store");
#endif
}

Json::Value CredentialVault::encrypt(Json::Value& document, const std::string& profileId,
                                     const std::string& password) {
#ifdef WIN32
  if (password.size() > 65536) throw std::runtime_error("Password is too long");
  Secret key(32);
  masterKey(document, key, true);
  Cipher cipher(key);
  Bytes nonce = randomBytes(12), tag(16), output(password.size() + 1);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = nonce.data(); auth.cbNonce = ULONG(nonce.size());
  auth.pbTag = tag.data(); auth.cbTag = ULONG(tag.size());
  auth.pbAuthData = (PUCHAR)profileId.data(); auth.cbAuthData = ULONG(profileId.size());
  ULONG written = 0;
  check(BCryptEncrypt(cipher.key, (PUCHAR)password.data(), ULONG(password.size()), &auth,
                       nullptr, 0, output.data(), ULONG(output.size()), &written, 0));
  output.resize(written);
  Json::Value result(Json::objectValue);
  result["algorithm"] = "AES-256-GCM";
  result["nonce"] = encode(nonce);
  result["tag"] = encode(tag);
  result["ciphertext"] = encode(output);
  return result;
#else
  (void)document; (void)profileId; (void)password;
  throw std::runtime_error("Windows is required to save passwords");
#endif
}

std::string CredentialVault::decrypt(const Json::Value& source, const std::string& profileId,
                                     const Json::Value& encrypted) {
#ifdef WIN32
  if (!encrypted.isObject() || encrypted["algorithm"] != "AES-256-GCM")
    throw std::runtime_error("Unsupported saved password format");
  Json::Value document = source;
  Secret key(32);
  masterKey(document, key, false);
  Cipher cipher(key);
  Bytes nonce = decode(encrypted["nonce"]), tag = decode(encrypted["tag"]);
  Bytes input = decode(encrypted["ciphertext"]);
  if (nonce.size() != 12 || tag.size() != 16 || input.size() > 65536)
    throw std::runtime_error("Invalid saved password data");
  Secret output(input.size() + 1);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = nonce.data(); auth.cbNonce = ULONG(nonce.size());
  auth.pbTag = tag.data(); auth.cbTag = ULONG(tag.size());
  auth.pbAuthData = (PUCHAR)profileId.data(); auth.cbAuthData = ULONG(profileId.size());
  ULONG written = 0;
  unsigned char empty = 0;
  NTSTATUS status = BCryptDecrypt(cipher.key, input.empty() ? &empty : input.data(),
                                  ULONG(input.size()), &auth, nullptr, 0,
                                  output.data(), ULONG(output.size()), &written, 0);
  if (status < 0) throw std::runtime_error("Saved password is damaged or does not belong to this computer entry");
  return std::string(reinterpret_cast<char*>(output.data()), written);
#else
  (void)source; (void)profileId; (void)encrypted;
  throw std::runtime_error("Windows is required to unlock saved passwords");
#endif
}
