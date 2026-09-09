// C++ arm of the differential fuzzer: bind Sjors/bitcoin's
// wallet/encrypted_backup decode and decrypt to Rust through cxx. Encode is not
// bound: CreateEncryptedBackup draws its own randomness and parses a descriptor,
// so there is no deterministic low-level encode entry to compare byte-for-byte.

#include "encrypted_backup-fuzz/src/cpp_impl.rs.h"

#include <pubkey.h>
#include <uint256.h>
#include <util/translation.h>
#include <wallet/encrypted_backup.h>

#include <cstdint>
#include <span>
#include <utility>

// Bitcoin Core leaves this i18n hook for the application to define; a fuzz
// harness has no translations.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace bip138shim {

CppDecoded cpp_decode(rust::Slice<const std::uint8_t> data) {
    CppDecoded out;
    out.ok = false;
    std::span<const uint8_t> sp(data.data(), data.size());
    auto res = wallet::DecodeEncryptedBackup(sp);
    if (!res) return out;
    const wallet::EncryptedBackup& b = *res;
    for (const auto& p : b.derivation_paths) {
        CppPath cp;
        for (uint32_t c : p) cp.child.push_back(c);
        out.paths.push_back(std::move(cp));
    }
    for (const uint256& s : b.individual_secrets) {
        for (int i = 0; i < 32; ++i) out.secrets.push_back(s.data()[i]);
    }
    for (uint8_t n : b.nonce) out.nonce.push_back(n);
    for (uint8_t c : b.ciphertext) out.ciphertext.push_back(c);
    out.ok = true;
    return out;
}

CppItems cpp_decrypt(rust::Slice<const std::uint8_t> data,
                     rust::Slice<const std::uint8_t> key) {
    CppItems out;
    out.ok = false;
    if (key.size() != 32) return out;
    std::span<const uint8_t> sp(data.data(), data.size());
    auto res = wallet::DecodeEncryptedBackup(sp);
    if (!res) return out;
    XOnlyPubKey xkey{std::span<const unsigned char>(key.data(), 32)};
    auto items = wallet::DecryptBackupContentsWithKey(*res, xkey);
    if (!items) return out;
    for (const auto& it : *items) {
        CppItem ci;
        for (uint8_t byte : it) ci.data.push_back(byte);
        out.items.push_back(std::move(ci));
    }
    out.ok = true;
    return out;
}

}  // namespace bip138shim
