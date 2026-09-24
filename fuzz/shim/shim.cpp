// C++ arm of the differential fuzzer: bind Sjors/bitcoin's
// wallet/encrypted_backup decode, decrypt and component codecs to Rust through
// cxx. Container encode is not bound: CreateEncryptedBackup draws its own
// randomness and parses a descriptor, so there is no deterministic low-level
// encode entry to compare byte-for-byte.

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

CppContent cpp_decode_content(rust::Slice<const std::uint8_t> data) {
    CppContent out;
    out.ok = false;
    out.known = false;
    out.type_ = 0;
    out.bip = 0;
    out.consumed = 0;
    auto res = wallet::DecodeContentType(std::span<const uint8_t>(data.data(), data.size()));
    if (!res) return out;
    const auto& [content, consumed] = *res;
    if (content) {
        out.known = true;
        out.type_ = static_cast<uint8_t>(content->type);
        out.bip = content->bip_number;
        for (uint8_t b : content->payload) out.payload.push_back(b);
    }
    out.consumed = consumed;
    out.ok = true;
    return out;
}

CppPaths cpp_decode_paths(rust::Slice<const std::uint8_t> data) {
    CppPaths out;
    out.ok = false;
    auto res = wallet::DecodeDerivationPaths(std::span<const uint8_t>(data.data(), data.size()));
    if (!res) return out;
    for (const auto& p : *res) {
        CppPath cp;
        for (uint32_t c : p) cp.child.push_back(c);
        out.paths.push_back(std::move(cp));
    }
    out.ok = true;
    return out;
}

CppBytes cpp_decode_secrets(rust::Slice<const std::uint8_t> data) {
    CppBytes out;
    out.ok = false;
    auto res = wallet::DecodeIndividualSecrets(std::span<const uint8_t>(data.data(), data.size()));
    if (!res) return out;
    for (const uint256& s : *res) {
        for (int i = 0; i < 32; ++i) out.bytes.push_back(s.data()[i]);
    }
    out.ok = true;
    return out;
}

// Copy an encoder's result into the shared byte vector.
static CppBytes to_bytes(const util::Result<std::vector<uint8_t>>& res) {
    CppBytes out;
    out.ok = false;
    if (!res) return out;
    for (uint8_t b : *res) out.bytes.push_back(b);
    out.ok = true;
    return out;
}

CppBytes cpp_encode_content(std::uint8_t type_, std::uint16_t bip,
                            rust::Slice<const std::uint8_t> payload) {
    wallet::EncryptedBackupContentType content;
    content.type = static_cast<wallet::DataType>(type_);
    content.bip_number = bip;
    content.payload.assign(payload.begin(), payload.end());
    return to_bytes(wallet::EncodeContentType(content));
}

CppBytes cpp_encode_paths(rust::Slice<const CppPath> paths) {
    std::vector<wallet::DerivationPath> in;
    for (const CppPath& p : paths) in.emplace_back(p.child.begin(), p.child.end());
    return to_bytes(wallet::EncodeDerivationPaths(in));
}

CppBytes cpp_encode_secrets(rust::Slice<const std::uint8_t> secrets) {
    std::vector<uint256> in;
    for (size_t i = 0; i + 32 <= secrets.size(); i += 32) {
        in.emplace_back(std::span<const unsigned char>(secrets.data() + i, 32));
    }
    return to_bytes(wallet::EncodeIndividualSecrets(in));
}

CppBytes cpp_reencode(rust::Slice<const std::uint8_t> data) {
    CppBytes out;
    out.ok = false;
    auto res = wallet::DecodeEncryptedBackup(std::span<const uint8_t>(data.data(), data.size()));
    if (!res) return out;
    for (uint8_t b : wallet::EncodeEncryptedBackup(*res)) out.bytes.push_back(b);
    out.ok = true;
    return out;
}

}  // namespace bip138shim
