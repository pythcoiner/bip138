// Included at the top of the cxx-generated bridge header, so it declares the C++
// functions (defined in shim.cpp) that cxx's trampolines call. The shared structs
// are only forward-declared here; a by-value return in a declaration needs no
// complete type, and shim.cpp sees the full definitions from the generated header.
#pragma once

#include "rust/cxx.h"

#include <cstdint>

namespace bip138shim {

struct CppDecoded;
struct CppItems;
struct CppContent;
struct CppPaths;
struct CppBytes;
struct CppPath;

CppDecoded cpp_decode(::rust::Slice<::std::uint8_t const> data);
CppItems cpp_decrypt(::rust::Slice<::std::uint8_t const> data,
                     ::rust::Slice<::std::uint8_t const> key);
CppContent cpp_decode_content(::rust::Slice<::std::uint8_t const> data);
CppPaths cpp_decode_paths(::rust::Slice<::std::uint8_t const> data);
CppBytes cpp_decode_secrets(::rust::Slice<::std::uint8_t const> data);
CppBytes cpp_encode_content(::std::uint8_t type_, ::std::uint16_t bip,
                            ::rust::Slice<::std::uint8_t const> payload);
CppBytes cpp_encode_paths(::rust::Slice<CppPath const> paths);
CppBytes cpp_encode_secrets(::rust::Slice<::std::uint8_t const> secrets);

}  // namespace bip138shim
