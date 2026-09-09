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

CppDecoded cpp_decode(::rust::Slice<::std::uint8_t const> data);
CppItems cpp_decrypt(::rust::Slice<::std::uint8_t const> data,
                     ::rust::Slice<::std::uint8_t const> key);

}  // namespace bip138shim
