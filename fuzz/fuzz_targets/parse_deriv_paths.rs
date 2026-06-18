#![no_main]

use bip138::ll::parse_derivation_paths;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = parse_derivation_paths(bytes);
});
