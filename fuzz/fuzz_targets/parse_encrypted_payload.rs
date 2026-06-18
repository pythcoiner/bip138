#![no_main]

use bip138::ll::parse_encrypted_payload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = parse_encrypted_payload(bytes);
});
