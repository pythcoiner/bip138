#![no_main]

use encrypted_backup_fuzz::EncodeInput;
use libfuzzer_sys::fuzz_target;

// Encode a valid container, then decrypt it in every arm and compare the
// recovered items (cross-implementation encrypt/decrypt interop).
fuzz_target!(|input: EncodeInput| {
    encrypted_backup_fuzz::diff_decrypt(input);
});
