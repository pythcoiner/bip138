#![no_main]

use encrypted_backup_fuzz::EncodeInput;
use libfuzzer_sys::fuzz_target;

// Encode the same structured input in every arm with an explicit nonce and
// decoys, then compare the container byte-for-byte.
fuzz_target!(|input: EncodeInput| {
    encrypted_backup_fuzz::diff_encode(input);
});
