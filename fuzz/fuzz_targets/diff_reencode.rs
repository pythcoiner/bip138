#![no_main]

use libfuzzer_sys::fuzz_target;

// Decode the same bytes in every arm and, when all accept, re-serialize each
// arm's own parse and compare the containers byte-for-byte.
fuzz_target!(|data: &[u8]| {
    encrypted_backup_fuzz::diff_reencode(data);
});
