#![no_main]

use libfuzzer_sys::fuzz_target;

// Wrap the bytes as the plaintext of a valid container, then decrypt it in every
// arm and compare accept/reject and the recovered items.
fuzz_target!(|data: &[u8]| {
    encrypted_backup_fuzz::diff_plaintext(data);
});
