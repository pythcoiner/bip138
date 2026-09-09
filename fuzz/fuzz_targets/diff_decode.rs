#![no_main]

use libfuzzer_sys::fuzz_target;

// Feed the same bytes to every decoder and compare accept/reject and the parsed
// fields. Pure framing, no crypto.
fuzz_target!(|data: &[u8]| {
    encrypted_backup_fuzz::diff_decode(data);
});
