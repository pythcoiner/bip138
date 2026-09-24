#![no_main]

use encrypted_backup_fuzz::ComponentInput;
use libfuzzer_sys::fuzz_target;

// Run every arm's component codecs (content type, derivation paths, individual
// secrets) on the same input and compare accept/reject and the results.
fuzz_target!(|input: ComponentInput| {
    encrypted_backup_fuzz::diff_components(input);
});
