#![no_main]

extern crate bip138;
use bip138::ll::decode_v1;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|d: &[u8]| {
    let _ = decode_v1(d);
});
