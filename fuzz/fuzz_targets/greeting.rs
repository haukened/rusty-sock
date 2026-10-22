#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((_, used)) = rusty_sock::proto::greeting::parse(data) {
        assert!(used <= data.len());
    }
});
