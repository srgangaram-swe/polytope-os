#![no_main]

use libfuzzer_sys::fuzz_target;
use polytope_boot_contract::{BOOT_INFO_SIZE, parse};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(validated) = parse(bytes) {
        let info = validated.into_inner();
        let mut encoded = [0_u8; BOOT_INFO_SIZE];
        let length = info
            .encode(&mut encoded)
            .expect("a validated contract must remain encodable");
        assert_eq!(length, BOOT_INFO_SIZE);
        assert_eq!(&encoded, bytes);
        assert!(parse(&encoded).is_ok());
    }
});
