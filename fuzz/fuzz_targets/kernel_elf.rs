#![no_main]

use libfuzzer_sys::fuzz_target;
use polytope_boot_elf::{
    MAX_LOAD_ADDRESS_EXCLUSIVE, MAX_LOAD_SEGMENTS, MAX_TOTAL_LOAD_SIZE, MIN_LOAD_ADDRESS,
    PAGE_SIZE, parse,
};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(elf) = parse(bytes) {
        let segments: Vec<_> = elf.segments().collect();
        assert!(!segments.is_empty());
        assert_eq!(segments.len(), usize::from(elf.segment_count()));
        assert!(segments.len() <= usize::from(MAX_LOAD_SEGMENTS));
        assert!(segments.iter().all(|segment| {
            segment.physical_address() == segment.virtual_address()
                && segment.physical_address() >= MIN_LOAD_ADDRESS
                && segment
                    .physical_address()
                    .checked_add(segment.memory_size())
                    .is_some_and(|end| end <= MAX_LOAD_ADDRESS_EXCLUSIVE)
                && segment.memory_size() > 0
                && segment.file_size() <= segment.memory_size()
                && segment.flags().is_readable()
                && !(segment.flags().is_writable() && segment.flags().is_executable())
        }));
        assert!(segments.windows(2).all(|pair| {
            pair[0]
                .physical_address()
                .checked_add(pair[0].memory_size())
                .and_then(|end| end.checked_add(PAGE_SIZE - 1))
                .map(|end| end & !(PAGE_SIZE - 1))
                .is_some_and(|page_end| page_end <= pair[1].physical_address())
        }));
        let total_memory_size = segments
            .iter()
            .try_fold(0_u64, |total, segment| {
                total.checked_add(segment.memory_size())
            })
            .expect("validated aggregate load size cannot overflow");
        assert!(total_memory_size <= MAX_TOTAL_LOAD_SIZE);
        assert!(segments.iter().any(|segment| {
            segment.flags().is_executable()
                && elf.entry_point() >= segment.virtual_address()
                && elf.entry_point()
                    < segment
                        .virtual_address()
                        .checked_add(segment.memory_size())
                        .expect("validated segment end cannot overflow")
        }));
    }
});
