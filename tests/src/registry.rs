#[repr(C)]
struct Record {
    version: u32,
    record_size: u32,
    signature_id: u64,
    flags: u64,
    name: *const u8,
    name_len: u64,
    function: u64,
    context_size: u64,
}

// Discovery must expose metadata and the native function address to Rust.
#[test]
fn assembly_testing_registry_is_discoverable() {
    assert_eq!(unsafe { crate::ffi::asmvil_test_registry_version() }, 1);
    let begin = unsafe { crate::ffi::asmvil_test_registry_begin() };
    let end = unsafe { crate::ffi::asmvil_test_registry_end() };
    assert!(!begin.is_null());
    assert!(end as usize >= begin as usize);
    let bytes = end as usize - begin as usize;
    assert_eq!(bytes % core::mem::size_of::<Record>(), 0);
    assert!(bytes >= core::mem::size_of::<Record>());
    let record = unsafe { &*(begin as *const Record) };
    assert_eq!(record.version, 1);
    assert_eq!(record.record_size, 56);
    assert_ne!(record.signature_id, 0);
    assert!(record.name_len > 0);
    assert_ne!(record.function, 0);
}
