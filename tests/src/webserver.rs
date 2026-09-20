#[cfg(target_arch = "x86_64")]
#[test]
fn socket_syscalls_support_loopback_lifecycle() {
    const AF_INET: u64 = 2;
    const SOCK_STREAM_NONBLOCK: u64 = 1 | 0x800;

    let listener = unsafe { crate::ffi::web_socket(AF_INET, SOCK_STREAM_NONBLOCK, 0) };
    assert!(listener >= 0, "socket failed: {listener}");

    let address = [2u8, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let bound = unsafe { crate::ffi::web_bind(listener, address.as_ptr(), address.len() as u64) };
    assert_eq!(bound, 0, "bind failed: {bound}");

    let listening = unsafe { crate::ffi::web_listen(listener, 1) };
    assert_eq!(listening, 0, "listen failed: {listening}");

    let mut accepted_address = [0u8; 128];
    let mut accepted_length = accepted_address.len() as u32;
    let accepted = unsafe {
        crate::ffi::web_accept(
            listener,
            accepted_address.as_mut_ptr(),
            &mut accepted_length,
        )
    };
    assert!(
        accepted < 0,
        "accept should block without a client: {accepted}"
    );

    assert_eq!(unsafe { crate::ffi::web_close(listener) }, 0);
}
