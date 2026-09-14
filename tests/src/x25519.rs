use crate::{ffi::x25519, fixture::fixture, helpers::eq};

#[test]
fn x25519_vectors_and_iterative_result() {
    let f = fixture("x25519_test.asm");
    let mut o = [0; 32];
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["alice_scalar"].as_ptr(),
            f["basepoint"].as_ptr(),
        )
    };
    eq(&o, &f["alice_public"]);
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["bob_scalar"].as_ptr(),
            f["basepoint"].as_ptr(),
        )
    };
    eq(&o, &f["bob_public"]);
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["alice_scalar"].as_ptr(),
            f["bob_public"].as_ptr(),
        )
    };
    eq(&o, &f["shared1"]);
    for (s, u, e) in [
        ("scalar1", "u1", "expected1"),
        ("scalar2", "u2", "expected2"),
    ] {
        unsafe { x25519(o.as_mut_ptr(), f[s].as_ptr(), f[u].as_ptr()) };
        eq(&o, &f[e]);
    }
    let i = fixture("x25519_iterative_test.asm");
    unsafe { x25519(o.as_mut_ptr(), i["value"].as_ptr(), i["value"].as_ptr()) };
    eq(&o, &i["expected"]);
}
