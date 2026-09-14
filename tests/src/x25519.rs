use crate::{ffi::x25519, fixture::fixture, helpers::eq};
use x25519_dalek::x25519 as reference_x25519;

// x25519-dalek provides the independent scalar multiplication result.
#[test]
fn x25519_vectors_and_iterative_result() {
    let f = fixture("x25519_test.asm");
    let mut o = [0; 32];
    let bob_public = reference_x25519(
        f["bob_scalar"].as_slice().try_into().unwrap(),
        f["basepoint"].as_slice().try_into().unwrap(),
    );
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["alice_scalar"].as_ptr(),
            f["basepoint"].as_ptr(),
        )
    };
    eq(
        &o,
        &reference_x25519(
            f["alice_scalar"].as_slice().try_into().unwrap(),
            f["basepoint"].as_slice().try_into().unwrap(),
        ),
    );
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["bob_scalar"].as_ptr(),
            f["basepoint"].as_ptr(),
        )
    };
    eq(
        &o,
        &reference_x25519(
            f["bob_scalar"].as_slice().try_into().unwrap(),
            f["basepoint"].as_slice().try_into().unwrap(),
        ),
    );
    unsafe {
        x25519(
            o.as_mut_ptr(),
            f["alice_scalar"].as_ptr(),
            bob_public.as_ptr(),
        )
    };
    eq(
        &o,
        &reference_x25519(f["alice_scalar"].as_slice().try_into().unwrap(), bob_public),
    );
    for (s, u) in [("scalar1", "u1"), ("scalar2", "u2")] {
        unsafe { x25519(o.as_mut_ptr(), f[s].as_ptr(), f[u].as_ptr()) };
        eq(
            &o,
            &reference_x25519(
                f[s].as_slice().try_into().unwrap(),
                f[u].as_slice().try_into().unwrap(),
            ),
        );
    }
    let i = fixture("x25519_iterative_test.asm");
    let value = reference_x25519(
        i["value"].as_slice().try_into().unwrap(),
        i["value"].as_slice().try_into().unwrap(),
    );
    unsafe { x25519(o.as_mut_ptr(), i["value"].as_ptr(), i["value"].as_ptr()) };
    eq(&o, &value);
}
