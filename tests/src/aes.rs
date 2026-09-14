use crate::{ffi::*, fixture::fixture, helpers::eq};
use aes::{Aes128, Aes256};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

// Schedules remain assembly-specific, while block results come from RustCrypto.
#[test]
fn aes_vectors_schedules_generic_and_decrypt() {
    let f = fixture("aes_test.asm");
    let mut s = [0; 176];
    let mut o = [0; 16];
    unsafe {
        aes128_expand(f["key128a"].as_ptr(), s.as_mut_ptr());
        aes128_encrypt(s.as_ptr(), f["pt_a1"].as_ptr(), o.as_mut_ptr());
    }
    let c = Aes128::new_from_slice(&f["key128a"]).unwrap();
    let mut want = GenericArray::clone_from_slice(&f["pt_a1"]);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    unsafe { aes128_decrypt(s.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &f["pt_a1"]);
    unsafe {
        aes128_expand(f["key128b"].as_ptr(), s.as_mut_ptr());
        aes_encrypt(s.as_ptr(), f["pt_c1"].as_ptr(), o.as_mut_ptr(), 10);
    }
    let c = Aes128::new_from_slice(&f["key128b"]).unwrap();
    let mut want = GenericArray::clone_from_slice(&f["pt_c1"]);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    let mut s256 = [0; 240];
    unsafe {
        aes256_expand(f["key256"].as_ptr(), s256.as_mut_ptr());
        aes256_encrypt(s256.as_ptr(), f["pt_c3"].as_ptr(), o.as_mut_ptr());
    }
    let c = Aes256::new_from_slice(&f["key256"]).unwrap();
    let mut want = GenericArray::clone_from_slice(&f["pt_c3"]);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    unsafe { aes256_decrypt(s256.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &f["pt_c3"]);
}
