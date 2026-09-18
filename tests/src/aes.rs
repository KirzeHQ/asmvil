use crate::{ffi::*, helpers::eq};
use aes::{Aes128, Aes256};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

// Schedules remain assembly-specific, while block results come from RustCrypto.
#[test]
fn aes_vectors_schedules_generic_and_decrypt() {
    let key128a = [0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let key128b: Vec<u8> = (0..16).collect();
    let key256: Vec<u8> = (0..32).collect();
    let pt_a1 = [0x32u8, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let pt_c1: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
    let pt_c3 = pt_c1.clone();
    let mut s = [0; 176];
    let mut o = [0; 16];
    unsafe {
        aes128_expand(key128a.as_ptr(), s.as_mut_ptr());
        aes128_encrypt(s.as_ptr(), pt_a1.as_ptr(), o.as_mut_ptr());
    }
    let c = Aes128::new_from_slice(&key128a).unwrap();
    let mut want = GenericArray::clone_from_slice(&pt_a1);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    unsafe { aes128_decrypt(s.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &pt_a1);
    unsafe {
        aes128_expand(key128b.as_ptr(), s.as_mut_ptr());
        aes_encrypt(s.as_ptr(), pt_c1.as_ptr(), o.as_mut_ptr(), 10);
    }
    let c = Aes128::new_from_slice(&key128b).unwrap();
    let mut want = GenericArray::clone_from_slice(&pt_c1);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    let mut s256 = [0; 240];
    unsafe {
        aes256_expand(key256.as_ptr(), s256.as_mut_ptr());
        aes256_encrypt(s256.as_ptr(), pt_c3.as_ptr(), o.as_mut_ptr());
    }
    let c = Aes256::new_from_slice(&key256).unwrap();
    let mut want = GenericArray::clone_from_slice(&pt_c3);
    c.encrypt_block(&mut want);
    eq(&o, &want);
    unsafe { aes256_decrypt(s256.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &pt_c3);
}
