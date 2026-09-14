use crate::{
    ffi::{
        aes_encrypt, aes128_decrypt, aes128_encrypt, aes128_expand, aes256_decrypt, aes256_encrypt,
        aes256_expand,
    },
    fixture::fixture,
    helpers::eq,
};

#[test]
fn aes_vectors_schedules_generic_and_decrypt() {
    let f = fixture("aes_test.asm");
    let k128 = f["key128a"].clone();
    let p = f["pt_a1"].clone();
    let mut s = [0; 176];
    let mut o = [0; 16];
    unsafe {
        aes128_expand(k128.as_ptr(), s.as_mut_ptr());
        aes128_encrypt(s.as_ptr(), p.as_ptr(), o.as_mut_ptr());
    }
    eq(&s, &f["exp_sched128a"]);
    eq(&o, &f["exp_ct_a1"]);
    unsafe { aes128_decrypt(s.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &p);
    let k = f["key128b"].clone();
    unsafe {
        aes128_expand(k.as_ptr(), s.as_mut_ptr());
        aes_encrypt(s.as_ptr(), f["pt_c1"].as_ptr(), o.as_mut_ptr(), 10)
    };
    eq(&o, &f["exp_ct_c1"]);
    let k = f["key256"].clone();
    let mut s256 = [0; 240];
    unsafe {
        aes256_expand(k.as_ptr(), s256.as_mut_ptr());
        aes256_encrypt(s256.as_ptr(), f["pt_c3"].as_ptr(), o.as_mut_ptr())
    };
    eq(&s256, &f["exp_sched256"]);
    eq(&o, &f["exp_ct_c3"]);
    unsafe { aes256_decrypt(s256.as_ptr(), o.as_ptr(), o.as_mut_ptr()) };
    eq(&o, &f["pt_c3"]);
}
