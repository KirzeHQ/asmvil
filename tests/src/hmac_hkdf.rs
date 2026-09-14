use crate::{ffi::*, fixture::fixture, helpers::eq};
use std::collections::HashMap;

#[test]
fn hmac_all_vectors() {
    let f = fixture("hmac_test.asm");
    for (k, m, n) in [
        ("key1", "msg1", 20),
        ("key2", "msg2", 4),
        ("key3", "msg3", 20),
        ("key4", "msg4", 25),
        ("key6", "msg6", 131),
        ("key7", "msg7", 131),
    ] {
        let key = &f[k][..n];
        let msg = &f[m];
        let mut o = [0; 64];
        unsafe {
            hmac_sha256(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                o.as_mut_ptr(),
            )
        };
        eq(
            &o[..32],
            &f[&format!("exp_tc{}_256", k.trim_start_matches("key"))],
        );
        unsafe {
            hmac_sha384(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                o.as_mut_ptr(),
            )
        };
        eq(
            &o[..48],
            &f[&format!("exp_tc{}_384", k.trim_start_matches("key"))],
        );
        unsafe {
            hmac_sha512(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                o.as_mut_ptr(),
            )
        };
        eq(
            &o[..64],
            &f[&format!("exp_tc{}_512", k.trim_start_matches("key"))],
        );
    }
}

fn hkdf_case(
    _f: &HashMap<String, Vec<u8>>,
    hash: usize,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    prk: &[u8],
    okm: &[u8],
) {
    let mut p = [0; 64];
    let mut o = [0; 128];
    unsafe {
        match hash {
            32 => {
                hkdf_sha256_extract(
                    salt.as_ptr(),
                    salt.len(),
                    ikm.as_ptr(),
                    ikm.len(),
                    p.as_mut_ptr(),
                );
                hkdf_sha256_expand(
                    p.as_ptr(),
                    info.as_ptr(),
                    info.len(),
                    o.as_mut_ptr(),
                    okm.len(),
                )
            }
            48 => {
                hkdf_sha384_extract(
                    salt.as_ptr(),
                    salt.len(),
                    ikm.as_ptr(),
                    ikm.len(),
                    p.as_mut_ptr(),
                );
                hkdf_sha384_expand(
                    p.as_ptr(),
                    info.as_ptr(),
                    info.len(),
                    o.as_mut_ptr(),
                    okm.len(),
                )
            }
            _ => {
                hkdf_sha512_extract(
                    salt.as_ptr(),
                    salt.len(),
                    ikm.as_ptr(),
                    ikm.len(),
                    p.as_mut_ptr(),
                );
                hkdf_sha512_expand(
                    p.as_ptr(),
                    info.as_ptr(),
                    info.len(),
                    o.as_mut_ptr(),
                    okm.len(),
                )
            }
        }
    };
    eq(&p[..hash], prk);
    eq(&o[..okm.len()], okm);
}

#[test]
fn hkdf_extract_expand_tls_label_and_derive_secret() {
    let f = fixture("hkdf_test.asm");
    for (h, ik, s, inf, pr, ok) in [
        (32, "ikm1", "salt1", "info1", "prk1", "okm1"),
        (32, "ikm2", "salt2", "info2", "prk2", "okm2"),
        (32, "ikm3", "salt3", "info3", "prk3", "okm3"),
        (64, "ikm512", "salt512", "info512", "prk512a", "okm512a"),
        (64, "ikm512", "salt3", "info512", "prk512z", "okm512z"),
        (48, "ikm384", "salt384", "info384", "prk384a", "okm384a"),
        (48, "ikm384", "salt3", "info384", "prk384z", "okm384z"),
    ] {
        let ikmlen = match ik {
            "ikm1" | "ikm3" => 22,
            "ikm2" => 80,
            _ => 32,
        };
        hkdf_case(
            &f,
            h,
            &f[ik][..ikmlen],
            &f[s][..if s == "salt3" { 0 } else { f[s].len() }],
            &f[inf],
            &f[pr],
            &f[ok],
        );
    }
    let mut o = [0; 64];
    unsafe {
        hkdf_expand_label_sha256(
            f["sec25_32"].as_ptr(),
            f["lbl_exp"].as_ptr(),
            9,
            f["ctx0"].as_ptr(),
            0,
            o.as_mut_ptr(),
            42,
        )
    };
    eq(&o[..42], &f["el256a_out"]);
    unsafe {
        hkdf_expand_label_sha384(
            f["sec25_48"].as_ptr(),
            f["lbl_skey"].as_ptr(),
            5,
            f["ctx24"].as_ptr(),
            24,
            o.as_mut_ptr(),
            48,
        )
    };
    eq(&o[..48], &f["el384_out"]);
    unsafe {
        hkdf_expand_label_sha512(
            f["sec25_64"].as_ptr(),
            f["lbl_ctx"].as_ptr(),
            3,
            f["ctx64"].as_ptr(),
            64,
            o.as_mut_ptr(),
            64,
        )
    };
    eq(&o, &f["el512_out"]);
    unsafe {
        hkdf_derive_secret_sha256(
            f["sec25_32"].as_ptr(),
            f["lbl_der"].as_ptr(),
            7,
            f["ctx0"].as_ptr(),
            0,
            o.as_mut_ptr(),
        )
    };
    eq(&o[..32], &f["ds256_out"]);
    unsafe {
        hkdf_derive_secret_sha384(
            f["sec25_48"].as_ptr(),
            f["lbl_der"].as_ptr(),
            7,
            f["ctx99_32"].as_ptr(),
            32,
            o.as_mut_ptr(),
        )
    };
    eq(&o[..48], &f["ds384_out"]);
}
