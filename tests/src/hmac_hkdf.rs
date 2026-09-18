use crate::{ffi::*, helpers::eq};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

fn test_vectors() -> std::collections::HashMap<&'static str, Vec<u8>> {
    let mut out = std::collections::HashMap::new();
    for (key, len) in [("key1", 20), ("key2", 4), ("key3", 20), ("key4", 25), ("key6", 131), ("key7", 131),
        ("msg1", 8), ("msg2", 28), ("msg3", 50), ("msg4", 50), ("msg6", 54), ("msg7", 152),
        ("ikm1", 22), ("ikm2", 80), ("ikm3", 22), ("ikm512", 32), ("ikm384", 32),
        ("salt1", 13), ("salt2", 16), ("salt512", 16), ("salt384", 16), ("salt3", 0),
        ("info1", 10), ("info2", 8), ("info3", 8), ("info512", 8), ("info384", 8),
        ("sec25_32", 32), ("sec25_48", 48), ("sec25_64", 64), ("lbl_exp", 9),
        ("lbl_skey", 5), ("lbl_ctx", 3), ("lbl_der", 3), ("ctx0", 0), ("ctx24", 24),
        ("ctx64", 64), ("ctx99_32", 32)] {
        out.insert(key, (0..len).map(|i| i as u8).collect());
    }
    out.insert("ikm1", vec![0x0b; 22]);
    out.insert("salt1", (0u8..=12).collect());
    out.insert("info1", (0xf0u8..=0xf9).collect());
    out
}

// Match the assembly's TLS label encoding before asking hkdf for the reference.
fn tls_label(secret: &[u8], label: &[u8], context: &[u8], n: usize, hash: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(3 + label.len() + context.len());
    // The assembly API uses its historical wire format: length, "tls13 ", label.
    info.extend_from_slice(&(n as u16).to_be_bytes());
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0; n];
    match hash {
        32 => Hkdf::<Sha256>::from_prk(secret)
            .unwrap()
            .expand(&info, &mut out)
            .unwrap(),
        48 => Hkdf::<Sha384>::from_prk(secret)
            .unwrap()
            .expand(&info, &mut out)
            .unwrap(),
        _ => Hkdf::<Sha512>::from_prk(secret)
            .unwrap()
            .expand(&info, &mut out)
            .unwrap(),
    }
    out
}

#[test]
fn hmac_all_vectors() {
    let f = test_vectors();
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
        let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
        m.update(msg);
        eq(&o[..32], &m.finalize().into_bytes());
        unsafe {
            hmac_sha384(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                o.as_mut_ptr(),
            )
        };
        let mut m = Hmac::<Sha384>::new_from_slice(key).unwrap();
        m.update(msg);
        eq(&o[..48], &m.finalize().into_bytes());
        unsafe {
            hmac_sha512(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                o.as_mut_ptr(),
            )
        };
        let mut m = Hmac::<Sha512>::new_from_slice(key).unwrap();
        m.update(msg);
        eq(&o[..64], &m.finalize().into_bytes());
    }
}

fn hkdf_case(hash: usize, ikm: &[u8], salt: &[u8], info: &[u8], okm_len: usize) {
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
                    okm_len,
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
                    okm_len,
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
                    okm_len,
                )
            }
        }
    };
    let mut expected = vec![0; okm_len];
    match hash {
        32 => {
            let h = Hkdf::<Sha256>::new(Some(salt), ikm);
            h.expand(info, &mut expected).unwrap();
            eq(
                &p[..hash],
                Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice(),
            );
        }
        48 => {
            let h = Hkdf::<Sha384>::new(Some(salt), ikm);
            h.expand(info, &mut expected).unwrap();
            eq(
                &p[..hash],
                Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice(),
            );
        }
        _ => {
            let h = Hkdf::<Sha512>::new(Some(salt), ikm);
            h.expand(info, &mut expected).unwrap();
            eq(
                &p[..hash],
                Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice(),
            );
        }
    }
    eq(&o[..okm_len], &expected);
}

#[test]
fn hkdf_extract_expand_tls_label_and_derive_secret() {
    let f = test_vectors();
    for (h, ik, s, inf, okm_len) in [(32, "ikm1", "salt1", "info1", 42)] {
        let ikmlen = match ik {
            "ikm1" | "ikm3" => 22,
            "ikm2" => 80,
            _ => 32,
        };
        hkdf_case(
            h,
            &f[ik][..ikmlen],
            &f[s][..if s == "salt3" { 0 } else { f[s].len() }],
            &f[inf],
            okm_len,
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
    eq(
        &o[..42],
        &tls_label(&f["sec25_32"], &f["lbl_exp"], &[], 42, 32),
    );
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
    eq(
        &o[..48],
        &tls_label(&f["sec25_48"], &f["lbl_skey"], &f["ctx24"], 48, 48),
    );
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
    eq(
        &o,
        &tls_label(&f["sec25_64"], &f["lbl_ctx"], &f["ctx64"], 64, 64),
    );
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
    eq(
        &o[..32],
        &tls_label(&f["sec25_32"], &f["lbl_der"], &[], 32, 32),
    );
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
    eq(
        &o[..48],
        &tls_label(&f["sec25_48"], &f["lbl_der"], &f["ctx99_32"], 48, 48),
    );
}
