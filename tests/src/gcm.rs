use crate::{
    ffi::*,
    helpers::{ctx, eq},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};

fn test_vectors() -> std::collections::HashMap<&'static str, Vec<u8>> {
    let mut out = std::collections::HashMap::new();
    for (key, len) in [("key0", 16), ("iv0", 12), ("key3", 16), ("iv3", 12),
        ("aad17", 17), ("pt3", 64), ("zero_pt", 160)] {
        out.insert(key, (0..len).map(|i| i as u8).collect());
    }
    out
}

// AES-GCM computes the expected ciphertext and tag independently of assembly.
fn gcm_ref(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut data = plaintext.to_vec();
    let tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut data)
            .unwrap(),
        32 => Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut data)
            .unwrap(),
        _ => panic!("unsupported AES-GCM key length"),
    };
    (data, tag.into())
}

#[test]
fn gcm_vectors_streaming_partials_failures_and_open() {
    let f = test_vectors();
    let mut c = ctx();
    let mut out = vec![0; 160];
    let mut tag = [0; 16];
    unsafe {
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr()),
            1
        );
        assert_eq!(gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr()), 1);
        eq(&tag, &gcm_ref(&f["key0"], &f["iv0"], &[], &[]).1);
        assert_eq!(gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr()), 1);
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr()),
            1
        );
        gcm_seal(c.as_mut_ptr(), f["zero_pt"].as_ptr(), out.as_mut_ptr(), 16);
        let (expected, expected_tag) = gcm_ref(&f["key0"], &f["iv0"], &[], &f["zero_pt"][..16]);
        eq(&out[..16], &expected);
        assert_eq!(gcm_verify(c.as_mut_ptr(), expected_tag.as_ptr()), 1);
        gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
        let mut bad_tag = expected_tag;
        bad_tag[15] ^= 1;
        assert_eq!(gcm_verify(c.as_mut_ptr(), bad_tag.as_ptr()), 0);
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key3"].as_ptr(), 10, f["iv3"].as_ptr()),
            1
        );
        gcm_update_aad(c.as_mut_ptr(), f["aad17"].as_ptr(), 1);
        gcm_update_aad(c.as_mut_ptr(), f["key0"].as_ptr(), 0);
        gcm_update_aad(c.as_mut_ptr(), f["aad17"][1..].as_ptr(), 16);
        gcm_seal(c.as_mut_ptr(), f["pt3"].as_ptr(), out.as_mut_ptr(), 64);
        let (expected, _) = gcm_ref(&f["key3"], &f["iv3"], &f["aad17"], &f["pt3"]);
        eq(&out[..64], &expected);
        gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
        eq(
            &tag,
            &gcm_ref(&f["key3"], &f["iv3"], &f["aad17"], &f["pt3"]).1,
        );
        for n in [1, 15, 17, 31] {
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr());
            gcm_seal(c.as_mut_ptr(), f["zero_pt"].as_ptr(), out.as_mut_ptr(), n);
            let (expected, expected_tag) = gcm_ref(&f["key0"], &f["iv0"], &[], &f["zero_pt"][..n]);
            eq(&out[..n], &expected);
            gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
            eq(&tag, &expected_tag);
        }
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 12, f["iv0"].as_ptr()),
            0
        );
        assert_eq!(gcm_verify(c.as_mut_ptr(), f["key0"].as_ptr()), 0);
    }
}
