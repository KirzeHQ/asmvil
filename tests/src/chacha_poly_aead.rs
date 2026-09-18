use crate::{
    ffi::*,
    helpers::{ctx, eq},
};
use chacha20::ChaCha20;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::{Key, Poly1305, universal_hash::UniversalHash};

fn test_vectors() -> std::collections::HashMap<&'static str, Vec<u8>> {
    let mut out = std::collections::HashMap::new();
    for (key, len) in [("key", 32), ("block_nonce", 12), ("cipher_nonce", 12),
        ("plaintext", 114), ("ciphertext", 114), ("zeroes", 65), ("nonce", 12), ("aad", 12),
        ("key_rfc", 32), ("msg_rfc", 34), ("key_r2_s0", 32), ("key_r2_sff", 32),
        ("key_r1_s0", 32), ("key_r10_s0", 32), ("msg5", 16), ("msg6", 16),
        ("msg7", 48), ("msg8", 48), ("msg9", 16), ("msg10", 64)] {
        out.insert(key, (0..len).map(|i| i as u8).collect());
    }
    out.insert("key", (0x80..=0x9f).collect());
    out.insert("nonce", vec![0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
    out.insert("aad", vec![0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]);
    out.insert("plaintext", b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec());
    out.insert("ciphertext", vec![
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ]);
    out
}

// Compare stream and block output with the independent cipher implementations.
#[test]
fn zchacha_block_streaming_in_place_and_failure() {
    let f = test_vectors();
    let mut b = [0; 64];
    unsafe {
        chacha20_block(
            f["key"].as_ptr(),
            1,
            f["block_nonce"].as_ptr(),
            b.as_mut_ptr(),
        )
    };
    let mut expected = [0; 64];
    let mut block = ChaCha20::new(
        f["key"].as_slice().into(),
        f["block_nonce"].as_slice().into(),
    );
    block.seek(64);
    block.apply_keystream(&mut expected);
    eq(&b, &expected);
    let mut c = ctx();
    let mut out = vec![0; 114];
    unsafe {
        chacha20_init(
            c.as_mut_ptr(),
            f["key"].as_ptr(),
            1,
            f["cipher_nonce"].as_ptr(),
        );
        assert_eq!(
            chacha20_xor(
                c.as_mut_ptr(),
                f["plaintext"].as_ptr(),
                out.as_mut_ptr(),
                63
            ),
            1
        );
        assert_eq!(
            chacha20_xor(
                c.as_mut_ptr(),
                f["plaintext"][63..].as_ptr(),
                out[63..].as_mut_ptr(),
                0
            ),
            1
        );
        assert_eq!(
            chacha20_xor(
                c.as_mut_ptr(),
                f["plaintext"][63..].as_ptr(),
                out[63..].as_mut_ptr(),
                51
            ),
            1
        )
    };
    let mut expected = f["plaintext"].clone();
    let mut stream = ChaCha20::new(
        f["key"].as_slice().into(),
        f["cipher_nonce"].as_slice().into(),
    );
    stream.seek(64);
    stream.apply_keystream(&mut expected);
    eq(&out, &expected);
    let mut in_place = out.clone();
    unsafe {
        chacha20_init(
            c.as_mut_ptr(),
            f["key"].as_ptr(),
            1,
            f["cipher_nonce"].as_ptr(),
        );
        assert_eq!(
            chacha20_xor(
                c.as_mut_ptr(),
                in_place.as_ptr(),
                in_place.as_mut_ptr(),
                114
            ),
            1
        )
    };
    eq(&in_place, &f["plaintext"]);
    unsafe {
        chacha20_init(
            c.as_mut_ptr(),
            f["key"].as_ptr(),
            u32::MAX,
            f["cipher_nonce"].as_ptr(),
        );
        assert_eq!(
            chacha20_xor(c.as_mut_ptr(), f["zeroes"].as_ptr(), out.as_mut_ptr(), 65),
            0
        );
        assert_eq!(
            chacha20_xor(c.as_mut_ptr(), f["zeroes"].as_ptr(), out.as_mut_ptr(), 64),
            1
        );
        assert_eq!(
            chacha20_xor(
                c.as_mut_ptr(),
                f["zeroes"].as_ptr(),
                out[64..].as_mut_ptr(),
                1
            ),
            0
        )
    };
}

#[test]
fn poly1305_vectors_partitions_empty_and_verify() {
    let f = test_vectors();
    let mut c = ctx();
    let mut t = [0; 16];
    unsafe {
        poly1305_init(c.as_mut_ptr(), f["key_rfc"].as_ptr());
        assert_eq!(
            poly1305_update(c.as_mut_ptr(), f["msg_rfc"].as_ptr(), 15),
            1
        );
        assert_eq!(
            poly1305_update(c.as_mut_ptr(), f["msg_rfc"][15..].as_ptr(), 0),
            1
        );
        assert_eq!(
            poly1305_update(c.as_mut_ptr(), f["msg_rfc"][15..].as_ptr(), 1),
            1
        );
        assert_eq!(
            poly1305_update(c.as_mut_ptr(), f["msg_rfc"][16..].as_ptr(), 18),
            1
        );
        assert_eq!(poly1305_final(c.as_mut_ptr(), t.as_mut_ptr()), 1);
        assert_eq!(poly1305_verify(c.as_mut_ptr(), t.as_ptr()), 1);
        let mut bad_tag = t;
        bad_tag[15] ^= 1;
        assert_eq!(poly1305_verify(c.as_mut_ptr(), bad_tag.as_ptr()), 0);
        assert_eq!(poly1305_update(c.as_mut_ptr(), f["msg_rfc"].as_ptr(), 1), 0);
        poly1305_init(c.as_mut_ptr(), f["key_rfc"].as_ptr());
        poly1305_final(c.as_mut_ptr(), t.as_mut_ptr())
    };
    let mut p = Poly1305::new(Key::from_slice(&f["key_rfc"]));
    p.update_padded(&[]);
    let expected = p.finalize();
    eq(&t, &expected);
    for (k, m, n, _tg) in [
        ("key_r2_s0", "msg5", 16, "tag3"),
        ("key_r2_sff", "msg6", 16, "tag3"),
        ("key_r1_s0", "msg7", 48, "tag5"),
        ("key_r1_s0", "msg8", 48, "tag0"),
        ("key_r2_s0", "msg9", 16, "tag9"),
        ("key_r10_s0", "msg10", 64, "tag10"),
        ("key_r10_s0", "msg10", 48, "tag11"),
    ] {
        unsafe {
            poly1305_init(c.as_mut_ptr(), f[k].as_ptr());
            poly1305_update(c.as_mut_ptr(), f[m].as_ptr(), n);
            poly1305_final(c.as_mut_ptr(), t.as_mut_ptr())
        };
        let mut p = Poly1305::new(Key::from_slice(&f[k]));
        p.update_padded(&f[m][..n]);
        let expected = p.finalize();
        eq(&t, &expected);
    }
}

#[test]
fn aead_vectors_streaming_empty_open_and_verify_failure() {
    let f = test_vectors();
    let mut c = ctx();
    let mut out = vec![0; 114];
    let mut tag = [0; 16];
    let empty = [0u8; 1];
    unsafe {
        aead_init(c.as_mut_ptr(), f["key"].as_ptr(), f["nonce"].as_ptr());
        aead_update_aad(c.as_mut_ptr(), f["aad"].as_ptr(), 12);
        aead_seal(
            c.as_mut_ptr(),
            f["plaintext"].as_ptr(),
            out.as_mut_ptr(),
            114,
        );
        let cipher = ChaCha20Poly1305::new(f["key"].as_slice().into());
        let mut expected = f["plaintext"].clone();
        let expected_tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&f["nonce"]), &f["aad"], &mut expected)
            .unwrap();
        eq(&out, &expected);
        aead_final(c.as_mut_ptr(), tag.as_mut_ptr());
        eq(&tag, &expected_tag);
        aead_init(c.as_mut_ptr(), f["key"].as_ptr(), f["nonce"].as_ptr());
        aead_update_aad(c.as_mut_ptr(), f["aad"].as_ptr(), 5);
        aead_update_aad(c.as_mut_ptr(), f["aad"][5..].as_ptr(), 7);
        aead_seal(
            c.as_mut_ptr(),
            f["plaintext"].as_ptr(),
            out.as_mut_ptr(),
            63,
        );
        aead_seal(
            c.as_mut_ptr(),
            f["plaintext"][63..].as_ptr(),
            out[63..].as_mut_ptr(),
            51,
        );
        aead_final(c.as_mut_ptr(), tag.as_mut_ptr());
        eq(&out, &expected);
        eq(&tag, &expected_tag);
        aead_final(c.as_mut_ptr(), tag.as_mut_ptr());
        aead_init(c.as_mut_ptr(), f["key"].as_ptr(), f["nonce"].as_ptr());
        aead_update_aad(c.as_mut_ptr(), empty.as_ptr(), 0);
        aead_seal(c.as_mut_ptr(), empty.as_ptr(), empty.as_ptr() as *mut u8, 0);
        aead_final(c.as_mut_ptr(), tag.as_mut_ptr());
        assert_eq!(aead_verify(c.as_mut_ptr(), tag.as_ptr()), 1);
        aead_init(c.as_mut_ptr(), f["key"].as_ptr(), f["nonce"].as_ptr());
        aead_update_aad(c.as_mut_ptr(), f["aad"].as_ptr(), 12);
        aead_open(
            c.as_mut_ptr(),
            f["ciphertext"].as_ptr(),
            out.as_mut_ptr(),
            114,
        );
        eq(&out, &f["plaintext"]);
        assert_eq!(aead_verify(c.as_mut_ptr(), expected_tag.as_ptr()), 1);
        let mut bad_tag = expected_tag;
        bad_tag[15] ^= 1;
        assert_eq!(aead_verify(c.as_mut_ptr(), bad_tag.as_ptr()), 0);
    }
}
