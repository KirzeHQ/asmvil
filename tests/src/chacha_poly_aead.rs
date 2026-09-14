use crate::{
    ffi::*,
    fixture::fixture,
    helpers::{ctx, eq},
};
use chacha20::ChaCha20;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::{Key, Poly1305, universal_hash::UniversalHash};

// Compare stream and block output with the independent cipher implementations.
#[test]
fn zchacha_block_streaming_in_place_and_failure() {
    let f = fixture("chacha20_test.asm");
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
    let f = fixture("poly1305_test.asm");
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
    let f = fixture("aead_test.asm");
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
