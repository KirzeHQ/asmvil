use crate::{
    ffi::{bcrypt_decode, bcrypt_encode, bcrypt_generate_salt, bcrypt_hash, bcrypt_verify},
    helpers::eq,
};
use blowfish::Blowfish;

#[repr(C)]
struct BlowfishState {
    s: [[u32; 256]; 4],
    p: [u32; 18],
}

#[test]
fn bcrypt_known_vector() {
    let password = b"password";
    let salt = [
        0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
        0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0,
    ];
    let mut output = [0u8; 24];
    let status = unsafe {
        bcrypt_hash(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, 0);
    eq(
        &output[..23],
        &[
            0x27, 0xd8, 0xa1, 0x7c, 0x40, 0xba, 0x71, 0xc4,
            0xb9, 0x6c, 0xb8, 0x0b, 0x12, 0x81, 0xb7, 0xd3,
            0x46, 0xba, 0x0f, 0x62, 0x08, 0x22, 0x71,
        ],
    );
    assert_eq!(unsafe {
        bcrypt_verify(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_ptr(),
        )
    }, 1);
    output[0] ^= 1;
    assert_eq!(unsafe {
        bcrypt_verify(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_ptr(),
        )
    }, 0);

    for cost in [0, 3, 32] {
        output.fill(0xa5);
        let status = unsafe {
            bcrypt_hash(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                cost,
                output.as_mut_ptr(),
            )
        };
        assert_eq!(status, 1, "cost {cost} should be rejected");
        assert_eq!(output, [0xa5; 24]);
    }

    let password_72 = [0x5a; 72];
    assert_eq!(unsafe {
        bcrypt_hash(
            password_72.as_ptr(),
            password_72.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    }, 0);
    let password_73 = [0x5a; 73];
    output.fill(0xa5);
    assert_eq!(unsafe {
        bcrypt_hash(
            password_73.as_ptr(),
            password_73.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    }, 2);
    assert_eq!(output, [0xa5; 24]);

    for salt_len in [0, 15, 17] {
        output.fill(0xa5);
        assert_eq!(unsafe {
            bcrypt_hash(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt_len,
                4,
                output.as_mut_ptr(),
            )
        }, 3);
        assert_eq!(output, [0xa5; 24]);
    }

    let mut generated = [0u8; 16];
    assert_eq!(unsafe { bcrypt_generate_salt(generated.as_mut_ptr()) }, 0);
    assert_ne!(generated, [0u8; 16]);

    let mut encoded = [0u8; 61];
    assert_eq!(unsafe {
        bcrypt_hash(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(unsafe {
        bcrypt_encode(
            salt.as_ptr(),
            output.as_ptr(),
            4,
            encoded.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(
        &encoded,
        b"$2b$04$0123456789abcdef......H7gfdCA4aaQ3ZJeJCmE1yyY4B0GGGlC\0",
    );
    let mut decoded_salt = [0u8; 16];
    let mut decoded_cost = 0;
    let mut decoded_checksum = [0u8; 23];
    assert_eq!(unsafe {
        bcrypt_decode(
            encoded.as_ptr(),
            60,
            decoded_salt.as_mut_ptr(),
            &mut decoded_cost,
            decoded_checksum.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(decoded_salt, salt);
    assert_eq!(decoded_cost, 4);
    eq(&decoded_checksum, &output[..23]);

    assert_eq!(unsafe {
        bcrypt_encode(
            salt.as_ptr(),
            output.as_ptr(),
            31,
            encoded.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(&encoded[..6], b"$2b$31");
    assert_eq!(unsafe {
        bcrypt_decode(
            encoded.as_ptr(),
            60,
            decoded_salt.as_mut_ptr(),
            &mut decoded_cost,
            decoded_checksum.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(decoded_cost, 31);

    for invalid in [
        b"$2a$04$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
        b"$2b$32$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
    ] {
        assert_eq!(unsafe {
            bcrypt_decode(
                invalid.as_ptr(),
                invalid.len(),
                decoded_salt.as_mut_ptr(),
                &mut decoded_cost,
                decoded_checksum.as_mut_ptr(),
            )
        }, 1);
    }
}

#[test]
fn bcrypt_external_compatibility_vectors() {
    for (password, salt_input, cost) in [
        (
            b"password".as_slice(),
            [
                0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
                0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0,
            ],
            4,
        ),
        (
            b"password".as_slice(),
            [
                0x07, 0x11, 0x1b, 0x25, 0x2f, 0x39, 0x43, 0x4d,
                0x57, 0x61, 0x6b, 0x75, 0x7f, 0x89, 0x93, 0x9d,
            ],
            5,
        ),
        (
            b"hunter2".as_slice(),
            [
                0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
                0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01,
            ],
            10,
        ),
        (
            b"".as_slice(),
            [
                0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
                0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0,
            ],
            4,
        ),
    ] {
        let encoded = bcrypt::hash_with_salt_bytes(password, cost, salt_input).unwrap();
        let mut salt = [0u8; 16];
        let mut decoded_cost = 0;
        let mut expected = [0u8; 23];
        assert_eq!(unsafe {
            bcrypt_decode(
                encoded.as_ptr(),
                encoded.len(),
                salt.as_mut_ptr(),
                &mut decoded_cost,
                expected.as_mut_ptr(),
            )
        }, 0);
        assert_eq!(salt, salt_input);
        assert_eq!(decoded_cost, cost);
        let mut checksum = [0u8; 24];
        assert_eq!(unsafe {
            bcrypt_hash(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                cost,
                checksum.as_mut_ptr(),
            )
        }, 0);
        eq(&checksum[..23], &expected);
        assert_eq!(unsafe {
            bcrypt_verify(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                cost,
                checksum.as_ptr(),
            )
        }, 1);
    }
}

#[test]
fn bcrypt_salt_stream_words_are_big_endian_and_cyclic() {
    let salt = [
        0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
        0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0,
    ];
    for (index, word, next) in [
        (0, 0xdb7e39eb, 4),
        (4, 0xbf3dfbf7, 8),
        (8, 0x1d79f821, 12),
        (12, 0x00000000, 0),
    ] {
        let packed = unsafe { crate::ffi::bcrypt_debug_stream_word(salt.as_ptr(), 16, index) };
        assert_eq!(packed >> 32, word);
        assert_eq!(packed as u32, next);
    }
}

#[test]
fn bcrypt_initial_expand_matches_rust_blowfish_state() {
    let password = b"password";
    let salt = [
        0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
        0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0,
    ];
    let mut p = [0u32; 18];
    let mut s = [0u32; 16];
    assert_eq!(unsafe {
        crate::ffi::bcrypt_debug_initial_state(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            p.as_mut_ptr(),
            s.as_mut_ptr(),
        )
    }, 0);

    let mut key = password.to_vec();
    key.push(0);
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(&salt, &key);
    let raw = unsafe { &*(
        &state as *const Blowfish as *const BlowfishState
    ) };
    assert_eq!(p, raw.p);
    assert_eq!(s, raw.s[0][..16]);
}
