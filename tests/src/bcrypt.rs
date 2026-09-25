use crate::{
    ffi::{bcrypt_decode, bcrypt_decode_v2, bcrypt_encode, bcrypt_encode_v2, bcrypt_generate_salt, bcrypt_hash, bcrypt_hash_v1, bcrypt_hash_v2, bcrypt_verify, bcrypt_verify_v2},
    helpers::eq,
};
use blowfish::Blowfish;

#[repr(C)]
pub(crate) struct BcryptHashRequestV2 {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) variant: u32,
    pub(crate) reserved: u32,
    pub(crate) password: *const u8,
    pub(crate) password_len: usize,
    pub(crate) salt: *const u8,
    pub(crate) salt_len: usize,
    pub(crate) cost: u32,
    pub(crate) reserved2: u32,
    pub(crate) output: *mut u8,
    pub(crate) output_len: usize,
}

#[repr(C)]
pub(crate) struct BcryptEncodeRequestV2 {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) variant: u32,
    pub(crate) reserved: u32,
    pub(crate) salt: *const u8,
    pub(crate) checksum: *const u8,
    pub(crate) cost: u32,
    pub(crate) reserved2: u32,
    pub(crate) output: *mut u8,
    pub(crate) output_len: usize,
}

#[repr(C)]
pub(crate) struct BcryptDecodeRequestV2 {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) hash: *const u8,
    pub(crate) hash_len: usize,
    pub(crate) salt: *mut u8,
    pub(crate) cost: *mut u32,
    pub(crate) checksum: *mut u8,
    pub(crate) variant: *mut u32,
}

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
    output[23] = 1;
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

    for prefix in [b'y'] {
        let mut variant = encoded;
        variant[2] = prefix;
        assert_eq!(unsafe {
            bcrypt_decode(
                variant.as_ptr(),
                60,
                decoded_salt.as_mut_ptr(),
                &mut decoded_cost,
                decoded_checksum.as_mut_ptr(),
            )
        }, 0);
        assert_eq!(decoded_cost, 4);
        assert_eq!(decoded_salt, salt);
        eq(&decoded_checksum, &output[..23]);
    }

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

    let mut noncanonical = encoded;
    noncanonical[59] = b'/';
    decoded_salt.fill(0xa5);
    decoded_checksum.fill(0xa5);
    decoded_cost = 0xa5;
    assert_eq!(unsafe {
        bcrypt_decode(
            noncanonical.as_ptr(),
            60,
            decoded_salt.as_mut_ptr(),
            &mut decoded_cost,
            decoded_checksum.as_mut_ptr(),
        )
    }, 1);
    assert_eq!(decoded_salt, [0xa5; 16]);
    assert_eq!(decoded_cost, 0xa5);
    assert_eq!(decoded_checksum, [0xa5; 23]);

    for invalid in [
        b"$2a$04$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
        b"$2x$04$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
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
fn bcrypt_v1_symbol_matches_unversioned_abi() {
    let password = b"password";
    let salt = [0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
        0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0];
    let mut unversioned = [0u8; 24];
    let mut versioned = [0u8; 24];
    assert_eq!(unsafe {
        bcrypt_hash(
            password.as_ptr(), password.len(), salt.as_ptr(), salt.len(), 4,
            unversioned.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(unsafe {
        bcrypt_hash_v1(
            password.as_ptr(), password.len(), salt.as_ptr(), salt.len(), 4,
            versioned.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(unversioned, versioned);
}

#[test]
fn bcrypt_v2_variants_share_versioned_request_abi() {
    let password = [0x80u8, b'p', b'a', b's', b's'];
    let salt = [0x80u8; 16];
    let mut v1 = [0u8; 24];
    let mut v2 = [0u8; 24];
    let mut v2a = [0u8; 24];
    let base = BcryptHashRequestV2 {
        version: 2,
        size: 72,
        variant: 2,
        reserved: 0,
        password: password.as_ptr(),
        password_len: password.len(),
        salt: salt.as_ptr(),
        salt_len: salt.len(),
        cost: 4,
        reserved2: 0,
        output: v2.as_mut_ptr(),
        output_len: v2.len(),
    };
    assert_eq!(unsafe {
        bcrypt_hash(
            password.as_ptr(), password.len(), salt.as_ptr(), salt.len(), 4,
            v1.as_mut_ptr(),
        )
    }, 0);
    assert_eq!(unsafe { bcrypt_hash_v2(&base) }, 0);
    assert_eq!(v1, v2);

    let mut request_2a = base;
    request_2a.variant = 1;
    request_2a.output = v2a.as_mut_ptr();
    assert_eq!(unsafe { bcrypt_hash_v2(&request_2a) }, 0);
    assert_eq!(v2, v2a);

    let mut verify_request = request_2a;
    verify_request.output_len = 23;
    assert_eq!(unsafe { bcrypt_verify_v2(&verify_request) }, 1);
    v2a[0] ^= 1;
    assert_eq!(unsafe { bcrypt_verify_v2(&verify_request) }, 0);
    v2a[0] ^= 1;

    let mut encoded = [0u8; 61];
    let encode_2a = BcryptEncodeRequestV2 {
        version: 2,
        size: 56,
        variant: 1,
        reserved: 0,
        salt: salt.as_ptr(),
        checksum: v2a.as_ptr(),
        cost: 4,
        reserved2: 0,
        output: encoded.as_mut_ptr(),
        output_len: encoded.len(),
    };
    assert_eq!(unsafe { bcrypt_encode_v2(&encode_2a) }, 0);
    assert_eq!(&encoded[..4], b"$2a$");

    let mut decoded_salt = [0u8; 16];
    let mut decoded_cost = 0;
    let mut decoded_variant = 0;
    let mut decoded_checksum = [0u8; 23];
    let decode_2a = BcryptDecodeRequestV2 {
        version: 2,
        size: 56,
        hash: encoded.as_ptr(),
        hash_len: 60,
        salt: decoded_salt.as_mut_ptr(),
        cost: &mut decoded_cost,
        checksum: decoded_checksum.as_mut_ptr(),
        variant: &mut decoded_variant,
    };
    assert_eq!(unsafe { bcrypt_decode_v2(&decode_2a) }, 0);
    assert_eq!(decoded_salt, salt);
    assert_eq!(decoded_cost, 4);
    assert_eq!(decoded_variant, 1);
    assert_eq!(&decoded_checksum, &v2a[..23]);
}

#[test]
fn bcrypt_v2_2a_matches_independent_high_bit_vector() {
    let password = [0x80u8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd'];
    let external = b"$2a$04$0123456789abcdef......6gCbKslS5cl4cLlycMUxLi2e6o3YMVi";
    let mut salt = [0u8; 16];
    let mut cost = 0;
    let mut variant = 0;
    let mut checksum = [0u8; 23];
    let decode = BcryptDecodeRequestV2 {
        version: 2,
        size: 56,
        hash: external.as_ptr(),
        hash_len: 60,
        salt: salt.as_mut_ptr(),
        cost: &mut cost,
        checksum: checksum.as_mut_ptr(),
        variant: &mut variant,
    };
    assert_eq!(unsafe { bcrypt_decode_v2(&decode) }, 0);
    assert_eq!(cost, 4);
    assert_eq!(variant, 1);

    let mut raw = [0u8; 24];
    let hash = BcryptHashRequestV2 {
        version: 2,
        size: 72,
        variant,
        reserved: 0,
        password: password.as_ptr(),
        password_len: password.len(),
        salt: salt.as_ptr(),
        salt_len: salt.len(),
        cost,
        reserved2: 0,
        output: raw.as_mut_ptr(),
        output_len: raw.len(),
    };
    assert_eq!(unsafe { bcrypt_hash_v2(&hash) }, 0);

    let mut encoded = [0u8; 61];
    let encode = BcryptEncodeRequestV2 {
        version: 2,
        size: 56,
        variant,
        reserved: 0,
        salt: salt.as_ptr(),
        checksum: raw.as_ptr(),
        cost,
        reserved2: 0,
        output: encoded.as_mut_ptr(),
        output_len: encoded.len(),
    };
    assert_eq!(unsafe { bcrypt_encode_v2(&encode) }, 0);
    assert_eq!(&encoded[..60], external);
}

#[test]
fn bcrypt_v2_2a_matches_collision_safety_vector() {
    let password = [0xff, 0xa3, b'3', b'4', 0xff, 0xff, 0xff, 0xa3, b'3', b'4', b'5'];
    let external = b"$2a$04$abcdefghijklmnopqrstuuE8Lpo1/qkGPTBDBxEsJjeEzh9nkZ9uW";
    let mut salt = [0u8; 16];
    let mut cost = 0;
    let mut variant = 0;
    let mut expected = [0u8; 23];
    let decode = BcryptDecodeRequestV2 {
        version: 2,
        size: 56,
        hash: external.as_ptr(),
        hash_len: 60,
        salt: salt.as_mut_ptr(),
        cost: &mut cost,
        checksum: expected.as_mut_ptr(),
        variant: &mut variant,
    };
    assert_eq!(unsafe { bcrypt_decode_v2(&decode) }, 0);

    let mut raw = [0u8; 24];
    let hash = BcryptHashRequestV2 {
        version: 2,
        size: 72,
        variant,
        reserved: 0,
        password: password.as_ptr(),
        password_len: password.len(),
        salt: salt.as_ptr(),
        salt_len: salt.len(),
        cost,
        reserved2: 0,
        output: raw.as_mut_ptr(),
        output_len: raw.len(),
    };
    assert_eq!(unsafe { bcrypt_hash_v2(&hash) }, 0);

    let mut encoded = [0u8; 61];
    let encode = BcryptEncodeRequestV2 {
        version: 2,
        size: 56,
        variant,
        reserved: 0,
        salt: salt.as_ptr(),
        checksum: raw.as_ptr(),
        cost,
        reserved2: 0,
        output: encoded.as_mut_ptr(),
        output_len: encoded.len(),
    };
    assert_eq!(unsafe { bcrypt_encode_v2(&encode) }, 0);
    assert_eq!(&encoded[..60], external);
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
fn bcrypt_null_pointer_contracts() {
    let password = b"password";
    let salt = [0u8; 16];
    let checksum = [0u8; 23];
    let mut output = [0xa5u8; 24];

    assert_eq!(unsafe {
        bcrypt_hash(
            std::ptr::null(),
            1,
            salt.as_ptr(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    }, 2);
    assert_eq!(output, [0xa5; 24]);

    assert_eq!(unsafe {
        bcrypt_hash(
            password.as_ptr(),
            password.len(),
            std::ptr::null(),
            salt.len(),
            4,
            output.as_mut_ptr(),
        )
    }, 3);
    assert_eq!(output, [0xa5; 24]);

    assert_eq!(unsafe {
        bcrypt_hash(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            std::ptr::null_mut(),
        )
    }, 4);

    assert_eq!(unsafe {
        bcrypt_verify(
            std::ptr::null(),
            1,
            salt.as_ptr(),
            salt.len(),
            4,
            checksum.as_ptr(),
        )
    }, 0);
    assert_eq!(unsafe {
        bcrypt_verify(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            4,
            std::ptr::null(),
        )
    }, 0);
    assert_eq!(unsafe { bcrypt_generate_salt(std::ptr::null_mut()) }, 1);

    let mut encoded = [0xa5u8; 61];
    assert_eq!(unsafe {
        bcrypt_encode(
            std::ptr::null(),
            checksum.as_ptr(),
            4,
            encoded.as_mut_ptr(),
        )
    }, 1);
    assert_eq!(encoded, [0xa5; 61]);
    assert_eq!(unsafe {
        bcrypt_encode(
            salt.as_ptr(),
            checksum.as_ptr(),
            4,
            std::ptr::null_mut(),
        )
    }, 1);

    let hash = b"$2b$04$0123456789abcdef......H7gfdCA4aaQ3ZJeJCmE1yyY4B0GGGlC";
    let decoded_salt = [0xa5u8; 16];
    let mut decoded_cost = 0xa5a5_a5a5;
    let mut decoded_checksum = [0xa5u8; 23];
    assert_eq!(unsafe {
        bcrypt_decode(
            hash.as_ptr(),
            hash.len(),
            std::ptr::null_mut(),
            &mut decoded_cost,
            decoded_checksum.as_mut_ptr(),
        )
    }, 1);
    assert_eq!(decoded_salt, [0xa5; 16]);
    assert_eq!(decoded_cost, 0xa5a5_a5a5);
    assert_eq!(decoded_checksum, [0xa5; 23]);
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
