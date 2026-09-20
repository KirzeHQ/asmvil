use crate::{
    ffi::{bcrypt_decode, bcrypt_encode, bcrypt_generate_salt, bcrypt_hash, bcrypt_verify},
    helpers::eq,
};

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
            0x3a, 0xbe, 0xe1, 0x76, 0xf8, 0xbc, 0xbf, 0x3d,
            0x96, 0x12, 0xae, 0x9d, 0x5c, 0xd6, 0xc4, 0xda,
            0xef, 0xf0, 0x8c, 0x68, 0x13, 0xda, 0x5d,
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

    for cost in [0, 3, 17, 31, 32] {
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
        b"$2b$04$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy\0",
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

    for invalid in [
        b"$2a$04$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
        b"$2b$17$0123456789abcdef......Mp5fbtg6tx0UCo4bVLZC0s9uhEeR0jy",
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
