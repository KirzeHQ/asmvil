use crate::{ffi::{bcrypt_hash, bcrypt_verify}, helpers::eq};

#[test]
fn bcrypt_known_vector() {
    let password = b"password\0";
    let salt = [
        0xdb, 0x7e, 0x39, 0xeb, 0xbf, 0x3d, 0xfb, 0xf7,
        0x1d, 0x79, 0xf8, 0x21, 0, 0, 0, 0, 0,
    ];
    let mut output = [0u8; 24];
    unsafe {
        bcrypt_hash(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            4,
            output.as_mut_ptr(),
        );
    }
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
            4,
            output.as_ptr(),
        )
    }, 0);
}
