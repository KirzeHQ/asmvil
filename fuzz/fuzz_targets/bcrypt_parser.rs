#![no_main]

use libfuzzer_sys::fuzz_target;

#[repr(C)]
struct BcryptDecodeRequestV2 {
    version: u32,
    size: u32,
    hash: *const u8,
    hash_len: usize,
    salt: *mut u8,
    cost: *mut u32,
    checksum: *mut u8,
    variant: *mut u32,
}

unsafe extern "C" {
    fn bcrypt_decode(
        hash: *const u8,
        hash_len: usize,
        salt: *mut u8,
        cost: *mut u32,
        checksum: *mut u8,
    ) -> u64;
    fn bcrypt_decode_v2(request: *const BcryptDecodeRequestV2) -> u64;
}

fuzz_target!(|data: &[u8]| {
    let mut hash = [0u8; 60];
    let copy_len = data.len().min(hash.len());
    hash[..copy_len].copy_from_slice(&data[..copy_len]);

    let mut salt = [0xa5u8; 16];
    let mut cost = 0xa5a5_a5a5;
    let mut checksum = [0xa5u8; 23];
    let mut variant = 0xa5a5_a5a5;

    unsafe {
        let _ = bcrypt_decode(
            hash.as_ptr(),
            hash.len(),
            salt.as_mut_ptr(),
            &mut cost,
            checksum.as_mut_ptr(),
        );
    }

    let request = BcryptDecodeRequestV2 {
        version: data.get(0).copied().unwrap_or(2) as u32,
        size: data.get(1).copied().unwrap_or(56) as u32,
        hash: hash.as_ptr(),
        hash_len: data.get(2).copied().unwrap_or(60) as usize,
        salt: salt.as_mut_ptr(),
        cost: &mut cost,
        checksum: checksum.as_mut_ptr(),
        variant: &mut variant,
    };
    unsafe {
        let _ = bcrypt_decode_v2(&request);
    }
});
