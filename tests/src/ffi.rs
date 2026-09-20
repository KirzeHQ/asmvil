#![allow(improper_ctypes)]

unsafe extern "C" {
    pub(crate) fn asmvil_test_registry_version() -> u64;
    pub(crate) fn asmvil_test_registry_begin() -> *const u8;
    pub(crate) fn asmvil_test_registry_end() -> *const u8;
    pub(crate) fn aes128_expand(k: *const u8, s: *mut u8);
    pub(crate) fn aes256_expand(k: *const u8, s: *mut u8);
    pub(crate) fn aes128_encrypt(s: *const u8, i: *const u8, o: *mut u8);
    pub(crate) fn aes256_encrypt(s: *const u8, i: *const u8, o: *mut u8);
    pub(crate) fn aes128_decrypt(s: *const u8, i: *const u8, o: *mut u8);
    pub(crate) fn aes256_decrypt(s: *const u8, i: *const u8, o: *mut u8);
    pub(crate) fn aes_encrypt(s: *const u8, i: *const u8, o: *mut u8, rounds: u32);
    pub(crate) fn sha256_init(c: *mut u8);
    pub(crate) fn sha256_update(c: *mut u8, p: *const u8, n: usize);
    pub(crate) fn sha256_final(c: *mut u8, d: *mut u8);
    pub(crate) fn sha512_init(c: *mut u8);
    pub(crate) fn sha384_init(c: *mut u8);
    pub(crate) fn sha512_update(c: *mut u8, p: *const u8, n: usize);
    pub(crate) fn sha512_final(c: *mut u8, d: *mut u8);
    pub(crate) fn hmac_sha256(k: *const u8, kl: usize, p: *const u8, n: usize, o: *mut u8);
    pub(crate) fn hmac_sha384(k: *const u8, kl: usize, p: *const u8, n: usize, o: *mut u8);
    pub(crate) fn hmac_sha512(k: *const u8, kl: usize, p: *const u8, n: usize, o: *mut u8);
    pub(crate) fn hkdf_sha256_extract(s: *const u8, sl: usize, i: *const u8, il: usize, o: *mut u8);
    pub(crate) fn hkdf_sha256_expand(p: *const u8, x: *const u8, xl: usize, o: *mut u8, n: usize);
    pub(crate) fn hkdf_sha384_extract(s: *const u8, sl: usize, i: *const u8, il: usize, o: *mut u8);
    pub(crate) fn hkdf_sha384_expand(p: *const u8, x: *const u8, xl: usize, o: *mut u8, n: usize);
    pub(crate) fn hkdf_sha512_extract(s: *const u8, sl: usize, i: *const u8, il: usize, o: *mut u8);
    pub(crate) fn hkdf_sha512_expand(p: *const u8, x: *const u8, xl: usize, o: *mut u8, n: usize);
    pub(crate) fn hkdf_expand_label_sha256(
        s: *const u8,
        l: *const u8,
        ll: usize,
        c: *const u8,
        cl: usize,
        o: *mut u8,
        n: usize,
    );
    pub(crate) fn hkdf_expand_label_sha384(
        s: *const u8,
        l: *const u8,
        ll: usize,
        c: *const u8,
        cl: usize,
        o: *mut u8,
        n: usize,
    );
    pub(crate) fn hkdf_expand_label_sha512(
        s: *const u8,
        l: *const u8,
        ll: usize,
        c: *const u8,
        cl: usize,
        o: *mut u8,
        n: usize,
    );
    pub(crate) fn hkdf_derive_secret_sha256(
        s: *const u8,
        l: *const u8,
        ll: usize,
        c: *const u8,
        cl: usize,
        o: *mut u8,
    );
    pub(crate) fn hkdf_derive_secret_sha384(
        s: *const u8,
        l: *const u8,
        ll: usize,
        c: *const u8,
        cl: usize,
        o: *mut u8,
    );
    pub(crate) fn chacha20_block(k: *const u8, counter: u32, n: *const u8, o: *mut u8);
    pub(crate) fn chacha20_init(c: *mut u8, k: *const u8, counter: u32, n: *const u8);
    pub(crate) fn chacha20_xor(c: *mut u8, i: *const u8, o: *mut u8, n: usize) -> u8;
    pub(crate) fn poly1305_init(c: *mut u8, k: *const u8);
    pub(crate) fn poly1305_update(c: *mut u8, p: *const u8, n: usize) -> u8;
    pub(crate) fn poly1305_final(c: *mut u8, o: *mut u8) -> u8;
    pub(crate) fn poly1305_verify(c: *mut u8, t: *const u8) -> u64;
    pub(crate) fn bigint_add(o: *mut u64, a: *const u64, b: *const u64, n: usize) -> u64;
    pub(crate) fn bigint_sub(o: *mut u64, a: *const u64, b: *const u64, n: usize) -> u64;
    pub(crate) fn bigint_mul(o: *mut u64, a: *const u64, b: *const u64, n: usize);
    pub(crate) fn bigint_sqr(o: *mut u64, a: *const u64, n: usize);
    pub(crate) fn bigint_shl(o: *mut u64, a: *const u64, n: usize, bits: usize);
    pub(crate) fn bigint_shr(o: *mut u64, a: *const u64, n: usize, bits: usize);
    pub(crate) fn bigint_mod_reduce(o: *mut u64, a: *const u64, m: *const u64, n: usize);
    pub(crate) fn bigint_mod_inv_prime(o: *mut u64, a: *const u64, m: *const u64, n: usize) -> u64;
    pub(crate) fn bigint_mod_inv_odd(o: *mut u64, a: *const u64, m: *const u64, n: usize) -> u64;
    pub(crate) fn bigint_cmp(a: *const u64, b: *const u64, n: usize) -> i64;
    pub(crate) fn ct_eq(a: *const u64, b: *const u64, n: usize) -> u64;
    pub(crate) fn ct_lt(a: *const u64, b: *const u64, n: usize) -> u8;
    pub(crate) fn ct_select(o: *mut u64, a: *const u64, b: *const u64, n: usize, bit: u64);
    pub(crate) fn x25519(o: *mut u8, s: *const u8, u: *const u8);
    pub(crate) fn gcm_init(c: *mut u8, k: *const u8, nr: u32, iv: *const u8) -> u8;
    pub(crate) fn gcm_update_aad(c: *mut u8, p: *const u8, n: usize) -> u8;
    pub(crate) fn gcm_seal(c: *mut u8, i: *const u8, o: *mut u8, n: usize) -> u8;
    pub(crate) fn gcm_final_tag(c: *mut u8, t: *mut u8) -> u8;
    pub(crate) fn gcm_verify(c: *mut u8, t: *const u8) -> u64;
    pub(crate) fn aead_init(c: *mut u8, k: *const u8, n: *const u8) -> u8;
    pub(crate) fn aead_update_aad(c: *mut u8, p: *const u8, n: usize) -> u8;
    pub(crate) fn aead_seal(c: *mut u8, i: *const u8, o: *mut u8, n: usize) -> u8;
    pub(crate) fn aead_open(c: *mut u8, i: *const u8, o: *mut u8, n: usize) -> u8;
    pub(crate) fn aead_final(c: *mut u8, t: *mut u8) -> u8;
    pub(crate) fn aead_verify(c: *mut u8, t: *const u8) -> u64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn bcrypt_hash(
        p: *const u8,
        pl: usize,
        s: *const u8,
        sl: usize,
        cost: u32,
        o: *mut u8,
    ) -> u64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn bcrypt_verify(
        p: *const u8,
        pl: usize,
        s: *const u8,
        sl: usize,
        cost: u32,
        o: *const u8,
    ) -> u64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn bcrypt_generate_salt(o: *mut u8) -> u64;

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn web_socket(domain: u64, kind: u64, protocol: u64) -> i64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn web_bind(fd: i64, address: *const u8, length: u64) -> i64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn web_listen(fd: i64, backlog: u64) -> i64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn web_accept(fd: i64, address: *mut u8, length: *mut u32) -> i64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn web_close(fd: i64) -> i64;
}
