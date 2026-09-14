macro_rules! missing_crypto_test {
    ($name:ident, $label:literal) => {
        #[test]
        fn $name() {
            panic!("FAIL {label}: Implementation missing for {arch}", label = $label, arch = env!("ASMVIL_TEST_ARCH"));
        }
    };
}

missing_crypto_test!(aes, "aes");
missing_crypto_test!(bigint, "bigint");
missing_crypto_test!(chacha_poly_aead, "chacha/poly1305/aead");
missing_crypto_test!(gcm, "gcm");
missing_crypto_test!(hashes, "sha2");
missing_crypto_test!(hmac_hkdf, "hmac/hkdf");
missing_crypto_test!(registry, "testing registry");
missing_crypto_test!(x25519, "x25519");
