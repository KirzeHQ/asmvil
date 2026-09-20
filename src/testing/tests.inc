# Shared manifest for functions exposed to the Rust test harness.
# Registry implementations add the target architecture to each source path.
# Add one entry here, then add the behavioral comparison in Rust.
ASM_TEST_ARCHES x86_64, aarch64

# ASM_FUNC symbol, signature ID, CPU or policy flags, source directory, file.
# The registry adds the architecture and `.asm` to locate the source file.
# The symbol and signature tell Rust what function to call and how to call it.

# AES
ASM_FUNC aes128_expand, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes256_expand, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes128_encrypt, ASM_TEST_SIG_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes256_encrypt, ASM_TEST_SIG_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes128_decrypt, ASM_TEST_SIG_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes256_decrypt, ASM_TEST_SIG_BUFFER_TO_BUFFER, 0, crypto, aes
ASM_FUNC aes_encrypt, ASM_TEST_SIG_BUFFER_TO_BUFFER, 0, crypto, aes

# SHA-2
ASM_FUNC sha256_init, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, sha256
ASM_FUNC sha256_update, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, sha256
ASM_FUNC sha256_final, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, sha256
ASM_FUNC sha512_init, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, sha512
ASM_FUNC sha384_init, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, sha512
ASM_FUNC sha512_update, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, sha512
ASM_FUNC sha512_final, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, sha512

# HMAC and HKDF
ASM_FUNC hmac_sha256, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hmac
ASM_FUNC hmac_sha384, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hmac
ASM_FUNC hmac_sha512, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hmac
ASM_FUNC hkdf_sha256_extract, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hkdf
ASM_FUNC hkdf_sha256_expand, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_sha384_extract, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hkdf
ASM_FUNC hkdf_sha384_expand, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_sha512_extract, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, hkdf
ASM_FUNC hkdf_sha512_expand, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_expand_label_sha256, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_expand_label_sha384, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_expand_label_sha512, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_derive_secret_sha256, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf
ASM_FUNC hkdf_derive_secret_sha384, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, hkdf

# ChaCha20 and Poly1305
ASM_FUNC chacha20_block, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, chacha20
ASM_FUNC chacha20_init, ASM_TEST_SIG_CONTEXT_KEY_NONCE, 0, crypto, chacha20
ASM_FUNC chacha20_xor, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, chacha20
ASM_FUNC poly1305_init, ASM_TEST_SIG_CONTEXT_KEY_NONCE, 0, crypto, poly1305
ASM_FUNC poly1305_update, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, poly1305
ASM_FUNC poly1305_final, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, poly1305
ASM_FUNC poly1305_verify, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, poly1305

# Big integer primitives
ASM_FUNC bigint_add, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC bigint_sub, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC bigint_mul, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC bigint_sqr, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC bigint_shl, ASM_TEST_SIG_BIGINT_SHIFT, 0, crypto, bigint
ASM_FUNC bigint_shr, ASM_TEST_SIG_BIGINT_SHIFT, 0, crypto, bigint
ASM_FUNC bigint_mod_reduce, ASM_TEST_SIG_BIGINT_MOD_REDUCE, 0, crypto, bigint
ASM_FUNC bigint_mod_inv_prime, ASM_TEST_SIG_BIGINT_MOD_INV_PRIME, 0, crypto, bigint
ASM_FUNC bigint_mod_inv_odd, ASM_TEST_SIG_BIGINT_MOD_INV_ODD, 0, crypto, bigint
ASM_FUNC bigint_cmp, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC ct_eq, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC ct_lt, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint
ASM_FUNC ct_select, ASM_TEST_SIG_BIGINT_BINARY, 0, crypto, bigint

# X25519 and AEAD
ASM_FUNC bcrypt_hash, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, bcrypt
ASM_FUNC bcrypt_verify, ASM_TEST_SIG_KEY_BUFFER_TO_BUFFER, 0, crypto, bcrypt
ASM_FUNC x25519, ASM_TEST_SIG_X25519, 0, crypto, x25519
ASM_FUNC gcm_init, ASM_TEST_SIG_CONTEXT_KEY_NONCE, 0, crypto, gcm
ASM_FUNC gcm_update_aad, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, gcm
ASM_FUNC gcm_seal, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, gcm
ASM_FUNC gcm_open, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, gcm
ASM_FUNC gcm_final_tag, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, gcm
ASM_FUNC gcm_verify, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, gcm
ASM_FUNC aead_init, ASM_TEST_SIG_CONTEXT_KEY_NONCE, 0, crypto, aead
ASM_FUNC aead_update_aad, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, aead
ASM_FUNC aead_seal, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, aead
ASM_FUNC aead_open, ASM_TEST_SIG_CONTEXT_INPUT_OUTPUT_LENGTH, 0, crypto, aead
ASM_FUNC aead_final, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, aead
ASM_FUNC aead_verify, ASM_TEST_SIG_CONTEXT_BUFFER_TO_BUFFER, 0, crypto, aead
