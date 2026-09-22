# bcrypt_hash and bcrypt_hash_v1 share the v1 ABI.
# bcrypt_verify and bcrypt_verify_v1 share the v1 ABI.
# bcrypt_generate_salt and bcrypt_generate_salt_v1 share the v1 ABI.
# bcrypt_encode and bcrypt_encode_v1 share the v1 ABI.
# bcrypt_decode and bcrypt_decode_v1 share the v1 ABI.
# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt, rcx=salt_len, r8=cost, r9=output).
# Returns 0 on success, 1 for cost failure, 2 for password failure, 3 for salt failure, and 4 for output failure.
# A null password is valid only when password_len is zero.
# Salt length must be exactly 16 bytes.
# bcrypt_generate_salt(rdi=output16) returns 0 on success and 1 for a null output pointer or getrandom failure.
# bcrypt_verify uses the hash arguments and takes checksum in r9.
# Null pointers or invalid arguments return 0.
# bcrypt_verify returns 1 when the raw checksum matches.
# bcrypt_encode(rdi=salt16, rsi=checksum23, edx=cost, rcx=output61) returns 0 on success and 1 for invalid arguments or null pointers.
# bcrypt_decode(rdi=hash60, rsi=60, rdx=salt16, rcx=cost, r8=checksum23) returns 0 on success and 1 for invalid input or null pointers.
# bcrypt_decode accepts $2b$ and $2y$ and rejects $2a$ because its historical high-bit password semantics are not implemented.
