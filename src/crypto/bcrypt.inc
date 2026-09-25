# bcrypt_hash and bcrypt_hash_v1 share the v1 ABI.
# bcrypt_verify and bcrypt_verify_v1 share the v1 ABI.
# bcrypt_generate_salt and bcrypt_generate_salt_v1 share the v1 ABI.
# bcrypt_encode and bcrypt_encode_v1 share the v1 ABI.
# bcrypt_decode and bcrypt_decode_v1 share the v1 ABI.
# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt, rcx=salt_len, r8=cost, r9=output23).
# Returns 0 on success, 1 for cost failure, 2 for password failure, 3 for salt failure, and 4 for output failure.
# A null password is valid only when password_len is zero.
# Salt length must be exactly 16 bytes.
# Hash output may overlap the password or salt buffers because inputs are consumed before output is written.
# bcrypt_generate_salt(rdi=output16) returns 0 on success and 1 for a null output pointer or getrandom failure.
# bcrypt_verify uses the hash arguments and takes checksum23 in r9.
# Null pointers or invalid arguments return 0.
# bcrypt_verify returns 1 when the raw checksum matches.
# bcrypt_encode(rdi=salt16, rsi=checksum23, edx=cost, rcx=output61) returns 0 on success and 1 for invalid arguments or null pointers.
# Encode input buffers may overlap the output buffer.
# bcrypt_decode(rdi=hash60, rsi=60, rdx=salt16, rcx=cost, r8=checksum23) returns 0 on success and 1 for invalid input or null pointers.
# Decode output buffers may overlap the hash input because decoded data is committed after validation.
# bcrypt_decode v1 accepts $2b$ and $2y$ and rejects $2a$ because its historical high-bit password semantics are not part of the v1 ABI.
# The $2x$ variant is explicitly unsupported because it represents the vulnerable historical signed-byte behavior.
# bcrypt_hash_v2(rdi=request) uses a versioned request structure with ABI version 2 and supports variants 1 ($2a$), 2 ($2b$), and 3 ($2y$).
# The v2 hash request layout is version:u32, size:u32, variant:u32, reserved:u32, password:u64, password_len:u64, salt:u64, salt_len:u64, cost:u32, max_cost:u32, output23:u64, output_len:u64.
# bcrypt_verify_v2(rdi=request) uses the same layout, with output23 pointing to the expected checksum.
# A v2 max_cost of zero disables the caller limit; otherwise cost and max_cost must be within 4..31 and cost must not exceed max_cost.
# bcrypt_encode_v2(rdi=request) uses ABI version 2 with variant:u32, salt:u64, checksum:u64, cost:u32, output:u64, and output_len:u64 after the versioned header.
# bcrypt_decode_v2(rdi=request) uses ABI version 2 with hash:u64, hash_len:u64, salt:u64, cost:u64, checksum:u64, and variant:u64 after the versioned header.
# Variant 4 is reserved for $2x$ and is rejected by all v2 entry points.
