# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt, rcx=salt_len, r8=cost, r9=output).
# Returns 0 on success, 1 for cost failure, and 2 for passwords over 72 bytes.
# Salt length must be exactly 16 bytes. bcrypt_generate_salt(rdi=output16).
# bcrypt_verify uses the hash arguments and takes checksum in r9.
# Returns 1 when the raw checksum matches, otherwise 0.
# bcrypt_encode(rdi=salt16, rsi=checksum23, edx=cost, rcx=output61).
# bcrypt_decode(rdi=hash60, rsi=60, rdx=salt16, rcx=cost, r8=checksum23).
