# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=output).
# Returns 0 on success, 1 for cost failure, and 2 for passwords over 72 bytes.
# bcrypt_verify(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=checksum).
# Returns 1 when the raw checksum matches, otherwise 0.
