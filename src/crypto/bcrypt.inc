# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=output).
# Returns 0 on success and 1 when cost is outside 4..31 or above the app limit.
# bcrypt_verify(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=checksum).
# Returns 1 when the raw checksum matches, otherwise 0.
