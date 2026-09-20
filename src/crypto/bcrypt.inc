# bcrypt_hash(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=output).
# Computes the raw 24-byte checksum; cost must be in the range 4..31.
# bcrypt_verify(rdi=password, rsi=password_len, rdx=salt16, rcx=cost, r8=checksum).
# Returns 1 when the raw checksum matches, otherwise 0.
