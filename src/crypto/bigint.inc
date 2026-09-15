# Crypto big-integer API.

# Big integers are fixed-width unsigned arrays of 64-bit limbs, stored
# little-endian (limb 0 is least significant). The number of limbs is fixed
# per operation and never varies at runtime, which is what keeps the code
# constant-time.

# Word size for aarch64 is 128 bits (2 limbs); x86-64 supports 128-bit muls.

# bigint_add(dst, a, b, limbs): dst = a + b, returns carry (0/1).
# bigint_sub(dst, a, b, limbs): dst = a - b, returns borrow (0/1).
# bigint_mul(dst, a, b, limbs): dst = a * b (dst must hold 2*limbs).
# bigint_mul_wide(hi, lo, a, b, limbs): (hi,lo) = a * b, 2*limbs each.
# bigint_sqr(dst, a, limbs): dst = a * a (dst must hold 2*limbs).
# bigint_shl(dst, a, limbs, bits): dst = a << bits (bits < 64).
# bigint_shr(dst, a, limbs, bits): dst = a >> bits (bits < 64).
# bigint_cmp(a, b, limbs): constant-ish compare, returns -1/0/1 (unsigned).
# ct_eq(a, b, limbs): returns 1 if a == b else 0, constant time.
# ct_lt(a, b, limbs): returns 1 if a < b else 0, constant time (unsigned).
# ct_select(dst, a, b, limbs, bit): if bit then dst=b else dst=a, constant time.
# bigint_mod_reduce(dst, input[2*limbs], modulus, limbs): input mod modulus.
# bigint_mod_inv_prime(dst, a, prime, limbs): a^(prime-2) mod prime.
