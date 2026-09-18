use crate::ffi::*;
use num_bigint::{BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::One;

fn number(limbs: &[u64]) -> BigUint {
    BigUint::from_bytes_le(
        &limbs
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
fn limbs(n: &BigUint, count: usize) -> Vec<u64> {
    let mut b = n.to_bytes_le();
    b.resize(count * 8, 0);
    b.chunks(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .collect()
}

fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let modulus = modulus.to_bigint().unwrap();
    let egcd = a.to_bigint().unwrap().extended_gcd(&modulus);
    if !egcd.gcd.is_one() {
        return None;
    }
    egcd.x.mod_floor(&modulus).to_biguint()
}

fn check_odd_inverse(a: &BigUint, modulus: &BigUint, count: usize) {
    let a_limbs = limbs(a, count);
    let modulus_limbs = limbs(modulus, count);
    let mut out = vec![0u64; count];
    let expected = mod_inverse(a, modulus);
    let status = unsafe {
        bigint_mod_inv_odd(
            out.as_mut_ptr(),
            a_limbs.as_ptr(),
            modulus_limbs.as_ptr(),
            count,
        )
    };
    assert_eq!(status, u64::from(expected.is_none()), "a={a}, modulus={modulus}");
    if let Some(expected) = expected {
        assert_eq!(out, limbs(&expected, count), "a={a}, modulus={modulus}");
    }
}

// BigUint supplies arithmetic expectations; constant-time return flags stay explicit.
#[test]
fn zbigint_all_operations_and_constant_time_helpers() {
    let a = [0x100u64, 0];
    let b = [0x40u64, 0];
    let a2 = [0x100u64, 0];
    let b2 = [0x20u64, 0];
    let a3 = [0x1234_5678u64, 0];
    let mut o = [0; 4];
    unsafe {
        assert_eq!(bigint_add(o.as_mut_ptr(), a2.as_ptr(), b2.as_ptr(), 2), 0);
        assert_eq!(&o[..2], limbs(&(number(&a2) + number(&b2)), 2).as_slice());
        assert_eq!(bigint_sub(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2), 0);
        assert_eq!(&o[..2], limbs(&(number(&a) - number(&b)), 2).as_slice());
        assert_eq!(bigint_sub(o.as_mut_ptr(), b.as_ptr(), a.as_ptr(), 2), 1);
        bigint_mul(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2);
        assert_eq!(o.to_vec(), limbs(&(number(&a) * number(&b)), 4));
        bigint_sqr(o.as_mut_ptr(), a.as_ptr(), 2);
        assert_eq!(o.to_vec(), limbs(&(number(&a) * number(&a)), 4));
        bigint_shl(o.as_mut_ptr(), a2.as_ptr(), 2, 37);
        let mut q = [0; 2];
        bigint_shr(q.as_mut_ptr(), o.as_ptr(), 2, 37);
        assert_eq!(q.to_vec(), limbs(&number(&a2), 2));
        bigint_shr(o.as_mut_ptr(), a3.as_ptr(), 2, 37);
        bigint_shl(q.as_mut_ptr(), o.as_ptr(), 2, 37);
        assert_eq!(q.to_vec(), limbs(&(number(&a3) >> 37 << 37), 2));
        assert_eq!(bigint_cmp(a.as_ptr(), a.as_ptr(), 2), 0);
        assert_eq!(bigint_cmp(a.as_ptr(), b.as_ptr(), 2), 1);
        assert_eq!(bigint_cmp(b.as_ptr(), a.as_ptr(), 2), -1);
        ct_select(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2, 0);
        assert_eq!(&o[..2], &a);
        ct_select(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2, 1);
        assert_eq!(&o[..2], &b);
        assert_eq!(ct_eq(a.as_ptr(), a.as_ptr(), 2), 1);
        assert_eq!(ct_eq(a.as_ptr(), b.as_ptr(), 2), 0);
        assert_eq!(ct_lt(b.as_ptr(), a.as_ptr(), 2), 1);
        assert_eq!(ct_lt(a.as_ptr(), a.as_ptr(), 2), 0);
    }
}

#[test]
fn bigint_mod_reduce_and_prime_inverse_match_biguint() {
    let modulus = [17u64, 0];
    let input = [0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210, 0, 0];
    let a = [5u64, 0];
    let m = number(&modulus);
    let wide = number(&input);
    let mut reduced = [0u64; 2];
    let mut inverse = [0u64; 2];
    unsafe {
        bigint_mod_reduce(reduced.as_mut_ptr(), input.as_ptr(), modulus.as_ptr(), 2);
        eprintln!("bigint_mod_inv_prime: a={:?}, modulus={:?}", a, modulus);
        assert_eq!(
            bigint_mod_inv_prime(inverse.as_mut_ptr(), a.as_ptr(), modulus.as_ptr(), 2),
            0
        );
        eprintln!("bigint_mod_inv_prime returned: {:?}", inverse);
    }
    assert_eq!(reduced.to_vec(), limbs(&(wide % &m), 2));
    assert_eq!(
        inverse.to_vec(),
        limbs(&number(&a).modpow(&(&m - 2u32), &m), 2)
    );

    let wide_modulus = (BigUint::one() << 127) - BigUint::one();
    let wide_input = &wide_modulus + BigUint::from(5u32);
    let mut input = limbs(&wide_input, 4);
    input[2..].fill(0);
    let modulus: [u64; 2] = limbs(&wide_modulus, 2).try_into().unwrap();
    unsafe {
        bigint_mod_reduce(reduced.as_mut_ptr(), input.as_ptr(), modulus.as_ptr(), 2);
    }
    assert_eq!(reduced.to_vec(), limbs(&(wide_input % wide_modulus), 2));
}

#[test]
fn bigint_mod_inv_odd_matches_biguint() {
    let wide_prime = (BigUint::one() << 127) - BigUint::one();
    let factor = (BigUint::one() << 64) - BigUint::from(59u32);
    let wide_composite: BigUint = &factor * ((BigUint::one() << 32usize) - BigUint::from(5u32));
    let cases = [
        (BigUint::from(3u32), BigUint::from(101u32)),
        (BigUint::from(17u32), BigUint::from(221u32)),
        (BigUint::from(37u32), BigUint::from(255u32)),
        (BigUint::from(64u32), BigUint::from(899u32)),
        (BigUint::from(123u32), BigUint::from(1001u32)),
        (&wide_prime + BigUint::from(5u32), wide_prime),
        (BigUint::from(65537u32), wide_composite.clone()),
        (factor, wide_composite),
    ];
    for (a_big, modulus_big) in cases {
        let a: [u64; 2] = limbs(&a_big, 2).try_into().unwrap();
        let modulus: [u64; 2] = limbs(&modulus_big, 2).try_into().unwrap();
        let mut out = [0u64; 2];
        let expected = mod_inverse(&a_big, &modulus_big);
        eprintln!("bigint_mod_inv_odd: a={a_big}, modulus={modulus_big}");
        let status = unsafe { bigint_mod_inv_odd(out.as_mut_ptr(), a.as_ptr(), modulus.as_ptr(), 2) };
        eprintln!("bigint_mod_inv_odd returned: status={status}, output={out:?}");
        assert_eq!(status, u64::from(expected.is_none()));
        if let Some(expected) = expected {
            assert_eq!(out.to_vec(), limbs(&expected, 2));
        }
    }

    for (a, modulus) in [(3u64, 101u64), (17, 221), (64, 899), (123, 1001)] {
        check_odd_inverse(&BigUint::from(a), &BigUint::from(modulus), 1);
    }

    let mut state = 0x9e37_79b9_7f4a_7c15_d1b5_4a32_d192_ed03u128;
    for _ in 0..64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let a = BigUint::from(state);
        state = state.rotate_left(47) ^ 0xa5a5_a5a5_5a5a_5a5a_0123_4567_89ab_cdef;
        let modulus = BigUint::from(state | 3);
        check_odd_inverse(&a, &modulus, 2);
    }
}
