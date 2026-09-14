use crate::{ffi::*, fixture::fixture};
use num_bigint::BigUint;

fn read_limbs(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .collect()
}
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

// BigUint supplies arithmetic expectations; constant-time return flags stay explicit.
#[test]
fn zbigint_all_operations_and_constant_time_helpers() {
    let f = fixture("bigint_test.asm");
    let a = read_limbs(&f["a1"]);
    let b = read_limbs(&f["b1"]);
    let a2 = read_limbs(&f["a2"]);
    let b2 = read_limbs(&f["b2"]);
    let a3 = read_limbs(&f["a3"]);
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
