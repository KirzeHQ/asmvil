use crate::{ffi::*, fixture::fixture};

#[test]
fn zbigint_all_operations_and_constant_time_helpers() {
    let f = fixture("bigint_test.asm");
    let a = [15, 16];
    let b = [5, 2];
    let mut o = [0; 4];
    unsafe {
        assert_eq!(
            bigint_add(
                o.as_mut_ptr(),
                f["a2"].as_ptr() as *const u64,
                f["b2"].as_ptr() as *const u64,
                2
            ),
            0
        );
        assert_eq!(o[..2], [1, 4]);
        assert_eq!(bigint_sub(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2), 0);
        assert_eq!(o[..2], [10, 14]);
        assert_eq!(bigint_sub(o.as_mut_ptr(), b.as_ptr(), a.as_ptr(), 2), 1);
        bigint_mul(o.as_mut_ptr(), a.as_ptr(), b.as_ptr(), 2);
        assert_eq!(o, [75, 110, 32, 0]);
        bigint_sqr(o.as_mut_ptr(), a.as_ptr(), 2);
        assert_eq!(o, [225, 480, 256, 0]);
        bigint_shl(o.as_mut_ptr(), f["a2"].as_ptr() as *const u64, 2, 37);
        let mut q = [0; 2];
        bigint_shr(q.as_mut_ptr(), o.as_ptr(), 2, 37);
        assert_eq!(q, [u64::MAX, 1]);
        bigint_shr(o.as_mut_ptr(), f["a3"].as_ptr() as *const u64, 2, 37);
        bigint_shl(q.as_mut_ptr(), o.as_ptr(), 2, 37);
        assert_eq!(q, [0, 1]);
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
