use crate::{
    ffi::*,
    fixture::fixture,
    helpers::{ctx, eq},
};

#[test]
fn gcm_vectors_streaming_partials_failures_and_open() {
    let f = fixture("gcm_test.asm");
    let mut c = ctx(384);
    let mut out = vec![0; 160];
    let mut tag = [0; 16];
    unsafe {
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr()),
            1
        );
        assert_eq!(gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr()), 1);
        eq(&tag, &f["tag_case1"]);
        assert_eq!(gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr()), 1);
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr()),
            1
        );
        gcm_seal(c.as_mut_ptr(), f["zero_pt"].as_ptr(), out.as_mut_ptr(), 16);
        eq(&out[..16], &f["ct_case2"]);
        assert_eq!(gcm_verify(c.as_mut_ptr(), f["tag_case2"].as_ptr()), 1);
        gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
        assert_eq!(gcm_verify(c.as_mut_ptr(), f["bad_tag"].as_ptr()), 0);
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key3"].as_ptr(), 10, f["iv3"].as_ptr()),
            1
        );
        gcm_update_aad(c.as_mut_ptr(), f["aad17"].as_ptr(), 1);
        gcm_update_aad(c.as_mut_ptr(), f["key0"].as_ptr(), 0);
        gcm_update_aad(c.as_mut_ptr(), f["aad17"][1..].as_ptr(), 16);
        gcm_seal(c.as_mut_ptr(), f["pt3"].as_ptr(), out.as_mut_ptr(), 64);
        eq(&out[..64], &f["ct3"]);
        gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
        eq(&tag, &f["tag_case4"]);
        for (n, ct, tg) in [
            (1, "ct_partial1", "tag_partial1"),
            (15, "ct_partial15", "tag_partial15"),
            (17, "ct_partial17", "tag_partial17"),
            (31, "ct_partial31", "tag_partial31"),
        ] {
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 10, f["iv0"].as_ptr());
            gcm_seal(c.as_mut_ptr(), f["zero_pt"].as_ptr(), out.as_mut_ptr(), n);
            eq(&out[..n], &f[ct]);
            gcm_final_tag(c.as_mut_ptr(), tag.as_mut_ptr());
            eq(&tag, &f[tg]);
        }
        assert_eq!(
            gcm_init(c.as_mut_ptr(), f["key0"].as_ptr(), 12, f["iv0"].as_ptr()),
            0
        );
        assert_eq!(gcm_verify(c.as_mut_ptr(), f["key0"].as_ptr()), 0);
    }
}
