use crate::{
    fixture::fixture,
    helpers::{digest256, digest512, eq},
};

#[test]
fn sha256_all_vectors_partitions_and_million() {
    let f = fixture("sha256_test.asm");
    let abc = &f["msg_abc"][..3];
    eq(&digest256(&[], &[]), &f["expect_empty"]);
    eq(&digest256(abc, &[3]), &f["expect_abc"]);
    eq(&digest256(abc, &[1, 1, 1]), &f["expect_abc"]);
    let m = &f["msg_448"][..56];
    eq(&digest256(m, &[56]), &f["expect_448"]);
    eq(&digest256(m, &[48, 8]), &f["expect_448"]);
    let m = &f["msg_100"][..100];
    eq(&digest256(m, &[100]), &digest256(m, &[60, 40]));
    let million = vec![b'a'; 1_000_000];
    eq(&digest256(&million, &[1_000_000]), &f["expect_1ma"]);
}

#[test]
fn sha512_sha384_all_vectors_partitions_and_million() {
    let f = fixture("sha512_test.asm");
    eq(&digest512(&[], &[], false), &f["expect_512_empty"]);
    let abc = &f["msg_abc"][..3];
    eq(&digest512(abc, &[3], false), &f["expect_512_abc"]);
    eq(&digest512(abc, &[1, 1, 1], false), &f["expect_512_abc"]);
    let m = &f["msg_448"][..56];
    eq(&digest512(m, &[56], false), &f["expect_512_448"]);
    let m = &f["msg_100"][..100];
    eq(&digest512(m, &[100], false), &f["expect_512_100"]);
    let m = &f["msg_200"][..200];
    eq(
        &digest512(m, &[200], false),
        &digest512(m, &[60, 140], false),
    );
    let million = vec![b'a'; 1_000_000];
    eq(
        &digest512(&million, &[1_000_000], false),
        &f["expect_512_1ma"],
    );
    eq(&digest512(&[], &[], true), &f["expect_384_empty"]);
    eq(&digest512(abc, &[3], true), &f["expect_384_abc"]);
    eq(&digest512(&m, &[200], true), &f["expect_384_200"]);
    eq(
        &digest512(&million, &[1_000_000], true),
        &f["expect_384_1ma"],
    );
}
