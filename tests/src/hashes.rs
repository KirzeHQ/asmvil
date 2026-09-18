use crate::helpers::{digest256, digest512, eq};
use sha2::{Digest, Sha256, Sha384, Sha512};

fn test_vectors() -> std::collections::HashMap<&'static str, Vec<u8>> {
    [
        ("msg_abc", b"abc".to_vec()),
        ("msg_448", vec![0x5a; 56]),
        ("msg_100", vec![0xa5; 100]),
        ("msg_200", vec![0x3c; 200]),
    ].into_iter().collect()
}

// Assembly processes the input; sha2 supplies the independent expected digest.
#[test]
fn sha256_all_vectors_partitions_and_million() {
    let f = test_vectors();
    let abc = &f["msg_abc"][..3];
    eq(&digest256(&[], &[]), Sha256::digest([]).as_slice());
    let expected = Sha256::digest(abc);
    eq(&digest256(abc, &[3]), &expected);
    eq(&digest256(abc, &[1, 1, 1]), &expected);
    let m = &f["msg_448"][..56];
    let expected = Sha256::digest(m);
    eq(&digest256(m, &[56]), &expected);
    eq(&digest256(m, &[48, 8]), &expected);
    let m = &f["msg_100"][..100];
    eq(&digest256(m, &[100]), &digest256(m, &[60, 40]));
    let million = vec![b'a'; 1_000_000];
    eq(
        &digest256(&million, &[1_000_000]),
        Sha256::digest(&million).as_slice(),
    );
}

#[test]
fn sha512_sha384_all_vectors_partitions_and_million() {
    eq(&digest512(&[], &[], false), Sha512::digest([]).as_slice());
    let f = test_vectors();
    let abc = &f["msg_abc"][..3];
    let expected = Sha512::digest(abc);
    eq(&digest512(abc, &[3], false), &expected);
    eq(&digest512(abc, &[1, 1, 1], false), &expected);
    let m = &f["msg_448"][..56];
    eq(&digest512(m, &[56], false), Sha512::digest(m).as_slice());
    let m = &f["msg_100"][..100];
    eq(&digest512(m, &[100], false), Sha512::digest(m).as_slice());
    let m = &f["msg_200"][..200];
    eq(
        &digest512(m, &[200], false),
        &digest512(m, &[60, 140], false),
    );
    let million = vec![b'a'; 1_000_000];
    eq(
        &digest512(&million, &[1_000_000], false),
        Sha512::digest(&million).as_slice(),
    );
    eq(&digest512(&[], &[], true), Sha384::digest([]).as_slice());
    eq(&digest512(abc, &[3], true), Sha384::digest(abc).as_slice());
    eq(&digest512(m, &[200], true), Sha384::digest(m).as_slice());
    eq(
        &digest512(&million, &[1_000_000], true),
        Sha384::digest(&million).as_slice(),
    );
}
