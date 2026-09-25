use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let source = root.join("src/crypto/x86_64/bcrypt.asm");
    let object = out.join("bcrypt.o");
    let archive = out.join("libbcrypt.a");

    assert!(cfg!(target_arch = "x86_64"), "bcrypt fuzzing requires x86-64");
    let status = Command::new("as")
        .args(["--64", "--defsym", "ASMVIL_TESTING=1"])
        .arg("-I")
        .arg(root.join("src"))
        .arg("-I")
        .arg(root.join("include/x86_64"))
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .status()
        .expect("assemble bcrypt fuzz target");
    assert!(status.success(), "bcrypt assembly failed: {status}");

    let _ = fs::remove_file(&archive);
    let status = Command::new("ar")
        .args(["crus"])
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("archive bcrypt fuzz target");
    assert!(status.success(), "bcrypt archive failed: {status}");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=bcrypt");
    println!("cargo:rerun-if-changed={}", source.display());
}
