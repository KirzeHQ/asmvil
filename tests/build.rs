use std::{env, fs, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("run assembler tool");
    assert!(status.success(), "assembler tool failed: {status}");
}

fn main() {
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        println!(
            "cargo:warning=assembly crypto tests are x86_64-only; aarch64 has the exit test only"
        );
        return;
    }

    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let crypto = root.join("src/crypto/x86_64");
    let mut objects = Vec::new();
    for entry in fs::read_dir(&crypto).unwrap() {
        let source = entry.unwrap().path();
        if source.extension().and_then(|x| x.to_str()) != Some("asm") {
            continue;
        }
        let object = out.join(source.file_stem().unwrap()).with_extension("o");
        run(Command::new("as")
            .arg("--64")
            .arg("-o")
            .arg(&object)
            .arg(&source));
        println!("cargo:rerun-if-changed={}", source.display());
        objects.push(object);
    }
    let archive = out.join("libasmvil_crypto.a");
    let mut ar = Command::new("ar");
    ar.arg("crus").arg(&archive).args(&objects);
    run(&mut ar);
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=asmvil_crypto");
}
