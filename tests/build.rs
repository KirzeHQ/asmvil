use std::{env, fs, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("run assembler tool");
    assert!(status.success(), "assembler tool failed: {status}");
}

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture");
    println!("cargo:rustc-env=ASMVIL_TEST_ARCH={arch}");
    let as_args: &[&str] = match arch.as_str() {
        "x86_64" => &["--64"],
        "aarch64" => &["-march=armv8-a"],
        other => panic!("unsupported target architecture: {other}"),
    };
    let crypto = root.join("src/crypto").join(&arch);
    let testing_dir = root.join("src/testing").join(&arch);
    println!("cargo:rerun-if-changed={}", root.join("src/testing/tests.inc").display());
    let manifest = fs::read_to_string(root.join("src/testing/tests.inc")).unwrap();
    let mut missing = String::new();
    for line in manifest.lines() {
        let Some(args) = line.trim().strip_prefix("ASM_FUNC ") else {
            continue;
        };
        let fields: Vec<_> = args.split(',').map(str::trim).collect();
        if fields.len() < 5 {
            continue;
        }
        let symbol = fields[0];
        let source = root.join("src").join(fields[3]).join(&arch).join(fields[4]).with_extension("asm");
        let present = source.exists()
            && fs::read_to_string(&source).map(|text| text.contains(symbol)).unwrap_or(false);
        if !present {
            missing.push_str(&format!(
                "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {symbol}() -> u64 {{\n    eprintln!(\"FAIL {symbol}: Implementation missing for {arch}\");\n    0\n}}\n\n"
            ));
        }
    }
    let missing_file = out.join("missing_symbols.rs");
    fs::write(&missing_file, missing).unwrap();
    println!("cargo:rerun-if-changed={}", missing_file.display());
    let mut objects = Vec::new();
    if crypto.is_dir() {
        for entry in fs::read_dir(&crypto).unwrap() {
            let source = entry.unwrap().path();
            if source.extension().and_then(|x| x.to_str()) != Some("asm") {
                continue;
            }
            let object = out.join(source.file_stem().unwrap()).with_extension("o");
            run(Command::new("as")
                .args(as_args)
                .arg("--defsym")
                .arg("ASMVIL_TESTING=1")
                .arg("-I")
                .arg(root.join("src"))
                .arg("-I")
                .arg(root.join("include").join(&arch))
                .arg("-o")
                .arg(&object)
                .arg(&source));
            println!("cargo:rerun-if-changed={}", source.display());
            objects.push(object);
        }
    }
    for entry in fs::read_dir(&testing_dir).unwrap() {
        let source = entry.unwrap().path();
        if source.extension().and_then(|x| x.to_str()) != Some("asm") {
            continue;
        }
        let object = out.join(source.file_stem().unwrap()).with_extension("o");
        run(Command::new("as")
            .args(as_args)
            .arg("--defsym")
            .arg("ASMVIL_TESTING=1")
            .arg("-I")
            .arg(root.join("src"))
            .arg("-I")
            .arg(root.join("include").join(&arch))
            .arg("-o")
            .arg(&object)
            .arg(&source));
        println!("cargo:rerun-if-changed={}", source.display());
        objects.push(object);
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("src/testing/signatures.inc").display()
    );
    let archive = out.join("libasmvil_crypto.a");
    let _ = fs::remove_file(&archive);
    let mut ar = Command::new("ar");
    ar.arg("crus").arg(&archive).args(&objects);
    run(&mut ar);
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-arg=-Wl,--whole-archive,{},--no-whole-archive",
        archive.display()
    );
    let linker_script = out.join("testing-registry.ld");
    fs::write(
        &linker_script,
        concat!(
            "SECTIONS {\n",
            "  .asmvil_test_registry : ALIGN(8) {\n",
            "    __start_asmvil_test_registry = .;\n",
            "    KEEP(*(.asmvil_test_registry))\n",
            "    KEEP(*(asmvil_test_registry))\n",
            "    __stop_asmvil_test_registry = .;\n",
            "  }\n",
            "}\n",
            "INSERT AFTER .rodata;\n",
        ),
    )
    .unwrap();
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    println!("cargo:rustc-link-arg=-no-pie");
}
