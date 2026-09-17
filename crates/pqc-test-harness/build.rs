fn main() {
    println!("cargo:rerun-if-changed=src/valgrind_secret.c");
    println!("cargo:rustc-check-cfg=cfg(pqc_valgrind_available)");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var_os("CARGO_FEATURE_VALGRIND_SECRET_TAINT").is_none()
    {
        return;
    }

    let probe = cc::Build::new()
        .file("src/valgrind_secret.c")
        .cargo_metadata(false)
        .try_compile("pqc_valgrind_secret_probe");

    if probe.is_err() {
        println!(
            "cargo:warning=Valgrind headers unavailable; \
             valgrind-secret-taint support disabled for this build"
        );
        return;
    }

    println!("cargo:rustc-cfg=pqc_valgrind_available");

    cc::Build::new()
        .file("src/valgrind_secret.c")
        .compile("pqc_valgrind_secret");
}
