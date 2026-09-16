fn main() {
    println!("cargo:rerun-if-changed=src/valgrind_secret.c");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var_os("CARGO_FEATURE_VALGRIND_SECRET_TAINT").is_none()
    {
        return;
    }

    cc::Build::new()
        .file("src/valgrind_secret.c")
        .compile("pqc_valgrind_secret");
}
