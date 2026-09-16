fn main() {
    println!("cargo:rerun-if-changed=src/valgrind_secret.c");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    cc::Build::new()
        .file("src/valgrind_secret.c")
        .compile("pqc_valgrind_secret");
}
