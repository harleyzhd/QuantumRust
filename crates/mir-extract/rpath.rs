
fn embed_rpath() {
    println!("cargo:rerun-if-env-changed=RUSTUP_HOME");
    println!("cargo:rerun-if-env-changed=RUSTUP_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let out = std::process::Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc --print sysroot");
    let sysroot = String::from_utf8(out.stdout).expect("a UTF-8 sysroot path");
    println!(
        "cargo:rustc-link-arg-bins=-Wl,-rpath,{}/lib",
        sysroot.trim()
    );
}
