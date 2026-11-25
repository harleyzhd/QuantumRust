use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTUP_HOME");
    println!("cargo:rerun-if-env-changed=RUSTUP_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let Ok(out) = Command::new(rustc).args(["--print", "sysroot"]).output() else {
        return;
    };
    let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_string();
    println!("cargo:rustc-env=QR_BUILD_SYSROOT={sysroot}");
    let sysroot = Path::new(&sysroot);
    let in_rustup = sysroot
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|dir| dir == "toolchains");
    if let (true, Some(name)) = (in_rustup, sysroot.file_name().and_then(|n| n.to_str())) {
        println!("cargo:rustc-env=QR_BUILD_TOOLCHAIN={name}");
    }
}
