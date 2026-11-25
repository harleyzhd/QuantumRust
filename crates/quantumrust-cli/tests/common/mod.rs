#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;

pub const NOT_IN_A_PLAIN_SHELL: [&str; 7] = [
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "RUSTUP_TOOLCHAIN",
    "CARGO",
    "RUSTC",
    "CARGO_TARGET_DIR",
];

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn driver_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_quantumrust"))
        .parent()
        .expect("the binary sits in a profile directory")
        .to_path_buf()
}

pub fn drivers() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut build = Command::new(cargo);
        build.current_dir(workspace_root()).args([
            "build",
            "-q",
            "-p",
            "mir-extract",
            "--bin",
            "mir-extract-driver",
            "-p",
            "llvm-extract",
            "--bin",
            "llvm-extract-driver",
        ]);
        if driver_dir().file_name().is_some_and(|d| d == "release") {
            build.arg("--release");
        }
        let status = build.status().expect("cargo build of the drivers");
        assert!(status.success(), "building the drivers failed");
    });
}

pub fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_quantumrust"));
    c.env("RUST_LOG", "warn");
    c
}

pub fn plain_bin() -> Command {
    let mut c = bin();
    for var in NOT_IN_A_PLAIN_SHELL {
        c.env_remove(var);
    }
    c
}

pub fn scratch(name: &str) -> PathBuf {
    let root = workspace_root()
        .canonicalize()
        .unwrap_or_else(|_| workspace_root());
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in root.to_string_lossy().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    std::env::temp_dir()
        .join("quantumrust-tests")
        .join(format!("{hash:08x}").get(..8).unwrap_or("0"))
        .join(name)
}

pub fn explain(out: &Output) -> String {
    format!(
        "status {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
