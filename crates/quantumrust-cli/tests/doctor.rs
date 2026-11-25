mod common;

use std::fs;
use std::time::{Duration, SystemTime};

use common::{bin, drivers, explain, scratch};

fn line_for(stdout: &str, check: &str) -> Vec<String> {
    stdout
        .lines()
        .find(|l| l.split_whitespace().next() == Some(check))
        .unwrap_or_else(|| panic!("no `{check}` line in:\n{stdout}"))
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

#[test]
fn doctor_passes_in_a_dev_build() {
    drivers();
    let out = bin().arg("doctor").output().unwrap();
    assert!(out.status.success(), "{}", explain(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for check in ["toolchain", "mir-extract-driver", "llvm-extract-driver"] {
        assert_eq!(line_for(&stdout, check)[1], "ok", "{}", explain(&out));
    }
}

#[test]
fn doctor_reports_a_missing_driver() {
    drivers();
    let out = bin()
        .arg("doctor")
        .env("QR_MIR_DRIVER", "/nonexistent/mir-extract-driver")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", explain(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        line_for(&stdout, "mir-extract-driver")[1],
        "FAIL",
        "{}",
        explain(&out)
    );
    assert!(stdout.contains("QR_MIR_DRIVER"), "{}", explain(&out));
    assert!(stdout.contains("unset"), "{}", explain(&out));
    assert!(!stdout.contains("cargo build"), "{}", explain(&out));
}

#[test]
fn doctor_fails_when_qr_toolchain_names_another_toolchain() {
    drivers();
    let out = bin()
        .arg("doctor")
        .env("QR_TOOLCHAIN", "stable")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", explain(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        line_for(&stdout, "toolchain")[1],
        "FAIL",
        "{}",
        explain(&out)
    );
    assert!(stdout.contains("QR_TOOLCHAIN"), "{}", explain(&out));
}

#[test]
fn an_installed_driver_is_not_held_to_the_sources() {
    drivers();
    let dir = scratch("installed-driver");
    fs::create_dir_all(&dir).unwrap();
    let built = common::driver_dir().join("mir-extract-driver");
    let installed = dir.join("mir-extract-driver");
    fs::copy(&built, &installed).unwrap();
    fs::File::options()
        .write(true)
        .open(&installed)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();

    let out = bin()
        .arg("doctor")
        .env("QR_MIR_DRIVER", &installed)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        line_for(&stdout, "mir-extract-driver")[1],
        "ok",
        "{}",
        explain(&out)
    );
}

#[test]
fn doctor_tells_a_missing_toolchain_from_a_missing_rustc() {
    drivers();
    let toolchain_line = |out: &std::process::Output| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.starts_with("toolchain"))
            .unwrap_or_default()
            .to_string()
    };
    let missing = bin()
        .arg("doctor")
        .env("QR_TOOLCHAIN", "nightly-1999-01-01")
        .output()
        .unwrap();
    let line = toolchain_line(&missing);
    assert!(
        line.contains("not installed") && line.contains("rustup toolchain install"),
        "{line}"
    );
    let no_path = bin()
        .arg("doctor")
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    let line = toolchain_line(&no_path);
    assert!(
        line.contains("could not start") && line.contains("PATH"),
        "{line}"
    );
    assert!(!line.contains("rustup toolchain install"), "{line}");
}
