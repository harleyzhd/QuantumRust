use std::path::Path;
use std::time::SystemTime;

use crate::CpgError;

pub const ALLOW_STALE_ENV: &str = "QR_ALLOW_STALE_DRIVER";

pub fn ensure_fresh(driver: &Path, src_dir: &Path, rebuild_cmd: &str) -> Result<(), CpgError> {
    if std::env::var_os(ALLOW_STALE_ENV).is_some() {
        return Ok(());
    }
    check(driver, src_dir, rebuild_cmd)
}

pub fn check_driver(driver: &Path, src_dir: &Path) -> Result<(), CpgError> {
    driver_check(driver, src_dir, std::env::var_os(ALLOW_STALE_ENV).is_some())
}

fn driver_check(driver: &Path, src_dir: &Path, allow_stale: bool) -> Result<(), CpgError> {
    if !driver.is_file() {
        return Err(CpgError::Extraction(format!(
            "{} not found; fix: {}",
            driver.display(),
            rebuild_command(driver)
        )));
    }
    if allow_stale || !in_cargo_build_dir(driver) {
        return Ok(());
    }
    check(driver, src_dir, &rebuild_command(driver))
}

fn in_cargo_build_dir(driver: &Path) -> bool {
    driver
        .parent()
        .is_some_and(|dir| dir.join(".fingerprint").is_dir())
}

pub fn rebuild_command(driver: &Path) -> String {
    let profile = driver
        .parent()
        .filter(|dir| dir.join(".fingerprint").is_dir())
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    let both = "-p mir-extract --bin mir-extract-driver -p llvm-extract --bin llvm-extract-driver";
    match profile {
        Some("release") => format!("cargo build --release {both}"),
        Some(_) => format!("cargo build {both}"),
        None => "cargo xtask install".to_string(),
    }
}

fn check(driver: &Path, src_dir: &Path, rebuild_cmd: &str) -> Result<(), CpgError> {
    if !src_dir.is_dir() {
        return Ok(());
    }
    let Ok(built) = driver.metadata().and_then(|m| m.modified()) else {
        return Ok(());
    };
    let Some((newest, at)) = newest_source(src_dir) else {
        return Ok(());
    };
    if at <= built {
        return Ok(());
    }
    Err(CpgError::Extraction(format!(
        "{} is older than {} — it cannot contain your latest changes.\n\
         `cargo run -p quantumrust-cli` does not rebuild driver binaries, so the \
         analysis would silently use the previous build.\n\
         Rebuild it with:\n    {rebuild_cmd}\n\
         To run it anyway, set {ALLOW_STALE_ENV}=1.",
        driver.display(),
        newest.display(),
    )))
}

pub fn newest_source(dir: &Path) -> Option<(std::path::PathBuf, SystemTime)> {
    let mut stack = vec![dir.to_path_buf()];
    let mut newest: Option<(std::path::PathBuf, SystemTime)> = None;
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(at) = meta.modified() {
                    if newest.as_ref().is_none_or(|(_, best)| at > *best) {
                        newest = Some((path, at));
                    }
                }
            }
        }
    }
    newest
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tick() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    fn scratch(driver_first: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let driver = dir.path().join("driver");
        let source = src.join("nested").join("extract.rs");
        std::fs::create_dir_all(source.parent().expect("parent")).expect("mkdir");

        if driver_first {
            std::fs::write(&driver, "binary").expect("write");
            tick();
            std::fs::write(&source, "// edited after the build").expect("write");
        } else {
            std::fs::write(&source, "// source").expect("write");
            tick();
            std::fs::write(&driver, "binary").expect("write");
        }
        (dir, driver, src)
    }

    fn stale_in(layout: &[&str], cargo_dir: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut bin = dir.path().to_path_buf();
        bin.extend(layout);
        std::fs::create_dir_all(&bin).expect("mkdir");
        if cargo_dir {
            std::fs::create_dir_all(bin.join(".fingerprint")).expect("mkdir");
        }
        let driver = bin.join("mir-extract-driver");
        std::fs::write(&driver, "binary").expect("write");
        tick();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(src.join("extract.rs"), "// edited after the build").expect("write");
        (dir, driver, src)
    }

    const RELEASE_REBUILD: &str = "cargo build --release -p mir-extract --bin mir-extract-driver -p llvm-extract --bin llvm-extract-driver";

    #[test]
    fn a_stale_driver_in_a_cargo_build_dir_is_refused_with_the_release_rebuild() {
        let (_dir, driver, src) = stale_in(&["target", "release"], true);
        let msg = driver_check(&driver, &src, false).unwrap_err().to_string();
        assert!(msg.contains(RELEASE_REBUILD), "{msg}");
    }

    #[test]
    fn a_build_dir_outside_the_checkout_is_still_checked() {
        let (_dir, driver, src) = stale_in(&["elsewhere", "debug"], true);
        let msg = driver_check(&driver, &src, false).unwrap_err().to_string();
        assert!(
            msg.contains("cargo build -p mir-extract --bin mir-extract-driver"),
            "{msg}"
        );
        assert!(!msg.contains("--release"), "{msg}");
    }

    #[test]
    fn a_stale_installed_driver_is_allowed() {
        let (_dir, driver, src) = stale_in(&["bin"], false);
        assert!(driver_check(&driver, &src, false).is_ok());
    }

    #[test]
    fn allow_stale_lets_a_stale_build_dir_driver_run() {
        let (_dir, driver, src) = stale_in(&["target", "release"], true);
        assert!(driver_check(&driver, &src, true).is_ok());
    }

    #[test]
    fn a_missing_installed_driver_names_one_fix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let driver = dir.path().join("bin").join("mir-extract-driver");
        let msg = driver_check(&driver, dir.path(), false)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("cargo xtask install"), "{msg}");
        assert!(!msg.contains("cargo build"), "{msg}");
    }

    #[test]
    fn a_driver_older_than_its_sources_is_refused() {
        let (_dir, driver, src) = scratch(true);
        let err = check(&driver, &src, "cargo build -p x --bin d").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("extract.rs"), "names the file: {msg}");
        assert!(
            msg.contains("cargo build -p x --bin d"),
            "names the fix: {msg}"
        );
    }

    #[test]
    fn a_driver_built_after_its_sources_passes() {
        let (_dir, driver, src) = scratch(false);
        assert!(check(&driver, &src, "cargo build").is_ok());
    }

    #[test]
    fn sources_in_subdirectories_are_seen() {
        let (_dir, driver, src) = scratch(false);
        tick();
        let deep = src.join("nested").join("deeper");
        std::fs::create_dir_all(&deep).expect("mkdir");
        std::fs::write(deep.join("late.rs"), "// newer").expect("write");
        let err = check(&driver, &src, "cargo build").unwrap_err();
        assert!(format!("{err}").contains("late.rs"));
    }

    #[test]
    fn a_missing_source_tree_is_not_an_error() {
        let (dir, driver, _src) = scratch(true);
        let absent = dir.path().join("no-such-src");
        assert!(check(&driver, &absent, "cargo build").is_ok());
    }

    #[test]
    fn an_empty_source_tree_is_not_an_error() {
        let (dir, driver, _src) = scratch(true);
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).expect("mkdir");
        assert!(check(&driver, &empty, "cargo build").is_ok());
    }
}
