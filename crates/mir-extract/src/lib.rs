#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

pub mod dataflow;
pub mod descent;
pub mod extract;
pub mod fnptr;
pub mod link;
pub mod reaching;

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

use cpg_core::{Cpg, CpgError, FeaturePolicy, MirProvider, PassReport};

pub const OUT_DIR_ENV: &str = "QR_MIR_OUT_DIR";
pub const SYSROOT_ENV: &str = "QR_SYSROOT";
pub const DRIVER_ENV: &str = "QR_MIR_DRIVER";

pub fn rustc_driver_linked() -> &'static str {
    std::any::type_name::<rustc_driver::Compilation>()
}

#[derive(Debug, Default)]
pub struct RustcMirProvider {
    pub driver: Option<PathBuf>,
    pub features: FeaturePolicy,
    pub descent: Option<cpg_core::DescentPlan>,
}

impl MirProvider for RustcMirProvider {
    fn extract(&self, crate_root: &Path) -> Result<Cpg, CpgError> {
        let crate_root = crate_root.canonicalize()?;
        let crate_root = crate_root.as_path();
        let driver = checked_driver(self.driver.as_deref())?;
        let sysroot = rustc_sysroot()?;

        let target_dir = crate_root.join("target").join(if self.descent.is_some() {
            "qr-extract-descend"
        } else {
            "qr-extract"
        });
        let _lock = cpg_core::lock::extraction_lock(&target_dir)?;
        let out_dir = target_dir.join("cpg");
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir)?;

        touch_sources(crate_root)?;

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let (cpg, report) = cpg_core::passes::extract_with(crate_root, self.features, |pass| {
            let pass_dir = if pass.is_default() {
                out_dir.clone()
            } else {
                out_dir.join(format!("pass-{}", pass.label))
            };
            fs::create_dir_all(&pass_dir)?;
            let mut command = Command::new(&cargo);
            command
                .arg("check")
                .arg("--quiet")
                .args(&pass.cargo_args)
                .current_dir(crate_root)
                .env("RUSTC_WRAPPER", &driver)
                .env("CARGO_TARGET_DIR", &target_dir)
                .env(OUT_DIR_ENV, &pass_dir)
                .env(SYSROOT_ENV, &sysroot)
                .env(dylib_path_var(), dylib_path(&sysroot));
            if let Some(plan) = &self.descent {
                let rustflags = match std::env::var("RUSTFLAGS") {
                    Ok(f) if !f.is_empty() => format!("{f} -Zalways-encode-mir"),
                    _ => "-Zalways-encode-mir".to_string(),
                };
                command.env("RUSTFLAGS", rustflags);
                for (key, value) in plan.env() {
                    command.env(key, value);
                }
            }
            cpg_core::toolchain::apply(&mut command);
            let output = command.output()?;
            if !output.status.success() {
                return Err(cpg_core::toolchain::cargo_failure(
                    "cargo check failed under the extraction wrapper",
                    crate_root,
                    &output.stderr,
                ));
            }
            merge_dumped_cpgs(&pass_dir)
        })?;
        log_passes(&report);
        Ok(cpg)
    }
}

fn log_passes(report: &PassReport) {
    if report.is_multi_pass() {
        tracing::info!(layer = "MIR", passes = ?report.ran, "extracted under several feature configurations");
    }
    if let Some(Err(why)) = &report.all_features {
        tracing::info!(layer = "MIR", reason = %why, "--all-features did not build; trying features one at a time");
    }
    if let Some(gap) = report.gap() {
        tracing::warn!(layer = "MIR", "{gap}");
    }
}

fn merge_dumped_cpgs(out_dir: &Path) -> Result<Cpg, CpgError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(out_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    let Some(first) = paths.first() else {
        return Err(CpgError::Extraction(format!(
            "the extraction wrapper produced no CPG in {}",
            out_dir.display()
        )));
    };
    let mut merged = Cpg::load_json(first)?;
    for path in &paths[1..] {
        let extra = Cpg::load_json(path)?;
        let mut id_map = std::collections::HashMap::new();
        for node in extra.nodes() {
            let idx = merged.copy_node(node);
            id_map.insert(node.id, idx);
        }
        for (s, t, edge) in extra.edges_full() {
            if let (Some(&a), Some(&b)) = (id_map.get(&s), id_map.get(&t)) {
                merged.add_edge_full(a, b, edge);
            }
        }
    }
    let linked = link::link_across_units(&mut merged);
    if linked > 0 {
        tracing::debug!(linked, "linked call sites across compilation units");
    }
    Ok(merged)
}

pub fn checked_driver(explicit: Option<&Path>) -> Result<PathBuf, CpgError> {
    let driver = explicit
        .map(Path::to_path_buf)
        .or_else(locate_driver)
        .ok_or_else(|| {
            CpgError::Extraction(format!(
                "mir-extract-driver is not beside the executable and {DRIVER_ENV} is unset; install it with `cargo xtask install`"
            ))
        })?;
    if explicit.is_none() && !driver.is_file() && std::env::var_os(DRIVER_ENV).is_some() {
        return Err(CpgError::Extraction(format!(
            "{DRIVER_ENV} points to {}, which does not exist; fix: correct or unset {DRIVER_ENV}",
            driver.display()
        )));
    }
    cpg_core::check_driver(
        &driver,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
    )?;
    Ok(driver)
}

fn locate_driver() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(DRIVER_ENV) {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = format!("mir-extract-driver{}", std::env::consts::EXE_SUFFIX);
    [dir.join(&name), dir.parent()?.join(&name)]
        .into_iter()
        .find(|candidate| candidate.is_file())
}

fn rustc_sysroot() -> Result<String, CpgError> {
    let mut rustc = Command::new("rustc");
    rustc.args(["--print", "sysroot"]);
    cpg_core::toolchain::apply(&mut rustc);
    let output = rustc.output()?;
    if !output.status.success() {
        return Err(CpgError::Extraction("rustc --print sysroot failed".into()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn dylib_path_var() -> &'static str {
    if cfg!(target_os = "macos") {
        "DYLD_FALLBACK_LIBRARY_PATH"
    } else {
        "LD_LIBRARY_PATH"
    }
}

fn dylib_path(sysroot: &str) -> String {
    let lib = Path::new(sysroot).join("lib");
    match std::env::var(dylib_path_var()) {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", lib.display()),
        _ => lib.display().to_string(),
    }
}

fn touch_sources(crate_root: &Path) -> Result<(), CpgError> {
    let now = std::time::SystemTime::now();
    let mut touched = 0usize;
    for root in crate_roots(crate_root) {
        for name in ["src/main.rs", "src/lib.rs"] {
            let path = root.join(name);
            if path.is_file() {
                let file = File::options().append(true).open(&path)?;
                let _ = file.set_times(fs::FileTimes::new().set_modified(now));
                touched += 1;
            }
        }
    }
    if touched == 0 {
        return Err(CpgError::Extraction(format!(
            "no crate root found under {}: expected src/main.rs or src/lib.rs, \
             in the package itself or in a workspace member",
            crate_root.display()
        )));
    }
    Ok(())
}

fn crate_roots(crate_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![crate_root.to_path_buf()];
    if let Ok(entries) = fs::read_dir(crate_root) {
        let mut members: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.join("Cargo.toml").is_file())
            .collect();
        members.sort();
        roots.extend(members);
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_rustc_driver() {
        assert!(rustc_driver_linked().contains("Compilation"));
    }
}
