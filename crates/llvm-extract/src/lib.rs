pub mod dataflow;
mod debug;
pub mod parse;
mod symbol_types;

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

use cpg_core::{AblationMode, Cpg, CpgError, FeaturePolicy, LlvmProvider, PassReport};

pub const OUT_DIR_ENV: &str = "QR_LLVM_OUT_DIR";
pub const DRIVER_ENV: &str = "QR_LLVM_DRIVER";

#[derive(Debug, Default)]
pub struct LlvmIrProvider {
    pub driver: Option<PathBuf>,
    pub features: FeaturePolicy,
    pub descent: Option<cpg_core::DescentPlan>,
}

impl LlvmProvider for LlvmIrProvider {
    fn extract(&self, crate_root: &Path) -> Result<Cpg, CpgError> {
        let crate_root = crate_root.canonicalize()?;
        let crate_root = crate_root.as_path();
        let driver = checked_driver(self.driver.as_deref())?;

        let target_dir = crate_root.join("target").join("qr-extract-llvm");
        let _lock = cpg_core::lock::extraction_lock(&target_dir)?;
        let out_dir = target_dir.join("llvm");
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir)?;

        touch_sources(crate_root)?;

        let rustflags = match std::env::var("RUSTFLAGS") {
            Ok(f) if !f.is_empty() => format!("{f} -Zalways-encode-mir"),
            _ => "-Zalways-encode-mir".to_string(),
        };

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
                .env("RUSTFLAGS", &rustflags)
                .env(OUT_DIR_ENV, &pass_dir);
            cpg_core::toolchain::apply(&mut command);
            let output = command.output()?;
            if !output.status.success() {
                return Err(cpg_core::toolchain::cargo_failure(
                    "cargo check failed under the llvm-ir wrapper",
                    crate_root,
                    &output.stderr,
                ));
            }
            parse_dumped_ll(&pass_dir, self.descent.as_ref())
        })?;
        log_passes(&report);
        Ok(cpg)
    }
}

fn log_passes(report: &PassReport) {
    if report.is_multi_pass() {
        tracing::info!(layer = "LLVM", passes = ?report.ran, "extracted under several feature configurations");
    }
    if let Some(Err(why)) = &report.all_features {
        tracing::info!(layer = "LLVM", reason = %why, "--all-features did not build; trying features one at a time");
    }
    if let Some(gap) = report.gap() {
        tracing::warn!(layer = "LLVM", "{gap}");
    }
}

fn parse_dumped_ll(
    out_dir: &Path,
    descent: Option<&cpg_core::DescentPlan>,
) -> Result<Cpg, CpgError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(out_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "ll"))
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(CpgError::Extraction(format!(
            "the llvm-ir wrapper produced no .ll in {}",
            out_dir.display()
        )));
    }
    let mut merged = Cpg::new(AblationMode::LlvmOnly);
    for path in &paths {
        let text = fs::read_to_string(path)?;
        let local_crate = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let cpg = match descent {
            Some(plan) => parse::descend_ll(&text, local_crate, plan),
            None => parse::parse_ll(&text, local_crate),
        };
        let mut id_map = std::collections::HashMap::new();
        for node in cpg.nodes() {
            let idx = merged.copy_node(node);
            id_map.insert(node.id, idx);
        }
        for (s, t, edge) in cpg.edges_full() {
            if let (Some(&a), Some(&b)) = (id_map.get(&s), id_map.get(&t)) {
                merged.add_edge_full(a, b, edge);
            }
        }
    }
    Ok(merged)
}

pub fn checked_driver(explicit: Option<&Path>) -> Result<PathBuf, CpgError> {
    let driver = explicit
        .map(Path::to_path_buf)
        .or_else(locate_driver)
        .ok_or_else(|| {
            CpgError::Extraction(format!(
                "llvm-extract-driver is not beside the executable and {DRIVER_ENV} is unset; install it with `cargo xtask install`"
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
    let name = format!("llvm-extract-driver{}", std::env::consts::EXE_SUFFIX);
    [dir.join(&name), dir.parent()?.join(&name)]
        .into_iter()
        .find(|candidate| candidate.is_file())
}

fn touch_sources(crate_root: &Path) -> Result<(), CpgError> {
    let now = std::time::SystemTime::now();
    for name in ["src/main.rs", "src/lib.rs"] {
        let path = crate_root.join(name);
        if path.is_file() {
            let file = File::options().append(true).open(&path)?;
            let _ = file.set_times(fs::FileTimes::new().set_modified(now));
        }
    }
    Ok(())
}
