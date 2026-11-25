use std::process::Command;

pub fn run() -> bool {
    let mut all = true;
    let mut report = |check: &str, result: Result<String, String>| match result {
        Ok(detail) => println!("{check:<22}{:<6}{detail}", "ok"),
        Err(detail) => {
            all = false;
            println!("{check:<22}{:<6}{detail}", "FAIL");
        }
    };
    report("toolchain", toolchain());
    report(
        "mir-extract-driver",
        mir_extract::checked_driver(None)
            .map(|p| p.display().to_string())
            .map_err(|e| e.to_string()),
    );
    report(
        "llvm-extract-driver",
        llvm_extract::checked_driver(None)
            .map(|p| p.display().to_string())
            .map_err(|e| e.to_string()),
    );
    all
}

fn toolchain() -> Result<String, String> {
    let name = cpg_core::toolchain::pinned();
    let probe = |arg: &str| -> Result<String, Probe> {
        let mut rustc = Command::new("rustc");
        rustc.arg(arg);
        cpg_core::toolchain::apply(&mut rustc);
        rustc.env("RUSTUP_AUTO_INSTALL", "0");
        let out = rustc.output().map_err(Probe::NotStarted)?;
        if !out.status.success() {
            return Err(Probe::Failed(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let shown = name.unwrap_or("the rustc on PATH");
    let install = |name: &str| {
        format!("rustup toolchain install {name} --component rustc-dev llvm-tools-preview rust-src")
    };
    let sysroot = match probe("--print=sysroot") {
        Ok(sysroot) => sysroot,
        Err(Probe::NotStarted(err)) => {
            return Err(format!(
                "could not start rustc ({err}); fix: put rustup's bin directory \
                 (usually ~/.cargo/bin) on PATH"
            ))
        }
        Err(Probe::Failed(stderr)) => {
            let first = stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            return Err(match name {
                Some(name) if stderr.contains("is not installed") => {
                    format!("{name} is not installed; fix: {}", install(name))
                }
                Some(name) => format!("{name} fails to run ({first}); fix: {}", install(name)),
                None => format!(
                    "the rustc on PATH fails to run ({first}); fix: put the toolchain \
                     QuantumRust was built with on PATH"
                ),
            });
        }
    };
    if let Some(built) = cpg_core::toolchain::build_sysroot() {
        if sysroot != built {
            let fix = if std::env::var_os(cpg_core::toolchain::OVERRIDE_ENV).is_some() {
                format!("unset {}", cpg_core::toolchain::OVERRIDE_ENV)
            } else {
                "put the toolchain QuantumRust was built with first on PATH".into()
            };
            return Err(format!(
                "{shown} resolves to {sysroot}, but the drivers were built against {built}; fix: {fix}"
            ));
        }
    }
    let version = probe("--version").unwrap_or_default();
    Ok(format!("{shown} ({version})"))
}

enum Probe {
    NotStarted(std::io::Error),
    Failed(String),
}
