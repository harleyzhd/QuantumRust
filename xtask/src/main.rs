mod bench;
mod bench_deps;

use std::path::PathBuf;

use anyhow::Result;

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("bench") => {
            let root = std::env::args().nth(2).map_or_else(
                || {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../benchmark/mutants")
                        .canonicalize()
                        .unwrap_or_else(|_| {
                            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../benchmark/mutants")
                        })
                },
                PathBuf::from,
            );
            bench::generate(&root)?;
        }
        Some(command @ ("compare" | "ablate" | "risk-checks")) => {
            let script = match command {
                "compare" => "compare_tools.py",
                "ablate" => "ablate_layers.py",
                _ => "risk_checks.py",
            };
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
            let status = std::process::Command::new("python3")
                .arg(root.join("docs/scripts").join(script))
                .arg(root.join("benchmark/mutants"))
                .args(std::env::args().skip(2))
                .current_dir(&root)
                .status()?;
            anyhow::ensure!(status.success(), "{script} exited with {status}");
        }
        Some("install") => install(std::env::args().skip(2).collect())?,
        Some("scale") => {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
            let status = std::process::Command::new("python3")
                .arg(root.join("docs/scripts/measure_scale.py"))
                .args(std::env::args().skip(2))
                .current_dir(&root)
                .status()?;
            anyhow::ensure!(status.success(), "measure_scale.py exited with {status}");
        }
        _ => {
            println!("usage: cargo xtask <install|bench|compare|ablate|risk-checks|scale> [args]");
            println!("  install [--root DIR] [--offline]  install quantumrust and both extraction drivers");
            println!("  bench [dir]   generate the mutation benchmark (default benchmark/mutants)");
            println!("  compare [..]  QuantumRust against the comparator scanners");
            println!("  ablate [..]   dual vs mir-only vs llvm-only on the same suite");
            println!("  risk-checks [..]  checks of the risk ranking, on fold B");
            println!("  scale run DIR | scale report DIR  per-stage runtime and memory");
        }
    }
    Ok(())
}

fn install(args: Vec<String>) -> Result<()> {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let plan = install_plan(&args, &workspace, &std::env::current_dir()?)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let toolchain = pinned_toolchain(&workspace);
    for (krate, bin) in [
        ("crates/quantumrust-cli", None),
        ("crates/mir-extract", Some("mir-extract-driver")),
        ("crates/llvm-extract", Some("llvm-extract-driver")),
    ] {
        let mut command = std::process::Command::new(&cargo);
        command
            .args(["install", "--locked", "--force", "--path"])
            .arg(workspace.join(krate))
            .arg("--target-dir")
            .arg(&plan.target_dir);
        if let Some(bin) = bin {
            command.args(["--bin", bin]);
        }
        if let Some(dir) = &plan.root {
            command.arg("--root").arg(dir);
        }
        if plan.offline {
            command.arg("--offline");
        }
        if let (Some(t), None) = (&toolchain, std::env::var_os("RUSTUP_TOOLCHAIN")) {
            command.env("RUSTUP_TOOLCHAIN", t);
        }
        let status = command.current_dir(&workspace).status()?;
        anyhow::ensure!(status.success(), "installing {krate} failed with {status}");
    }
    println!("installed; run `quantumrust doctor` to check the install");
    Ok(())
}

#[derive(Debug)]
struct InstallPlan {
    root: Option<PathBuf>,
    target_dir: PathBuf,
    offline: bool,
}

fn install_plan(
    args: &[String],
    workspace: &std::path::Path,
    cwd: &std::path::Path,
) -> Result<InstallPlan> {
    let usage = "usage: cargo xtask install [--root DIR] [--offline]";
    let mut plan = InstallPlan {
        root: None,
        target_dir: workspace.join("target/install"),
        offline: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let dir = args.next().ok_or_else(|| anyhow::anyhow!(usage))?;
                plan.root = Some(cwd.join(dir));
            }
            "--offline" => plan.offline = true,
            _ => anyhow::bail!(usage),
        }
    }
    Ok(plan)
}

fn pinned_toolchain(workspace: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(workspace.join("rust-toolchain.toml")).ok()?;
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("channel"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string())
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn install_resolves_root_from_the_callers_directory_and_builds_apart() {
        let plan = install_plan(
            &["--root".into(), "out".into()],
            Path::new("/work/tool"),
            Path::new("/home/me/elsewhere"),
        )
        .unwrap();
        assert_eq!(
            plan.root.as_deref(),
            Some(Path::new("/home/me/elsewhere/out"))
        );
        assert_eq!(plan.target_dir, Path::new("/work/tool/target/install"));
        assert!(!plan.offline);
        let offline =
            install_plan(&["--offline".into()], Path::new("/w"), Path::new("/c")).unwrap();
        assert!(offline.offline && offline.root.is_none());
        assert!(install_plan(&["--bogus".into()], Path::new("/w"), Path::new("/c")).is_err());
    }

    #[test]
    fn the_pinned_channel_is_read_from_the_toolchain_file() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(
            pinned_toolchain(&workspace).as_deref(),
            Some("nightly-2026-06-01")
        );
    }
}
