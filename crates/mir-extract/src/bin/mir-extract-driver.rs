#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;
use std::process::{exit, Command, ExitCode};

use mir_extract::extract::ExtractCallbacks;
use mir_extract::{OUT_DIR_ENV, SYSROOT_ENV};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let real_rustc = args.get(1).cloned().unwrap_or_else(|| "rustc".into());
    let rustc_args: Vec<String> = args.iter().skip(2).cloned().collect();

    if !should_extract(&rustc_args) {
        passthrough(&real_rustc, &rustc_args);
    }

    let mut compiler_args = Vec::with_capacity(rustc_args.len() + 3);
    compiler_args.push("rustc".to_string());
    compiler_args.extend(rustc_args.iter().cloned());
    let has_sysroot = rustc_args
        .iter()
        .any(|a| a == "--sysroot" || a.starts_with("--sysroot="));
    if !has_sysroot {
        if let Ok(sysroot) = std::env::var(SYSROOT_ENV) {
            compiler_args.push("--sysroot".into());
            compiler_args.push(sysroot);
        }
    }

    let mut callbacks = ExtractCallbacks::default();
    let exit_code = rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(&compiler_args, &mut callbacks)
    });

    if let Some(cpg) = callbacks.cpg {
        let out_dir =
            PathBuf::from(std::env::var_os(OUT_DIR_ENV).expect("checked by should_extract"));
        let crate_name = arg_value(&rustc_args, "--crate-name").unwrap_or_else(|| "unknown".into());
        let crate_type = arg_value(&rustc_args, "--crate-type").unwrap_or_else(|| "bin".into());
        let out = out_dir.join(format!("{crate_name}.{crate_type}.mir-cpg.json"));
        if let Err(e) = cpg.save_json(&out) {
            eprintln!("mir-extract-driver: failed to write {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
    }
    exit_code
}

fn should_extract(rustc_args: &[String]) -> bool {
    if std::env::var_os(OUT_DIR_ENV).is_none()
        || std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none()
    {
        return false;
    }
    if rustc_args.iter().any(|a| a.starts_with("--print")) {
        return false;
    }
    arg_value(rustc_args, "--crate-name").is_some_and(|n| n != "build_script_build")
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
        if let Some(rest) = arg.strip_prefix(flag) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn passthrough(real_rustc: &str, rustc_args: &[String]) -> ! {
    let status = Command::new(real_rustc)
        .args(rustc_args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("mir-extract-driver: failed to spawn {real_rustc}: {e}");
            exit(1);
        });
    exit(status.code().unwrap_or(1));
}
