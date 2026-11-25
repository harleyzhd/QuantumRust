use std::path::PathBuf;
use std::process::{exit, Command};

use llvm_extract::OUT_DIR_ENV;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let real_rustc = args.get(1).cloned().unwrap_or_else(|| "rustc".into());
    let rustc_args: Vec<String> = args.iter().skip(2).cloned().collect();

    if !should_extract(&rustc_args) {
        run(&real_rustc, &rustc_args);
    }

    let rewritten: Vec<String> = rustc_args
        .iter()
        .map(|a| {
            if a.starts_with("--emit=") && !a.contains("llvm-ir") {
                format!("{a},llvm-ir")
            } else {
                a.clone()
            }
        })
        .collect();

    let status = Command::new(&real_rustc)
        .args(&rewritten)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("llvm-extract-driver: failed to spawn {real_rustc}: {e}");
            exit(1);
        });
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }

    if let Err(e) = copy_ll_out(&rustc_args) {
        eprintln!("llvm-extract-driver: {e}");
        exit(1);
    }
    exit(0);
}

fn copy_ll_out(rustc_args: &[String]) -> Result<(), String> {
    let out_dir = std::env::var_os(OUT_DIR_ENV).expect("checked by should_extract");
    let crate_name =
        arg_value(rustc_args, "--crate-name").ok_or("missing --crate-name".to_string())?;
    let emit_dir = arg_value(rustc_args, "--out-dir").ok_or("missing --out-dir".to_string())?;
    let extra = codegen_value(rustc_args, "extra-filename").unwrap_or_default();

    let ll = PathBuf::from(emit_dir).join(format!("{crate_name}{extra}.ll"));
    if !ll.is_file() {
        return Err(format!("expected emitted IR at {}", ll.display()));
    }
    let dest = PathBuf::from(out_dir).join(format!("{crate_name}.ll"));
    std::fs::copy(&ll, &dest).map_err(|e| format!("copying {}: {e}", ll.display()))?;
    Ok(())
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

fn codegen_value(args: &[String], key: &str) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let candidate = if arg == "-C" {
            iter.peek().map(|s| s.as_str())
        } else {
            arg.strip_prefix("-C")
        };
        if let Some(rest) = candidate {
            if let Some(value) = rest.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn run(real_rustc: &str, rustc_args: &[String]) -> ! {
    let status = Command::new(real_rustc)
        .args(rustc_args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("llvm-extract-driver: failed to spawn {real_rustc}: {e}");
            exit(1);
        });
    exit(status.code().unwrap_or(1));
}
