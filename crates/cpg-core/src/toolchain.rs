use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use crate::CpgError;

pub const OVERRIDE_ENV: &str = "QR_TOOLCHAIN";

pub fn pinned() -> Option<&'static str> {
    static PINNED: OnceLock<Option<String>> = OnceLock::new();
    PINNED
        .get_or_init(|| {
            std::env::var(OVERRIDE_ENV)
                .ok()
                .filter(|t| !t.is_empty())
                .or_else(|| option_env!("QR_BUILD_TOOLCHAIN").map(str::to_string))
        })
        .as_deref()
}

pub fn build_sysroot() -> Option<&'static str> {
    option_env!("QR_BUILD_SYSROOT")
}

pub fn apply(cmd: &mut Command) {
    if let Some(toolchain) = pinned() {
        cmd.env("RUSTUP_TOOLCHAIN", toolchain);
        cmd.env_remove("RUSTC");
    }
}

pub fn is_unlisted_workspace_member(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("believes it's in a workspace when it's not")
}

pub fn cargo_failure(what: &str, crate_root: &Path, stderr: &[u8]) -> CpgError {
    let stderr = String::from_utf8_lossy(stderr);
    if is_unlisted_workspace_member(stderr.as_bytes()) {
        let workspace = stderr
            .lines()
            .find_map(|l| l.trim().strip_prefix("workspace:"))
            .map(|w| {
                w.trim()
                    .trim_end_matches("Cargo.toml")
                    .trim_end_matches('/')
            })
            .unwrap_or("an enclosing directory");
        return CpgError::Extraction(format!(
            "{} is inside the cargo workspace at {workspace}, which does not list it; \
             add an empty [workspace] table to its Cargo.toml or analyse it from that workspace",
            crate_root.display()
        ));
    }
    CpgError::Extraction(format!("{what}:\n{stderr}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlisted_workspace_member_gets_one_line() {
        let stderr = b"error: current package believes it's in a workspace when it's not:\n\
            current:   /work/tool/vault/Cargo.toml\n\
            workspace: /work/tool/Cargo.toml\n\n\
            this may be fixable by adding `vault` to the `workspace.members` array";
        let err = cargo_failure("cargo build failed", Path::new("/work/tool/vault"), stderr);
        let text = err.to_string();
        assert!(
            text.contains("/work/tool/vault is inside the cargo workspace at /work/tool,"),
            "{text}"
        );
        assert!(
            text.contains("[workspace]") && !text.contains("workspace.members"),
            "{text}"
        );
    }

    #[test]
    fn a_pinned_child_does_not_inherit_rustc() {
        let mut cmd = std::process::Command::new("cargo");
        apply(&mut cmd);
        if pinned().is_some() {
            assert!(
                cmd.get_envs().any(|(k, v)| k == "RUSTC" && v.is_none()),
                "{:?}",
                cmd.get_envs().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn any_other_failure_keeps_cargos_output() {
        let err = cargo_failure("cargo build failed", Path::new("/c"), b"error[E0425]: oops");
        let text = err.to_string();
        assert!(
            text.contains("cargo build failed:") && text.contains("error[E0425]: oops"),
            "{text}"
        );
    }
}
