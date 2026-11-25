mod common;

use std::fs;
use std::path::Path;
use std::process::Output;

use common::{bin, drivers, explain, plain_bin, scratch, workspace_root};

fn copy_crate(from: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let to = dest.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_crate(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

fn findings_count(out: &Output) -> usize {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let at = stdout
        .find("Findings (")
        .unwrap_or_else(|| panic!("no findings header in:\n{stdout}"));
    stdout[at + "Findings (".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

#[test]
fn binary_starts_without_library_path_env() {
    let out = plain_bin().arg("--version").output().unwrap();
    assert!(out.status.success(), "{}", explain(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("quantumrust "),
        "{}",
        explain(&out)
    );
}

#[test]
fn analyses_a_crate_pinned_to_stable() {
    drivers();
    let fixture = workspace_root().join("fixtures/demo-crate");
    let in_place = bin()
        .current_dir(workspace_root())
        .arg("analyze")
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(in_place.status.success(), "{}", explain(&in_place));
    let expected = findings_count(&in_place);

    let dest = scratch("pinned-to-stable").join("demo-crate");
    copy_crate(&fixture, &dest);
    fs::write(
        dest.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"stable\"\n",
    )
    .unwrap();
    let out = plain_bin()
        .current_dir(dest.parent().unwrap())
        .arg("analyze")
        .arg(&dest)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", explain(&out));
    assert_eq!(findings_count(&out), expected, "{}", explain(&out));
}

#[test]
fn a_crate_inside_an_unrelated_workspace_gets_an_actionable_error() {
    drivers();
    let outer = scratch("unrelated-workspace");
    fs::create_dir_all(&outer).unwrap();
    fs::write(outer.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let dest = outer.join("demo-crate");
    copy_crate(&workspace_root().join("fixtures/demo-crate"), &dest);

    let out = bin().arg("analyze").arg(&dest).output().unwrap();
    assert!(!out.status.success(), "{}", explain(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is inside the cargo workspace at"),
        "{}",
        explain(&out)
    );
    assert!(
        stderr.contains("add an empty [workspace] table"),
        "{}",
        explain(&out)
    );
    assert!(stderr.lines().count() < 6, "{}", explain(&out));
}

#[test]
fn descend_inside_an_unrelated_workspace_gets_the_same_one_line_error() {
    drivers();
    let outer = scratch("unrelated-workspace-descend");
    fs::create_dir_all(&outer).unwrap();
    fs::write(outer.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let dest = outer.join("demo-crate");
    copy_crate(&workspace_root().join("fixtures/demo-crate"), &dest);

    let out = bin()
        .arg("analyze")
        .arg(&dest)
        .arg("--descend")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", explain(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is inside the cargo workspace at"),
        "{}",
        explain(&out)
    );
    assert!(
        !stderr.contains("believes it's in a workspace"),
        "{}",
        explain(&out)
    );
    assert!(stderr.lines().count() < 6, "{}", explain(&out));
}
