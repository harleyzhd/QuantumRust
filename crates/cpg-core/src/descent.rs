use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

use crate::CpgError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DescentPlan {
    pub depth: u8,
    pub crates: BTreeSet<String>,
}

impl DescentPlan {
    pub const DEPTH_ENV: &'static str = "QR_DESCEND";
    pub const CRATES_ENV: &'static str = "QR_DESCEND_CRATES";

    pub fn env(&self) -> [(&'static str, String); 2] {
        let crates: Vec<&str> = self.crates.iter().map(String::as_str).collect();
        [
            (Self::DEPTH_ENV, self.depth.to_string()),
            (Self::CRATES_ENV, crates.join(",")),
        ]
    }

    pub fn from_env() -> Option<Self> {
        let depth = std::env::var(Self::DEPTH_ENV).ok()?;
        let crates = std::env::var(Self::CRATES_ENV).unwrap_or_default();
        Self::parse(&depth, &crates)
    }

    pub fn parse(depth: &str, crates: &str) -> Option<Self> {
        Some(Self {
            depth: depth.parse().ok().filter(|d| *d > 0)?,
            crates: crates
                .split(',')
                .filter(|c| !c.is_empty())
                .map(String::from)
                .collect(),
        })
    }
}

const STD: [&str; 5] = ["std", "core", "alloc", "proc_macro", "test"];

struct Graph<'a> {
    name: HashMap<&'a str, &'a str>,
    lib: HashMap<&'a str, &'a str>,
    members: HashSet<&'a str>,
    deps: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> Graph<'a> {
    fn of(metadata: &'a Value) -> Self {
        let mut name = HashMap::new();
        let mut lib = HashMap::new();
        for p in metadata["packages"].as_array().into_iter().flatten() {
            let id = p["id"].as_str().unwrap_or_default();
            name.insert(id, p["name"].as_str().unwrap_or_default());
            let target = p["targets"].as_array().into_iter().flatten().find(|t| {
                t["kind"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|k| matches!(k.as_str(), Some("lib" | "rlib" | "dylib")))
            });
            if let Some(t) = target {
                lib.insert(id, t["name"].as_str().unwrap_or_default());
            }
        }
        let members = metadata["workspace_members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mut deps = HashMap::new();
        for node in metadata["resolve"]["nodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = node["id"].as_str().unwrap_or_default();
            let normal = node["deps"].as_array().into_iter().flatten().filter(|d| {
                d["dep_kinds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|k| k["kind"].is_null())
            });
            deps.insert(id, normal.filter_map(|d| d["pkg"].as_str()).collect());
        }
        Self {
            name,
            lib,
            members,
            deps,
        }
    }

    fn of_units(unit_graph: &'a Value) -> Result<Self, CpgError> {
        let units: Vec<&Value> = unit_graph["units"]
            .as_array()
            .into_iter()
            .flatten()
            .collect();
        let pkg = |u: &'a Value| u["pkg_id"].as_str().unwrap_or_default();
        let kind_is = |u: &Value, k: &str| {
            u["target"]["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|x| x.as_str() == Some(k))
        };
        let mut name = HashMap::new();
        let mut lib = HashMap::new();
        let mut deps: HashMap<&str, Vec<&str>> = HashMap::new();
        for &u in &units {
            if kind_is(u, "custom-build") {
                continue;
            }
            let id = pkg(u);
            name.insert(id, package_name(id));
            if ["lib", "rlib", "dylib"].iter().any(|k| kind_is(u, k)) {
                lib.insert(id, u["target"]["name"].as_str().unwrap_or_default());
            }
            let out = deps.entry(id).or_default();
            for d in u["dependencies"].as_array().into_iter().flatten() {
                let Some(&to) = d["index"]
                    .as_u64()
                    .and_then(|i| units.get(usize::try_from(i).ok()?))
                else {
                    continue;
                };
                if !kind_is(to, "custom-build") && !out.contains(&pkg(to)) {
                    out.push(pkg(to));
                }
            }
        }
        let members: HashSet<&str> = unit_graph["roots"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|i| units.get(usize::try_from(i.as_u64()?).ok()?))
            .map(|&u| pkg(u))
            .collect();
        if members.is_empty() {
            return Err(CpgError::Extraction("the unit graph has no roots".into()));
        }
        Ok(Self {
            name,
            lib,
            members,
            deps,
        })
    }

    fn descendable(&self, roots: &[&'a str], is_crypto: &dyn Fn(&str) -> bool) -> BTreeSet<String> {
        let mut reachable: HashSet<&str> = HashSet::new();
        let mut stack = roots.to_vec();
        while let Some(p) = stack.pop() {
            for &d in self.deps.get(p).into_iter().flatten() {
                if reachable.insert(d) {
                    stack.push(d);
                }
            }
        }
        let mut memo = HashMap::new();
        reachable
            .into_iter()
            .filter(|p| !self.members.contains(p))
            .filter(|p| !self.is_crypto(p, is_crypto))
            .filter(|p| self.reaches(p, is_crypto, &mut memo))
            .filter_map(|p| self.lib.get(p).map(|l| l.replace('-', "_")))
            .filter(|l| !STD.contains(&l.as_str()))
            .collect()
    }

    fn is_crypto(&self, p: &str, is_crypto: &dyn Fn(&str) -> bool) -> bool {
        self.name.get(p).is_some_and(|n| is_crypto(n))
            || self.lib.get(p).is_some_and(|l| is_crypto(l))
    }

    fn reaches(
        &self,
        p: &'a str,
        is_crypto: &dyn Fn(&str) -> bool,
        memo: &mut HashMap<&'a str, bool>,
    ) -> bool {
        if let Some(&r) = memo.get(p) {
            return r;
        }
        memo.insert(p, false);
        let r = self
            .deps
            .get(p)
            .into_iter()
            .flatten()
            .any(|&d| self.is_crypto(d, is_crypto) || self.reaches(d, is_crypto, memo));
        memo.insert(p, r);
        r
    }
}

fn package_name(pkg_id: &str) -> &str {
    let (url, fragment) = pkg_id.rsplit_once('#').unwrap_or((pkg_id, ""));
    match fragment.split_once('@') {
        Some((name, _)) => name,
        None => url
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default(),
    }
}

pub fn descendable(
    metadata: &Value,
    is_crypto: &dyn Fn(&str) -> bool,
) -> Result<BTreeSet<String>, CpgError> {
    let root = metadata["resolve"]["root"].as_str().ok_or_else(|| {
        CpgError::Extraction("descent needs a package, not a virtual workspace".into())
    })?;
    Ok(Graph::of(metadata).descendable(&[root], is_crypto))
}

pub fn descendable_from_unit_graph(
    unit_graph: &Value,
    is_crypto: &dyn Fn(&str) -> bool,
) -> Result<BTreeSet<String>, CpgError> {
    let graph = Graph::of_units(unit_graph)?;
    let roots: Vec<&str> = graph.members.iter().copied().collect();
    Ok(graph.descendable(&roots, is_crypto))
}

pub const PLANNER_ENV: &str = "QR_DESCENT_PLANNER";

pub fn plan(
    crate_root: &Path,
    depth: u8,
    is_crypto: &dyn Fn(&str) -> bool,
) -> Result<DescentPlan, CpgError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    plan_with(crate_root, depth, is_crypto, &|args| {
        let mut command = Command::new(&cargo);
        command.args(args);
        crate::toolchain::apply(&mut command);
        command.output()
    })
}

pub fn plan_with(
    crate_root: &Path,
    depth: u8,
    is_crypto: &dyn Fn(&str) -> bool,
    run: &dyn Fn(&[&str]) -> std::io::Result<Output>,
) -> Result<DescentPlan, CpgError> {
    let manifest = crate_root.join("Cargo.toml");
    let manifest = manifest
        .to_str()
        .ok_or_else(|| CpgError::Extraction(format!("{} is not UTF-8", manifest.display())))?;
    let metadata_error = if std::env::var(PLANNER_ENV).is_ok_and(|v| v == "unit-graph") {
        format!("not run: {PLANNER_ENV}=unit-graph")
    } else {
        let out = run(&[
            "metadata",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
            manifest,
        ])?;
        if out.status.success() {
            let metadata: Value = serde_json::from_slice(&out.stdout)?;
            return Ok(DescentPlan {
                depth,
                crates: descendable(&metadata, is_crypto)?,
            });
        }
        if crate::toolchain::is_unlisted_workspace_member(&out.stderr) {
            return Err(crate::toolchain::cargo_failure(
                "cargo metadata failed",
                crate_root,
                &out.stderr,
            ));
        }
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let out = run(&[
        "check",
        "--offline",
        "--unit-graph",
        "-Z",
        "unstable-options",
        "--manifest-path",
        manifest,
    ])?;
    if !out.status.success() {
        return Err(CpgError::Extraction(format!(
            "cannot plan descent.\ncargo metadata failed:\n{}\ncargo check --unit-graph failed:\n{}",
            metadata_error.trim_end(),
            String::from_utf8_lossy(&out.stderr).trim_end()
        )));
    }
    let unit_graph: Value = serde_json::from_slice(&out.stdout)?;
    Ok(DescentPlan {
        depth,
        crates: descendable_from_unit_graph(&unit_graph, is_crypto)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pkg(id: &str, name: &str, lib: Option<(&str, &str)>) -> serde_json::Value {
        let targets = match lib {
            Some((tname, kind)) => json!([{ "name": tname, "kind": [kind] }]),
            None => json!([{ "name": name, "kind": ["bin"] }]),
        };
        json!({ "id": id, "name": name, "targets": targets })
    }

    fn dep(pkg: &str, kind: Option<&str>) -> serde_json::Value {
        json!({ "pkg": pkg, "dep_kinds": [{ "kind": kind }] })
    }

    fn metadata() -> serde_json::Value {
        json!({
            "packages": [
                pkg("app", "app", Some(("app", "lib"))),
                pkg("vault", "vault", Some(("vault", "lib"))),
                pkg("relay", "relay", Some(("relay", "lib"))),
                pkg("sha2", "sha2", Some(("sha2", "lib"))),
                pkg("serde", "serde", Some(("serde", "lib"))),
                pkg("md5u", "md5-user", Some(("md5-user", "lib"))),
                pkg("md5", "md-5", Some(("md5", "lib"))),
                pkg("pm", "pm", Some(("pm", "proc-macro"))),
                pkg("member2", "member2", Some(("member2", "lib"))),
                pkg("devonly", "devonly", Some(("devonly", "lib"))),
                pkg("renamed", "renamed-pkg", Some(("renamed_lib", "lib"))),
            ],
            "workspace_members": ["app", "member2"],
            "resolve": {
                "root": "app",
                "nodes": [
                    { "id": "app", "deps": [
                        dep("vault", None), dep("relay", None), dep("serde", None),
                        dep("md5u", None), dep("pm", None), dep("member2", None),
                        dep("devonly", Some("dev")), dep("renamed", None)
                    ]},
                    { "id": "vault", "deps": [dep("sha2", None)] },
                    { "id": "relay", "deps": [dep("vault", None)] },
                    { "id": "md5u", "deps": [dep("md5", None)] },
                    { "id": "pm", "deps": [dep("sha2", None)] },
                    { "id": "member2", "deps": [dep("sha2", None)] },
                    { "id": "devonly", "deps": [dep("sha2", None)] },
                    { "id": "renamed", "deps": [dep("sha2", None)] },
                    { "id": "sha2", "deps": [] }, { "id": "serde", "deps": [] },
                    { "id": "md5", "deps": [] }
                ]
            }
        })
    }

    #[test]
    fn descendable_crates_reach_crypto_and_are_named_as_rustc_names_them() {
        let crypto = |name: &str| name == "sha2" || name == "md5";
        let got = descendable(&metadata(), &crypto).unwrap();
        let want: BTreeSet<String> = ["md5_user", "relay", "renamed_lib", "vault"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(got, want);
    }

    fn want() -> BTreeSet<String> {
        ["md5_user", "relay", "renamed_lib", "vault"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn unit(pkg: &str, kind: &str, name: &str, mode: &str, deps: &[usize]) -> serde_json::Value {
        let deps: Vec<_> = deps.iter().map(|i| json!({ "index": i })).collect();
        let pkg_id = if pkg == "app" {
            "path+file:///work/app#0.1.0".to_string()
        } else {
            format!("registry+https://github.com/rust-lang/crates.io-index#{pkg}@1.0.0")
        };
        json!({
            "pkg_id": pkg_id,
            "target": { "kind": [kind], "name": name },
            "mode": mode,
            "dependencies": deps,
        })
    }

    fn unit_graph() -> serde_json::Value {
        json!({
            "version": 1,
            "roots": [0],
            "units": [
                unit("app", "lib", "app", "check", &[1, 2, 4, 5, 7, 9, 11]),
                unit("vault", "lib", "vault", "check", &[3]),
                unit("relay", "lib", "relay", "check", &[1]),
                unit("sha2", "lib", "sha2", "check", &[]),
                unit("serde", "lib", "serde", "check", &[]),
                unit("md5-user", "lib", "md5_user", "check", &[6]),
                unit("md-5", "lib", "md5", "check", &[]),
                unit("pm", "proc-macro", "pm", "build", &[8]),
                unit("sha2", "lib", "sha2", "build", &[]),
                unit("renamed-pkg", "lib", "renamed_lib", "check", &[3]),
                unit("app", "custom-build", "build-script-build", "build", &[12]),
                unit("app", "custom-build", "build-script-build", "run-custom-build", &[10]),
                unit("buildonly", "lib", "buildonly", "build", &[8]),
            ]
        })
    }

    fn crypto(name: &str) -> bool {
        name == "sha2" || name == "md5"
    }

    #[test]
    fn package_names_come_from_both_forms_of_package_id() {
        let registry = "registry+https://github.com/rust-lang/crates.io-index#md-5@0.10.6";
        assert_eq!(package_name(registry), "md-5");
        assert_eq!(package_name("path+file:///work/app#0.1.0"), "app");
        assert_eq!(package_name("path+file:///w/age-0.12.1#age@0.12.1"), "age");
        assert_eq!(
            package_name("git+https://github.com/o/ring?rev=abc#0.17.8"),
            "ring"
        );
    }

    #[test]
    fn unit_graph_plan_equals_metadata_plan() {
        let from_metadata = descendable(&metadata(), &crypto).unwrap();
        let from_units = descendable_from_unit_graph(&unit_graph(), &crypto).unwrap();
        assert_eq!(from_units, want());
        assert_eq!(from_units, from_metadata);
    }

    #[cfg(unix)]
    fn output(code: i32, stdout: Vec<u8>, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout,
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    const UNFETCHED: &str = "error: failed to download `windows-sys v0.59.0`";

    #[cfg(unix)]
    #[test]
    fn plan_falls_back_to_the_unit_graph_when_metadata_fails() {
        let calls = std::cell::RefCell::new(Vec::new());
        let run = |args: &[&str]| {
            calls.borrow_mut().push(args[0].to_string());
            Ok(match args[0] {
                "metadata" => output(101, Vec::new(), UNFETCHED),
                _ => {
                    assert!(args.contains(&"--unit-graph") && args.contains(&"--offline"));
                    output(0, unit_graph().to_string().into_bytes(), "")
                }
            })
        };
        let plan = plan_with(Path::new("/work/app"), 3, &crypto, &run).unwrap();
        assert_eq!(
            plan,
            DescentPlan {
                depth: 3,
                crates: want()
            }
        );
        assert_eq!(*calls.borrow(), ["metadata", "check"]);
    }

    #[cfg(unix)]
    #[test]
    fn plan_reports_an_unlisted_workspace_member_in_one_line() {
        const WORKSPACE: &str =
            "error: current package believes it's in a workspace when it's not:\n\
            current:   /w/app/Cargo.toml\n\
            workspace: /w/Cargo.toml\n\n\
            this may be fixable by adding `app` to the `workspace.members` array";
        let calls = std::cell::RefCell::new(Vec::new());
        let run = |args: &[&str]| {
            calls.borrow_mut().push(args[0].to_string());
            Ok(output(101, Vec::new(), WORKSPACE))
        };
        let err = plan_with(Path::new("/w/app"), 3, &crypto, &run)
            .unwrap_err()
            .to_string();
        assert_eq!(*calls.borrow(), ["metadata"], "no fallback: {err}");
        assert!(err.contains("is inside the cargo workspace at /w"), "{err}");
        assert!(!err.contains("believes it's in a workspace"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn plan_reports_both_failures_when_neither_planner_runs() {
        let run = |args: &[&str]| {
            Ok(match args[0] {
                "metadata" => output(101, Vec::new(), UNFETCHED),
                _ => output(
                    101,
                    Vec::new(),
                    "error: the -Z flag is only accepted on nightly",
                ),
            })
        };
        let err = plan_with(Path::new("/work/app"), 3, &crypto, &run)
            .unwrap_err()
            .to_string();
        assert!(err.contains("windows-sys"), "{err}");
        assert!(err.contains("only accepted on nightly"), "{err}");
    }

    #[test]
    fn a_virtual_workspace_root_is_refused() {
        let mut m = metadata();
        m["resolve"]["root"] = serde_json::Value::Null;
        assert!(descendable(&m, &|_| false).is_err());
    }

    #[test]
    fn the_plan_round_trips_through_the_environment() {
        let plan = DescentPlan {
            depth: 3,
            crates: ["relay".to_string(), "vault".to_string()].into(),
        };
        let env = plan.env();
        assert_eq!(env[0], (DescentPlan::DEPTH_ENV, "3".to_string()));
        assert_eq!(env[1], (DescentPlan::CRATES_ENV, "relay,vault".to_string()));
        assert_eq!(DescentPlan::parse(&env[0].1, &env[1].1), Some(plan));
    }
}
