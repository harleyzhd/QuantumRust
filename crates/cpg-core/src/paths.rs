pub fn display_path(file: &str) -> String {
    for (at, _) in file.match_indices("/registry/src/") {
        let after = &file[at + "/registry/src/".len()..];
        if let Some((index, rest)) = after.split_once('/') {
            if is_index_dir(index) && !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    if let Some((_, after)) = file.split_once("/git/checkouts/") {
        let mut parts = after.splitn(3, '/');
        if let (Some(checkout), Some(rev), Some(rest)) = (parts.next(), parts.next(), parts.next())
        {
            let repo = checkout
                .rsplit_once('-')
                .map_or(checkout, |(repo, _hash)| repo);
            return format!("{repo}@{rev}/{rest}");
        }
    }
    if file.starts_with('/') {
        if let Some(at) = file.rfind("/src/") {
            if let Some(package) = file[..at].rsplit('/').next().filter(|d| !d.is_empty()) {
                return format!("{package}{}", &file[at..]);
            }
        }
        let mut tail = file.rsplitn(3, '/');
        return match (tail.next(), tail.next()) {
            (Some(name), Some(parent)) if !parent.is_empty() => format!("{parent}/{name}"),
            (Some(name), _) => name.to_string(),
            _ => file.to_string(),
        };
    }
    file.to_string()
}

fn is_index_dir(segment: &str) -> bool {
    segment.rsplit_once('-').is_some_and(|(name, hash)| {
        !name.is_empty() && hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit())
    })
}

pub fn display_loc(loc: &crate::SourceLoc) -> crate::SourceLoc {
    crate::SourceLoc::new(display_path(&loc.file), loc.line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_paths_lose_the_cargo_home() {
        assert_eq!(
            display_path(
                "/Users/x/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/age-core-0.12.0/src/primitives.rs"
            ),
            "age-core-0.12.0/src/primitives.rs"
        );
    }

    #[test]
    fn git_checkouts_keep_the_repository_and_revision() {
        assert_eq!(
            display_path("/home/ci/.cargo/git/checkouts/rpgp-3f1c2a9b8d7e6f50/a1b2c3d/src/lib.rs"),
            "rpgp@a1b2c3d/src/lib.rs"
        );
    }

    #[test]
    fn local_paths_are_unchanged() {
        for path in ["src/lib.rs", "_deps/vault/src/lib.rs", "<unknown>"] {
            assert_eq!(display_path(path), path);
        }
    }

    #[test]
    fn a_registry_is_recognised_by_its_index_directory() {
        assert_eq!(
            display_path(
                "/opt/cargo/registry/src/github.com-1ecc6299db9ec823/age-core-0.12.0/src/x.rs"
            ),
            "age-core-0.12.0/src/x.rs"
        );
        assert_eq!(
            display_path("/home/me/registry/src/tool/lib.rs"),
            "registry/src/tool/lib.rs"
        );
    }

    #[test]
    fn other_absolute_paths_print_from_their_package_directory() {
        assert_eq!(
            display_path("/Users/x/project/vault/src/lib.rs"),
            "vault/src/lib.rs"
        );
        assert_eq!(
            display_path("/rustc/0123abcd/library/core/src/ops/mod.rs"),
            "core/src/ops/mod.rs"
        );
        assert_eq!(
            display_path("/Users/x/gen/out/bindings.rs"),
            "out/bindings.rs"
        );
    }
}
