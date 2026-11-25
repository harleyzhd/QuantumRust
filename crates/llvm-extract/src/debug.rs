use std::collections::{HashMap, HashSet};
use std::path::Path;

use cpg_core::SourceLoc;

struct Location {
    line: u32,
    scope: Option<u32>,
    inlined_at: Option<u32>,
}

#[derive(Default)]
pub(crate) struct DebugInfo {
    locations: HashMap<u32, Location>,
    scope_files: HashMap<u32, u32>,
    scope_parents: HashMap<u32, u32>,
    files: HashMap<u32, String>,
}

impl DebugInfo {
    pub(crate) fn parse(text: &str) -> Self {
        let mut info = Self::default();
        let mut raw_files: HashMap<u32, (String, String)> = HashMap::new();
        let mut unit_files: Vec<u32> = Vec::new();
        for line in text.lines() {
            let Some(rest) = line.strip_prefix('!') else {
                continue;
            };
            let Some((id, body)) = rest.split_once(" = ") else {
                continue;
            };
            let Ok(id) = id.parse::<u32>() else {
                continue;
            };
            let body = body.strip_prefix("distinct ").unwrap_or(body);

            if let Some(args) = body.strip_prefix("!DILocation(") {
                let Some(line) = field_int(args, "line") else {
                    continue;
                };
                info.locations.insert(
                    id,
                    Location {
                        line,
                        scope: field_ref(args, "scope"),
                        inlined_at: field_ref(args, "inlinedAt"),
                    },
                );
            } else if let Some(args) = body.strip_prefix("!DIFile(") {
                if let Some(name) = field_str(args, "filename") {
                    let directory = field_str(args, "directory").unwrap_or_default();
                    raw_files.insert(id, (normalize_path(name), directory.to_string()));
                }
            } else if body.starts_with("!DI") {
                if body.starts_with("!DICompileUnit(") {
                    unit_files.extend(field_ref(args_of(body), "file"));
                }
                if let Some(file) = field_ref(args_of(body), "file") {
                    info.scope_files.insert(id, file);
                }
                if let Some(parent) = field_ref(args_of(body), "scope") {
                    info.scope_parents.insert(id, parent);
                }
            }
        }
        let local_dirs: HashSet<&str> = unit_files
            .iter()
            .filter_map(|file| raw_files.get(file))
            .map(|(_, directory)| directory.as_str())
            .collect();
        for (id, (name, directory)) in &raw_files {
            info.files
                .insert(*id, render_path(name, directory, &local_dirs));
        }
        info
    }

    pub(crate) fn location(&self, dbg: u32) -> Option<SourceLoc> {
        let mut frame = self.locations.get(&dbg)?;
        for _ in 0..64 {
            let Some(outer) = frame.inlined_at.and_then(|id| self.locations.get(&id)) else {
                break;
            };
            frame = outer;
        }
        let file = self.file_of_scope(frame.scope?)?;
        Some(SourceLoc::new(file, frame.line))
    }

    fn file_of_scope(&self, mut scope: u32) -> Option<&str> {
        for _ in 0..64 {
            if let Some(file) = self.scope_files.get(&scope) {
                return self.files.get(file).map(String::as_str);
            }
            scope = *self.scope_parents.get(&scope)?;
        }
        None
    }
}

pub(crate) fn dbg_ref(lines: &[&str], at: usize) -> Option<u32> {
    let first = lines.get(at)?;
    if let Some(id) = parse_dbg(first) {
        return Some(id);
    }
    if !is_invoke(first) {
        return None;
    }
    for line in lines.iter().skip(at + 1).take(3) {
        if let Some(id) = parse_dbg(line) {
            return Some(id);
        }
        if line.contains("unwind label") {
            break;
        }
    }
    None
}

fn is_invoke(line: &str) -> bool {
    let body = match line.split_once(" = ") {
        Some((lhs, rhs)) if lhs.trim_start().starts_with('%') => rhs,
        _ => line,
    };
    body.trim_start().starts_with("invoke ")
}

fn parse_dbg(line: &str) -> Option<u32> {
    let at = line.find("!dbg !")? + "!dbg !".len();
    let digits: String = line[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn args_of(body: &str) -> &str {
    match body.find('(') {
        Some(open) => &body[open + 1..],
        None => body,
    }
}

fn field_ref(args: &str, name: &str) -> Option<u32> {
    let needle = format!("{name}: !");
    let at = args.find(&needle)? + needle.len();
    let digits: String = args[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn field_int(args: &str, name: &str) -> Option<u32> {
    let needle = format!("{name}: ");
    let at = args.find(&needle)? + needle.len();
    let digits: String = args[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn field_str<'a>(args: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}: \"");
    let at = args.find(&needle)? + needle.len();
    let end = args[at..].find('"')?;
    Some(&args[at..at + end])
}

fn render_path(filename: &str, directory: &str, local_dirs: &HashSet<&str>) -> String {
    let relative = !Path::new(filename).is_absolute();
    if relative
        && !directory.is_empty()
        && !local_dirs.is_empty()
        && !local_dirs.contains(directory)
    {
        return Path::new(directory).join(filename).display().to_string();
    }
    filename.to_string()
}

fn normalize_path(filename: &str) -> String {
    match filename.find("/@/") {
        Some(cut) => filename[..cut].to_string(),
        None => filename.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const METADATA: &str = r#"
!16164 = !DILocation(line: 53, column: 9, scope: !16147)
!16147 = distinct !DILexicalBlock(scope: !16145, file: !3736, line: 51, column: 5)
!3736 = !DIFile(filename: "src/main.rs", directory: "/repo/fixtures/demo-crate", checksumkind: CSK_MD5, checksum: "7891f8")
!16145 = distinct !DILexicalBlock(scope: !16139, file: !3736, line: 50, column: 5)
!900 = !DILocation(line: 1916, column: 9, scope: !901, inlinedAt: !16164)
!901 = distinct !DISubprogram(name: "lt", linkageName: "_RNvXs12_", scope: !902, file: !903, line: 1916)
!903 = !DIFile(filename: "/rustup/lib/core/src/cmp.rs", directory: "")
!904 = !DILocation(line: 7, column: 1, scope: !905)
!905 = distinct !DILexicalBlock(scope: !906, line: 6, column: 1)
!906 = distinct !DISubprogram(name: "outer", file: !3736, line: 5)
!1407 = !DIFile(filename: "src/main.rs/@/0muahfmp34bsw7n7f26pnev1w", directory: "/repo")
!1408 = !DILocation(line: 12, column: 3, scope: !1409)
!1409 = distinct !DISubprogram(name: "incremental", file: !1407, line: 11)
"#;

    #[test]
    fn resolves_a_direct_location_through_its_lexical_block() {
        let info = DebugInfo::parse(METADATA);
        let loc = info.location(16164).expect("resolves");
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 53);
    }

    #[test]
    fn an_inlined_frame_resolves_to_the_call_site_that_pulled_it_in() {
        let info = DebugInfo::parse(METADATA);
        let loc = info.location(900).expect("resolves");
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 53);
    }

    #[test]
    fn a_scope_without_a_file_walks_outward() {
        let info = DebugInfo::parse(METADATA);
        let loc = info.location(904).expect("resolves");
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 7);
    }

    #[test]
    fn the_incremental_disambiguator_is_stripped() {
        let info = DebugInfo::parse(METADATA);
        assert_eq!(info.location(1408).expect("resolves").file, "src/main.rs");
    }

    #[test]
    fn a_missing_or_unknown_reference_is_none_not_a_guess() {
        let info = DebugInfo::parse(METADATA);
        assert!(info.location(999_999).is_none());
        assert!(dbg_ref(&["  ret void"], 0).is_none());
    }

    #[test]
    fn reads_the_dbg_reference_off_an_instruction() {
        let lines = [
            "  %_0 = call i32 @RSA_sign(i32 672, ptr null) #35, !dbg !16164",
            "define void @f() personality ptr @rust_eh_personality !dbg !16184 {",
        ];
        assert_eq!(dbg_ref(&lines, 0), Some(16164));
        assert_eq!(dbg_ref(&lines, 1), Some(16184));
    }

    #[test]
    fn an_invoke_carries_its_dbg_on_the_continuation_line() {
        let lines = [
            "  invoke void @_RNvMNtCs_14elliptic_curve4ecdh14diffie_hellman(ptr %a)",
            "          to label %bb13 unwind label %cleanup, !dbg !93715",
        ];
        assert_eq!(dbg_ref(&lines, 0), Some(93715));

        let with_result = [
            "  %_3 = invoke i32 @f(ptr %a)",
            "          to label %ok unwind label %bad, !dbg !42",
        ];
        assert_eq!(dbg_ref(&with_result, 0), Some(42));
    }

    #[test]
    fn a_plain_call_does_not_borrow_the_next_instructions_location() {
        let lines = [
            "  call void @llvm.memcpy.p0.p0.i64(ptr %a, ptr %b, i64 8, i1 false)",
            "  %_1 = call i32 @g(ptr %a), !dbg !77",
        ];
        assert_eq!(dbg_ref(&lines, 0), None);
    }

    #[test]
    fn an_invoke_stops_at_its_own_unwind_clause() {
        let lines = [
            "  invoke void @f(ptr %a)",
            "          to label %ok unwind label %bad",
            "  %_1 = call i32 @g(ptr %a), !dbg !77",
        ];
        assert_eq!(dbg_ref(&lines, 0), None);
    }

    const WITH_DEPENDENCY: &str = r#"
!3332 = !DIFile(filename: "src/crypto/rust_crypto/mod.rs", directory: "/crates/jsonwebtoken-11.1.0", checksumkind: CSK_MD5, checksum: "7df8d8")
!3959 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !3960, producer: "clang LLVM (rustc version 1.98.0-nightly)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!3960 = !DIFile(filename: "src/lib.rs/@/8qzj9jv8hsdp9lfoj9peopvsp", directory: "/crates/jsonwebtoken-11.1.0")
!10 = !DILocation(line: 41, column: 9, scope: !11)
!11 = distinct !DISubprogram(name: "sign", scope: !3332, file: !3332, line: 40)
!20 = !DILocation(line: 16, column: 9, scope: !21)
!21 = distinct !DISubprogram(name: "sign<jsonwebtoken::crypto::rust_crypto::rsa::Rsa256Signer>", file: !85836, line: 15)
!85836 = !DIFile(filename: "src/signer.rs", directory: "/registry/signature-2.2.0", checksumkind: CSK_MD5, checksum: "566389")
!30 = !DILocation(line: 1916, column: 9, scope: !31)
!31 = distinct !DISubprogram(name: "lt", file: !903, line: 1916)
!903 = !DIFile(filename: "/rustup/lib/core/src/cmp.rs", directory: "")
!40 = !DILocation(line: 3, column: 5, scope: !41)
!41 = distinct !DISubprogram(name: "decode", file: !3960, line: 2)
"#;

    #[test]
    fn a_dependency_file_keeps_its_directory() {
        let info = DebugInfo::parse(WITH_DEPENDENCY);
        let loc = info.location(20).expect("resolves");
        assert_eq!(loc.file, "/registry/signature-2.2.0/src/signer.rs");
        assert_eq!(loc.line, 16);
    }

    #[test]
    fn the_compile_units_own_files_stay_relative() {
        let info = DebugInfo::parse(WITH_DEPENDENCY);
        assert_eq!(
            info.location(10).expect("resolves").file,
            "src/crypto/rust_crypto/mod.rs"
        );
        assert_eq!(info.location(40).expect("resolves").file, "src/lib.rs");
        assert_eq!(
            info.location(30).expect("resolves").file,
            "/rustup/lib/core/src/cmp.rs"
        );
    }

    #[test]
    fn a_filename_is_not_a_file_reference() {
        assert_eq!(
            field_ref(r#"filename: "x.rs", directory: """#, "file"),
            None
        );
        assert_eq!(field_ref(r#"scope: !1, file: !2"#, "file"), Some(2));
    }
}
