use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub(crate) struct Expectation {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) api: &'static str,
}

pub(crate) struct Mutant {
    pub(crate) id: String,
    pub(crate) failure_mode: &'static str,
    pub(crate) family: &'static str,
    pub(crate) parameter: &'static str,
    pub(crate) polarity: &'static str,
    pub(crate) nist_tier: Option<u8>,
    pub(crate) expected: Vec<Expectation>,
    pub(crate) conservatively_mapped: bool,
    pub(crate) fold: char,
    pub(crate) deps: Vec<&'static str>,
    pub(crate) dev_deps: Vec<&'static str>,
    pub(crate) source: String,
    pub(crate) extra_files: Vec<(&'static str, String)>,
}

pub(crate) struct CryptoCase {
    pub(crate) family: &'static str,
    pub(crate) parameter: &'static str,
    pub(crate) tier: u8,
    pub(crate) dep: &'static str,
    pub(crate) uses: &'static [&'static str],
    pub(crate) setup: &'static [&'static str],
    pub(crate) call: &'static str,
    pub(crate) api: &'static str,
}

pub(crate) const CASES: &[CryptoCase] = &[
    CryptoCase {
        family: "F-RSA",
        parameter: "2048",
        tier: 1,
        dep: "rsa = { version = \"0.9\", features = [\"sha2\"] }\nrand = \"0.8\"",
        uses: &["use rsa::RsaPrivateKey;"],
        setup: &["let mut rng = rand::thread_rng();"],
        call: "let _key = RsaPrivateKey::new(&mut rng, 2048).expect(\"keygen\");",
        api: "rsa::RsaPrivateKey::new",
    },
    CryptoCase {
        family: "F-RSA",
        parameter: "3072",
        tier: 1,
        dep: "rsa = { version = \"0.9\", features = [\"sha2\"] }\nrand = \"0.8\"",
        uses: &["use rsa::RsaPrivateKey;"],
        setup: &["let mut rng = rand::thread_rng();"],
        call: "let _key = RsaPrivateKey::new(&mut rng, 3072).expect(\"keygen\");",
        api: "rsa::RsaPrivateKey::new",
    },
    CryptoCase {
        family: "F-ECC",
        parameter: "P-256",
        tier: 1,
        dep: "p256 = { version = \"0.13\", features = [\"ecdsa\"] }\nrand = \"0.8\"",
        uses: &["use p256::ecdsa::SigningKey;"],
        setup: &["let mut rng = rand::thread_rng();"],
        call: "let _sk = SigningKey::random(&mut rng);",
        api: "ecdsa::SigningKey::random",
    },
    CryptoCase {
        family: "F-KEX",
        parameter: "X25519",
        tier: 1,
        dep: "x25519-dalek = { version = \"2\", features = [\"static_secrets\"] }\nrand = \"0.8\"",
        uses: &["use x25519_dalek::StaticSecret;"],
        setup: &["let mut rng = rand::thread_rng();"],
        call: "let _s = StaticSecret::random_from_rng(&mut rng);",
        api: "x25519_dalek::StaticSecret::random_from_rng",
    },
    CryptoCase {
        family: "F-HASH",
        parameter: "SHA-256",
        tier: 3,
        dep: "sha2 = \"0.10\"",
        uses: &["use sha2::{Digest, Sha256};"],
        setup: &[],
        call: "let _d = Sha256::digest(msg);",
        api: "sha2::Sha256::digest",
    },
    CryptoCase {
        family: "F-HASH",
        parameter: "SHA-512",
        tier: 3,
        dep: "sha2 = \"0.10\"",
        uses: &["use sha2::{Digest, Sha512};"],
        setup: &[],
        call: "let _d = Sha512::digest(msg);",
        api: "sha2::Sha512::digest",
    },
    CryptoCase {
        family: "F-HASH-DEP",
        parameter: "SHA-1",
        tier: 2,
        dep: "sha1 = \"0.10\"",
        uses: &["use sha1::{Digest, Sha1};"],
        setup: &[],
        call: "let _d = Sha1::digest(msg);",
        api: "sha1::Sha1::digest",
    },
    CryptoCase {
        family: "F-HASH-DEP",
        parameter: "MD5",
        tier: 2,
        dep: "md-5 = \"0.10\"",
        uses: &["use md5::{Digest, Md5};"],
        setup: &[],
        call: "let _d = Md5::digest(msg);",
        api: "md5::Md5::digest",
    },
    CryptoCase {
        family: "F-SYM",
        parameter: "AES-128",
        tier: 2,
        dep: "aes = \"0.8\"",
        uses: &["use aes::Aes128;", "use aes::cipher::KeyInit;"],
        setup: &["let key = [0u8; 16];"],
        call: "let _c = Aes128::new(&key.into());",
        api: "aes::Aes128::new",
    },
    CryptoCase {
        family: "F-SYM",
        parameter: "AES-256",
        tier: 3,
        dep: "aes = \"0.8\"",
        uses: &["use aes::Aes256;", "use aes::cipher::KeyInit;"],
        setup: &["let key = [0u8; 32];"],
        call: "let _c = Aes256::new(&key.into());",
        api: "aes::Aes256::new",
    },
    CryptoCase {
        family: "F-SYM",
        parameter: "ChaCha20",
        tier: 3,
        dep: "chacha20poly1305 = \"0.10\"",
        uses: &["use chacha20poly1305::{ChaCha20Poly1305, KeyInit};"],
        setup: &["let key = [0u8; 32];"],
        call: "let _c = ChaCha20Poly1305::new(&key.into());",
        api: "chacha20poly1305::ChaCha20Poly1305::new",
    },
    CryptoCase {
        family: "F-PQC",
        parameter: "ML-KEM-768",
        tier: 3,
        dep: "ml-kem = \"0.2\"\nrand = \"0.8\"",
        uses: &["use ml_kem::{KemCore, MlKem768};"],
        setup: &["let mut rng = rand::thread_rng();"],
        call: "let (_dk, _ek) = MlKem768::generate(&mut rng);",
        api: "ml_kem::KemCore::generate",
    },
];

struct NegativeCase {
    id: &'static str,
    count: usize,
    deps: &'static [&'static str],
    dev_deps: &'static [&'static str],
    body: fn(usize) -> String,
    example: Option<fn(usize) -> String>,
}

const NEGATIVES: &[NegativeCase] = &[
    NegativeCase {
        id: "N0",
        count: 2,
        deps: &["sha2 = \"0.10\""],
        dev_deps: &[],
        body: negative_cache_key,
        example: None,
    },
    NegativeCase {
        id: "N1",
        count: 2,
        deps: &["sha2 = \"0.10\""],
        dev_deps: &[],
        body: negative_checksum,
        example: None,
    },
    NegativeCase {
        id: "N2",
        count: 2,
        deps: &["aes = \"0.8\""],
        dev_deps: &[],
        body: negative_test_only,
        example: None,
    },
    NegativeCase {
        id: "N3",
        count: 2,
        deps: &[],
        dev_deps: &[
            "rsa = { version = \"0.9\", features = [\"sha2\"] }",
            "rand = \"0.8\"",
        ],
        body: negative_dev_binary,
        example: Some(negative_dev_binary_example),
    },
    NegativeCase {
        id: "N4",
        count: 2,
        deps: &["sha2 = \"0.10\""],
        dev_deps: &[],
        body: negative_unused_import,
        example: None,
    },
    NegativeCase {
        id: "N5",
        count: 6,
        deps: &[],
        dev_deps: &[],
        body: negative_reads_like_crypto,
        example: None,
    },
];

pub fn generate(root: &Path) -> Result<()> {
    let mut mutants = Vec::new();
    for case in CASES {
        for mode in ["M0", "M1", "M2", "M3", "M4", "M5"] {
            if let Some(m) = build_positive(mode, case, mutants.len()) {
                mutants.push(m);
            }
        }
    }
    for neg in NEGATIVES {
        for i in 0..neg.count {
            mutants.push(build_negative(neg, i, mutants.len()));
        }
    }
    for mode in ["M6", "M7"] {
        for case in CASES {
            if let Some(m) = build_name_free(mode, case, mutants.len())? {
                mutants.push(m);
            }
        }
    }
    for mode in ["M8", "M9", "M10"] {
        for case in CASES {
            if let Some(m) = crate::bench_deps::build_dependency_shaped(mode, case, mutants.len())?
            {
                mutants.push(m);
            }
        }
    }
    for i in 0..2 {
        mutants.push(crate::bench_deps::build_n6(i, mutants.len()));
    }

    if root.exists() {
        fs::remove_dir_all(root).with_context(|| format!("clearing {}", root.display()))?;
    }
    fs::create_dir_all(root)?;

    for m in &mutants {
        let dir = root.join(&m.id);
        fs::create_dir_all(dir.join("src"))?;
        fs::write(
            dir.join("Cargo.toml"),
            manifest(&m.id, &m.deps, &m.dev_deps),
        )?;
        fs::write(dir.join("src/lib.rs"), &m.source)?;
        for (path, contents) in &m.extra_files {
            let path = dir.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, contents)?;
        }
    }
    crate::bench_deps::write_deps(root)?;
    fs::write(root.join("Cargo.toml"), workspace_manifest(&mutants))?;
    let pinned = Path::new(env!("CARGO_MANIFEST_DIR")).join("../benchmark/mutants.Cargo.lock");
    fs::copy(&pinned, root.join("Cargo.lock"))
        .with_context(|| format!("copying the pinned lockfile {}", pinned.display()))?;
    fs::write(root.join("labels.json"), labels_json(&mutants))?;

    let positives = mutants.iter().filter(|m| m.polarity == "positive").count();
    println!(
        "generated {} mutants ({} positive, {} negative) into {}",
        mutants.len(),
        positives,
        mutants.len() - positives,
        root.display()
    );
    println!(
        "  fold A: {}",
        mutants.iter().filter(|m| m.fold == 'A').count()
    );
    println!(
        "  fold B: {}",
        mutants.iter().filter(|m| m.fold == 'B').count()
    );

    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
    overlap_diagnostic(&rules)?;
    Ok(())
}

fn build_positive(mode: &'static str, case: &CryptoCase, seq: usize) -> Option<Mutant> {
    if mode == "M5" && case.family != "F-RSA" {
        return None;
    }
    let id = format!(
        "{mode}-{}-{}-p-{seq:04}",
        case.family,
        case.parameter.replace(' ', "")
    );
    let (source, call_line) = match mode {
        "M0" => emit_direct(case),
        "M1" => emit_wrapped(case),
        "M2" => emit_trait_object(case),
        "M3" => emit_macro(case),
        "M4" => emit_cfg(case),
        "M5" => emit_ffi(),
        _ => unreachable!(),
    };
    let api = if mode == "M5" { "RSA_sign" } else { case.api };
    let deps = if mode == "M5" {
        Vec::new()
    } else {
        vec![case.dep]
    };
    Some(Mutant {
        fold: fold_of(&id),
        id,
        failure_mode: mode,
        family: case.family,
        parameter: case.parameter,
        polarity: "positive",
        nist_tier: Some(case.tier),
        expected: vec![Expectation {
            file: "src/lib.rs".into(),
            line: call_line,
            api,
        }],
        conservatively_mapped: false,
        deps,
        dev_deps: Vec::new(),
        source,
        extra_files: Vec::new(),
    })
}

fn build_name_free(mode: &'static str, case: &CryptoCase, seq: usize) -> Result<Option<Mutant>> {
    let emitted = match mode {
        "M6" => Some(emit_aliased(case)),
        "M7" => emit_generic(case),
        _ => unreachable!(),
    };
    let Some((source, call_line)) = emitted else {
        return Ok(None);
    };
    let labelled = source.lines().nth(call_line - 1).unwrap_or_default();
    if let Some(token) = names_crypto(labelled, case) {
        anyhow::bail!(
            "{mode} {} {}: labelled line names `{token}`: {labelled}",
            case.family,
            case.parameter
        );
    }
    let id = format!(
        "{mode}-{}-{}-p-{seq:04}",
        case.family,
        case.parameter.replace(' ', "")
    );
    Ok(Some(Mutant {
        fold: fold_of(&id),
        id,
        failure_mode: mode,
        family: case.family,
        parameter: case.parameter,
        polarity: "positive",
        nist_tier: Some(case.tier),
        expected: vec![Expectation {
            file: "src/lib.rs".into(),
            line: call_line,
            api: case.api,
        }],
        conservatively_mapped: false,
        deps: vec![case.dep],
        dev_deps: Vec::new(),
        source,
        extra_files: Vec::new(),
    }))
}

const NAMES_CRYPTO: &[&str] = &[
    "rsa", "ecdsa", "p256", "x25519", "dalek", "ecdh", "diffie", "hellman", "sha", "md5", "md-5",
    "aes", "chacha", "poly1305", "ml_kem", "mlkem", "kyber",
];

pub(crate) fn names_crypto(line: &str, case: &CryptoCase) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let type_name = type_of(case).to_ascii_lowercase();
    NAMES_CRYPTO
        .iter()
        .copied()
        .chain(std::iter::once(type_name.as_str()))
        .find(|token| lower.contains(token))
        .map(str::to_string)
}

fn build_negative(neg: &NegativeCase, index: usize, seq: usize) -> Mutant {
    let id = format!("{}-n-{seq:04}", neg.id);
    Mutant {
        fold: fold_of(&id),
        id,
        failure_mode: "N",
        family: "-",
        parameter: "-",
        polarity: "negative",
        nist_tier: None,
        expected: Vec::new(),
        conservatively_mapped: false,
        deps: neg.deps.to_vec(),
        dev_deps: neg.dev_deps.to_vec(),
        source: (neg.body)(index),
        extra_files: neg
            .example
            .map(|example| vec![("examples/demo.rs", example(index))])
            .unwrap_or_default(),
    }
}

pub(crate) fn assemble(
    header: &[String],
    before: &[String],
    call: &str,
    after: &[String],
) -> (String, usize) {
    let mut lines: Vec<String> = Vec::new();
    lines.extend(header.iter().cloned());
    lines.extend(before.iter().cloned());
    let call_line = lines.len() + 1;
    lines.push(call.to_string());
    lines.extend(after.iter().cloned());
    (format!("{}\n", lines.join("\n")), call_line)
}

fn header(case: &CryptoCase, mode: &str) -> Vec<String> {
    let mut h = vec![
        format!(
            "//! Positive case: failure mode {mode}, family {}.",
            case.family
        ),
        "//! Generated by `cargo xtask bench`; do not edit.".to_string(),
        String::new(),
    ];
    h.extend(case.uses.iter().map(|u| (*u).to_string()));
    h.push(String::new());
    h
}

fn emit_direct(case: &CryptoCase) -> (String, usize) {
    let mut before = vec![format!("pub fn target({}: &[u8]) {{", param(case))];
    before.extend(indent(case.setup, 1));
    let after = vec!["}".to_string(), String::new(), silence(case)];
    assemble(&header(case, "M0"), &before, &ind(1, case.call), &after)
}

fn emit_wrapped(case: &CryptoCase) -> (String, usize) {
    let mut before = vec![format!("fn inner({}: &[u8]) {{", param(case))];
    before.extend(indent(case.setup, 1));
    let after = vec![
        "}".to_string(),
        String::new(),
        "fn middle(msg: &[u8]) { inner(msg) }".to_string(),
        "fn outer(msg: &[u8]) { middle(msg) }".to_string(),
        "pub fn target(msg: &[u8]) { outer(msg) }".to_string(),
        String::new(),
        silence(case),
    ];
    assemble(&header(case, "M1"), &before, &ind(1, case.call), &after)
}

fn emit_trait_object(case: &CryptoCase) -> (String, usize) {
    let mut before = vec![
        "trait Op { fn run(&self, msg: &[u8]); }".to_string(),
        String::new(),
        "struct Real;".to_string(),
        "impl Op for Real {".to_string(),
        ind(1, &format!("fn run(&self, {}: &[u8]) {{", param(case))),
    ];
    before.extend(indent(case.setup, 2));
    let after = vec![
        ind(1, "}"),
        "}".to_string(),
        String::new(),
        "pub fn target(msg: &[u8], on: bool) {".to_string(),
        ind(1, "let op: &dyn Op = if on { &Real } else { &Real };"),
        ind(1, "op.run(msg);"),
        "}".to_string(),
        String::new(),
        silence(case),
    ];
    assemble(&header(case, "M2"), &before, &ind(2, case.call), &after)
}

fn emit_macro(case: &CryptoCase) -> (String, usize) {
    let mut before = vec![
        "macro_rules! do_crypto {".to_string(),
        ind(1, "($m:expr) => {{"),
        ind(2, &format!("let {} = $m;", param(case))),
    ];
    before.extend(indent(case.setup, 2));
    let after = vec![
        ind(1, "}};"),
        "}".to_string(),
        String::new(),
        "pub fn target(msg: &[u8]) {".to_string(),
        ind(1, "do_crypto!(msg);"),
        "}".to_string(),
        String::new(),
        silence(case),
    ];
    assemble(&header(case, "M3"), &before, &ind(2, case.call), &after)
}

fn emit_cfg(case: &CryptoCase) -> (String, usize) {
    let mut head = vec![
        format!(
            "//! Positive case: failure mode M4, family {}.",
            case.family
        ),
        "//! Generated by `cargo xtask bench`; do not edit.".to_string(),
        String::new(),
    ];
    for u in case.uses {
        head.push("#[cfg(feature = \"crypto\")]".to_string());
        head.push((*u).to_string());
    }
    head.push(String::new());
    let mut before = vec![
        "#[cfg(feature = \"crypto\")]".to_string(),
        format!("pub fn target({}: &[u8]) {{", param(case)),
    ];
    before.extend(indent(case.setup, 1));
    let after = vec![
        "}".to_string(),
        String::new(),
        "#[cfg(not(feature = \"crypto\"))]".to_string(),
        "pub fn target(_msg: &[u8]) {}".to_string(),
        String::new(),
        silence(case),
    ];
    assemble(&head, &before, &ind(1, case.call), &after)
}

pub(crate) fn type_of(case: &CryptoCase) -> &'static str {
    let before = &case.call[..case.call.find("::").unwrap_or(0)];
    let start = before
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1);
    &before[start..]
}

fn replace_word(s: &str, word: &str, with: &str) -> String {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(i) = s[from..].find(word).map(|i| i + from) {
        let end = i + word.len();
        let left = s[..i].chars().next_back().is_none_or(|c| !is_ident(c));
        let right = s[end..].chars().next().is_none_or(|c| !is_ident(c));
        if left && right {
            return format!("{}{with}{}", &s[..i], &s[end..]);
        }
        from = end;
    }
    s.to_string()
}

fn header_with(mode: &str, family: &str, uses: &[String]) -> Vec<String> {
    let mut h = vec![
        format!("//! Positive case: failure mode {mode}, family {family}."),
        "//! Generated by `cargo xtask bench`; do not edit.".to_string(),
        String::new(),
    ];
    h.extend(uses.iter().cloned());
    h.push(String::new());
    h
}

fn emit_aliased(case: &CryptoCase) -> (String, usize) {
    let ty = type_of(case);
    let uses: Vec<String> = case
        .uses
        .iter()
        .map(|u| replace_word(u, ty, &format!("{ty} as K")))
        .collect();
    let call = case.call.replacen(&format!("{ty}::"), "K::", 1);
    let mut before = vec![format!("pub fn target({}: &[u8]) {{", param(case))];
    before.extend(indent(case.setup, 1));
    let after = vec!["}".to_string()];
    assemble(
        &header_with("M6", case.family, &uses),
        &before,
        &ind(1, &call),
        &after,
    )
}

fn emit_generic(case: &CryptoCase) -> Option<(String, usize)> {
    let ty = type_of(case);
    let krate = case.uses[0]
        .trim_start_matches("use ")
        .split("::")
        .next()
        .unwrap_or_default();
    let mut uses: Vec<String> = case.uses.iter().map(|u| (*u).to_string()).collect();
    let (signature, call, instantiate): (String, &str, Vec<String>) = match case.family {
        "F-HASH" | "F-HASH-DEP" => {
            uses.push(format!("use {krate}::digest::Output;"));
            (
                "fn op<D: Digest>(msg: &[u8]) -> Output<D> {".to_string(),
                "D::digest(msg)",
                vec![format!("let _d = op::<{ty}>(msg);")],
            )
        }
        "F-SYM" => {
            uses.push(if krate == "aes" {
                "use aes::cipher::Key;".to_string()
            } else {
                format!("use {krate}::aead::Key;")
            });
            let mut lines: Vec<String> = case.setup.iter().map(|l| (*l).to_string()).collect();
            lines.push(format!("let _c = op::<{ty}>(&key.into());"));
            (
                "fn op<C: KeyInit>(key: &Key<C>) -> C {".to_string(),
                "C::new(key)",
                lines,
            )
        }
        "F-PQC" => {
            let mut lines: Vec<String> = case.setup.iter().map(|l| (*l).to_string()).collect();
            lines.push(format!("let (_dk, _ek) = op::<{ty}, _>(&mut rng);"));
            (
                "fn op<K: KemCore, R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> (K::DecapsulationKey, K::EncapsulationKey) {"
                    .to_string(),
                "K::generate(rng)",
                lines,
            )
        }
        _ => return None,
    };
    let target_param = if case.family.starts_with("F-HASH") {
        "msg"
    } else {
        "_msg"
    };
    let mut after = vec![
        "}".to_string(),
        String::new(),
        format!("pub fn target({target_param}: &[u8]) {{"),
    ];
    after.extend(instantiate.iter().map(|l| ind(1, l)));
    after.push("}".to_string());
    Some(assemble(
        &header_with("M7", case.family, &uses),
        &[signature],
        &ind(1, call),
        &after,
    ))
}

fn emit_ffi() -> (String, usize) {
    let case = CryptoCase {
        family: "F-RSA",
        parameter: "2048",
        tier: 1,
        dep: "",
        uses: &[],
        setup: &[],
        call: "",
        api: "RSA_sign",
    };
    let before = vec![
        "mod openssl_sys {".to_string(),
        ind(1, "extern \"C\" {"),
        ind(2, "pub fn RSA_sign(t: i32, m: *const u8, ml: u32, s: *mut u8, sl: *mut u32, r: *mut u8) -> i32;"),
        ind(1, "}"),
        "}".to_string(),
        String::new(),
        "pub fn target(msg: &[u8]) -> i32 {".to_string(),
        ind(1, "let mut sig = vec![0u8; 256];"),
        ind(1, "let mut sig_len = 0u32;"),
        ind(1, "unsafe {"),
    ];
    let call = ind(2, "openssl_sys::RSA_sign(672, msg.as_ptr(), msg.len() as u32, sig.as_mut_ptr(), &mut sig_len, std::ptr::null_mut())");
    let after = vec![ind(1, "}"), "}".to_string()];
    assemble(&header(&case, "M5"), &before, &call, &after)
}

fn negative_cache_key(i: usize) -> String {
    format!(
        "//! Negative case N0/{i}: hashing for a cache key. Real `sha2`, no security role.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         use sha2::{{Digest, Sha256}};\n\n\
         /// Content-addressed cache key for a rendered template.\n\
         pub fn cache_key(template: &str) -> String {{\n\
         \x20   let digest = Sha256::digest(template.as_bytes());\n\
         \x20   format!(\"tpl-{{:x}}\", digest)\n\
         }}\n"
    )
}

fn negative_checksum(i: usize) -> String {
    format!(
        "//! Negative case N1/{i}: non-adversarial integrity check.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         use sha2::{{Digest, Sha256}};\n\n\
         /// Detects accidental corruption of a downloaded artefact. Not a\n\
         /// security boundary: the manifest is fetched over the same channel.\n\
         pub fn matches_manifest(bytes: &[u8], expected: &str) -> bool {{\n\
         \x20   format!(\"{{:x}}\", Sha256::digest(bytes)) == expected\n\
         }}\n"
    )
}

fn negative_test_only(i: usize) -> String {
    format!(
        "//! Negative case N2/{i}: crypto only under `#[cfg(test)]`, hardcoded key.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         pub fn encode(input: &[u8]) -> Vec<u8> {{\n\
         \x20   input.iter().rev().copied().collect()\n\
         }}\n\n\
         #[cfg(test)]\n\
         mod tests {{\n\
         \x20   use aes::Aes128;\n\
         \x20   use aes::cipher::KeyInit;\n\n\
         \x20   #[test]\n\
         \x20   fn fixture_cipher_is_constructible() {{\n\
         \x20       let key = [0u8; 16];\n\
         \x20       let _c = Aes128::new(&key.into());\n\
         \x20   }}\n\
         }}\n"
    )
}

fn negative_dev_binary(i: usize) -> String {
    format!(
        "//! Negative case N3/{i}: the crypto lives in an example, not the library.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         /// The shipped surface does no cryptography at all.\n\
         pub fn normalise(path: &str) -> String {{\n\
         \x20   path.trim_end_matches('/').to_ascii_lowercase()\n\
         }}\n"
    )
}

fn negative_dev_binary_example(i: usize) -> String {
    format!(
        "//! Negative case N3/{i}: the example the library's docs point to.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         use rsa::RsaPrivateKey;\n\n\
         fn main() {{\n\
         \x20   let mut rng = rand::thread_rng();\n\
         \x20   let _key = RsaPrivateKey::new(&mut rng, 2048).expect(\"keygen\");\n\
         }}\n"
    )
}

fn negative_unused_import(i: usize) -> String {
    format!(
        "//! Negative case N4/{i}: a crypto crate in `Cargo.toml`, never called.\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         /// `sha2` is a declared dependency of this crate and is never used.\n\
         /// A manifest-derived inventory would report it; a call-site one\n\
         /// must not.\n\
         pub fn slug(title: &str) -> String {{\n\
         \x20   title.replace(' ', \"-\").to_ascii_lowercase()\n\
         }}\n"
    )
}

fn negative_reads_like_crypto(i: usize) -> String {
    let bodies = [
        ("sign", "/// The arithmetic sign of a ledger entry.\npub fn sign(amount: i64) -> i64 { amount.signum() }"),
        ("encrypt", "/// ROT13 for a puzzle game. Not encryption in any sense.\npub fn encrypt(s: &str) -> String {\n    s.chars().map(|c| if c.is_ascii_alphabetic() { (((c as u8 - b'a' + 13) % 26) + b'a') as char } else { c }).collect()\n}"),
        ("key", "/// A sort key for a leaderboard row.\npub struct Key(pub u64);\npub fn key_for(score: u64) -> Key { Key(score) }"),
        ("cipher", "/// A Caesar-cipher toy in a crossword app.\npub struct Cipher { pub shift: u8 }\nimpl Cipher {\n    pub fn apply(&self, b: u8) -> u8 { b.wrapping_add(self.shift) }\n}"),
        ("digest", "/// A digest *of an article*, for an email newsletter.\npub fn digest(paragraphs: &[String]) -> String { paragraphs.join(\"\\n\\n\") }"),
        ("hash", "/// A hash *map* helper. `std` hashing, no cryptography.\nuse std::collections::HashMap;\npub fn tally(words: &[&str]) -> HashMap<String, usize> {\n    let mut m = HashMap::new();\n    for w in words { *m.entry((*w).to_string()).or_insert(0) += 1; }\n    m\n}"),
    ];
    let (name, body) = bodies[i % bodies.len()];
    format!(
        "//! Negative case N5/{i}: non-crypto code that reads like crypto (`{name}`).\n\
         //! Generated by `cargo xtask bench`; do not edit.\n\n\
         {body}\n"
    )
}

pub(crate) fn ind(depth: usize, s: &str) -> String {
    format!("{}{s}", "    ".repeat(depth))
}

pub(crate) fn indent(lines: &[&str], depth: usize) -> Vec<String> {
    lines.iter().map(|l| ind(depth, l)).collect()
}

fn silence(_case: &CryptoCase) -> String {
    String::new()
}

fn param(case: &CryptoCase) -> &'static str {
    if case.call.contains("msg") {
        "msg"
    } else {
        "_msg"
    }
}

fn manifest(id: &str, deps: &[&str], dev_deps: &[&str]) -> String {
    let mut s = format!(
        "# Generated by `cargo xtask bench`; do not edit.\n\
         [package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [features]\ncrypto = []\n\n[dependencies]\n",
        id.to_ascii_lowercase().replace('-', "_")
    );
    for d in deps {
        let _ = writeln!(s, "{d}");
    }
    if !dev_deps.is_empty() {
        s.push_str("\n[dev-dependencies]\n");
        for d in dev_deps {
            let _ = writeln!(s, "{d}");
        }
    }
    s
}

fn workspace_manifest(mutants: &[Mutant]) -> String {
    let members: Vec<String> = mutants
        .iter()
        .map(|m| format!("    \"{}\",", m.id))
        .collect();
    format!(
        "# Generated by `cargo xtask bench`; do not edit.\n\
         #\n\
         # One workspace so the crypto dependencies resolve and compile once.\n\
         # Each member is a mutant and an independent analysis target.\n\
         [workspace]\nresolver = \"2\"\nmembers = [\n{}\n]\nexclude = [\"_deps\"]\n",
        members.join("\n")
    )
}

pub(crate) fn fold_of(id: &str) -> char {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h.is_multiple_of(2) {
        'A'
    } else {
        'B'
    }
}

fn labels_json(mutants: &[Mutant]) -> String {
    let mut out = String::from("[\n");
    for (i, m) in mutants.iter().enumerate() {
        let expected: Vec<String> = m
            .expected
            .iter()
            .map(|e| {
                format!(
                    "{{\"file\": \"{}\", \"line\": {}, \"api\": \"{}\"}}",
                    e.file, e.line, e.api
                )
            })
            .collect();
        let tier = m
            .nist_tier
            .map_or_else(|| "null".to_string(), |t| t.to_string());
        let _ = writeln!(
            out,
            "  {{\"id\": \"{}\", \"failure_mode\": \"{}\", \"family\": \"{}\", \
             \"parameter\": \"{}\", \"polarity\": \"{}\", \"nist_tier\": {tier}, \
             \"expected\": [{}], \"conservatively_mapped\": {}, \"fold\": \"{}\"}}{}",
            m.id,
            m.failure_mode,
            m.family,
            m.parameter,
            m.polarity,
            expected.join(", "),
            m.conservatively_mapped,
            m.fold,
            if i + 1 == mutants.len() { "" } else { "," }
        );
    }
    out.push_str("]\n");
    out
}

fn overlap_diagnostic(rules_dir: &Path) -> Result<()> {
    let bench_apis: BTreeSet<&str> = CASES.iter().map(|c| c.api).collect();
    let mut rule_apis: BTreeSet<String> = BTreeSet::new();
    let entries =
        fs::read_dir(rules_dir).with_context(|| format!("reading {}", rules_dir.display()))?;
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let mut in_signatures = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("signatures") {
                in_signatures = true;
                continue;
            }
            if in_signatures {
                if t.starts_with(']') {
                    in_signatures = false;
                } else if let Some(inner) = t.strip_prefix('"') {
                    if let Some(api) = inner.split('"').next() {
                        rule_apis.insert(api.to_string());
                    }
                }
            }
        }
    }
    let hits: Vec<&String> = rule_apis
        .iter()
        .filter(|a| bench_apis.contains(a.as_str()))
        .collect();
    let pct = if rule_apis.is_empty() {
        0
    } else {
        hits.len() * 100 / rule_apis.len()
    };
    println!("\noverlap between the rules and the benchmark");
    println!(
        "  rule APIs the benchmark calls  : {}/{} ({pct}%)",
        hits.len(),
        rule_apis.len()
    );
    let covered = bench_apis
        .iter()
        .filter(|a| rule_apis.contains(**a))
        .count();
    println!(
        "  benchmark APIs named by a rule : {covered}/{} ({}%)  <- the direction that can bias recall",
        bench_apis.len(),
        covered * 100 / bench_apis.len().max(1)
    );
    if covered == bench_apis.len() {
        println!(
            "\n  Note: every API this benchmark calls is already named by a rule.\n  \
             The rules were not written from the benchmark, but its call sites\n  \
             were written with the rules in view, so recall on this benchmark is\n  \
             an upper bound, not an estimate. Precision is not affected: no\n  \
             negative case depends on which API a positive case calls."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_type_is_the_identifier_before_the_first_path_separator() {
        let types: Vec<&str> = CASES.iter().map(type_of).collect();
        assert_eq!(
            types,
            [
                "RsaPrivateKey",
                "RsaPrivateKey",
                "SigningKey",
                "StaticSecret",
                "Sha256",
                "Sha512",
                "Sha1",
                "Md5",
                "Aes128",
                "Aes256",
                "ChaCha20Poly1305",
                "MlKem768",
            ]
        );
    }

    #[test]
    fn an_alias_replaces_the_whole_word_only() {
        assert_eq!(
            replace_word("use sha2::{Digest, Sha256};", "Sha256", "Sha256 as K"),
            "use sha2::{Digest, Sha256 as K};"
        );
        assert_eq!(
            replace_word("use aes::Aes1281;", "Aes128", "X"),
            "use aes::Aes1281;"
        );
    }

    #[test]
    fn the_check_rejects_a_named_line_and_passes_a_name_free_one() {
        let sha256 = &CASES[4];
        assert_eq!(
            names_crypto("let _d = Sha256::digest(msg);", sha256).as_deref(),
            Some("sha")
        );
        assert_eq!(names_crypto("    D::digest(msg)", sha256), None);
        assert_eq!(names_crypto("    let _d = K::digest(msg);", sha256), None);
    }

    #[test]
    fn the_name_free_modes_produce_the_expected_cells() {
        let built = |mode| {
            CASES
                .iter()
                .filter_map(|case| build_name_free(mode, case, 0).expect("name-free"))
                .map(|m| format!("{} {}", m.family, m.parameter))
                .collect::<Vec<_>>()
        };
        assert_eq!(built("M6").len(), 12);
        assert_eq!(
            built("M7"),
            [
                "F-HASH SHA-256",
                "F-HASH SHA-512",
                "F-HASH-DEP SHA-1",
                "F-HASH-DEP MD5",
                "F-SYM AES-128",
                "F-SYM AES-256",
                "F-SYM ChaCha20",
                "F-PQC ML-KEM-768",
            ]
        );
    }
}
