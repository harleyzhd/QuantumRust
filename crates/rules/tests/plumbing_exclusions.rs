use cpg_core::{AblationMode, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::RuleSet;

use IrLayer::{Llvm, Mir};
use NodeKind::{CallSite, TraitMethod};

fn node(
    layer: IrLayer,
    kind: NodeKind,
    symbol: &str,
    canonical: Option<&str>,
    type_args: &[&str],
) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::Dual);
    let n = cpg.add_node_full(
        layer,
        kind,
        symbol,
        canonical.map(str::to_string),
        Some(SourceLoc::new("src/lib.rs", 9)),
        SafetyCtx::Safe,
    );
    cpg.set_type_args(n, type_args.iter().map(|s| s.to_string()).collect());
    cpg
}

fn rule_ids(cpg: &Cpg) -> Vec<String> {
    let mut ids: Vec<String> = RuleSet::builtin()
        .match_cpg(cpg)
        .into_iter()
        .flat_map(|f| std::iter::once(f.rule_id).chain(f.with.into_iter().map(|p| p.rule_id)))
        .collect();
    ids.sort();
    ids
}

type Shape<'a> = (IrLayer, NodeKind, &'a str, Option<&'a str>, &'a [&'a str]);

const EXCLUDED: &[Shape] = &[
    (
        Mir,
        CallSite,
        "eax::online::Eax::<Cipher, Op, M>::update_assoc",
        None,
        &["aes::Aes128", "eax::online::Encrypt"],
    ),
    (
        Llvm,
        CallSite,
        "<eax::online::Eax<aes::autodetect::Aes128, eax::online::Encrypt>>::update_assoc",
        None,
        &[
            "eax::online::Eax",
            "aes::autodetect::Aes128",
            "eax::online::Encrypt",
        ],
    ),
    (
        Mir,
        CallSite,
        "eax::online::Eax::<Cipher, Op, M>::tag_clone",
        None,
        &["eax::online::Encrypt"],
    ),
    (
        Mir,
        CallSite,
        "ocb3::GenericArray::<T, N>::clone_from_slice",
        None,
        &[],
    ),
    (
        Llvm,
        CallSite,
        "<hkdf::errors::InvalidLength as alloc::string::ToString>::to_string",
        None,
        &["hkdf::errors::InvalidLength"],
    ),
    (
        Llvm,
        CallSite,
        "<cx448::sign::error::SigningError as alloc::string::ToString>::to_string",
        None,
        &["cx448::sign::error::SigningError"],
    ),
    (
        Llvm,
        CallSite,
        "<argon2::error::Error as alloc::string::ToString>::to_string",
        None,
        &["argon2::error::Error"],
    ),
    (
        Mir,
        CallSite,
        "cx448::subtle::CtOption::<T>::is_some",
        None,
        &["primeorder::affine::AffinePoint", "p256::NistP256"],
    ),
    (
        Mir,
        CallSite,
        "cx448::subtle::CtOption::<T>::unwrap",
        None,
        &["primeorder::affine::AffinePoint", "p256::NistP256"],
    ),
    (Mir, CallSite, "argon2::ParamsBuilder::new", None, &[]),
    (Mir, CallSite, "argon2::ParamsBuilder::t_cost", None, &[]),
    (
        Llvm,
        CallSite,
        "<argon2::params::ParamsBuilder>::p_cost",
        None,
        &["argon2::params::ParamsBuilder"],
    ),
    (Mir, CallSite, "argon2::ParamsBuilder::m_cost", None, &[]),
    (Mir, CallSite, "argon2::ParamsBuilder::build", None, &[]),
    (Mir, CallSite, "argon2::Params::block_count", None, &[]),
    (
        Mir,
        CallSite,
        "sha1collisiondetection::Builder::detect_collisions",
        None,
        &[],
    ),
    (
        Llvm,
        CallSite,
        "<sha1collisiondetection::Builder>::use_ubc",
        None,
        &["sha1collisiondetection::Builder"],
    ),
    (
        Mir,
        CallSite,
        "sha1collisiondetection::Builder::safe_hash",
        None,
        &[],
    ),
    (
        Mir,
        CallSite,
        "sha1collisiondetection::Sha1CD::finalize_into_dirty_cd",
        None,
        &[],
    ),
    (Mir, CallSite, "scrypt::Params::new", None, &[]),
    (
        Llvm,
        CallSite,
        "<scrypt::params::Params>::new",
        None,
        &["scrypt::params::Params"],
    ),
];

#[test]
fn the_calls_behind_a6s_wrong_findings_stay_silent() {
    let matched: Vec<String> = EXCLUDED
        .iter()
        .filter_map(|(layer, kind, symbol, canonical, args)| {
            let ids = rule_ids(&node(*layer, kind.clone(), symbol, *canonical, args));
            (!ids.is_empty()).then(|| format!("{layer:?} {symbol} -> {ids:?}"))
        })
        .collect();
    assert!(matched.is_empty(), "{matched:#?}");
}

#[test]
fn a_mir_to_string_on_an_anchored_error_stays_silent() {
    let cpg = node(
        Mir,
        TraitMethod,
        "std::string::ToString::to_string",
        Some("<hkdf::errors::InvalidLength as alloc::string::ToString>::to_string"),
        &["hkdf::InvalidLength"],
    );
    assert!(rule_ids(&cpg).is_empty());
}

#[test]
fn typed_crypto_calls_still_match_their_rules() {
    let cases: &[(Shape, &str)] = &[
        (
            (
                Mir,
                CallSite,
                "eax::online::Eax::<Cipher, Op, M>::with_key_and_nonce",
                None,
                &["aes::Aes128", "eax::online::Encrypt"],
            ),
            "R-AES-002",
        ),
        (
            (
                Mir,
                CallSite,
                "hkdf::Hkdf::<H, I>::new",
                None,
                &["sha2::Sha256VarCore", "sha2::OidSha256"],
            ),
            "R-SHA2-001",
        ),
        (
            (
                Mir,
                CallSite,
                "sha1collisiondetection::Builder::build",
                None,
                &[],
            ),
            "R-SHA1-001",
        ),
        ((Mir, CallSite, "scrypt::scrypt", None, &[]), "R-SCRYPT-001"),
    ];
    for ((layer, kind, symbol, canonical, args), rule) in cases {
        let cpg = node(*layer, kind.clone(), symbol, *canonical, args);
        assert_eq!(rule_ids(&cpg), [*rule], "{symbol}");
    }
}

#[test]
fn the_subtle_entries_exclude_only_subtle() {
    let cpg = node(Mir, CallSite, "aes::Probe::is_some", None, &[]);
    assert_eq!(rule_ids(&cpg), ["R-SYM-999"]);
}
