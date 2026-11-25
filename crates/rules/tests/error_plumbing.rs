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

fn llvm_call(symbol: &str, error_type: &str) -> Cpg {
    node(Llvm, CallSite, symbol, Some(symbol), &[error_type])
}

#[test]
fn error_trait_plumbing_on_crypto_error_types_stays_silent() {
    for (symbol, error_type) in [
        (
            "<digest::mac::MacError as thiserror::aserror::AsDynError>::as_dyn_error",
            "digest::mac::MacError",
        ),
        (
            "<&digest::mac::MacError as thiserror::display::AsDisplay>::as_display",
            "digest::mac::MacError",
        ),
        (
            "<aead::Error as thiserror::aserror::AsDynError>::as_dyn_error",
            "aead::Error",
        ),
        (
            "<&aead::Error as thiserror::display::AsDisplay>::as_display",
            "aead::Error",
        ),
        (
            "<signature::error::Error as thiserror::aserror::AsDynError>::as_dyn_error",
            "signature::error::Error",
        ),
        (
            "<&signature::error::Error as thiserror::display::AsDisplay>::as_display",
            "signature::error::Error",
        ),
    ] {
        assert_eq!(
            rule_ids(&llvm_call(symbol, error_type)),
            Vec::<String>::new(),
            "{symbol}"
        );
    }
    let mir = node(
        Mir,
        TraitMethod,
        "thiserror::__private20::AsDynError::as_dyn_error",
        Some("<digest::mac::MacError as thiserror::aserror::AsDynError>::as_dyn_error"),
        &["hmac::digest::MacError"],
    );
    assert_eq!(rule_ids(&mir), Vec::<String>::new());
}

#[test]
fn no_fallback_anchors_a_wrapped_error() {
    for anchor in [
        "p256",
        "dsa",
        "ed25519",
        "ecdsa",
        "ml_kem",
        "sha2",
        "rsa",
        "signature",
        "x25519",
        "aes",
    ] {
        let error_type = format!("{anchor}::Error");
        for symbol in [
            format!("<{error_type} as thiserror::aserror::AsDynError>::as_dyn_error"),
            format!("<&{error_type} as thiserror::display::AsDisplay>::as_display"),
        ] {
            assert_eq!(
                rule_ids(&llvm_call(&symbol, &error_type)),
                Vec::<String>::new(),
                "{symbol}"
            );
        }
    }
}

#[test]
fn a_trait_call_that_is_crypto_still_matches() {
    let symbol = "<hmac::Hmac<sha2::Sha256> as crypto_common::KeyInit>::new_from_slice";
    let hmac = node(
        Llvm,
        CallSite,
        symbol,
        Some(symbol),
        &["hmac::Hmac", "sha2::Sha256"],
    );
    assert_eq!(rule_ids(&hmac), vec!["R-SHA2-001".to_string()]);
}
