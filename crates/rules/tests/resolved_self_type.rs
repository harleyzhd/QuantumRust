use cpg_core::{AblationMode, Cpg, IrLayer, NodeKind, SafetyCtx, SourceLoc};
use qr_rules::RuleSet;

const AES128: &str = "<aes::autodetect::Aes128 as crypto_common::KeyInit>::new";
const AES256: &str = "<aes::autodetect::Aes256 as crypto_common::KeyInit>::new";
const CHACHA: &str = "<chacha20poly1305::ChaChaPoly1305<cipher::stream_wrapper::\
    StreamCipherCoreWrapper<chacha20::ChaChaCore<typenum::uint::UInt<typenum::uint::\
    UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, \
    typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>>>> as crypto_common::KeyInit>::new";
const CHACHA_ARGS: &[&str] = &[
    "chacha20poly1305::ChaChaPoly1305",
    "cipher::stream_wrapper::StreamCipherCoreWrapper",
    "chacha20::ChaChaCore",
    "typenum::uint::UInt",
    "typenum::uint::UTerm",
    "typenum::bit::B1",
    "typenum::bit::B0",
];

fn trait_call(layer: IrLayer, symbol: &str, canonical: &str, type_args: &[&str]) -> Cpg {
    let mut cpg = Cpg::new(AblationMode::Dual);
    let node = cpg.add_node_full(
        layer,
        NodeKind::TraitMethod,
        symbol,
        Some(canonical.to_string()),
        Some(SourceLoc::new("src/lib.rs", 7)),
        SafetyCtx::Safe,
    );
    cpg.set_type_args(node, type_args.iter().map(|s| s.to_string()).collect());
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

#[test]
fn the_self_type_is_read_off_a_qualified_trait_path() {
    use qr_rules::rule::qualified_self_type;

    assert_eq!(qualified_self_type(AES128), Some("aes::autodetect::Aes128"));
    let chacha = qualified_self_type(CHACHA).expect("a trait impl");
    assert!(
        chacha.starts_with("chacha20poly1305::ChaChaPoly1305<"),
        "{chacha}"
    );
    assert!(chacha.ends_with(">>>>"), "{chacha}");
    assert_eq!(
        qualified_self_type("<foo::W<<T as bar::Tr>::X> as baz::Trait>::m"),
        Some("foo::W<<T as bar::Tr>::X>")
    );
    for other in [
        "crypto_common::KeyInit::new",
        "<rsa::key::RsaPrivateKey>::new",
        "<dyn rsa::signature::Signer>::sign",
        "<dyn rsa::signature::Signer as core::fmt::Debug>::fmt",
    ] {
        assert_eq!(qualified_self_type(other), None, "{other}");
    }
}

#[test]
fn a_cipher_reached_through_crypto_common_is_named_by_its_self_type() {
    let cases = [
        (AES128, &["aes::autodetect::Aes128"][..], "R-AES-002"),
        (AES256, &["aes::autodetect::Aes256"][..], "R-AES-001"),
        (CHACHA, CHACHA_ARGS, "R-CHACHA-002"),
    ];
    for (canonical, args, rule) in cases {
        let cpg = trait_call(IrLayer::Mir, "crypto_common::KeyInit::new", canonical, args);
        assert_eq!(rule_ids(&cpg), [rule], "{canonical}");
    }
}

#[test]
fn clone_on_a_named_type_is_silent() {
    let cpg = trait_call(
        IrLayer::Mir,
        "core::clone::Clone::clone",
        "<aes::autodetect::Aes128 as core::clone::Clone>::clone",
        &["aes::autodetect::Aes128"],
    );
    assert!(rule_ids(&cpg).is_empty());
}

#[test]
fn an_excluded_call_is_not_named_by_its_self_type() {
    let cases = [
        (
            "signature::SignatureEncoding::to_vec",
            "<rsa::pss::signature::Signature as signature::encoding::SignatureEncoding>::to_vec",
            "rsa::pss::Signature",
        ),
        (
            "signature::SignatureEncoding::to_vec",
            "<rsa::pkcs1v15::signature::Signature as signature::encoding::SignatureEncoding>::to_vec",
            "rsa::pkcs1v15::Signature",
        ),
        (
            "cipher::BlockSizeUser::block_size",
            "<idea::Idea as crypto_common::BlockSizeUser>::block_size",
            "idea::Idea",
        ),
        (
            "cipher::BlockSizeUser::block_size",
            "<camellia::camellia::Camellia256 as crypto_common::BlockSizeUser>::block_size",
            "camellia::Camellia256",
        ),
    ];
    for (symbol, canonical, self_ty) in cases {
        let cpg = trait_call(IrLayer::Mir, symbol, canonical, &[self_ty]);
        assert!(rule_ids(&cpg).is_empty(), "{canonical}");
    }
}

#[test]
fn an_exclusion_on_the_resolved_instance_also_holds() {
    let cpg = trait_call(
        IrLayer::Mir,
        "crypto_common::Accessor::get",
        "<aes::autodetect::Aes128 as crypto_common::Accessor>::block_size",
        &["aes::autodetect::Aes128"],
    );
    assert!(rule_ids(&cpg).is_empty());
}

#[test]
fn a_closure_defined_in_a_crypto_crate_matches_nothing() {
    let cpg = trait_call(
        IrLayer::Mir,
        "core::ops::FnOnce::call_once",
        "<rsa::key::RsaPrivateKey::new::{{closure}} as core::ops::function::FnOnce<()>>::call_once",
        &[],
    );
    assert!(rule_ids(&cpg).is_empty());
}

#[test]
fn a_resolved_self_type_no_rule_names_stays_silent() {
    let cpg = trait_call(
        IrLayer::Mir,
        "core::default::Default::default",
        "<generic_array::GenericArray<u8, typenum::uint::UTerm> as core::default::Default>::default",
        &["generic_array::GenericArray", "u8", "typenum::uint::UTerm"],
    );
    assert!(rule_ids(&cpg).is_empty());
}

#[test]
fn the_llvm_layer_is_untouched() {
    let cpg = trait_call(
        IrLayer::Llvm,
        "crypto_common::KeyInit::new",
        AES128,
        &["aes::autodetect::Aes128"],
    );
    assert!(rule_ids(&cpg).is_empty());
}
