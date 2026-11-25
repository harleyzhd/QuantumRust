pub fn type_args(symbol: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut token = String::new();
    let mut previous = String::new();
    let mut last = '\0';
    for c in symbol.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '{' || c == '}' {
            token.push(c);
            last = c;
            continue;
        }
        if !token.is_empty() {
            let path = token.trim_matches(':');
            let names_a_trait = matches!(previous.as_str(), "as" | "dyn" | "impl");
            let is_type = depth > 0 && path.contains("::") && !path.contains('{') && !names_a_trait;
            if is_type && !out.iter().any(|seen| seen == path) {
                out.push(path.to_string());
            }
            previous = std::mem::take(&mut token);
        }
        match c {
            '<' => depth += 1,
            '>' if last != '-' => depth = depth.saturating_sub(1),
            _ => {}
        }
        last = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_monomorphised_digest_names_its_oid_and_core() {
        let symbol = "<digest::core_api::wrapper::CoreWrapper<digest::core_api::ct_variable::CtVariableCoreWrapper<sha2::core_api::Sha256VarCore, typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, sha2::OidSha256>> as digest::digest::Digest>::digest::<&[u8]>";
        let args = type_args(symbol);
        assert!(args.contains(&"sha2::OidSha256".to_string()), "{args:?}");
        assert!(
            args.contains(&"sha2::core_api::Sha256VarCore".to_string()),
            "{args:?}"
        );
        assert!(
            !args.iter().any(|a| a.ends_with("::Digest")),
            "the trait is not a type: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.ends_with("::digest")),
            "nor is the callee: {args:?}"
        );
    }

    #[test]
    fn a_monomorphised_aead_names_its_cipher() {
        let symbol = "<chacha20poly1305::ChaChaPoly1305<cipher::stream_wrapper::StreamCipherCoreWrapper<chacha20::ChaChaCore<typenum::uint::UTerm>>> as crypto_common::KeyInit>::new";
        let args = type_args(symbol);
        assert_eq!(&args[..1], ["chacha20poly1305::ChaChaPoly1305"]);
        assert!(
            args.contains(&"chacha20::ChaChaCore".to_string()),
            "{args:?}"
        );
        assert!(
            !args.contains(&"crypto_common::KeyInit".to_string()),
            "{args:?}"
        );
    }

    #[test]
    fn a_non_generic_call_has_no_type_arguments() {
        assert!(type_args("sequoia_openpgp::crypto::mpi::MPI::new").is_empty());
        assert!(type_args("RSA_sign").is_empty());
    }

    #[test]
    fn traits_are_skipped_and_their_arguments_kept() {
        let symbol = "<dyn signature::Signer<ed25519::Signature> as signature::Signer<ed25519::Signature>>::sign";
        assert_eq!(type_args(symbol), ["ed25519::Signature"]);
        let turbofish =
            "core::ptr::drop_in_place::<alloc::boxed::Box<dyn core::ops::Fn(u8) -> u8>>";
        assert_eq!(type_args(turbofish), ["alloc::boxed::Box"]);
    }
}
