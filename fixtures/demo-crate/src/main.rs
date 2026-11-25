//! Representative crypto usage for QuantumRust to detect.
//!
//! It covers these cases, with the control and safety context the extraction
//! must carry:
//!  * a `dyn Signer` trait-object call (trait identity visible at MIR),
//!  * direct RSA key construction + signing (quantum-vulnerable),
//!  * an `extern "C"` FFI sink shaped like `openssl_sys::RSA_sign`
//!    (declaration only — this crate is `cargo check`ed, never linked),
//!  * a *guarded* crypto call (a Predicate / `ControlDep` case).
//!
//! This crate is an analysis target; it is not built by the workspace.

use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
use rsa::RsaPrivateKey;

/// Quantum-vulnerable: RSA signing via direct API.
fn sign_with_rsa(msg: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
    let signing_key = SigningKey::<Sha256>::new(key);
    signing_key.sign_with_rng(&mut rng, msg).to_vec()
}

/// Trait-object dispatch: the crypto identity is behind `&dyn Signer`
/// (devirtualised away in LLVM-IR, but preserved on the MIR receiver type).
fn use_signer(signer: &dyn Signer<rsa::pkcs1v15::Signature>, msg: &[u8]) -> Vec<u8> {
    signer.sign(msg).to_vec()
}

/// Mock of the `openssl-sys` surface: a foreign-item declaration is enough for
/// MIR-level FFI detection under `cargo check` (nothing is ever linked).
mod openssl_sys {
    extern "C" {
        pub fn RSA_sign(
            type_: i32,
            m: *const u8,
            m_len: u32,
            sig: *mut u8,
            sig_len: *mut u32,
            rsa: *mut u8,
        ) -> i32;
    }
}

/// Byte flow crossing an `extern` boundary: the callee is a foreign item, so
/// the MIR layer must tag it `SafetyCtx::Ffi`.
fn sign_via_ffi(msg: &[u8]) -> i32 {
    let mut sig = vec![0u8; 256];
    let mut sig_len = 0u32;
    unsafe {
        openssl_sys::RSA_sign(
            672,
            msg.as_ptr(),
            msg.len() as u32,
            sig.as_mut_ptr(),
            &mut sig_len,
            std::ptr::null_mut(),
        )
    }
}

/// Key material *leaving* a function: constructed here, returned to the caller.
/// The taint must escape through the return value.
fn make_signing_key() -> SigningKey<Sha256> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
    SigningKey::<Sha256>::new(key)
}

/// Key material *entering* a function: the signing sink consumes a parameter,
/// so the taint must cross the boundary in the other direction. Together with
/// `make_signing_key` this is the interprocedural case — source and sink live
/// in different functions, with `main` only passing the value between them.
fn sign_detached(signing_key: &SigningKey<Sha256>, msg: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    signing_key.sign_with_rng(&mut rng, msg).to_vec()
}

/// Every other signing call in this file imports through
/// `rsa::signature::…`, so the extracted symbol happens to contain `rsa` and the
/// RSA rules match it. That is the caller's `use` statement doing the work, not
/// the analysis.
///
/// This call imports the *same trait* straight from the `signature` crate.
/// Identical receiver, identical generated code, and a symbol that names no
/// algorithm at all. It resolves only if the rules read the receiver type
/// rather than the path the caller happened to write.
fn sign_via_bare_trait(signing_key: &SigningKey<Sha256>, msg: &[u8]) -> Vec<u8> {
    use signature::Signer as BareSigner;
    BareSigner::sign(signing_key, msg).to_vec()
}

fn main() {
    // Runtime predicate: `sign_with_rsa` is a *guarded* crypto call, which the
    // extraction must expose as a Predicate node + `ControlDep` edge.
    let use_rsa = std::env::args().len() > 1;
    if use_rsa {
        let sig = sign_with_rsa(b"hello");
        println!("rsa signature: {} bytes", sig.len());
    }
    // A *called* trait object, so the dispatch is codegenned at LLVM level
    // (an unused fn item would be dead-code-eliminated before codegen).
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
    let signing_key = SigningKey::<Sha256>::new(key);
    let sig = use_signer(&signing_key, b"msg");
    println!("dyn signature: {} bytes", sig.len());
    let _ = sign_via_ffi(b"x");

    // Interprocedural: the key never touches a crypto API in `main` — it is
    // built in one function and signed in another.
    let detached_key = make_signing_key();
    let detached = sign_detached(&detached_key, b"tx");
    println!("detached signature: {} bytes", detached.len());

    // The same signing operation, reached through the bare `signature`
    // trait rather than `rsa`'s re-export of it.
    let bare = sign_via_bare_trait(&detached_key, b"tx");
    println!("bare-trait signature: {} bytes", bare.len());
}
