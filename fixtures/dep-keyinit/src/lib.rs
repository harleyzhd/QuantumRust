//! Each function reaches a cipher only through `vault`, and this crate depends
//! on no cipher crate. `extract_dep_keyinit` asserts what descent names.

/// AES-128, built through `crypto_common::KeyInit` inside the dependency.
pub fn aes128() {
    vault::aes128();
}

/// ChaCha20-Poly1305, the same way.
pub fn chacha20() {
    vault::chacha20();
}

/// A trait call whose resolved self type no rule names.
pub fn blank() {
    vault::blank();
}

/// AES-128's block size: excluded, so not named.
pub fn block_size() -> usize {
    vault::block_size()
}
