//! A dependency building ciphers through `KeyInit`, like the benchmark's `vault`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockSizeUser, KeyInit};
use aes::Aes128;
use chacha20poly1305::ChaCha20Poly1305;

pub fn aes128() {
    let key = [0u8; 16];
    let _c = Aes128::new(&key.into());
}

pub fn chacha20() {
    let key = [0u8; 32];
    let _c = ChaCha20Poly1305::new(&key.into());
}

/// `Default::default` on a type from `generic_array`, which no rule names.
pub fn blank() {
    let _k: GenericArray<u8, aes::cipher::consts::U16> = Default::default();
}

/// A cipher's block size: a type a rule names, under a method the rule set
/// excludes as not an operation.
pub fn block_size() -> usize {
    <Aes128 as BlockSizeUser>::block_size()
}
