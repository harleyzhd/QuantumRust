//! Each function reaches crypto only through a dependency.
//! `extract_dep_descent` asserts where descent finds it.

use sha2::Sha512 as H;

/// M8: a non-generic dependency function hashes with SHA-256.
pub fn m8(msg: &[u8]) {
    vault::seal(msg);
}

/// M9: a generic dependency function, instantiated here with SHA-512.
pub fn m9(msg: &[u8]) {
    let _d = vault::digest_with::<H>(msg);
}

/// M10: two hops — `relay` has no crypto dependency; `vault` hashes with SHA-224.
pub fn m10(msg: &[u8]) {
    relay::forward(msg);
}

/// N6: the dependency's crypto-free function.
pub fn n6(id: u32) -> String {
    vault::label(id)
}
