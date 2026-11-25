//! A dependency doing crypto inside. `orphan` is never called by anyone.

use sha2::digest::Output;
use sha2::{Digest, Sha224, Sha256, Sha384};

pub fn seal(msg: &[u8]) {
    let _d = Sha256::digest(msg);
    countdown(3);
}

pub fn digest_with<D: Digest>(msg: &[u8]) -> Output<D> {
    D::digest(msg)
}

pub fn seal_twice(msg: &[u8]) {
    let _d = Sha224::digest(msg);
}

pub fn label(id: u32) -> String {
    format!("item-{id}")
}

pub fn orphan(msg: &[u8]) {
    let _d = Sha384::digest(msg);
}

/// Recursion inside a dependency: the walk must visit it once.
fn countdown(n: u32) {
    if n > 0 {
        countdown(n - 1);
    }
}
