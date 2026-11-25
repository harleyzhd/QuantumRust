//! The library half. `build_secret` constructs the value; the binary consumes
//! it, so any flow between them has to cross a compilation-unit boundary.

/// Produces the value that must stay tracked across the boundary.
pub fn build_secret(seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    out.push(0xAA);
    out
}

/// Consumes it again on the far side, through a parameter.
pub fn consume_secret(secret: &[u8]) -> usize {
    secret.len()
}
