//! Forwards to `vault`, with no crypto dependency of its own.

pub fn forward(msg: &[u8]) {
    vault::seal_twice(msg)
}
