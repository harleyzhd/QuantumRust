//! The binary half: it only passes the value between two library functions, so
//! a chain from `build_secret` to `consume_secret` exists only if extraction
//! links calls to callee bodies across units.

fn main() {
    let secret = multi_unit::build_secret(b"seed");
    let n = multi_unit::consume_secret(&secret);
    println!("{n}");
}
