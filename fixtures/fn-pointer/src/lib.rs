//! Each function isolates one way a Rust program calls a function it holds as
//! a value; `extract_fn_pointer` asserts what the MIR layer makes of each, and
//! `call_graph_bracket` what the two call-graph bounds make of them.
//! `#[inline(never)]` keeps every call a call in the MIR the extractor reads.

#[inline(never)]
pub fn keygen(bits: u32) -> u64 {
    mix(bits as u64, 7)
}

#[inline(never)]
pub fn mix(a: u64, b: u64) -> u64 {
    a.rotate_left(5) ^ b
}

#[inline(never)]
pub fn sign(key: u64, msg: u8) -> u64 {
    mix(key, msg as u64)
}

#[inline(never)]
pub fn verify(key: u64, msg: u8) -> u64 {
    mix(msg as u64, key)
}

#[inline(never)]
pub fn digest(data: &[u8]) -> u64 {
    mix(data.len() as u64, 0)
}

/// `jsonwebtoken`'s `CryptoProvider`, reduced: the operations are fields, and
/// the provider a process uses is a static chosen elsewhere.
pub struct Provider {
    pub sign: fn(u64, u8) -> u64,
    pub digest: fn(&[u8]) -> u64,
}

/// Function items coerced to pointers in a static's initialiser — the only
/// place `sign` and `digest` are named for `through_static` to reach.
pub static DEFAULT: Provider = Provider { sign, digest };

/// Closures coerced to pointers, as `jsonwebtoken` does for a provider that
/// was never installed.
pub static UNINSTALLED: Provider = Provider {
    sign: |_, _| panic!("no provider installed"),
    digest: |_| panic!("no provider installed"),
};

/// A pointer assigned once in the body that calls it: the target is known
/// without leaving the function.
pub fn local_pointer(msg: u8) -> u64 {
    let f: fn(u64, u8) -> u64 = sign;
    let key = keygen(2048);
    f(key, msg)
}

/// A pointer chosen between two functions: either may run, nothing else can.
pub fn chosen(strict: bool, msg: u8) -> u64 {
    let f: fn(u64, u8) -> u64 = if strict { sign } else { verify };
    f(keygen(2048), msg)
}

/// The `jsonwebtoken` shape: the pointer is loaded from a static's field, so
/// the body that calls it does not know which function it holds.
pub fn through_static(msg: u8) -> u64 {
    let key = keygen(2048);
    (DEFAULT.sign)(key, msg)
}

/// A pointer passed in by the caller.
pub fn callback(f: fn(u64, u8) -> u64, msg: u8) -> u64 {
    f(keygen(2048), msg)
}

/// A function item passed where `F: Fn` is expected: never coerced to a
/// pointer, and called inside `apply` through `Fn::call`.
pub fn item_as_value(msg: u8) -> u64 {
    apply(sign, msg)
}

#[inline(never)]
fn apply<F: Fn(u64, u8) -> u64>(f: F, msg: u8) -> u64 {
    f(keygen(1024), msg)
}

/// A table of pointers in a `const`.
const TABLE: [fn(u64, u8) -> u64; 2] = [sign, verify];

pub fn via_const(i: usize, msg: u8) -> u64 {
    (TABLE[i])(keygen(3072), msg)
}

/// A different signature: a call through it can never reach `sign`.
pub fn hash_with(provider: &Provider, data: &[u8]) -> u64 {
    (provider.digest)(data)
}
