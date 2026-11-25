//! Each function isolates one shape a reaching-definitions analysis has to get
//! right; `extract_flow_sensitivity` asserts the `DataDep` edges between these
//! calls. `#[inline(never)]` keeps every call a call in the MIR the extractor
//! reads.

pub struct Key(pub u32);

#[inline(never)]
pub fn keygen_2048() -> Key {
    Key(2048)
}

#[inline(never)]
pub fn keygen_4096() -> Key {
    Key(4096)
}

#[inline(never)]
pub fn sign(key: &Key) -> u32 {
    key.0
}

/// One local, reassigned between two uses. Each signing must see
/// only the key written before it.
pub fn reassigned() -> u32 {
    let mut key = keygen_2048();
    let first = sign(&key);
    key = keygen_4096();
    let second = sign(&key);
    first + second
}

/// Both definitions genuinely reach the one use. An analysis that kills too
/// eagerly would drop one of them.
pub fn branched(flag: bool) -> u32 {
    let key = if flag { keygen_2048() } else { keygen_4096() };
    sign(&key)
}

/// The second key reaches the signing only around the loop's back edge. A
/// single forward sweep would miss it; a fixpoint must not.
pub fn looped(n: u32) -> u32 {
    let mut key = keygen_2048();
    let mut total = 0;
    for _ in 0..n {
        total += sign(&key);
        key = keygen_4096();
    }
    total
}

#[inline(never)]
pub fn may_fail(ok: bool) -> Result<(), ()> {
    if ok {
        Ok(())
    } else {
        Err(())
    }
}

/// `?` returns early through `FromResidual::from_residual`, a call that writes
/// the return place directly. That write must not block the other paths out of
/// the function: the key returned on the normal path must still reach the
/// caller. `age`'s `encrypt_chunk` has this shape: it returns its ciphertext
/// after a `?`.
pub fn early_return(ok: bool) -> Result<Key, ()> {
    may_fail(ok)?;
    let key = keygen_2048();
    Ok(key)
}

#[inline(never)]
pub fn label() -> u32 {
    7
}

#[inline(never)]
pub fn record(label: u32) -> u32 {
    label + 1
}

/// Consumes its two parameters in two different calls: the key in `sign`, the
/// label in `record`.
#[inline(never)]
pub fn use_both(key: &Key, label: u32) -> u32 {
    sign(key) + record(label)
}

/// The key is `use_both`'s first argument, so its taint must
/// enter `sign` through the first parameter and never reach `record`.
pub fn two_params() -> u32 {
    let key = keygen_2048();
    use_both(&key, label())
}

pub struct Hasher(pub u32);

impl Hasher {
    #[inline(never)]
    pub fn absorb(&mut self, key: &Key) {
        self.0 ^= key.0;
    }

    #[inline(never)]
    pub fn finish(&self) -> u32 {
        self.0
    }
}

#[inline(never)]
pub fn new_hasher() -> Hasher {
    Hasher(0)
}

/// `absorb` returns nothing: it folds the key into `h` through
/// `&mut self`. The key must still reach `finish`, which reads `h`.
pub fn absorbed() -> u32 {
    let key = keygen_2048();
    let mut h = new_hasher();
    h.absorb(&key);
    h.finish()
}
