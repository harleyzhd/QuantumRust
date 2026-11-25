//! A method chain written over several lines. MIR's call span starts at the
//! receiver, which for `self.aead.encrypt(…)` below is the `self` line; LLVM IR
//! puts the call on the method line. Both layers must report it on that line.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub struct Stream {
    aead: ChaCha20Poly1305,
}

impl Stream {
    pub fn new(key: &[u8; 32]) -> Self {
        let aead = ChaCha20Poly1305::new(Key::from_slice(key)); // one line: new
        Stream { aead }
    }

    pub fn seal(&self, nonce: &[u8; 12], msg: &[u8]) -> Vec<u8> {
        self // chain: starts
            .aead
            .encrypt(Nonce::from_slice(nonce), msg) // chain: encrypt
            .expect("a chunk never reaches the cipher's limit")
    }

    pub fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> Option<Vec<u8>> {
        self.aead.decrypt(Nonce::from_slice(nonce), ct).ok() // one line: decrypt
    }
}

// Calls written by local macros. `call_span` checks only the file of the
// method's span, not its macro context. The layers must still meet on one
// line: the method's line in the macro body when the macro writes the call
// (`call!`), and the method's line at the invocation when the call is passed
// in whole (`wrap!`).
macro_rules! call {
    ($recv:expr, $method:ident) => {
        $recv
            .$method(Nonce::from_slice(&[0u8; 12]), &b"m"[..]) // macro: method
    };
}

macro_rules! wrap {
    ($e:expr) => {
        $e
    };
}

impl Stream {
    pub fn seal_by_macro(&self) -> Vec<u8> {
        call!(
            self.aead,
            encrypt
        )
        .unwrap()
    }

    pub fn open_through_macro(&self, ct: &[u8]) -> Option<Vec<u8>> {
        wrap!(self
            .aead
            .decrypt(Nonce::from_slice(&[0u8; 12]), ct)) // macro arg: decrypt
        .ok()
    }
}
