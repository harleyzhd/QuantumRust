//! A `dyn Signer` call that a pointer analysis can resolve and a
//! class-hierarchy analysis cannot: `Ecdsa` implements the trait but is never
//! constructed, so only `<Rsa as Signer>::sign` can run.

trait Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

struct Rsa;
struct Ecdsa;

impl Signer for Rsa {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        rsa_pad(msg)
    }
}

impl Signer for Ecdsa {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        ecdsa_digest(msg)
    }
}

fn rsa_pad(msg: &[u8]) -> Vec<u8> {
    msg.iter().rev().copied().collect()
}

fn ecdsa_digest(msg: &[u8]) -> Vec<u8> {
    msg.to_vec()
}

fn sign_with(signer: &dyn Signer, msg: &[u8]) -> Vec<u8> {
    signer.sign(msg)
}

fn main() {
    let signer = Rsa;
    let out = sign_with(&signer, b"message");
    println!("{}", out.len());
}
