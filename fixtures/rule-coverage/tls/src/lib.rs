//! Rule coverage: `rustls` with the `ring` provider. Each
//! call line names, after `// expect:`, the rules that must fire on it.
#![allow(dead_code, unused_must_use, unused_variables)]

pub fn client(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder() // expect: R-TLS-001
        .with_root_certificates(roots)
        .with_no_client_auth()
}
