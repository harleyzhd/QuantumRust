# Real crates

Three crates.io libraries to run the tool on, as unmodified upstream `.crate`
tarballs: `age` 0.12.1, `jsonwebtoken` 11.1.0 and `sequoia-openpgp` 2.4.1.

```bash
benchmark/real-crates/prepare.sh [DEST [age|sequoia|jsonwebtoken ...]]
```

This checks each tarball's sha256 and unpacks the named crates (default: all
three) into DEST, by default `analysed-crates/` next to the repository. DEST
must be outside the repository, because the tool will not analyse a crate
inside another cargo workspace. The patches switch `jsonwebtoken` and
`sequoia-openpgp` to pure-Rust crypto backends. Then, from the repository
root:

```bash
quantumrust analyze ../analysed-crates/age-0.12.1 --out out/age
quantumrust analyze ../analysed-crates/jsonwebtoken-11.1.0 --out out/jsonwebtoken
quantumrust analyze ../analysed-crates/sequoia-openpgp-2.4.1 --out out/sequoia
```
