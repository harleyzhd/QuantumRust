include!("../mir-extract/rpath.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../mir-extract/rpath.rs");
    embed_rpath();
}
