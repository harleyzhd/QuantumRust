include!("rpath.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=rpath.rs");
    embed_rpath();
}
