use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use cpg_core::LlvmProvider;
use llvm_extract::LlvmIrProvider;

fn demo_crate() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-crate")
}

fn extract() -> usize {
    LlvmIrProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_llvm-extract-driver"))),
        ..Default::default()
    }
    .extract(&demo_crate())
    .expect("LLVM extraction over fixtures/demo-crate")
    .nodes()
    .count()
}

#[test]
fn an_llvm_extraction_waits_while_another_holds_the_crate() {
    extract();
    let target = demo_crate()
        .canonicalize()
        .unwrap()
        .join("target/qr-extract-llvm");
    let held = cpg_core::lock::extraction_lock(&target).unwrap();
    let worker = thread::spawn(extract);
    thread::sleep(Duration::from_secs(2));
    assert!(
        !worker.is_finished(),
        "an extraction ran while another held the crate"
    );
    drop(held);
    assert!(worker.join().unwrap() > 0);
}
