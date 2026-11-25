#![feature(rustc_private)]

extern crate rustc_driver;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use cpg_core::MirProvider;
use mir_extract::RustcMirProvider;

fn demo_crate() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-crate")
}

fn extract() -> usize {
    RustcMirProvider {
        driver: Some(PathBuf::from(env!("CARGO_BIN_EXE_mir-extract-driver"))),
        ..Default::default()
    }
    .extract(&demo_crate())
    .expect("extraction over fixtures/demo-crate")
    .nodes()
    .count()
}

#[test]
fn two_extractions_at_once_each_get_the_whole_graph() {
    let alone = extract();
    assert!(alone > 0);
    for round in 0..4 {
        let a = thread::spawn(extract);
        let b = thread::spawn(extract);
        let (a, b) = (a.join().unwrap(), b.join().unwrap());
        assert_eq!((a, b), (alone, alone), "round {round}");
    }
}

#[test]
fn an_extraction_waits_while_another_holds_the_crate() {
    extract();
    let target = demo_crate()
        .canonicalize()
        .unwrap()
        .join("target/qr-extract");
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
