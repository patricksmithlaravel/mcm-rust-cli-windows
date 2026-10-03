#![cfg(all(unix, feature = "native", not(miri)))]
//! The FIFO refusal needs a subprocess because the safe filesystem wrapper
//! does not expose FIFO creation on every supported Unix platform.
//! Keep it in its own test target: a child briefly inherits open lock
//! descriptions before execution, even with close-on-exec set. Spawning
//! beside the parallel keystore tests can therefore make their just-dropped
//! locks temporarily appear held.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;

use std::sync::mpsc;
use std::time::Duration;

use keystore_harness::ScratchDir;
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::Error;

#[test]
fn unix_nonregular_snapshot_is_refused_without_blocking() {
    let root = ScratchDir::new("store-fifo");
    std::fs::create_dir(root.path()).unwrap();
    let path = root.path().join("store");
    drop(Keystore::create(&path, &keystore_harness::init()).unwrap());
    std::fs::remove_file(path.join("accounts.mks")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(path.join("accounts.mks")).status().unwrap().success());

    // A blocking open must fail this test promptly rather than hang the suite.
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let error = Keystore::open(&path, &keystore_harness::unlock()).err();
        let _ = send.send(error);
    });
    let error = receive.recv_timeout(Duration::from_secs(5))
        .expect("opening a FIFO snapshot blocked or the worker stopped");
    worker.join().expect("snapshot open worker panicked");
    assert!(matches!(error,
        Some(Error::Io { op: "open snapshot", kind: std::io::ErrorKind::InvalidInput })),
        "unexpected FIFO snapshot result: {error:?}");
}
