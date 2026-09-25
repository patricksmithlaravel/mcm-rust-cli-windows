#![cfg(all(feature = "native", not(miri)))]
//! Gated on `native` because the keystore module is (its integrity trailer is
//! the native sha3 called directly, so the plaintext image never transits the
//! C), and on `not(miri)` because Miri's isolation forbids the file I/O this
//! file is about. Not gated on `ffi-oracle`: the keystore has no C side, and
//! it must stay tested in the C-free configuration.
//!
//! The two censused proofs (I2, I3) live in `tests/invariants.rs`, where
//! their census rows demand them. Everything else about the keystore that is
//! measured rather than promised is here: the lock, monotonicity, keyed-by-tag,
//! every corrupt-file refusal by exact variant, the stale temp, the temp's
//! mode, the poisoned handle's refusal to launder a rollback, and the Debug
//! redaction. See `src/keystore/mod.rs` for what each enforces.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use keystore_harness::{
    derived_account, derived_account_0_of_the_imported_master, imported_account, reopen, ScratchDir,
    DERIVED_POSITION, DERIVED_TAG, DIGEST, FIGURES, IMPORTED_MASTER, IMPORTED_TAG, REOPEN_TRIES,
    REOPEN_WAIT, ROOT,
};
use mochimo_crypto::account::{Account, AccountKind, AccountRecord, WotsIndex};
use mochimo_crypto::consts::SEED_LEN;
use mochimo_crypto::keystore::{
    Call, Disk, Init, Instrumented, Kdf, KeyAccess, Keystore, Pending, Unlock, NONCE_SEED_LEN, SALT_LEN,
};
use mochimo_crypto::{Error, Secret};

fn read_snapshot(dir: &ScratchDir) -> Vec<u8> {
    dir.snapshot_bytes()
}

fn write_snapshot(dir: &ScratchDir, bytes: &[u8]) {
    dir.write_snapshot(bytes);
}

/// Position `i`, reached the only way a test can reach one: by advancing
/// from zero (`WotsIndex::from_raw` is the parser's, crate-private).
fn pos(i: u32) -> WotsIndex {
    let mut p = WotsIndex::ZERO;
    for _ in 0..i {
        p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    p
}


#[test]
fn create_then_open_round_trips_both_kinds() {
    let dir = ScratchDir::new("roundtrip");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG, DERIVED_TAG]);
    drop(ks);

    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.kind, AccountKind::Imported);
    assert_eq!(v.wots_index, WotsIndex::ZERO);
    let mut roots = 0;
    for r in ks.into_records().unwrap_or_else(|e| panic!("{e}")) {
        match r {
            AccountRecord::Imported { tag, root, .. } => {
                assert_eq!(tag, IMPORTED_TAG);
                assert_eq!(root.expose(), &ROOT);
                roots += 1;
            }
            AccountRecord::Derived { tag, account_index, .. } => {
                assert_eq!(tag, DERIVED_TAG);
                assert_eq!(account_index, DERIVED_POSITION);
            }
        }
    }
    assert_eq!(roots, 1);
}

/// **`adopt_master` refuses to replace a seed, and the refusal touches
/// nothing** (the debt an audit filed).
///
/// Every earlier call site adopted exactly once into a store with no master
/// and unwrapped the result, so the refusal arm had never run. A replaced
/// master leaves every derived account pointing at a key stream the store can
/// no longer produce -- I5's loss mode reached through a setter -- so the
/// arms are: the second adoption refused **by variant and field**, not by a
/// rendered string; and three observables that a refusal-after-commit would
/// move and a refusal-before-commit does not (the generation, the snapshot's
/// bytes, the seed in memory); then the handle still live, and the seed on
/// disk the first one after a reopen.
#[test]
fn adopt_master_refuses_to_replace_a_seed_and_leaves_the_store_untouched() {
    let dir = ScratchDir::new("adopt-twice");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let first = Secret::new([0x11u8; SEED_LEN]);
    let second = Secret::new([0x22u8; SEED_LEN]);
    assert!(
        ks.master().unwrap_or_else(|e| panic!("{e}")).is_none(),
        "a fresh store already holds a master seed"
    );
    let _durable = ks
        .adopt_master(&first)
        .unwrap_or_else(|e| panic!("the first adoption, into a store with no seed, was refused: {e}"));
    let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    let bytes = read_snapshot(&dir);

    let err = ks.adopt_master(&second).err();
    assert!(
        matches!(err, Some(Error::Exists { what: "master seed" })),
        "the second seed REPLACED the first, or the refusal came under another name than \
         Exists {{ what: \"master seed\" }}: {err:?}. Replacing the master leaves every derived \
         account pointing at a key stream the store can no longer produce (I5 through a setter)"
    );
    assert_eq!(
        ks.generation().unwrap_or_else(|e| panic!("{e}")),
        generation,
        "the refusal advanced the generation: the store is not untouched, something was \
         committed before the check"
    );
    assert_eq!(
        read_snapshot(&dir),
        bytes,
        "the refusal rewrote the snapshot: the store is not untouched"
    );
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the seed in memory is gone after a refusal"))
            .expose(),
        first.expose(),
        "the seed in memory is no longer the first adoption's"
    );
    // Not poisoned: a refusal is not a failed commit.
    ks.add(Account::derive(&first, 0))
        .unwrap_or_else(|e| panic!("the handle was poisoned by a refusal: {e}"));
    drop(ks);
    let ks = reopen("adopt twice", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the seed on disk is gone"))
            .expose(),
        first.expose(),
        "the seed on disk is not the first adoption's"
    );
    println!("  adopt_master: a second seed refused as Exists {{ master seed }}; generation, bytes and seed unchanged; handle live");
}

/// **A store sealed by an earlier build still opens under its password, and
/// this build reproduces its bytes** -- and since format version 4 the two
/// halves are two files.
///
/// # What this pins, and what it does not
///
/// `testdata/keystore_v3_snapshot.bin` is an `accounts.mks` written by
/// `Keystore::create` at `Kdf::RECOMMENDED`, then `adopt_master`, then
/// `add(Account::derive(master, 0))` -- what `cli::create::create` writes once
/// the phrase has become a seed -- under the fixed password, salt, nonce seed
/// and master below, by the build whose encoder wrote format version 3 at
/// that parameter point. **It is kept byte for
/// byte under its version**, as its README row prescribes, and its subject
/// changed meaning with version 4: it is the version-3 READ PATH, exercised at the
/// shipped parameter point, end to end from password to state -- the
/// migration oracle for the ordinary record. `testdata/keystore_v4_snapshot.bin`
/// is the same three calls under the same inputs by the version-4 build, and is what
/// the byte-for-byte arm moved to. Four arms:
///
/// 1. **the v3 file opens** through the public `Keystore::open`, with the
///    master and account 0 as written -- `derive_key` at 65536/3/1, the AEAD
///    and the v3 parser arm -- and nothing on disk moves: `open` does not
///    re-seal. A `derive_key` whose function moved makes every
///    existing store answer `WrongPassword`, and this is the arm that says so.
/// 2. **the v4 file is reproduced byte for byte** by the same three calls
///    under the same inputs -- the whole sealed path, `nonce_for` included,
///    which arm 1 cannot see because a reader takes the nonce from the header.
/// 3. **state, not bytes**: the v3 file opened by this build and the fresh v4
///    store agree on the master, the account, its index, its (absent)
///    reservation and retained block, and the generation. Not bytes, because
///    the two carry different version words and record widths.
/// 4. **the crossing is the first write's and one-way**: before any write the
///    handle reports no upgrade and the file is the v3 image; one `add` later
///    the file's version word is 4, its length is v4's, the handle names 3 as
///    what it crossed from, and a reopen reads it.
///
/// It pins this build against its own past. **It says nothing about
/// correctness** -- that is `argon2id_v13_matches_the_rfc9106_vector`'s claim,
/// against a standard, at 32/3/4 with a secret -- and nothing about the
/// parameter point beyond that this build agrees with the build that sealed
/// each file at 65536/3/1. The anchor session measured the gap this closes: with `derive_key`'s
/// production arm poisoned the whole board stayed green, because every test
/// derives the key it opens with. A fault-injection row is that
/// poison's shape -- `t_cost` clamped to 1, invisible at `CHEAP_FOR_TESTS`
/// where it already is 1 -- and only this test reds.
///
/// **If this goes red, do not re-capture either file.** A file re-captured
/// from the build that broke it is green by construction (a fault-injection
/// row, declared and observed green) -- an observation certifying itself. A red here means
/// the derivation, the nonce or the layout moved and every store on disk is
/// affected; re-capturing is right only after a deliberate format change,
/// with the old file kept under its version -- which is what version 4 did,
/// and why there are two files.
///
/// Not `fixtures/`: nothing here is oracle data -- no reference produced it,
/// it is what OUR code wrote -- so it lives beside the v1 snapshot in
/// `testdata/`, embedded rather than transcribed.
#[test]
fn a_store_sealed_by_an_earlier_build_opens_and_is_reproduced_byte_for_byte() {
    const V3_IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_snapshot.bin");
    const V4_IMAGE: &[u8] = include_bytes!("../testdata/keystore_v4_snapshot.bin");
    const PASSWORD: &[u8] = b"pinned-store-password-not-for-real-use";
    const SALT: [u8; SALT_LEN] = [0x3C; SALT_LEN];
    const NONCE_SEED: [u8; NONCE_SEED_LEN] = [0xC3; NONCE_SEED_LEN];
    const MASTER: [u8; SEED_LEN] = [0x7E; SEED_LEN];
    let unlock = Unlock {
        password: PASSWORD,
        nonce_seed: NONCE_SEED,
    };

    // Both headers are plaintext and advertise the shipped point: each pin is
    // about that point and no cheaper one, and a re-captured file at
    // CHEAP_FOR_TESTS would be a different claim wearing this test's name.
    for (what, image, version, record) in [("v3", V3_IMAGE, V3_VERSION, V3_RECORD), ("v4", V4_IMAGE, VERSION, RECORD)] {
        assert_eq!(&image[..8], b"MCMKSTOR");
        assert_eq!(u16::from_le_bytes([image[8], image[9]]), version, "the {what} pin is not version {version}");
        let field = |at: usize| u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]]);
        assert_eq!(
            (field(11), field(15), field(19)),
            (65536, 3, 1),
            "the {what} pin's header is not at Kdf::RECOMMENDED (65536/3/1); a cheaper capture would \
             pin a point no shipped store is sealed at"
        );
        assert_eq!(image.len(), HEADER + BODY_HEADER + record + TRAILER, "{what}: one derived record");
    }

    // Arm 1: the v3 file opens, through the public route, and holds what was
    // written -- and the read path writes nothing.
    let dir = ScratchDir::new("v3-pinned-open");
    drop(Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    write_snapshot(&dir, V3_IMAGE);
    let ks = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| {
        panic!(
            "a version-3 store sealed by an earlier build no longer opens under its own password: {e}. \
             Every version-3 store on disk is affected. If derive_key, the AEAD or the v3 parser \
             arm changed, that is the cause; do NOT re-capture the file (this test's doc says why)"
        )
    });
    let m = Secret::new(MASTER);
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the opened store holds no master seed"))
            .expose(),
        &MASTER,
        "the master seed read back is not the one the earlier build sealed"
    );
    let tag = mochimo_crypto::derive::derive_account_tag(&m, 0);
    assert_eq!(
        ks.tags().unwrap_or_else(|e| panic!("{e}")),
        vec![tag],
        "the earlier build's store does not hold account 0 of its master (as this build derives it)"
    );
    let view = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("account 0 is not viewable"));
    assert_eq!(view.wots_index, WotsIndex::ZERO);
    assert_eq!(view.pending, None);
    assert_eq!(view.settled, None, "a version-3 record has no retained block to read");
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), 2, "create, adopt, add: two commits after the empty image");
    assert_eq!(ks.upgraded_from(), None, "open reported a crossing before any write");
    drop(ks);
    assert_eq!(
        read_snapshot(&dir),
        V3_IMAGE,
        "open re-sealed the version-3 snapshot; the read path must not write"
    );

    // Arm 2: this build writes the same bytes as the v4 pin.
    let dir2 = ScratchDir::new("v4-pinned-recreate");
    {
        let mut ks = Keystore::create(
            dir2.path(),
            &Init {
                password: PASSWORD,
                salt: SALT,
                nonce_seed: NONCE_SEED,
                kdf: Kdf::RECOMMENDED,
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let _durable = ks.adopt_master(&m).unwrap_or_else(|e| panic!("{e}"));
        ks.add(Account::derive(&m, 0)).unwrap_or_else(|e| panic!("{e}"));
    }
    let fresh = dir2.snapshot_bytes_under(PASSWORD);
    let first_difference = fresh.iter().zip(V4_IMAGE.iter()).position(|(a, b)| a != b);
    assert!(
        fresh.len() == V4_IMAGE.len() && first_difference.is_none(),
        "this build does not reproduce, byte for byte, the version-4 store its own earlier build \
         sealed under the same password, salt, nonce seed and master at Kdf::RECOMMENDED: {} \
         bytes against {}, first difference at byte {:?}. The sealed path moved -- derive_key, \
         nonce_for, encode or the AEAD. Do NOT re-capture the file to make this green",
        fresh.len(),
        V4_IMAGE.len(),
        first_difference
    );

    // Arm 3: state equality across the two files -- the migrated read and the
    // fresh v4 store describe one wallet.
    let a = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| panic!("{e}"));
    let b = Keystore::open(dir2.path(), &unlock).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        a.master().unwrap_or_else(|e| panic!("{e}")).map(|s| *s.expose()),
        b.master().unwrap_or_else(|e| panic!("{e}")).map(|s| *s.expose()),
        "the v3 file and the v4 store disagree on the master"
    );
    assert_eq!(a.tags().unwrap_or_else(|e| panic!("{e}")), b.tags().unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        a.view(&tag).unwrap_or_else(|e| panic!("{e}")),
        b.view(&tag).unwrap_or_else(|e| panic!("{e}")),
        "the v3 file and the v4 store disagree on account 0's index, reservation or retained block"
    );
    assert_eq!(a.generation().unwrap_or_else(|e| panic!("{e}")), b.generation().unwrap_or_else(|e| panic!("{e}")));
    drop(b);

    // Arm 4: the first write crosses, one way.
    let mut a = a;
    a.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("the first write over a version-3 store was refused: {e}"));
    assert_eq!(
        a.upgraded_from(),
        Some(V3_VERSION),
        "the handle does not report the crossing after the first write"
    );
    drop(a);
    let crossed = read_snapshot(&dir);
    assert_eq!(u16::from_le_bytes([crossed[8], crossed[9]]), VERSION, "the first write did not re-seal the store as version 4");
    assert_eq!(crossed.len(), HEADER + BODY_HEADER + 2 * RECORD + TRAILER, "the re-sealed store is not two version-4 records long");
    // Under the PIN's password, not the harness's: `reopen` unlocks with the
    // harness password and this store was sealed under the pinned one.
    let again = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| panic!("the re-sealed store does not reopen: {e}"));
    assert_eq!(again.tags().unwrap_or_else(|e| panic!("{e}")).len(), 2);
    assert_eq!(again.upgraded_from(), None, "a store opened at version 4 reports a crossing");
    println!(
        "  pinned images: v3 ({} bytes) opens under its password with master and account 0 intact \
         and is left on disk as written; v4 ({} bytes) is reproduced byte for byte; the two agree on \
         state; the v3 store's first write re-seals it as version {VERSION}",
        V3_IMAGE.len(),
        V4_IMAGE.len()
    );
}

/// **A version-3 reservation is read with its figures absent, and the
/// reserved key still re-signs** -- the arm the
/// migration exists to preserve, against a real file rather than a forged
/// word.
///
/// `testdata/keystore_v3_reserved_snapshot.bin` was written by the last
/// build whose encoder wrote format version 3, for the
/// harness's imported master at account index 0 -- `create` at
/// `CHEAP_FOR_TESTS`, `adopt_master`, `add`, `persist_advance` -- so it
/// holds a reservation at 0 with the index at 1 and no figures anywhere in
/// it. The arms: it opens under the harness's password; the reservation is
/// present with `figures: None` -- declared absent, never read as zero, which
/// is the state the migration passes through without fabricating; the
/// open writes nothing; `resign_reserved` signs at the reserved index and
/// its bytes are identical to what a fresh version-4 store signs over the
/// same reservation (one key, one digest, one position -- WOTS+
/// determinism); and the first write -- a settle -- re-seals the store as
/// version 4 with the block retained under the third state, its figures
/// still absent, which a reopen reads back.
#[test]
fn a_version_3_reservation_is_read_with_its_figures_absent_and_still_resigns() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    assert_eq!(u16::from_le_bytes([IMAGE[8], IMAGE[9]]), V3_VERSION, "the reservation capture is not version 3");
    assert_eq!(IMAGE.len(), HEADER + BODY_HEADER + V3_RECORD + TRAILER, "one version-3 record");
    let master = Secret::new(IMPORTED_MASTER);
    assert_eq!(derived_account_0_of_the_imported_master().tag(), IMPORTED_TAG);
    let migrated_block = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: None,
    };

    let dir = ScratchDir::new("v3-reserved-read");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    write_snapshot(&dir, IMAGE);
    let ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| {
        panic!("the captured version-3 reservation no longer opens under the harness's password: {e}")
    });
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG]);
    let view = ks
        .view(&IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the capture's account is not viewable"));
    assert_eq!(view.wots_index.get(), 1, "the capture's reservation advanced the index to 1");
    assert_eq!(
        view.pending,
        Some(migrated_block),
        "a version-3 reservation must read back with figures: None -- declared absent, not zero"
    );
    assert_eq!(view.settled, None);
    assert_eq!(ks.upgraded_from(), None, "open reported a crossing before any write");
    let migrated = ks
        .resign_reserved(&IMPORTED_TAG, &KeyAccess::Master(&master))
        .unwrap_or_else(|e| panic!("the reserved key of a migrated reservation no longer re-signs: {e} -- the capability the migration exists to preserve"));
    assert_eq!(migrated.spent_index, WotsIndex::ZERO);
    drop(ks);
    assert_eq!(read_snapshot(&dir), IMAGE, "open or resign_reserved rewrote the version-3 snapshot");

    // Byte-identical to what a fresh version-4 store signs over the same reservation.
    let dir2 = ScratchDir::new("v3-reserved-fresh-v4");
    let mut fresh = keystore_harness::create(dir2.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = fresh.adopt_master(&master).unwrap_or_else(|e| panic!("{e}"));
    fresh.add(derived_account_0_of_the_imported_master()).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = fresh.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let native = fresh
        .resign_reserved(&IMPORTED_TAG, &KeyAccess::Master(&master))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(native.spent_index, WotsIndex::ZERO);
    assert_eq!(
        &migrated.signature[..],
        &native.signature[..],
        "the migrated reservation and a fresh version-4 store signed DIFFERENT bytes over one key, one \
         digest and one position; the read arm changed what resign_reserved signs"
    );
    assert_eq!(migrated.pub_seed, native.pub_seed);
    assert_eq!(&migrated.public_key[..], &native.public_key[..]);
    drop(fresh);

    // The first write re-seals as version 4 with the block retained and its
    // figures still absent -- on the live handle and after a reopen.
    let mut ks = reopen("v3 reserved settle", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.upgraded_from(), Some(V3_VERSION), "the first write did not report the crossing");
    let live = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(live.pending, None);
    assert_eq!(live.settled, Some(migrated_block), "memory: the settled block was not retained with its figures absent");
    drop(ks);
    let after = read_snapshot(&dir);
    assert_eq!(u16::from_le_bytes([after[8], after[9]]), VERSION, "the first write did not re-seal the store as version 4");
    assert_eq!(after.len(), HEADER + BODY_HEADER + RECORD + TRAILER, "one version-4 record");
    let ks = reopen("v3 reserved reopened", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let disk = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(disk.pending, None);
    assert_eq!(disk.settled, Some(migrated_block), "disk: the settled block was not retained with its figures absent");
    assert_eq!(ks.upgraded_from(), None, "a store opened at version 4 reports a crossing");
    println!(
        "  version-3 reservation capture: {} bytes read with figures absent, the reserved key re-signs \
         byte-identically to a fresh version-4 store, and the first write re-seals as version {VERSION} \
         with the block retained",
        IMAGE.len()
    );
}

/// **A settled block is retained through a reopen, released by the next
/// reservation and cleared by an acknowledged advance** -- each transition
/// observed on the live handle AND after a reopen,
/// because `advance_committed`'s contract is that memory is applied to
/// exactly what the image holds, and the new field is under it.
///
/// The retained block never blocks `persist_advance`: that freeze is the
/// direction the settle rule called unbounded, and the next reservation is what
/// releases the block. `persist_advance_to` clears it because an acknowledged
/// advance breaks the relation the encoder refuses to seal.
#[test]
fn a_settled_block_is_retained_through_a_reopen_and_released_by_the_next_reservation_or_advance() {
    const DIGEST_2: [u8; 32] = [0xD2; 32];
    let dir = ScratchDir::new("retained-block");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let first = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let view = |ks: &Keystore| ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));

    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view(&ks).pending, Some(first));
    assert_eq!(view(&ks).settled, None);

    // Settle: the block moves, on the live handle and on disk.
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, None, "memory: settle left the reservation open");
    assert_eq!(v.settled, Some(first), "memory: the settled block was not retained with its figures");
    drop(ks);
    let mut ks = reopen("retained block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, None, "disk: settle left the reservation open");
    assert_eq!(v.settled, Some(first), "disk: the settled block was not retained with its figures");

    // Released by the next reservation, which is NOT refused.
    let r2 = ks
        .persist_advance(&IMPORTED_TAG, &DIGEST_2, FIGURES)
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next reservation -- the freeze the retained block must not cause: {e}"));
    assert_eq!(r2.index().get(), 2);
    let second = Pending {
        spent_index: pos(1),
        digest: DIGEST_2,
        figures: Some(FIGURES),
    };
    let v = view(&ks);
    assert_eq!(v.pending, Some(second), "memory: the second reservation is not what was sealed");
    assert_eq!(v.settled, None, "memory: the new reservation did not release the retained block");
    drop(ks);
    let mut ks = reopen("released block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, Some(second), "disk: the second reservation is not what was sealed");
    assert_eq!(v.settled, None, "disk: the new reservation did not release the retained block");

    // Cleared by an acknowledged advance: settle again, then advance to 3.
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view(&ks).settled, Some(second));
    let three = pos(3);
    let _r3 = ks.persist_advance_to(&IMPORTED_TAG, three).unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.wots_index, three);
    assert_eq!(v.settled, None, "memory: persist_advance_to left the retained block in the live handle");
    assert_eq!(v.pending, None);
    drop(ks);
    let ks = reopen("cleared block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.wots_index, three);
    assert_eq!(v.settled, None, "disk: persist_advance_to left the retained block");
    assert_eq!(v.pending, None);
    println!("  retained block: kept through settle and reopen (memory and disk), released by the next reservation, cleared by persist_advance_to");
}

/// **A retained block survives a write that does not override its account**
///: `records_with` carries every slot's own `settled` when the write is
/// about some other account -- `add` (the `restore` path's write), a second
/// account's reservation, `adopt_master` -- so a settle recorded for one
/// account is not erased by the next thing the operator does to another.
#[test]
fn a_retained_block_survives_a_write_that_does_not_override_its_account() {
    let block = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let settled_imported = |ks: &Keystore| {
        ks.view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("gone"))
            .settled
    };

    // Store A: settle on the imported account, then `add` a second account,
    // then `adopt_master` -- two writes that override nothing.
    let a = ScratchDir::new("retained-add");
    let mut ks = Keystore::create(a.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: `add` of another account dropped the retained block");
    let _durable = ks.adopt_master(&Secret::new([0x11u8; SEED_LEN])).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: adopt_master dropped the retained block");
    drop(ks);
    let ks = reopen("retained add", a.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "disk: a write that did not override the account dropped its retained block");
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")).len(), 2);
    drop(ks);

    // Store B: both accounts; settle on the imported one; reserve on the OTHER.
    let b = ScratchDir::new("retained-other-reservation");
    let mut ks = Keystore::create(b.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: another account's reservation dropped the retained block");
    drop(ks);
    let ks = reopen("retained other", b.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "disk: another account's reservation dropped the retained block");
    let other = ks.view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert!(other.pending.is_some() && other.settled.is_none());
    println!("  retained block: survives `add`, `adopt_master` and another account's reservation, in memory and on disk");
}

#[test]
fn second_open_in_process_is_refused_while_the_first_is_held() {
    let dir = ScratchDir::new("lock");
    let a = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let b = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
    assert_eq!(b, Some(Error::Locked), "a second handle opened while the first was held");
    drop(a);
    let b = Keystore::open(dir.path(), &keystore_harness::unlock());
    assert!(b.is_ok(), "the lock did not release on drop: {:?}", b.err());
    // The lock file is never unlinked: it is the kernel that releases it.
    assert!(dir.listing().iter().any(|n| n == "keystore.lock"));
}

/// The crash proofs in `tests/invariants.rs` reopen only through the
/// harness's bounded helper. That binary is the one that spawns
/// -- the census runs some twenty-five children beside the proofs -- so a
/// bare `Keystore::open` there is the flake coming back at one run in seven.
/// This binary spawns nothing and its own bare opens are deliberate
/// (`second_open_in_process_is_refused_while_the_first_is_held` observes
/// `Locked` on purpose), so the domain is `invariants.rs` alone, stated
/// rather than widened. Line comments are stripped before the search so
/// prose naming the call does not count as a call; the positive control is
/// that the helper's own call sites are found.
#[test]
fn crash_proofs_reopen_only_through_the_bounded_helper() {
    // The domain, widened by the rule that any new test file
    // carries the same discipline: `invariants.rs` is the binary that spawns
    // (the census) and holds the positive control; `spend.rs` and `mesh.rs`
    // spawn nothing and reopen nothing today, so they carry the absence arm
    // alone -- a floor on helper uses there would be a floor over nothing.
    const FILES: &[(&str, usize)] = &[("tests/invariants.rs", 4), ("tests/spend.rs", 0), ("tests/mesh.rs", 0)];
    let mut files_read = 0usize;
    for (rel, min_helper_uses) in FILES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        files_read += 1;
        let code: String = text
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let bare: Vec<&str> = ["Keystore::open(", "Keystore::open_with("]
            .into_iter()
            .filter(|needle| code.contains(needle))
            .collect();
        assert!(
            bare.is_empty(),
            "{rel} reopens a keystore with a bare {bare:?}. A test binary that spawns processes \
             shares its lock descriptions with each child until its exec, and a just-released \
             flock can look held for ~200 µs there; route the reopen through \
             keystore_harness::reopen / reopen_with, which retries Error::Locked alone, bounded."
        );
        let through_helper = code.matches("keystore_harness::reopen").count();
        assert!(
            through_helper >= *min_helper_uses,
            "found {through_helper} reopen(s) through the helper in {rel}, fewer than {min_helper_uses}; \
             for invariants.rs the I2 proof has three and the I3 proof one, so fewer than four means \
             the search is not reading the file it thinks it is"
        );
    }
    assert_eq!(files_read, FILES.len());
}

/// The harness's bounded reopen must still refuse a **genuine**
/// second holder: a live handle on the directory is exactly what `Locked`
/// exists to report, and a helper that retried through it would be
/// indistinguishable from deleting the lock check. At the bound the count is
/// the bound, the waits demonstrably happened, and once the holder drops the
/// same call opens with no retry at all.
#[test]
fn reopen_helper_still_refuses_a_genuine_second_holder_at_the_bound() {
    let dir = ScratchDir::new("reopen-bound");
    let holder = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));

    let started = std::time::Instant::now();
    let r = reopen("genuine holder", dir.path());
    let elapsed = started.elapsed();
    assert!(
        matches!(r.result, Err(Error::Locked)),
        "a live handle was still held and the helper opened anyway: {:?}",
        r.result.as_ref().err()
    );
    assert_eq!(
        r.retries, REOPEN_TRIES,
        "the helper gave up after {} retries, not at the bound of {REOPEN_TRIES}",
        r.retries
    );
    let floor = REOPEN_WAIT * u32::try_from(REOPEN_TRIES).unwrap_or(u32::MAX);
    assert!(
        elapsed >= floor,
        "{REOPEN_TRIES} retries of {REOPEN_WAIT:?} took {elapsed:?}: the waits did not happen"
    );
    assert!(
        elapsed < floor * 200,
        "{REOPEN_TRIES} retries of {REOPEN_WAIT:?} took {elapsed:?}: the bound is not the bound"
    );

    drop(holder);
    let r = reopen("holder released", dir.path());
    assert!(r.result.is_ok(), "after the holder dropped: {:?}", r.result.as_ref().err());
    assert_eq!(r.retries, 0, "no child is being spawned here, so nothing should have retried");
}

/// Only `Locked` is retried. A directory with no snapshot is `Missing` on the
/// first try and stays `Missing`; a helper that retried every error would
/// report the bound here instead of zero.
#[test]
fn reopen_helper_returns_every_other_error_immediately() {
    let dir = ScratchDir::new("reopen-missing");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    let r = reopen("missing snapshot", dir.path());
    assert!(matches!(r.result, Err(Error::Missing)), "{:?}", r.result.as_ref().err());
    assert_eq!(r.retries, 0, "a non-Locked error was retried {} time(s)", r.retries);
}

#[test]
fn open_refuses_a_missing_snapshot_and_create_refuses_an_existing_store() {
    let dir = ScratchDir::new("missing");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::Missing));
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Exists { what: "snapshot" })
    );
}

trait Mode0700 {
    fn mode_0700(&mut self) -> &mut Self;
}
#[cfg(unix)]
impl Mode0700 for std::fs::DirBuilder {
    fn mode_0700(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}
/// Nothing, on Windows: `DirBuilder` takes no security descriptor there, so
/// the directory inherits its parent's access list. Under a checkout in the
/// user's profile that list grants only the user, `SYSTEM` and Administrators,
/// which the Windows arm accepts. Under a checkout whose ancestors let other
/// users write -- a folder directly under `C:\` inherits `Authenticated
/// Users` with modify rights -- the three tests that make their own directory
/// through this are refused as `UnsafeAcl`, which is the check working and
/// not the test. Every other scratch store here is made by the keystore
/// itself, under its own protected list, and does not depend on where the
/// checkout is.
#[cfg(windows)]
impl Mode0700 for std::fs::DirBuilder {
    fn mode_0700(&mut self) -> &mut Self {
        self
    }
}

#[test]
fn persist_advance_to_refuses_non_increasing_targets_and_writes_nothing() {
    let dir = ScratchDir::new("monotonic");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let mut a = imported_account();
    for _ in 0..3 {
        a.advance().unwrap_or_else(|e| panic!("{e}"));
    }
    ks.add(a).unwrap_or_else(|e| panic!("{e}"));
    let before = read_snapshot(&dir);
    ks.medium_mut().reset_calls();

    let stored = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index;
    assert_eq!(stored.get(), 3);
    let lower = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
    assert_eq!(
        lower,
        Some(Error::Range { what: "wots index for tag", min: 4, max: u64::from(u32::MAX), got: 0 }),
        "persist_advance_to accepted a target below the stored index"
    );
    let equal = ks.persist_advance_to(&IMPORTED_TAG, stored).err();
    assert_eq!(
        equal,
        Some(Error::Range { what: "wots index for tag", min: 4, max: u64::from(u32::MAX), got: 3 }),
        "persist_advance_to accepted a target equal to the stored index"
    );
    assert_eq!(read_snapshot(&dir), before, "a refusal rewrote the snapshot");
    assert!(ks.medium().calls().is_empty(), "a refusal touched the medium: {:?}", ks.medium().calls());

    let next = stored.advanced().unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance_to(&IMPORTED_TAG, next).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), next);
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, next);
}

#[test]
fn records_are_addressed_by_tag_not_position() {
    let d1 = ScratchDir::new("bytag-1");
    let d2 = ScratchDir::new("bytag-2");
    let mut k1 = Keystore::create(d1.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    k1.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    k1.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut k2 = Keystore::create(d2.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    k2.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    k2.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    // **What this equality covers under version 3, stated because it changed
    // and because `assert_eq!(bytes, bytes)` does not show it**.
    //
    // Under v2 the file was header + records + a hash of both, so byte
    // equality was exactly plaintext equality. Under v3 it is
    // `header | ciphertext | tag`, and the harness fixes the password, salt,
    // nonce seed and KDF — so byte equality now additionally requires that the
    // two stores derived the same key, built the same AAD, chose the same
    // nonce, and computed the same tag.
    //
    // **What that buys, precisely.** It does not catch more *plaintext*
    // differences: any record difference already showed here in v2. What it
    // catches that v2 could not is a salt or nonce that varied with something
    // it must not — insertion order, a pointer, a clock. That class is new,
    // and it is the class an AEAD introduces, so this test acquired coverage
    // of exactly the hazard the format change created.
    //
    // It holds at all only because nondeterminism here is a PARAMETER: the
    // crate has no RNG and the caller supplies the salt and the nonce seed.
    // The decision deferring the AEAD predicted it would delete this
    // observable; the encryption change recorded why it did not.
    let (f1, f2) = (read_snapshot(&d1), read_snapshot(&d2));
    assert_eq!(f1, f2, "insertion order leaked into the image");
    // Spelled out, so the three regions are visibly compared rather than
    // incidentally: a future reader should not have to re-derive that the tag
    // is inside the equality above.
    assert_eq!(f1[..HEADER], f2[..HEADER], "the plaintext headers differ: salt or nonce varied");
    assert_eq!(
        f1[f1.len() - TRAILER..],
        f2[f2.len() - TRAILER..],
        "the AEAD tags differ, so the two stores did not seal identical plaintext under an \
         identical key and nonce"
    );
    let target = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    let _receipt = k1.persist_advance_to(&DERIVED_TAG, target).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = k2.persist_advance_to(&DERIVED_TAG, target).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(read_snapshot(&d1), read_snapshot(&d2));
    for k in [&k1, &k2] {
        assert_eq!(k.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, WotsIndex::ZERO);
        assert_eq!(k.view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, target);
    }
}

#[cfg(unix)]
#[test]
fn medium_sequence_is_exactly_the_four_steps_with_their_arguments() {
    let dir = ScratchDir::new("sequence");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.medium_mut().reset_calls();
    let _receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let tmp = dir.path().join("accounts.mks.tmp");
    let snap = dir.path().join("accounts.mks");
    let len = read_snapshot(&dir).len();
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::WriteTemp { path: tmp.clone(), len },
            Call::FsyncFile { path: tmp.clone() },
            Call::Rename { from: tmp, to: snap },
            Call::FsyncDir { dir: dir.path().to_path_buf() },
        ]
    );
}

/// The Windows form of the test above: each commit is the slot layout's
/// steps, on the slot that does not hold the newest image, with the frame's
/// length -- forty-six bytes over the image's.
///
/// `create` writes slot 1 and then slot 0's vacant frame; a handle's later
/// commits alternate; and a handle opened on a store flushes the newest slot
/// as it found it before its first write, which a handle that wrote the
/// store itself has no need to.
#[cfg(windows)]
#[test]
fn medium_sequence_is_exactly_the_slot_steps_with_their_arguments() {
    const OVERHEAD: usize = 46;
    let dir = ScratchDir::new("sequence");
    let slot0 = dir.path().join("accounts.mks");
    let slot1 = dir.path().join("accounts.mks.1");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let len = OVERHEAD + read_snapshot(&dir).len();
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::WriteSlot { path: slot1.clone(), len },
            Call::FlushSlot { path: slot1.clone() },
            Call::WriteSlot { path: slot0.clone(), len: OVERHEAD },
            Call::FlushSlot { path: slot0.clone() },
        ],
        "create is slot 1's image and then slot 0's vacant frame, each flushed"
    );
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.medium_mut().reset_calls();
    let _receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let len = OVERHEAD + read_snapshot(&dir).len();
    assert_eq!(
        ks.medium().calls(),
        &[Call::WriteSlot { path: slot1.clone(), len }, Call::FlushSlot { path: slot1.clone() }],
        "the third commit is not slot 1's, written and flushed"
    );
    drop(ks);
    let mut ks = keystore_harness::reopen_with("sequence", dir.path(), || Instrumented::new(Disk))
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let len = OVERHEAD + read_snapshot(&dir).len();
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::FlushStanding { path: slot1 },
            Call::WriteSlot { path: slot0.clone(), len },
            Call::FlushSlot { path: slot0 },
        ],
        "a reopened handle's first commit does not flush the newest slot before writing the other"
    );
}

/// The image's own geometry, derived from the layout `src/keystore/format.rs`
/// documents rather than typed as numbers here — `format`'s constants are
/// `pub(crate)` and this is an external crate, so the derivation is written
/// out and then **checked against the file the store actually wrote**. A
/// stale literal fails at `SNAPSHOT_GEOMETRY` rather than silently addressing
/// the wrong field. Widths: tag 20, kind 1, body 32, first 64, stream 20,
/// index 4, pending 1, spent 4, digest 32.
const HEADER: usize = 8 + 2 + 1 + 4 + 4 + 4 + 16 + 12;
/// `generation | count | master_present | master`, inside the ciphertext.
const BODY_HEADER: usize = 8 + 4 + 1 + 32;
/// The version-4 record: v3's widths, then figures 1, reserved
/// balance 8, block-to-live 8.
const RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32 + 1 + 8 + 8;
/// The Poly1305 tag, where version 2 had a sha3_256 trailer.
const TRAILER: usize = 16;
/// The version this build writes.
const VERSION: u16 = 4;
/// Version 3's own geometry, for the two captured version-3 files this build
/// READS: the record without the seventeen figures
/// bytes, and its version word. Split from the pair above the way
/// `V1_HEADER`/`V1_TRAILER` are, so a v3 file is described through v3's
/// constants and never through the live ones.
const V3_RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32;
const V3_VERSION: u16 = 3;
/// Version 1's own widths, for the captured-file test. Written out rather than
/// reached through the constants above, which describe version 3 and moved.
const V1_HEADER: usize = 22;
const V1_TRAILER: usize = 32;

#[test]
fn corrupt_snapshots_are_refused_by_exact_variant_and_never_panic() {
    let dir = ScratchDir::new("corrupt");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let good = read_snapshot(&dir);

    // SNAPSHOT_GEOMETRY: two records, so the closed formula fixes the length,
    // and the version word is where the header says it is.
    assert_eq!(
        good.len(),
        HEADER + BODY_HEADER + 2 * RECORD + TRAILER,
        "the offsets below are derived from these widths; one of them moved"
    );
    assert_eq!(u16::from_le_bytes([good[8], good[9]]), VERSION);

    // **A flipped byte is `WrongPassword` now, not `Corrupt`**. The
    // AEAD refuses it before a record byte is read, and it cannot say whether
    // the file was damaged or the password was wrong -- deliberately, because
    // an error that distinguished them would tell an attacker which of his
    // guesses was closer. The cost lands on an operator with a bit-rotted
    // store, who will retype their password before suspecting the disk;
    // the encryption change recorded that as a price rather than a detail.
    let mut flipped = good.clone();
    flipped[HEADER + 5] ^= 1;
    write_snapshot(&dir, &flipped);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::WrongPassword),
        "a flipped byte loaded"
    );

    let mut newer = good.clone();
    newer[8..10].copy_from_slice(&(VERSION + 1).to_le_bytes());
    write_snapshot(&dir, &newer);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::UnsupportedVersion { got: VERSION + 1, supported: VERSION, first_account: None }),
        "an unknown version must say upgrade, not corrupt"
    );
    // And a NEWER version is told so: a newer build wrote the store;
    // the fresh-directory advice is an older store's and must not be given
    // for a file this build merely postdates.
    let Err(newer_refusal) = Keystore::open(dir.path(), &keystore_harness::unlock()) else {
        panic!("refused above")
    };
    let newer_text = format!("{newer_refusal}");
    for needle in [format!("format version {}", VERSION + 1), "NEWER build".to_owned(), "at least that new".to_owned()] {
        assert!(newer_text.contains(&needle), "the newer-version refusal does not say {needle:?}:\n{newer_text}");
    }
    assert!(
        !newer_text.contains("FRESH directory"),
        "a store a NEWER build wrote was given the older-store migration advice:\n{newer_text}"
    );

    // **The duplicate-tag row moved to `format.rs`'s table**. Reaching
    // a canonicality check now requires editing the PLAINTEXT and sealing it
    // again, which needs the store key -- and this file deliberately has no
    // access to it, because it tests the public `open` rather than the parser.
    // What it can still show from out here is that the same edit, unsealed, is
    // refused: which is the AEAD doing its job one layer above the rule.
    let mut dup = good.clone();
    dup.copy_within(HEADER..HEADER + 20, HEADER + RECORD);
    write_snapshot(&dir, &dup);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::WrongPassword),
        "an edited record loaded"
    );

    // every prefix truncation, and one trailing byte: an Err, never a panic
    for n in 0..good.len() {
        write_snapshot(&dir, &good[..n]);
        assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_err(), "prefix {n} opened");
    }
    let mut longer = good.clone();
    longer.push(0);
    write_snapshot(&dir, &longer);
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_err());

    write_snapshot(&dir, &good);
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_ok());
}

/// A store written by format version 1 says **upgrade**, through the public
/// `open` and not only through the parser.
///
/// # Why a captured file and not a v1-shaped buffer
///
/// The bytes below were written by the last build whose encoder wrote format
/// version 1 (`src/keystore/format.rs` carries the same
/// image with the capture recorded). A buffer assembled here would exercise
/// this test's idea of version 1; this exercises version 1.
///
/// # What each arm establishes
///
/// * a genuine v1 store reports `UnsupportedVersion`, so an operator holding
///   an older wallet is told to migrate rather than that their keys are
///   damaged;
/// * **with its trailer destroyed it still reports the version**, which is
///   the only way to see that the version is dispatched *before* the hash.
///   The two are indistinguishable on a well-formed file;
/// * migration is re-adding into a fresh directory, and the message says so
///   -- checked as rendered text, because failure-path text is
///   invisible to a passing suite.
#[test]
fn a_version_1_store_is_refused_with_upgrade_not_damage() {
    // The one copy, embedded: see `crates/mochimo-crypto/testdata/README.md`.
    // `src/keystore/format.rs` reads the same file, so the two version-
    // dispatch tests cannot drift apart.
    const V1: &[u8] = include_bytes!("../testdata/keystore_v1_snapshot.bin");
    // v1's own closed formula: 94-byte records. Checked so that a mangled
    // paste is a red here rather than a red somewhere downstream.
    assert_eq!(V1.len(), V1_HEADER + 2 * 94 + V1_TRAILER);
    assert_eq!(u16::from_le_bytes([V1[8], V1[9]]), 1);

    let dir = ScratchDir::new("v1-refused");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    write_snapshot(&dir, V1);
    let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
    // And names its first account: the v1 imported record
    // under the tag `0x1a * 20`, kind byte `1` at offset 42.
    let first = Some(([0x1a; 20], AccountKind::Imported));
    assert_eq!(
        err,
        Some(Error::UnsupportedVersion { got: 1, supported: VERSION, first_account: first }),
        "a version-1 store must report its version"
    );

    let mut broken = V1.to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0xff;
    write_snapshot(&dir, &broken);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::UnsupportedVersion { got: 1, supported: VERSION, first_account: first }),
        "the version must be dispatched BEFORE the trailer is verified"
    );

    let rendered = format!("{}", err.expect("checked above"));
    // "reads version 4" since format version 4 ("reads version 3" before it).
    // The needle names the CURRENT version on purpose -- it is what tells the
    // operator which build they are holding, and a needle that stopped
    // tracking it would go on passing while the message said something a
    // version out of date. Since version 4 the same sentence also says a version-3
    // store is read and re-sealed.
    for needle in ["format version 1", "reads version 4", "re-sealing it as version 4", "FRESH directory", "never by rewriting it in place"] {
        assert!(rendered.contains(needle), "the message does not say {needle:?}: {rendered}");
    }
}

#[test]
fn stale_temp_is_unlinked_and_never_adopted() {
    let dir = ScratchDir::new("stale-temp");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let target = read_snapshot(&dir);
    // A hash-valid image of a DIFFERENT state, left as the temp.
    let other = ScratchDir::new("stale-temp-other");
    let mut o = Keystore::create(other.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    o.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = o.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    drop(o);
    let advanced_image = other.snapshot_bytes();
    assert_ne!(advanced_image, target);
    std::fs::write(dir.path().join("accounts.mks.tmp"), &advanced_image).unwrap_or_else(|e| panic!("{e}"));

    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index,
        WotsIndex::ZERO,
        "open adopted the stale temp"
    );
    assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "open left the stale temp");
    assert_eq!(read_snapshot(&dir), target);
}

#[cfg(unix)]
#[test]
fn temp_file_is_created_mode_0600_and_the_directory_0700() {
    let dir = ScratchDir::new("modes");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let dmode = std::fs::metadata(dir.path()).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.medium_mut().stop_after(Some(1));
    let _ = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES);
    let tmode = std::fs::metadata(dir.path().join("accounts.mks.tmp")).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(tmode, 0o600, "the temp holds plaintext roots and must not be group/other readable");
}

#[cfg(unix)]
#[test]
fn open_refuses_a_group_writable_directory() {
    let dir = ScratchDir::new("perms");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::UnsafePermissions { mode: 0o775 }));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| panic!("{e}"));
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_ok());
}

/// `icacls` on `path`, with the arguments given, which must succeed.
///
/// Trustees are named by SID with `icacls`'s `*` prefix, so the command reads
/// the same in every Windows language; its output is localized and is never
/// parsed here. Whether a list says what these tests need is asked of the
/// keystore's own check instead, which is the thing under test.
#[cfg(windows)]
fn icacls(path: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("cannot run icacls: {e}"));
    assert!(status.success(), "icacls {} {args:?} failed: {status}", path.display());
}

/// The Windows form of `open_refuses_a_group_writable_directory`: a store
/// directory Everyone may modify is refused, by name, and naming Everyone;
/// the same directory with that entry removed opens.
///
/// Green on a GitHub Windows runner, Windows Server 2025 build 26100, whose
/// account is an elevated administrator and where a new directory is owned
/// by the Administrators group; `FORK.md` records the run.
#[cfg(windows)]
#[test]
fn open_refuses_a_directory_everyone_can_write_to() {
    let dir = ScratchDir::new("acl-everyone");
    drop(Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    icacls(dir.path(), &["/grant", "*S-1-1-0:(M)"]);
    match Keystore::open(dir.path(), &keystore_harness::unlock()).err() {
        Some(Error::UnsafeAcl { trustee, .. }) => assert_eq!(trustee, "S-1-1-0", "the refusal names the wrong trustee"),
        other => panic!("a directory Everyone may modify was not refused as UnsafeAcl: {other:?}"),
    }
    icacls(dir.path(), &["/remove:g", "*S-1-1-0"]);
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_ok(), "the directory does not open once the grant is gone");
}

/// A store created inside a directory Everyone may modify inherits none of
/// it: the keystore's protected list is what the directory gets, and the
/// keystore's own check is what reads it back.
///
/// The parent is granted Everyone with inheritance to files and directories,
/// and the premise is asserted -- the parent itself is refused. If the store
/// directory were created without the protected flag it would inherit that
/// grant and `create` would refuse it; that it opens is the evidence the flag
/// is set. Green on a Windows runner, as above.
#[cfg(windows)]
#[test]
fn a_store_created_under_a_writable_parent_inherits_nothing_from_it() {
    let parent = ScratchDir::new("acl-parent");
    std::fs::create_dir(parent.path()).unwrap_or_else(|e| panic!("{e}"));
    icacls(parent.path(), &["/grant", "*S-1-1-0:(OI)(CI)(M)"]);
    assert!(
        matches!(Keystore::open(parent.path(), &keystore_harness::unlock()).err(), Some(Error::UnsafeAcl { .. })),
        "premise: the parent Everyone may modify is itself refused"
    );
    let store = parent.path().join("store");
    let mut ks = Keystore::create(&store, &keystore_harness::init())
        .unwrap_or_else(|e| panic!("the store created under a writable parent is refused, so it inherited: {e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    assert!(Keystore::open(&store, &keystore_harness::unlock()).is_ok(), "the store does not reopen");
}

/// A slot file another process holds open without sharing write refuses
/// the store's `open` **by name**, before anything is read, and changes
/// nothing; the store opens once the holder lets go. And while a handle holds
/// its slots, a program that shares read alone cannot open them at all.
///
/// The holder shares read only, which is the shape of a scanner or an
/// indexer that asked for no more. On Windows `open` holds both slot files
/// for writing, sharing read alone, so such a holder is met there, as
/// `HeldOpen`, and never by a commit.
#[cfg(windows)]
#[test]
fn a_slot_held_open_without_write_sharing_refuses_the_open_by_name() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    let dir = ScratchDir::new("held-slot");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let before = dir.slot_bytes();
    let hold = |name: &str| {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(dir.path().join(name))
    };
    for name in ["accounts.mks", "accounts.mks.1"] {
        let holder = hold(name).unwrap_or_else(|e| panic!("cannot hold {name} open: {e}"));
        let refused = keystore_harness::open(dir.path()).err();
        drop(holder);
        assert!(
            matches!(refused, Some(Error::HeldOpen { .. })),
            "an open with {name} held was not refused as HeldOpen: {refused:?}"
        );
        assert_eq!(dir.slot_bytes(), before, "the open refused over {name} changed a slot");
    }
    let ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("the store does not open once the holder is gone: {e}"));
    for name in ["accounts.mks", "accounts.mks.1"] {
        assert!(
            hold(name).is_err(),
            "a program sharing read alone opened {name} while a handle holds it for writing"
        );
    }
    drop(ks);
}

#[cfg(unix)]
#[test]
fn poisoned_handle_refuses_to_launder_a_rollback() {
    // The rollback this refuses: advance_to(k+5) fails at the
    // directory fsync (disk = k+5, memory = k); a later advance on the same
    // handle would compute k+1 and write it over disk's k+5. The handle is
    // poisoned instead, and its message says drop-and-reopen, never retry.
    let dir = ScratchDir::new("poison");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut target = WotsIndex::ZERO;
    for _ in 0..5 {
        target = target.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    ks.medium_mut().stop_after(Some(4));
    let err = ks.persist_advance_to(&IMPORTED_TAG, target).err().unwrap_or_else(|| panic!("expected the injected error"));
    assert_eq!(err, Error::Io { op: "fsync_dir", kind: std::io::ErrorKind::Interrupted });
    ks.medium_mut().stop_after(None);
    let later = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).err().unwrap_or_else(|| panic!("a poisoned handle wrote"));
    assert!(matches!(later, Error::Poisoned { .. }), "{later:?}");
    let msg = later.to_string();
    assert!(msg.contains("drop this handle and reopen"), "{msg}");
    assert!(msg.contains("do not retry"), "{msg}");
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index,
        target,
        "disk's committed k+5 was overwritten"
    );
}

/// The Windows form of the test above, with the interruption after the
/// commit's last step there, the flush of the slot just written.
#[cfg(windows)]
#[test]
fn poisoned_handle_refuses_to_launder_a_rollback() {
    let dir = ScratchDir::new("poison");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut target = WotsIndex::ZERO;
    for _ in 0..5 {
        target = target.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    ks.medium_mut().stop_after(Some(2));
    let err = ks.persist_advance_to(&IMPORTED_TAG, target).err().unwrap_or_else(|| panic!("expected the injected error"));
    assert_eq!(err, Error::Io { op: "flush_slot", kind: std::io::ErrorKind::Interrupted });
    ks.medium_mut().stop_after(None);
    let later = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).err().unwrap_or_else(|| panic!("a poisoned handle wrote"));
    assert!(matches!(later, Error::Poisoned { .. }), "{later:?}");
    let msg = later.to_string();
    assert!(msg.contains("drop this handle and reopen"), "{msg}");
    assert!(msg.contains("do not retry"), "{msg}");
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index,
        target,
        "disk's committed k+5 was overwritten"
    );
}

#[test]
fn pending_gates_a_second_advance_until_settled() {
    let dir = ScratchDir::new("pending");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.persist_settled(&IMPORTED_TAG).err(), Some(Error::NothingPending));
    let _receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).err(),
        Some(Error::PendingUnresolved { spent_index: 0 })
    );
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.pending.map(|p| p.spent_index.get()), Some(0));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index().get(), 2);
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.wots_index.get(), 2);
    assert_eq!(v.pending.map(|p| p.spent_index.get()), Some(1));
}

/// The `Keystore`'s own `Debug` never renders an imported root.
///
/// # Two defects the reconciliation session found here, both from format v2's
///
/// The needles were `"b7b7"` and `"183"` — the hex and the decimal of
/// `0xB7`, the root this harness held until format v2 replaced it with
/// `F-address-widths`' account seed. **They stopped describing their subject
/// and nothing noticed**, because a needle asserting an *absence* keeps
/// passing when its subject moves: it goes on proving that a root nobody
/// holds is absent.
///
/// And it was **flaky by construction**. The rendering embeds the scratch
/// directory's path, which carries a nanosecond timestamp, so a short decimal
/// needle like `"183"` can appear in it by chance — which is how this
/// surfaced at all, on a run whose timestamp happened to contain those three
/// digits. A needle searched against text the test does not control is a
/// needle that fails on a clock.
///
/// Both are closed the same way: the needles are **derived from `ROOT`**
/// rather than typed, so they cannot go stale, and they are searched against
/// the rendering **with the directory path removed**, so nothing the test
/// does not control is in scope.
#[test]
fn debug_never_reveals_keystore_roots() {
    let dir = ScratchDir::new("debug");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let rendered = format!("{ks:?}");
    assert!(rendered.starts_with("Keystore { dir:"), "{rendered}");
    assert!(rendered.contains("accounts: 1"), "{rendered}");

    // Everything after the directory field: the part this test controls. The
    // path itself carries a nanosecond stamp and is not searched.
    let after_dir = rendered
        .split_once("\", generation")
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_else(|| panic!("the Debug shape moved; re-read what it renders: {rendered}"));

    // Needles derived from the root in play, never typed: its hex in both
    // cases, and the decimal of each byte.
    let hex_lower: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex_lower.to_ascii_uppercase();
    for needle in [&hex_lower, &hex_upper] {
        assert!(
            !after_dir.contains(needle.as_str()),
            "the root's hex reached the rendering: {rendered}"
        );
        // ...and any four-hex-digit prefix of it, so a partial leak is caught.
        assert!(
            !after_dir.contains(&needle[..4]),
            "a prefix of the root's hex reached the rendering: {rendered}"
        );
    }
    // The decimal form, as a `[u8; N]`'s own `Debug` renders it -- `102, 78,
    // 221, ...`. Taken as a SEQUENCE and not byte by byte: a single decimal
    // like `11` collides with a generation counter, which would make this a
    // check that fails on the store's own bookkeeping rather than on a leak.
    let decimals = format!("{:?}", &ROOT[..]);
    let inner = decimals.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !after_dir.contains(inner),
        "the root's decimal rendering reached the Debug output: {rendered}"
    );
    let head = inner.split(", ").take(4).collect::<Vec<_>>().join(", ");
    assert!(
        !after_dir.contains(&head),
        "a prefix of the root's decimal rendering reached the Debug output: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// I6 at rest: the proof `imported_root_is_encrypted_before_it_reaches_
// the_snapshot` demanded, in the shape it prescribed
// ---------------------------------------------------------------------------

/// **The imported root is not in the file, and it comes back.**
///
/// # Both halves, or neither
///
/// The marker that demanded this test named the trap in its own clearing
/// condition: *"a store that zeroes the root passes the first half alone."*
/// Absence is trivially achievable by destroying the data. So this asserts
/// absence in the bytes **and** an exact byte-for-byte restore through a
/// reopen, and neither arm is meaningful without the other.
///
/// # The premise arm, flipped
///
/// Measuring the premise live means writing a store with a patterned root and
/// asserting where the root's bytes are. Before encryption at rest that arm
/// asserted they **were** in the file at byte offset 43, which depended on
/// the defect existing; here it is flipped -- and the offset it
/// named is now the first place this test looks, because "not at 43" and "not
/// anywhere" are different claims and the weaker one is the one an encryption
/// bug would satisfy.
#[test]
fn snapshot_bytes_never_contain_the_imported_root() {
    use keystore_harness::{imported_account, ScratchDir, ROOT};

    let dir = ScratchDir::new("i6-at-rest-proof");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);

    let bytes = dir.snapshot_bytes();

    // 1. ABSENT. Not at the offset the plaintext format put it at, and not
    //    anywhere else either.
    const V2_ROOT_OFFSET: usize = 43;
    if bytes.len() > V2_ROOT_OFFSET + ROOT.len() {
        assert_ne!(
            &bytes[V2_ROOT_OFFSET..V2_ROOT_OFFSET + ROOT.len()],
            &ROOT[..],
            "the imported root is at byte {V2_ROOT_OFFSET}, where the version-2 plaintext format \
             put it"
        );
    }
    assert!(
        bytes.windows(ROOT.len()).all(|w| w != ROOT),
        "the imported root's 32 bytes appear somewhere in the snapshot. The whole point of \
         version 3 is that they do not."
    );
    // A Windows store is two slot files, and the older image is at rest too.
    #[cfg(windows)]
    assert!(
        dir.slot_bytes().windows(ROOT.len()).all(|w| w != ROOT),
        "the imported root's 32 bytes appear somewhere in the slot files"
    );

    // 2. AND PRESENT AFTER RESTORE. Without this, arm 1 is satisfied by a
    //    store that wrote zeroes.
    let ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let tag = keystore_harness::IMPORTED_TAG;
    let view = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the imported account did not survive the round trip"));
    assert_eq!(view.tag, tag);
    // The root itself, byte for byte, reached through the store's own
    // accessor rather than through the parser this test is about.
    // The root itself is not handed out -- `Account` is deliberately not
    // `Clone` and `to_record` consumes it -- so the restore is shown through
    // the observable that IS a function of the root: the key stream's public
    // identity. `stream_id` is `stream_id(derive_wots_key(root, 0))`, so a
    // root that came back wrong in any byte produces a different one.
    //
    // And the stronger half is structural: `Account::restore_from_record`
    // recomputes both the tag and the stream identity from the root and
    // REFUSES a record where they disagree, so a store that zeroed the root
    // would not have opened at all -- the `open` above would have been the
    // failure. Arm 1 cannot be satisfied by destroying the data.
    assert_eq!(
        ks.stream_id(&tag)
            .unwrap_or_else(|e| panic!("{e}"))
            .as_bytes(),
        &keystore_harness::IMPORTED_STREAM,
        "the imported account's key-stream identity changed across the round trip, so the root \
         did not come back byte-identical"
    );
    drop(ks);

    // 3. A BIT FLIP IS REFUSED. The AEAD tag is what replaced the sha3
    //    trailer, and this is the claim it makes.
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    dir.write_snapshot(&flipped);
    match keystore_harness::open(dir.path()) {
        Err(Error::WrongPassword) => {}
        other => panic!("a flipped tag byte was not refused: {other:?}"),
    }

    // 4. AND PASSPHRASE A'S FILE IS REFUSED UNDER B.
    dir.write_snapshot(&bytes);
    match Keystore::open(
        dir.path(),
        &keystore_harness::unlock_with(keystore_harness::OTHER_PASSWORD),
    ) {
        Err(Error::WrongPassword) => {}
        other => panic!("a store opened under a password it was not created with: {other:?}"),
    }
    // The control: it still opens under the right one, so arms 3 and 4 are
    // not satisfied by a store that refuses everything.
    let _reopened = keystore_harness::open(dir.path())
        .unwrap_or_else(|e| panic!("the store stopped opening: {e}"));

    println!(
        "  I6 at rest: root absent from {} snapshot bytes, restored byte-identical, bit flip \
         refused, wrong password refused",
        bytes.len()
    );
}

/// The lock file's existence means nothing; a live holder means everything.
///
/// # What this pins, in the order an operator meets it
///
/// 1. `open` on a directory with no snapshot refuses `Missing` and leaves no
///    lock -- the keystore's rule that a refusal has no side effects, asserted
///    directly here for the first time rather than through `create` succeeding
///    afterwards, because `create` now succeeds through a lock file anyway
///    and so no longer distinguishes the two.
/// 2. `open` on a snapshot it cannot read -- a version-2 file with its lock
///    absent -- refuses and DOES leave
///    `keystore.lock` behind. `take_lock` runs before the read, and the read
///    has to be under the lock to be authoritative. This arm asserts the side
///    effect exists so that the module doc's sentence saying so is a measured
///    claim: whoever makes a failed open side-effect-free will be told here to
///    update that sentence.
/// 3. With the snapshot still there, `create` refuses on the SNAPSHOT. The
///    leftover lock is not an overwrite path and never was.
/// 4. With the snapshot gone and the lock file still there, `create`
///    proceeds. It once refused with `Exists { what: "lock file" }` and
///    advised running "any other command against it", every one of which
///    refuses `Missing` -- the manufactured workaround I4's decision warns
///    against, and the stale-lock semantics the lock design chose `flock` precisely to avoid.
/// 5. A LIVE holder is refused by the flock, `Locked`, with no snapshot beside
///    it -- and released on drop. That, not the file's existence, is what
///    arbitrates.
///
/// What makes it red: restoring `occupied`'s lock-file arm (step 4), taking
/// the lock before the `Missing` check (step 1), taking it after the read
/// (step 2), or `create_with` no longer taking it at all (step 5).
#[test]
fn a_lock_file_with_no_snapshot_is_inert_and_only_a_live_holder_refuses_create() {
    use mochimo_crypto::keystore::occupied;
    let dir = ScratchDir::new("lock-inert");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    let has_lock = |d: &ScratchDir| d.listing().iter().any(|n| n == "keystore.lock");

    // 1.
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::Missing));
    assert!(
        !has_lock(&dir),
        "the Missing refusal left keystore.lock behind: the lock was taken before the snapshot \
         check, which the lock design fixed. Listing: {:?}",
        dir.listing()
    );

    // 2.
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut v2 = read_snapshot(&dir);
    // Forged to 2 -- `V3_VERSION - 1` -- and not to `VERSION - 1`, which is
    // 3 since format version 4 and a version this build READS: that forgery
    // would open rather than reach the version refusal this arm is about (the
    // version-4 decision named the arm as invalidated as a construction).
    v2[8..10].copy_from_slice(&(V3_VERSION - 1).to_le_bytes());
    write_snapshot(&dir, &v2);
    std::fs::remove_file(dir.path().join("keystore.lock")).unwrap_or_else(|e| panic!("{e}"));
    assert!(!has_lock(&dir), "premise: the copy has no lock");
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        // A v4 image under a version-2 word fits no v2 layout, so no account
        // is named: the bytes at 22..42 are this file's salt.
        Some(Error::UnsupportedVersion { got: V3_VERSION - 1, supported: VERSION, first_account: None })
    );
    assert!(
        has_lock(&dir),
        "a failed open at the version word did NOT leave keystore.lock behind. That is a \
         change to what `open_with` does before it reads, and the keystore module doc's \
         sentence recording the side effect (\"The lock\") now says something false -- update \
         it with this arm. Listing: {:?}",
        dir.listing()
    );

    // 3.
    assert_eq!(occupied(dir.path()), Some("snapshot"));
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Exists { what: "snapshot" }),
        "create over a directory holding a snapshot it cannot read must refuse on the snapshot"
    );

    // 4.
    std::fs::remove_file(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(dir.listing(), vec!["keystore.lock".to_string()], "premise: only the lock remains");
    assert_eq!(
        occupied(dir.path()),
        None,
        "a lock file with no snapshot beside it reads as an occupied directory. Nothing holds \
         it -- the flock is what says whether anything does -- so refusing here is the \
         stale-lock design the lock design rejected, and the refusal's advice (run another command) \
         is contradicted by every other command's `Missing`."
    );
    let held = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| {
        panic!("create refused a directory holding only an UNHELD keystore.lock: {e}")
    });

    // 5.
    #[cfg(unix)]
    std::fs::remove_file(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
    // On Windows a live handle holds its slot files without sharing delete,
    // so no snapshot can be removed from under it: the live holder here is
    // the lock alone, taken beside no store at all.
    #[cfg(windows)]
    let held = {
        drop(held);
        for name in ["accounts.mks", "accounts.mks.1"] {
            std::fs::remove_file(dir.path().join(name)).unwrap_or_else(|e| panic!("{e}"));
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("keystore.lock"))
            .unwrap_or_else(|e| panic!("{e}"));
        lock.try_lock().unwrap_or_else(|e| panic!("{e}"));
        lock
    };
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Locked),
        "a LIVE holder of keystore.lock was not refused by create; the flock is the only thing \
         standing between two processes writing one directory"
    );
    drop(held);
    let released = Keystore::create(dir.path(), &keystore_harness::init());
    assert!(released.is_ok(), "the lock did not release on drop: {:?}", released.err());

    println!("  lock file inert: 5 arms -- Missing leaves none, a failed read leaves one, the snapshot refuses, the file alone does not, a live holder does");
}

/// **The salt the header carries is the salt the key was derived from**.
///
/// Every create→open round trip in this file exercises the salt with ONE
/// degree of freedom: if the writer and the reader both consumed the same
/// wrong constant instead of the header's salt, every round trip would still
/// pass, and the sixteen salt bytes in the header would be decoration. This
/// closes that: two stores under the same password, nonce seed and KDF whose
/// headers carry DIFFERENT salts must seal different ciphertext. A KDF that
/// consumed a constant derives one key for both, and `nonce_for` is
/// salt-independent, so the same 45-byte plaintext under the same key and
/// nonce would give the same ciphertext byte for byte -- only the header's
/// salt field and the tag would differ.
///
/// Why here and not in `format.rs`: `format::encode` takes the salt and the
/// key as independent parameters, so no format-layer test can establish this;
/// it is a `Keystore` property, and `create_with`/`open_with` are the two
/// sites (`init.salt` and `framed.header.salt`). A fault-injection row replaces both with
/// a constant: this reds, every round trip stays green.
#[test]
fn the_header_salt_is_the_salt_the_key_was_derived_from() {
    let d1 = ScratchDir::new("salt-1");
    let d2 = ScratchDir::new("salt-2");
    let mut init1 = keystore_harness::init();
    init1.salt = [0x11; 16];
    let mut init2 = keystore_harness::init();
    init2.salt = [0x22; 16];
    let k1 = Keystore::create(d1.path(), &init1).unwrap_or_else(|e| panic!("{e}"));
    let k2 = Keystore::create(d2.path(), &init2).unwrap_or_else(|e| panic!("{e}"));
    drop((k1, k2));
    let (f1, f2) = (read_snapshot(&d1), read_snapshot(&d2));
    assert_eq!(f1.len(), f2.len(), "two empty stores differ in length");
    assert_ne!(
        f1[HEADER - 12 - 16..HEADER - 12],
        f2[HEADER - 12 - 16..HEADER - 12],
        "the two headers carry the same salt; the test's premise is broken"
    );
    assert_ne!(
        f1[HEADER..f1.len() - TRAILER],
        f2[HEADER..f2.len() - TRAILER],
        "two stores whose headers carry different salts sealed identical ciphertext: the KDF did \
         not consume the salt the header carries, so the salt is decoration and two stores under \
         one password share a key"
    );
}

// ---------------------------------------------------------------------------
// The version refusal and the seed of the store in hand
// ---------------------------------------------------------------------------

/// Bytes `[22..42)` and `[42]` of a version-1 or version-2 image: the first
/// record's tag and kind, read the way the two historical layouts place
/// them (`magic[8] | version u16 | generation u64 | count u32`, then records
/// sorted by tag, each `tag[20] | kind u8 | …`; v1's records are 94 bytes and
/// v2's 178 -- `git show 0c07b65^:crates/mochimo-crypto/src/keystore/format.rs`
/// for v2, the constants in `format.rs`'s version test for v1).
fn first_record_of_an_older_image(image: &[u8]) -> ([u8; 20], u8) {
    let mut tag = [0u8; 20];
    tag.copy_from_slice(&image[22..42]);
    (tag, image[42])
}

/// **The version refusal names the refused store's first account and how to
/// compare it** -- green under this name; red under
/// `the_version_refusal_does_not_say_how_to_tell_whether_the_refused_store_is_on_this_seed`
/// if it stopped naming them.
///
/// `~/mochimo-live/accounts.mks` is a format-2 store over the live wallet's
/// seed, on the operator's disk since 4 September, and what stops it spending
/// is `Error::UnsupportedVersion` -- a refusal that prescribes migration into
/// a fresh directory and says nothing about whether the store it
/// refused is the same wallet as the one the operator is running. The `Ahead`
/// arm's ACTION tells the operator to compare key streams with every other
/// wallet's report; a store this build cannot open prints no report. For a
/// version-1 or version-2 file the comparison is nevertheless available: the
/// first record's tag stands unencrypted at bytes 22..42, and `address` on the
/// store in hand answers whether that account is held here.
///
/// # The condition, verbatim from the entry that filed it
///
/// > Green when the `UnsupportedVersion` refusal says how to tell whether the
/// > refused store is on the seed of the store in hand.
///
/// # What is driven
///
/// Two captured files, both written by the encoder of their own version
/// rather than assembled here (`testdata/README.md`): a version-1 store and
/// a version-2 store, each written by the last build whose encoder wrote
/// that version, the second holding the harness's
/// two group-F accounts. Each is placed in a directory as `accounts.mks`,
/// opened through `Keystore::open`, and the refusal is rendered. The refusal
/// must name the file's first tag in hex and the procedure -- `address
/// 0x<that hex>` on the store in hand -- and must name the record's kind,
/// because what a tag match proves depends on it: for a derived account, one
/// master seed and index; for an imported account, one root and therefore
/// one WOTS+ key stream, which says nothing about the master. "On the seed"
/// in the condition is read per kind; both files lead with an imported
/// record, so the rendered word here is `imported`.
///
/// # Controls
///
/// The tag read from the v2 file must equal `IMPORTED_TAG`, the account the
/// capture was built with -- two sources for one value, so a wrong reading
/// of the layout fails here rather than certifying itself. The
/// v1 file's tag (`0x1a` twenty times, v1's unverified-tag import) must be
/// named for the v1 file and must not appear for the v2 one. A version-3
/// store whose version word is forged to 2 (bytes 22..42
/// there are the KDF's `p_cost` tail, the salt and the head of the nonce)
/// and a version-3 store with an unknown KDF id must render NO procedure:
/// the fix may only read a tag from an image whose length fits that
/// version's closed formula. And every proper prefix of the v2 file is
/// opened once, so the new reads are exercised at every truncation the
/// every-prefix walk over v3 images never reaches.
#[test]
fn the_version_refusal_names_the_refused_stores_first_account_and_how_to_compare_it() {
    const V1: &[u8] = include_bytes!("../testdata/keystore_v1_snapshot.bin");
    const V2: &[u8] = include_bytes!("../testdata/keystore_v2_snapshot.bin");
    const V2_RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32;
    const PROCEDURE: &str = "address 0x";
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    // The captured v2 file's geometry, checked before anything reads it.
    assert_eq!(V2.len(), V1_HEADER + 2 * V2_RECORD + V1_TRAILER, "the v2 capture is not two records long");
    assert_eq!(&V2[..8], b"MCMKSTOR");
    assert_eq!(u16::from_le_bytes([V2[8], V2[9]]), 2, "the v2 capture's version word is not 2");
    assert_eq!(u32::from_le_bytes([V2[18], V2[19], V2[20], V2[21]]), 2, "the v2 capture's count is not 2");
    let (v2_tag, v2_kind) = first_record_of_an_older_image(V2);
    assert_eq!(
        v2_tag, IMPORTED_TAG,
        "the v2 capture's first record is not the imported account it was built with: either the \
         layout reading (tag at 22..42) or the capture is wrong"
    );
    assert_eq!(v2_kind, 1, "the v2 capture's first record is not marked imported");
    let (v1_tag, v1_kind) = first_record_of_an_older_image(V1);
    assert_eq!(v1_tag, [0x1a; 20], "the v1 capture's first record is not the 0x1a tag it was written with");
    assert_eq!(v1_kind, 1);
    assert_ne!(v1_tag, v2_tag);

    let render = |dir: &ScratchDir, bytes: &[u8], want_got: u16| -> String {
        write_snapshot(dir, bytes);
        let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
        assert!(
            matches!(err, Some(Error::UnsupportedVersion { got, .. }) if got == want_got),
            "premise: the file was not refused as version {want_got}: {err:?}"
        );
        format!("{}", err.expect("checked"))
    };

    let mut failures: Vec<String> = Vec::new();
    // 1. The genuine version-2 store.
    let dir = ScratchDir::new("p10-207-v2");
    drop(Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    let v2_text = render(&dir, V2, 2);
    for needle in [hex(&v2_tag), format!("{PROCEDURE}{}", hex(&v2_tag)), "imported".to_owned()] {
        if !v2_text.contains(&needle) {
            failures.push(format!("the v2 refusal does not say {needle:?}"));
        }
    }
    // 2. The genuine version-1 store: its own tag, not the other file's.
    let v1_text = render(&dir, V1, 1);
    for needle in [hex(&v1_tag), format!("{PROCEDURE}{}", hex(&v1_tag)), "imported".to_owned()] {
        if !v1_text.contains(&needle) {
            failures.push(format!("the v1 refusal does not say {needle:?}"));
        }
    }
    assert!(!v1_text.contains(&hex(&v2_tag)), "the v1 refusal names the v2 file's tag: a constant, not a reading:\n{v1_text}");

    // 3. A v3 store under a forged version word: no tag can be read from it.
    let v3_dir = ScratchDir::new("p10-207-v3-image");
    drop(Keystore::create(v3_dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    let good = read_snapshot(&v3_dir);
    assert_eq!(u16::from_le_bytes([good[8], good[9]]), VERSION);
    let mut forged = good.clone();
    forged[8..10].copy_from_slice(&2u16.to_le_bytes());
    let forged_text = render(&v3_dir, &forged, 2);
    assert!(
        !forged_text.contains(PROCEDURE),
        "a v3 image under a forged version word was told to run `{PROCEDURE}` over bytes that are its salt:\n{forged_text}"
    );
    // 4. A v3 store with a KDF id this build does not have: the same variant,
    //    the same silence about a tag.
    let mut kdf = good.clone();
    kdf[10] ^= 0x7f;
    let kdf_text = render(&v3_dir, &kdf, u16::from(kdf[10]));
    assert!(!kdf_text.contains(PROCEDURE), "an unknown-KDF refusal names a procedure over ciphertext:\n{kdf_text}");
    // The KDF-id refusal reuses the variant with `got` = the id and
    // `supported` = 1, and the version producer's sentences -- the newer-build
    // advice and the re-seal clause -- must not leak onto it.
    for needle in ["NEWER build", "at least that new", "version-3 store", "re-sealing"] {
        assert!(
            !kdf_text.contains(needle),
            "the KDF-id refusal renders the version arm's sentence {needle:?} -- the Display's \
             guard on which producer made the variant is gone:\n{kdf_text}"
        );
    }

    // 5. Every proper prefix of the v2 file: refused, never a panic, never a
    //    procedure over a file whose length fits no version.
    let mut prefixes = 0usize;
    for n in 0..V2.len() {
        write_snapshot(&dir, &V2[..n]);
        let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err().unwrap_or_else(|| panic!("a {n}-byte prefix of the v2 capture OPENED"));
        assert!(
            !format!("{err}").contains(PROCEDURE),
            "a {n}-byte prefix of the v2 capture was told a procedure: {err}"
        );
        prefixes += 1;
    }
    assert_eq!(prefixes, V2.len());

    if failures.is_empty() {
        // Rendered on the green path too, so the text an operator reads is in
        // every board log rather than only in a failure.
        println!(
            "  version refusal names the refused store's first account: v1 and v2 captures, {prefixes} prefixes refused without a procedure\n  v2 refusal as rendered:\n    {v2_text}"
        );
        return;
    }
    panic!(
        "THE VERSION REFUSAL DOES NOT SAY HOW TO TELL WHETHER THE REFUSED STORE IS ON THE SEED OF THE \
         STORE IN HAND. An operator holding `~/mochimo-live` (format 2, over the live seed) \
         is told to migrate into a fresh directory and nothing about whether the refused store IS the \
         wallet they are running -- while the `Ahead` arm tells them to compare key streams with a \
         report that store cannot print. {} thing(s) missing:\n\x20 - {}\n\
         \n\
         The condition: \"Green when the `UnsupportedVersion` refusal says how to tell \
         whether the refused store is on the seed of the store in hand.\"\n\
         \n\
         What clears it: the refusal names the first record's tag, read from bytes 22..42 of a file \
         whose length fits its version's closed formula (v1: 22 + n*94 + 32; v2: 22 + n*178 + 32) and \
         nothing else, names the record's kind, and tells the operator to run `address 0x<tag>` on the \
         store in hand -- an answer means the same account is held in both (for a derived record one \
         master seed; for an imported one, one root, which says nothing about the master) and one WOTS+ \
         key stream can sign from each store; a refusal means that account is not held here, which does \
         not prove a different seed.\n\
         \n\
         v2 refusal as rendered:\n{v2_text}\n\nv1 refusal as rendered:\n{v1_text}",
        failures.len(),
        failures.join("\n  - ")
    );
}

// ---------------------------------------------------------------------------
// The three reports, on the values they carry
// ---------------------------------------------------------------------------

/// `open`'s stat gate and the parser's length gate name the same range for
/// the same refusal: `keystore image length`, minimum the empty store's
/// image (112), maximum the cap image (12,779,632). Driven with a snapshot
/// one byte over the cap: the
/// stat gate is the one that refuses it, before the file is read.
#[test]
fn the_image_length_range_names_one_minimum_at_both_gates() {
    let dir = ScratchDir::new("length-range");
    let ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut image = read_snapshot(&dir);
    image.resize(12_779_632 + 1, 0);
    dir.write_snapshot(&image);
    let err = keystore_harness::open(dir.path()).err();
    assert_eq!(
        err,
        Some(Error::Range {
            what: "keystore image length",
            min: 112,
            max: 12_779_632,
            got: 12_779_633,
        }),
        "the stat gate did not name the parser's range for an oversized snapshot: {err:?}"
    );
    println!("  image length: the stat gate names 112..=12779632, the parser's own range, for a 12779633-byte snapshot");
}

/// `Kdf::checked` names the parameter Argon2 refused, with that parameter's
/// bounds and value: memory below Argon2's floor of 8 KiB or above the
/// format's ceiling of 1 GiB, passes below 1, lanes outside 1..=16,777,215.
/// A `t_cost` of 0 is reported against passes and not as a memory problem,
/// and the ceiling refusal's minimum of 8 is Argon2's floor, enforced by the
/// second gate rather than the first.
#[test]
fn kdf_refusals_name_the_parameter_they_are_about() {
    let refused = |kdf: Kdf| kdf.checked().err();
    assert_eq!(
        refused(Kdf { m_cost_kib: 1_048_577, t_cost: 1, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf m_cost", min: 8, max: 1_048_576, got: 1_048_577 }),
        "the ceiling refusal"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 4, t_cost: 1, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf m_cost", min: 8, max: 1_048_576, got: 4 }),
        "memory below Argon2's floor"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 8, t_cost: 0, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf t_cost", min: 1, max: u64::from(u32::MAX), got: 0 }),
        "zero passes is a t_cost refusal, not a memory one"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 8, t_cost: 1, p_cost: 0 }),
        Some(Error::Range { what: "keystore kdf p_cost", min: 1, max: 0xFF_FFFF, got: 0 }),
        "zero lanes is a p_cost refusal"
    );
    assert_eq!(refused(Kdf::CHEAP_FOR_TESTS), None, "the cheap point is accepted");
    assert_eq!(refused(Kdf::RECOMMENDED), None, "the shipped point is accepted");
    println!("  kdf refusals: m_cost (ceiling and floor), t_cost and p_cost each named with their own bounds and value");
}

// ---------------------------------------------------------------------------
// A stale temp keeps no mode
// ---------------------------------------------------------------------------

/// A leftover `accounts.mks.tmp` with looser permissions does not reach the
/// snapshot. A mode passed at open applies only to a file being created,
/// so `write_temp`'s create+truncate kept a stale temp's 0644 and the
/// rename carried it onto the snapshot; `open` unlinked a leftover and
/// `create` did not. The temp is now unlinked before it is created, at the
/// one place every write goes through, so neither caller can forget. Read
/// back from disk, never assumed: the mode this asserts is the one `stat`
/// reports after the commit.
#[cfg(unix)]
#[test]
fn a_stale_temp_with_loose_permissions_does_not_reach_the_snapshot() {
    let dir = ScratchDir::new("stale-temp-mode");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let tmp = dir.path().join("accounts.mks.tmp");
    std::fs::write(&tmp, b"a leftover from an interrupted commit").unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let before = std::fs::metadata(&tmp).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(before, 0o644, "premise: the stale temp reads back as 0644 (a filesystem that honours mode bits)");

    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let snap = std::fs::metadata(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(
        snap,
        0o600,
        "THE SNAPSHOT INHERITED THE STALE TEMP'S MODE: accounts.mks reads back as {snap:o} after a \
         commit over a 0644 leftover"
    );
    assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "the temp outlived the commit");
    drop(ks);
    let reopened = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("the store written over the leftover does not open: {e}"));
    assert_eq!(reopened.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG]);
    println!("  stale temp: a 0644 leftover was unlinked before the commit; the snapshot reads back 0600");
}

// ---------------------------------------------------------------------------
// A derived record's identity is checked at the door
// ---------------------------------------------------------------------------

/// A derived account whose stored key-stream identity is not the one its
/// seed produces is refused at `add`, by the name `sign_spend` uses, when
/// the store holds the master it was derived from; and a derived account
/// from another master is refused as a tag the master does not reproduce.
/// The honest derived account and an imported account still add. Red with
/// the store-wide asymmetry restored (a fault row is the reversion), under
/// which the forged record added and was caught only at signing time.
#[test]
fn a_derived_record_with_a_forged_stream_identity_is_refused_at_add() {
    let master = Secret::new(IMPORTED_MASTER);
    let honest = derived_account_0_of_the_imported_master();
    let forged = match honest.to_record() {
        AccountRecord::Derived {
            tag,
            account_index,
            wots_index,
            ..
        } => Account::restore_from_record(AccountRecord::Derived {
            tag,
            account_index,
            stream_id: mochimo_crypto::account::StreamId::from_bytes([0x5Eu8; 20]),
            wots_index,
        })
        .unwrap_or_else(|e| panic!("a derived record restores without a master to check it: {e}")),
        other => panic!("the honest account is not a derived record: {other:?}"),
    };

    let dir = ScratchDir::new("forged-stream-at-add");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = ks.adopt_master(&master).unwrap_or_else(|e| panic!("{e}"));
    let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.add(forged).err(),
        Some(Error::StreamIdNotReproduced),
        "A DERIVED RECORD WITH A FORGED STREAM IDENTITY WAS ADDED to a store holding the master \
         that could have checked it"
    );
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), generation, "the refusal wrote");
    assert_eq!(
        ks.add(derived_account()).err(),
        Some(Error::DerivedTagNotReproduced { account_index: DERIVED_POSITION }),
        "a derived account from ANOTHER master was added to a store whose master does not derive it"
    );
    ks.add(derived_account_0_of_the_imported_master()).unwrap_or_else(|e| panic!("the honest derived account was refused: {e}"));
    let dir2 = ScratchDir::new("forged-stream-at-add-imported");
    let mut ks2 = keystore_harness::create(dir2.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = ks2.adopt_master(&Secret::new(keystore_harness::DERIVED_MASTER)).unwrap_or_else(|e| panic!("{e}"));
    ks2.add(imported_account()).unwrap_or_else(|e| panic!("an imported account was refused by the derived check: {e}"));
    ks2.add(derived_account()).unwrap_or_else(|e| panic!("the honest derived account was refused beside an imported one: {e}"));
    println!("  forged identity: refused at add by StreamIdNotReproduced; a foreign master's account by DerivedTagNotReproduced; honest accounts of both kinds add");
}

/// The sign-time check stays: a store holding no master cannot check a
/// derived record at `add`, and cannot sign for it either -- the stored
/// identity stands there -- and the day a master is in hand `key_at`
/// re-derives the identity and refuses the forged record by the same name.
#[test]
fn a_forged_derived_record_that_got_in_without_a_master_is_still_refused_at_signing_time() {
    let honest = derived_account_0_of_the_imported_master();
    let forged = match honest.to_record() {
        AccountRecord::Derived {
            tag,
            account_index,
            wots_index,
            ..
        } => Account::restore_from_record(AccountRecord::Derived {
            tag,
            account_index,
            stream_id: mochimo_crypto::account::StreamId::from_bytes([0x5Eu8; 20]),
            wots_index,
        })
        .unwrap_or_else(|e| panic!("{e}")),
        other => panic!("not a derived record: {other:?}"),
    };
    let dir = ScratchDir::new("forged-stream-no-master");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(forged).unwrap_or_else(|e| panic!("with no master in the store nothing can check the identity, and add refused: {e}"));
    let master = Secret::new(IMPORTED_MASTER);
    assert_eq!(
        ks.spend_addresses(&IMPORTED_TAG, &KeyAccess::Master(&master)).err(),
        Some(Error::StreamIdNotReproduced),
        "the forged record was acted on at signing time"
    );
    println!("  forged identity, no master at add: stored as carried, refused at signing time by StreamIdNotReproduced");
}

// ---------------------------------------------------------------------------
// Two refusals that say what to do
// ---------------------------------------------------------------------------

/// `Exists { what: "snapshot" }` renders with the next step -- a different
/// `--dir` for a new store, `restore --account N` into this one -- rather
/// than as a bare "already exists". The other `what`s keep the short form.
#[test]
fn an_existing_snapshot_is_refused_with_the_next_step() {
    let text = format!("{}", Error::Exists { what: "snapshot" });
    assert!(text.contains("use a different --dir"), "no next step for a new store: {text}");
    assert!(text.contains("restore --account N"), "no next step for an account in this store: {text}");
    assert!(text.contains("Nothing was changed"), "the refusal does not say nothing was changed: {text}");
    assert_eq!(format!("{}", Error::Exists { what: "account tag" }), "keystore: account tag already exists");
    println!("  existing snapshot: the refusal names a different --dir and restore --account N");
}

/// `WrongPassword` says it cannot tell a wrong password from a damaged file,
/// by design, and what to try -- the password, a backup, the phrase. One
/// variant for both on purpose (a decryption oracle otherwise); the remedy
/// is wording, and this pins it.
#[test]
fn a_store_that_does_not_decrypt_says_it_cannot_tell_why_and_what_to_try() {
    let text = format!("{}", Error::WrongPassword);
    assert!(text.contains("did not decrypt"), "{text}");
    assert!(text.contains("cannot tell you which, by design"), "the refusal does not say it cannot tell, by design: {text}");
    assert!(text.contains("What to try"), "the refusal names nothing to try: {text}");
    assert!(text.contains("create --from-phrase") && text.contains("restore --account N"), "the refusal does not name the recovery from the phrase: {text}");
    // The store still answers the variant, not a text: the pinned refusal
    // on a wrong password is the same value it always was.
    let dir = ScratchDir::new("wrong-password-text");
    let ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let err = Keystore::open(dir.path(), &keystore_harness::unlock_with(b"not-the-password-either")).err();
    assert_eq!(err, Some(Error::WrongPassword));
    println!("  wrong password: the refusal says by design and names three things to try; the variant is unchanged");
}
