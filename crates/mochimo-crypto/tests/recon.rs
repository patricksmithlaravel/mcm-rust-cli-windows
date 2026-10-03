#![cfg(all(feature = "native", not(miri)))]
//! Reconciliation: every divergence case driven against a scriptable
//! chain, the settle and re-sign policies, the acknowledgement gate, and the
//! restore scan's shape and bound. (This said *the settle and abandon
//! policies* for a session after `abandon_reservation` was removed, because
//! grepping the removed symbol did not find the removed concept -- grep for
//! the concept, not the symbol.)
//!
//! Gated as `spend.rs` is: `native` for the keystore and the derivation,
//! `not(miri)` for WOTS+ time and the filesystem. **What that removes from
//! the Miri claim:** the interpreter never walks this file's keystore round
//! trips or its `MeshClient` calls. Both are safe Rust over primitives
//! `walk_native` already walks and over `std::fs`, which Miri's isolation
//! forbids regardless; the codec paths these drive are the same ones
//! `tests/mesh.rs` drives under Miri with no filesystem.
//!
//! # Why the fake is a `Transport` and not a chain abstraction
//!
//! `MeshClient` is generic over [`Transport`] and the loopback tests in
//! `tests/mesh_http.rs` exercise the real one. Reconciliation's cases are
//! *chain states* — a tag at one address or another, an absent tag, an
//! unreachable node — and a fake is the only way to drive them
//! deterministically. Faking at the transport keeps the real `codec` and the
//! real `MeshClient` in every case, so a divergence test that passes is one
//! where the JSON was parsed by the shipping parser.
//!
//! # Where the numbers come from
//!
//! `F-address-widths` again (group F): its master seed, account index 0, its
//! recorded `account_tag`, and its recorded `wots_address` — the address of
//! the key at position 1. So the chain states these tests script are
//! TypeScript-emitted values wherever one exists.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/chain.rs"]
mod chain;

use chain::{access, addr_at, hexs, master, pos, tag1, Chain, ChainState, ADDRESS_AT_1, TAG};
use keystore_harness::{reopen, ScratchDir};
use mochimo_crypto::account::{Account, WotsIndex};
use mochimo_crypto::consts::{ADDR_TAG_LEN, MFEE};
use mochimo_crypto::keystore::{Disk, Figures, Keystore, Pending};
use mochimo_crypto::mesh::MeshClient;
use mochimo_crypto::recon::{
    self, AccountStatus, Cancel, ChainPosition, Diagnosis, Divergence, Expiry, Reservation,
    RestoreFailure, ScanScope, StoppedBy, DIVERGENCE_WINDOW, RECOVERY_CEILING,
};
use mochimo_crypto::tx::wire::Destination;
use mochimo_crypto::wallet::{OperatorAcknowledgement, Settlement, StartupRefusal, Wallet};
use mochimo_crypto::{addr, derive, Error};

/// A store holding `F-address-widths`' derived account 0, at position 0.
fn store(name: &str) -> (ScratchDir, Keystore) {
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

// ---------------------------------------------------------------------------
// The two derivations agree -- the second degree of freedom
// ---------------------------------------------------------------------------

/// `Keystore::address_at` and `recon::derived_address_at` reach the same
/// address by different routes: one through the store's `key_at` (the
/// derivation `sign_spend` uses), one from the master with no store at all.
/// If they could drift, a restore would place an account at an index its own
/// store would then disagree with.
///
/// Anchored on group F at position 1: the recorded `wots_address`.
#[test]
fn the_scan_and_the_store_derive_the_same_addresses() {
    let (_dir, ks) = store("recon-agree");
    let m = master();
    assert_eq!(
        ks.address_at(&TAG, pos(1), &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        ADDRESS_AT_1,
        "position 1 is not group F's recorded wots_address"
    );
    for i in 0..6 {
        assert_eq!(
            ks.address_at(&TAG, pos(i), &access(&m)).unwrap_or_else(|e| panic!("{e}")),
            addr_at(i),
            "the store and the scan disagree at position {i}"
        );
    }
    // Position 0 is the implicit first address: tag half equal to hash half.
    assert_eq!(addr_at(0), addr::from_implicit(&TAG));
}

// ---------------------------------------------------------------------------
// I5 -- the restore scan
// ---------------------------------------------------------------------------

/// Every position a scope names, walked at an **explicit** ceiling.
///
/// The property is that the scan stops **on the match** and not after a run
/// of misses, and that the bound is on the failing search alone. Neither
/// half needs the default ceiling, and neither can have it: this
/// loop runs one whole restore per position `i`, each scanning `0..=i`, so
/// it costs `n(n+1)/2` derivations. At the old default of 20 that was 210
/// derivations and about 0.3 s; at 10,000 it would be 50,005,000 and — at
/// the 44.4 ms a derivation costs in the debug profile `cargo test` builds —
/// about 616 hours. A test that does not finish is worse than a red one,
/// because a hang reads as a slow board. The scope is therefore named here,
/// and [`WALKED`] is what this property is about; what the DEFAULT ceiling
/// is, is pinned separately and without walking.
const WALKED: u32 = 20;

#[test]
fn the_restore_scan_stops_on_the_match_at_every_position_in_the_bound() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    for i in 0..WALKED {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(i), 1_000 + u64::from(i)))]);
        let client = MeshClient::new(chain);
        let found = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .unwrap_or_else(|e| panic!("position {i}: {e}"));
        assert_eq!(found.index, pos(i), "the scan found the wrong index for position {i}");
        assert_eq!(found.tag, TAG);
        assert_eq!(found.balance, 1_000 + u64::from(i));
        // One resolve, and the scan is local from there.
        assert_eq!(client.transport().calls(), 1, "position {i}: more than one query");
    }
}

/// Every failing path fails, and **none of them returns zero**. I5's clause
/// that restore never defaults to zero is unconditional, and zero is only
/// ever returned as a match like any other.
/// `NEVER` is an optimisation and not a second policy: it is never asked at
/// all, where a predicate that answers `false` is asked once per position, and
/// the two must reach the same index.
#[test]
fn a_cancel_that_never_fires_leaves_the_scan_exactly_as_it_was() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);

    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let found = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
        .expect("a scan nobody cancels must find the index");

    let never = || false;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let same =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&never))
            .expect("a predicate that never says stop must not stop the scan");

    assert_eq!(found.index, pos(3));
    assert_eq!(same.index, found.index, "the two forms of not cancelling disagree");
    assert_eq!(same.balance, found.balance);
    assert_eq!(same.tag, found.tag);
}

/// The chain here holds an address this bound DOES reach, so the only reason
/// the scan ends without an index is the cancel.
#[test]
fn a_cancel_that_fires_stops_the_scan_and_reports_that_nothing_was_decided() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let stop = || true;
    let err = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&stop))
        .expect_err("a cancel that fires must not return an index");

    match &err {
        RestoreFailure::CannotScan { cause, .. } => assert_eq!(
            *cause,
            Error::Cancelled,
            "a cancel was reported under another cause"
        ),
        other => panic!("{other:?}"),
    }

    // I4's message-quality clause, and the reason this arm exists at all: the
    // generic `CannotScan` sentence tells the reader to fix the cause and says
    // the scan could not run. For a cancel the reader IS the cause, and the
    // scan ran and was stopped.
    let text = err.to_string();
    assert!(text.contains("stopped before it found an index"), "{text}");
    assert!(!text.contains("fix the cause"), "a cancel is rendered as a fault: {text}");
    assert!(!text.contains("could not run"), "a cancel is rendered as a fault: {text}");
}

/// The two ways a walk ends without an index are OPPOSITE claims, and this is
/// the property that keeps them apart.
///
/// An exhausted bound says *no position this scan reached reproduces that
/// address*, which an operator acts on -- it is the shape of a wrong seed, a
/// wrong chain, or an account further along than the ceiling. A cancel says
/// nothing whatever was learned. Reporting the second as the first is how a
/// stopped scan teaches somebody their seed is wrong.
#[test]
fn a_cancelled_scan_is_never_reported_as_a_bound_that_found_nothing() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let mut alien = ADDRESS_AT_1;
    alien[ADDR_TAG_LEN] ^= 0x01;

    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let exhausted =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .expect_err("an address no index reproduces must fail");
    assert!(
        matches!(exhausted, RestoreFailure::NoIndexReproducesTheAddress { .. }),
        "{exhausted:?}"
    );

    let stop = || true;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let cancelled =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&stop))
            .expect_err("a cancel must fail");
    assert!(
        !matches!(cancelled, RestoreFailure::NoIndexReproducesTheAddress { .. }),
        "a cancelled scan was reported as an exhausted bound: {cancelled:?}"
    );
}

/// The predicate is asked once per position, and the walk ends where it says
/// rather than at the scope's end.
///
/// The address is placed at the LAST position the bound reaches, so a walk
/// that ignored the predicate would succeed and this test would fail by
/// returning an index rather than by counting wrong.
#[test]
fn the_cancel_is_asked_once_per_position_and_the_walk_ends_where_it_says() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALKED - 1), 5))]));

    let asked = std::cell::Cell::new(0u32);
    const STOP_AFTER: u32 = 4;
    let predicate = || {
        let n = asked.get();
        asked.set(n + 1);
        n >= STOP_AFTER
    };
    let err =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&predicate))
            .expect_err("the walk must stop before the position holding the address");

    assert!(
        matches!(err, RestoreFailure::CannotScan { cause: Error::Cancelled, .. }),
        "{err:?}"
    );
    assert_eq!(
        asked.get(),
        STOP_AFTER + 1,
        "the predicate is asked once per position, up to and including the one that says stop"
    );
}

/// The diagnostic walk is stoppable too, and the divergence is still
/// reported when it is stopped -- with its position uncharacterised rather
/// than with the report suppressed. Cancelling a diagnostic is not the same
/// act as cancelling a restore: a restore cancelled did nothing, and this ran
/// far enough to know the account diverges and not far enough to say where.
#[test]
fn a_cancelled_diagnostic_still_reports_the_divergence_it_had_already_found() {
    let (_d, ks) = store("recon-cancel-diagnostic");
    let m = master();
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let scope = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);

    let stop = || true;
    let d = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::when(&stop),
    )
    .expect_err("a diverged account must be reported whether or not the diagnostic finished");

    assert!(
        matches!(
            d,
            Divergence::IndexMismatch {
                found: ChainPosition::Unlocated { .. },
                ..
            }
        ),
        "{d:?}"
    );
}

/// The property the `failed_at` reshape exists for, and the one this commit
/// is really about: the record carries **what** stopped the walk, so the
/// report reads a cause instead of supplying one.
///
/// Before, `Unlocated` carried a position alone and both of its renderings
/// filled in the rest themselves -- *on a derivation error*, *deriving index
/// n failed*. That was true of every walk that could stop early when it was
/// written and false the moment one could be cancelled, and no renderer could
/// have been careful about it, because the distinction was not in what it was
/// handed.
#[test]
fn a_stopped_diagnostic_records_the_cause_rather_than_leaving_it_to_the_report() {
    let (_d, ks) = store("recon-stop-cause");
    let m = master();
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let scope = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);

    // (1) The control: a walk that reaches the scope's end records no stop.
    let finished = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    match &finished {
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { stopped, .. },
            ..
        } => assert_eq!(*stopped, None, "a walk that finished recorded a stop"),
        other => panic!("{other:?}"),
    }

    // (2) The same chain and the same scope, stopped: the cause is in the
    // record, and it is not the one the old rendering assumed.
    let stop = || true;
    let cancelled = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::when(&stop),
    )
    .expect_err("an alien address must diverge");
    match &cancelled {
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { stopped, .. },
            ..
        } => {
            let s = stopped.expect("a cancelled walk must record that it stopped");
            assert_eq!(s.by, StoppedBy::Cancelled, "a cancel was recorded as another cause");
        }
        other => panic!("{other:?}"),
    }

    // (3) And the words follow the record. `Derivation` is the only cause
    // this report may call a failure.
    let text = cancelled.to_string();
    assert!(!text.contains("deriving index"), "a cancel rendered as a fault: {text}");
    assert!(!text.contains("derivation error"), "a cancel rendered as a fault: {text}");
    assert!(
        text.contains("stopped at index"),
        "a stopped diagnostic does not say it stopped: {text}"
    );
}

#[test]
fn restore_fails_rather_than_assuming_zero_on_every_unavailable_path() {
    // (1) the chain cannot be reached
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    let err = recon::restore_account_index(&client, &master(), 0).expect_err("unreachable must fail");
    assert!(matches!(err, RestoreFailure::ChainUnreachable { .. }), "{err:?}");

    // (2) the ledger has no entry for the tag
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)]));
    let err = recon::restore_account_index(&client, &master(), 0).expect_err("absent must fail");
    assert!(matches!(err, RestoreFailure::TagUnresolved { .. }), "{err:?}");

    // (3) the tag resolves to an address no index reproduces: the bound is
    // walked in full and reported, and the answer is NOT "index zero". At an
    // explicit ceiling, because an exhausted walk at the default would cost
    // about 7 m 24 s in this profile; what is reported is the scope's
    // ceiling whatever it is, which is the property, and the default's own
    // value is pinned in `the_recovery_ceiling_is_the_extensions_own_number`.
    let mut alien = ADDRESS_AT_1;
    alien[ADDR_TAG_LEN] ^= 0x01;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(WALKED), &Cancel::NEVER)
        .expect_err("alien must fail");
    match err {
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => {
            assert_eq!(scanned, WALKED, "the bound reported is not the bound walked");
        }
        other => panic!("{other:?}"),
    }

    // (4) the control: with the address restored, the same call succeeds --
    // so the three failures above are the checks firing, not restore being
    // broken.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 7))]));
    assert_eq!(
        recon::restore_account_index(&client, &master(), 0)
            .unwrap_or_else(|e| panic!("{e}"))
            .index,
        pos(3)
    );
}

/// A position **past** a bound is not found, and the failure says so
/// without guessing. A failure here does NOT mean *"this seed does not own
/// this tag"*: the target it builds comes from the SAME master
/// it hands the scan, so the seed provably owns the tag and the account is
/// merely one position further along than the walk reaches. That is the one
/// cause a ceiling produces by construction; the other two (a foreign seed, a
/// foreign chain) are indistinguishable from it at this arm, which is why the
/// failure now names all three and prefers none, and why the remedy is a
/// higher ceiling and not a guess.
///
/// At [`WALKED`] and not at the default, for the reason that constant
/// carries: the boundary is a property of the walk at whatever ceiling it is
/// given, and an exhausted walk at 10,000 costs about 7 m 24 s here.
#[test]
fn a_position_past_the_bound_fails_rather_than_being_guessed_at() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let past = addr_at(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(past, 1))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER).expect_err("past the bound must fail");
    assert!(matches!(
        err,
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } if scanned == WALKED
    ));
    // And the last position INSIDE the bound is found, so the boundary is
    // where it is claimed to be and not one off.
    let last = addr_at(WALKED - 1);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(last, 1))]));
    assert_eq!(
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .unwrap_or_else(|e| panic!("{e}"))
            .index,
        pos(WALKED - 1)
    );
}

/// **The recovery ceiling is 10,000, and 10,000 is the extension's number**
/// -- pinned as a value, and as the words the operator reads, without
/// walking it.
///
/// # Why nothing here walks 10,000 positions
///
/// `derived_address_at` costs 44.4 ms in the debug profile `cargo test`
/// builds (measured on this machine, 60 samples; 1.58 ms in a release
/// build, 28x apart). An exhausted walk at the default is therefore about
/// 7 m 24 s on the board and about 15.8 s for an operator, and the board's
/// whole budget for this change was a minute. So the walk's mechanism is
/// exercised at ceilings of 20, 21, 30, 31, 60, 100, 101 and 5,001 by the
/// tests around this one, and what is pinned HERE is the default's value and
/// the rendering that value produces. **The gap that leaves, stated:**
/// nothing in this tree walks ten thousand positions end to end, so a
/// hypothetical clamp inside the walk that silently capped a large ceiling
/// would pass. That is a deliberate trade against a seven-minute test, not
/// an oversight.
///
/// The failure value is constructed rather than provoked, for the same
/// reason: its `scanned` field is `scope.ceiling` at the one site that
/// builds it (`restore_account_index_with`), which the bounded tests above
/// pin, and what this adds is that a `scanned` of 10,000 renders the
/// sentences an operator acts on.
#[test]
fn the_recovery_ceiling_is_the_extensions_own_number() {
    assert_eq!(
        RECOVERY_CEILING, 10_000,
        "the recovery ceiling is the bound the shipped browser extension walks for the same \
         quantity (MasterSeed.deriveWotsIndexFromWotsAddrHash, endIndex = 10000); it is not \
         BIP-44's 20, which bounds unused addresses and not spends already made"
    );
    assert_eq!(ScanScope::RESTORE.ceiling, RECOVERY_CEILING, "restore's default scope is not the recovery ceiling");
    assert_eq!(ScanScope::RESTORE.window, None, "restore has no local index to centre a window on");
    // The window did NOT move with it, which is what makes the module doc's
    // claim that they are two quantities a fact rather than an assertion.
    assert_eq!(DIVERGENCE_WINDOW, 20, "the divergence window moved; only the ceiling was raised");
    assert_ne!(RECOVERY_CEILING, DIVERGENCE_WINDOW, "the two bounds coincide again, and the claim they differ is back to being untestable");

    // What a failing restore at the default says, rendered from the value
    // the default produces.
    let text = format!(
        "{}",
        RestoreFailure::NoIndexReproducesTheAddress {
            tag: TAG,
            address: ADDRESS_AT_1,
            scanned: RECOVERY_CEILING,
        }
    );
    assert!(text.contains("none of key indices 0 through 9999"), "the default walk is not counted:\n{text}");
    assert!(text.contains("spent 10000 or more times"), "the far-along cause does not carry the default:\n{text}");
    assert!(text.contains("does not own this tag"), "the wrong-seed cause is not named:\n{text}");
    assert!(text.contains("another chain"), "the wrong-chain cause is not named:\n{text}");
    println!("  recovery ceiling: {RECOVERY_CEILING} (the extension's endIndex), divergence window {DIVERGENCE_WINDOW}, 0 positions walked to pin either");
}

/// **Hazard 2's decision, and the test that can tell which way it went**:
/// [`ScanScope::DIAGNOSTIC`]'s ceiling FOLLOWS [`RECOVERY_CEILING`].
///
/// A chain address one position past the window's high edge -- 71 above a
/// local of 50 -- is `Ahead 21`, because the ceiling reaches it. Pin the
/// diagnostic's ceiling at 20 and this
/// goes red on the first assertion; that is the whole point of the test.
///
/// The cost is stated because it is the cost of the decision: the window is
/// walked first (41 derivations), then the recovery range ascending with the
/// window's members skipped, so index 71 is reached after 30 more -- 72 in
/// all, about 3.2 s here. An account whose disagreement is INSIDE the window
/// pays 41 at worst and an account that reconciles pays none, which is why
/// the startup path for a healthy wallet did not move.
#[test]
fn the_diagnostics_ceiling_follows_the_recovery_ceiling() {
    assert_eq!(
        ScanScope::DIAGNOSTIC.ceiling, RECOVERY_CEILING,
        "the diagnostic's ceiling no longer follows the recovery ceiling; a store restored at a \
         far-along index would then be described as Unlocated by the wallet that placed it"
    );
    assert_eq!(ScanScope::DIAGNOSTIC.window, Some(DIVERGENCE_WINDOW));

    // One past the window's high edge, found through the ceiling.
    let div = diagnose("recon-hazard2-ahead", 50, 71, &ScanScope::DIAGNOSTIC);
    match &div {
        Divergence::IndexMismatch { found: ChainPosition::Ahead { index, gap }, .. } => {
            assert_eq!(*index, pos(71), "{div:?}");
            assert_eq!(*gap, 21, "{div:?}");
        }
        other => panic!("the default diagnostic did not reach index 71: {other:?}"),
    }
    // And it is describable rather than merely reached: the report names the
    // direction, which is what an Unlocated could not do.
    assert!(format!("{div}").contains("21 ahead of local"), "{div}");
    println!("  diagnostic ceiling: follows the recovery ceiling at {}, window {DIVERGENCE_WINDOW}; index 71 under a local of 50 is Ahead 21, not Unlocated", ScanScope::DIAGNOSTIC.ceiling);
}

// ---------------------------------------------------------------------------
// I4 -- reconciliation and the wallet gate
// ---------------------------------------------------------------------------

/// The healthy case: the chain holds the tag at the key the store would sign
/// with, so the wallet opens.
#[test]
fn a_wallet_opens_when_every_account_reconciles() {
    let (_dir, ks) = store("recon-ok");
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9_000))]));
    let m = master();
    let w = Wallet::open(ks, client, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.accounts().len(), 1);
    // By reference: `AccountStatus` is no longer `Copy` (its
    // outstanding arm carries a diagnosis that may hold an error).
    match &w.accounts()[0].1 {
        AccountStatus::InSync { index, balance, .. } => {
            assert_eq!(*index, WotsIndex::ZERO);
            assert_eq!(*balance, 9_000);
        }
        other => panic!("{other:?}"),
    }
}

/// Every refusal path the constructor has, each by its own variant. The
/// wallet is not constructed in any of them.
///
/// Four of the five go through `Wallet::open`; the unlocatable-address one
/// goes through the reconciler `open` calls, at a named ceiling, for the
/// reason written at that arm.
#[test]
fn the_wallet_refuses_to_open_on_every_unreconcilable_account() {
    let m = master();
    let mut refusals = 0usize;

    // local behind: the chain is at position 3, the store at 0
    let (_d1, ks) = store("recon-behind");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))])),
        Some(&m),
    )
    .expect_err("local behind must refuse");
    assert!(matches!(
        refusal.diverged[0],
        Divergence::IndexMismatch {
            found: ChainPosition::Ahead { gap: 3, .. },
            ..
        }
    ), "{:?}", refusal.diverged[0]);
    refusals += 1;

    // The chain holds an address no index reproduces. **Driven through the
    // reconciler at a named ceiling rather than through `Wallet::open`**,
    // and the reason is a number: `open` takes no scope -- it
    // is `ScanScope::DIAGNOSTIC` by construction -- and that ceiling is now
    // 10,000, so an address the walk cannot locate costs ten thousand
    // derivations, about 7 m 24 s in the profile `cargo test` builds. What
    // this arm claims is two things, and each is held where it costs
    // nothing: that an unlocatable address classifies as `Unlocated`, here,
    // through the same `reconcile_account_with` that `open` calls on every
    // account; and that `open` refuses on whatever the reconciler hands
    // back, which the four arms around this one show across four variants,
    // two of them `IndexMismatch`. What is NOT driven any more is the
    // composition -- `open` reaching an `Unlocated` end to end. That is the
    // ceiling's price, stated here rather than left to be discovered.
    let (_d2, ks) = store("recon-alien");
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let div = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &ScanScope::DIAGNOSTIC.with_ceiling(WALKED),
        &Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    assert!(matches!(
        div,
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { .. },
            ..
        }
    ), "{div:?}");
    refusals += 1;

    // the ledger has no entry for the tag
    let (_d3, ks) = store("recon-absent");
    let refusal3 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        Some(&m),
    )
    .expect_err("an absent tag must refuse");
    assert!(matches!(refusal3.diverged[0], Divergence::TagUnresolved { .. }));
    refusals += 1;

    // the chain cannot be reached
    let (_d4, ks) = store("recon-unreachable");
    let refusal4 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        Some(&m),
    )
    .expect_err("an unreachable chain must refuse");
    assert!(matches!(refusal4.diverged[0], Divergence::ChainUnreachable { .. }));
    refusals += 1;

    // a derived account with no master to derive it from
    let (_d5, ks) = store("recon-nomaster");
    let refusal5 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        None,
    )
    .expect_err("a derived account with no master must refuse");
    assert!(matches!(refusal5.diverged[0], Divergence::NoMasterForDerivedAccount { .. }));
    refusals += 1;

    assert_eq!(refusals, 5);
}

/// The refusal names **every** failing account, not the first. An operator
/// who fixes one and restarts into the next has been told the truth twice
/// and helped once.
#[test]
fn the_refusal_reports_every_failing_account_not_the_first() {
    let dir = ScratchDir::new("recon-many");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    // Account 1, NOT `imported_account()`: since format v2 the harness's imported
    // account IS `F-address-widths` -- the same account this file derives at
    // index 0 -- so adding both is refused on the tag and again on the key
    // stream. That refusal working is format v2's; a second account here needs a
    // second seed.
    ks.add(Account::derive(&master(), 1)).unwrap_or_else(|e| panic!("{e}"));
    let tag1 = derive::derive_account_tag(&master(), 1);
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(3), 1)),
            (tag1, ChainState::Absent),
        ])),
        Some(&m),
    )
    .expect_err("two bad accounts must refuse");
    assert_eq!(refusal.diverged.len(), 2, "only one account was reported");
    assert_eq!(refusal.accounts, 2);
}

/// **I4's message-quality clause, asserted as rendered text**.
/// A refusal that says only "state mismatch" satisfies the letter of the
/// invariant and manufactures the workaround it exists to prevent, so the
/// report must name what diverged, both indices, the gap and the action.
#[test]
fn the_divergence_report_names_what_diverged_by_how_much_and_what_to_do() {
    let (_dir, ks) = store("recon-message");
    let m = master();
    let refusal: StartupRefusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(4), 1))])),
        Some(&m),
    )
    .expect_err("must refuse");
    let text = format!("{refusal}");

    // what diverged: the account, and both addresses
    assert!(text.contains(&hexs(&TAG)), "no tag in the report:\n{text}");
    assert!(text.contains(&hexs(&addr_at(0))), "the local address is not printed");
    assert!(text.contains(&hexs(&addr_at(4))), "the chain's address is not printed");
    // both indices, and the size of the gap
    assert!(text.contains("local index 0"), "the local index is not named");
    assert!(text.contains("key at index 4"), "the chain's index is not named");
    assert!(text.contains("4 ahead of local"), "the gap is not stated");
    // the stream identity, so two stores on one seed can be compared
    let stream = hexs(
        Keystore::open(_dir.path(), &keystore_harness::unlock())
            .map(|k| *k.stream_id(&TAG).unwrap_or_else(|e| panic!("{e}")).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .as_slice(),
    );
    assert!(text.contains(&stream), "the key stream identity is not printed");
    // the action
    assert!(text.contains("ACTION:"), "no action is named");
    assert!(text.contains("Do NOT edit local state by hand"), "the action does not warn off hand edits");
    // Both causes an `Ahead` fits, neither preferred: this wallet's own
    // older state, or a second wallet on the seed. Asserting the first alone
    // and hedging only in the ACTION line is what this pins against.
    assert!(text.contains("SECOND WALLET"), "the ahead arm no longer names the second-wallet cause:\n{text}");
    assert!(text.contains("older copy"), "the ahead arm no longer names the older-local-state cause:\n{text}");
    // and the refusal explains itself rather than only refusing
    assert!(text.contains("WALLET WILL NOT START"), "the refusal does not say so");
    assert!(text.contains("three causes"), "the reason is not given");
    assert!(
        text.contains("Do not delete local state"),
        "the workaround I4's decision names is not warned against"
    );
}

/// The other direction: local **ahead** of the chain. The floor of 2 on I4's
/// marker is exactly this — a test that only builds the behind case passes
/// over the direction that means another instance is live.
#[test]
fn local_ahead_of_the_chain_refuses_and_says_which_direction() {
    let (dir, mut ks) = store("recon-ahead");
    // advance the store to 3 with no spend: local is now ahead of a chain
    // that still holds position 0.
    let _ = ks.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("recon ahead", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        Some(&m),
    )
    .expect_err("local ahead must refuse");
    let text = format!("{refusal}");
    assert!(matches!(
        refusal.diverged[0],
        Divergence::IndexMismatch {
            found: ChainPosition::Behind { gap: 3, .. },
            ..
        }
    ), "{:?}", refusal.diverged[0]);
    assert!(text.contains("3 BEHIND local"), "the direction is not stated:\n{text}");
    assert!(text.contains("advancing local state backwards is never a remedy"));
}

// ---------------------------------------------------------------------------
// The reservation states, settling, and re-signing
// ---------------------------------------------------------------------------

/// A store with a reservation open at position 0, and a wallet over a chain
/// that still holds the pre-spend address. The figures match the balance of
/// 5 its callers script, so the reservation reads live.
fn reserved(name: &str) -> (ScratchDir, Keystore) {
    let (dir, mut ks) = store(name);
    let _ = ks
        .persist_advance(&TAG, &[0xD1; 32], Figures { reserved_balance: 5, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

/// The live diagnosis `reserved()`'s reservation reads as, against the
/// balance of 5 its callers script.
fn live_at_five() -> Reservation {
    Reservation::Recorded(Diagnosis {
        figures: Figures { reserved_balance: 5, blk_to_live: 0 },
        balance_moved: false,
        balance_now: 5,
        expiry: Expiry::NoExpiry,
    })
}

/// A reservation with the chain still at the old address is `SpendOutstanding`
/// — not divergence. The wallet opens: a spend in flight is a known state.
#[test]
fn a_reservation_with_the_spend_not_landed_is_outstanding_not_divergence() {
    let (_dir, ks) = reserved("recon-outstanding");
    let m = master();
    let w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5))])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        w.accounts()[0].1,
        AccountStatus::SpendOutstanding { .. }
    ));
}

/// A reservation with the chain at the **change** key's address is
/// `SpendLanded`, and `settle_if_landed` clears it on that one observation.
#[test]
fn settling_takes_one_observation_of_the_change_address() {
    let (_dir, ks) = reserved("recon-settle");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    // Not landed yet: nothing is cleared, and the verdict rides with it.
    assert_eq!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::StillOutstanding {
            spent_index: WotsIndex::ZERO,
            reservation: live_at_five(),
        }
    );

    // The chain moves to the change key: one observation settles it.
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4));
    assert_eq!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled {
            spent_index: WotsIndex::ZERO,
            index: pos(1)
        }
    );
    // And the store agrees: no reservation, index 1 -- and, on the live
    // handle, the settled block RETAINED with its figures: the memory-side
    // observation of the settle transition.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1));
    assert!(v.pending.is_none());
    assert_eq!(
        v.settled,
        Some(Pending {
            spent_index: WotsIndex::ZERO,
            digest: [0xD1; 32],
            figures: Some(Figures { reserved_balance: 5, blk_to_live: 0 }),
        }),
        "memory: the settled block was not retained with its figures"
    );
}

/// **A settled block does not block the next spend, and the next spend
/// overwrites it** -- the wallet-layer detector for
/// the freeze the settle rule called the unbounded direction: `persist_advance`
/// refuses on an open reservation alone, so after a settle the account plans
/// and reserves again, and the new reservation is what releases the block.
#[test]
fn a_settled_block_does_not_block_the_next_spend_and_is_overwritten_by_it() {
    let (_dir, ks) = store("recon-freeze");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination {
        tag: [0x6b; ADDR_TAG_LEN],
        reference: [0; 16],
        amount: 1_000_000,
    }];
    let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("plan: {e}"));
    let first = plan.figures();
    let _signed = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4_000_000));
    assert!(matches!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled { .. }
    ));
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.pending, None);
    assert_eq!(v.settled.map(|s| s.figures), Some(Some(first)), "the settle did not retain the block with the plan's figures");

    // The next spend is NOT refused.
    let plan2 = w
        .plan(&TAG, &access(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next spend: {e} (the freeze the retained block must not cause)"));
    let _signed2 = w
        .reserve_and_sign(&plan2, access(&m))
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next reservation: {e}"));
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(2));
    assert_eq!(
        v.pending.map(|p| (p.spent_index, p.figures)),
        Some((pos(1), Some(plan2.figures()))),
        "the second reservation is not at index 1 with the second plan's figures"
    );
    assert_eq!(v.settled, None, "the new reservation did not release the retained block");
    println!("  settled block: spend, settle, spend again -- the second reservation overwrote the retained block");
}

/// **A reverted settle is reported `Behind` with the retained block, and
/// every cause that fits**: the consumer the retained
/// block was kept for, in the same session it landed.
///
/// The main arm settles on one observation, then meets a chain back at the
/// spent address: `Behind { index: 0, gap: 1 }` carrying the block, and a
/// report that names the digest and both figures, both causes (a reorg; a
/// settle against a node that does not share this chain, so the spend may
/// yet land) and neither preferred, keeps *wait ... reconcile
/// again* as the first action, and prints both halves of what is true of the
/// bytes: still acceptable while the balance has not moved and the
/// block-to-live has not passed, and no command in this build turns the block
/// back into them. The store is reopened FROM DISK before the divergent
/// open, so an encoder that dropped the block's figures reaches this test.
/// Three controls: a `Behind` with no retained block; a retained block with
/// the chain AHEAD; and a retained block at an index OTHER than the one the
/// chain sits at (advanced to 1, reserved at 1, settled, chain at 0) -- each
/// carries `reverted_settle: None` and none of the new sentences.
#[test]
fn a_reverted_settle_is_reported_behind_with_the_retained_block_and_every_cause() {
    const SENTENCES: [&str; 4] = ["recorded a SETTLE", "may yet land", "NO COMMAND", "Keep any copy"];
    let m = master();
    let dsts = || {
        vec![Destination {
            tag: [0x6b; ADDR_TAG_LEN],
            reference: [0; 16],
            amount: 1_000_000,
        }]
    };
    // Reserve at the store's index with block-to-live 4242 and settle on one
    // observation of the change key; hand back what was reserved.
    let reserve_and_settle = |w: &mut Wallet<Disk, Chain>, at: u32| -> Pending {
        w.client().transport().set_tip(4_241);
        let plan = w.plan(&TAG, &access(&m), dsts(), MFEE, 4_242).unwrap_or_else(|e| panic!("plan: {e}"));
        let block = Pending {
            spent_index: pos(at),
            digest: plan.digest(),
            figures: Some(plan.figures()),
        };
        let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
        w.client().transport().set(TAG, ChainState::At(addr_at(at + 1), 4_000_000));
        assert!(matches!(w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")), Settlement::Settled { .. }));
        block
    };

    // The main arm.
    let (dir, ks) = store("recon-reverted");
    let mut w = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let block = reserve_and_settle(&mut w, 0);
    drop(w);
    let ks = reopen("recon reverted", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .expect_err("a reverted settle must refuse");
    match &refusal.diverged[0] {
        Divergence::IndexMismatch {
            found: ChainPosition::Behind { index, gap },
            reverted_settle,
            ..
        } => {
            assert_eq!((index.get(), *gap), (0, 1));
            assert_eq!(*reverted_settle, Some(block), "the retained block is not on the report");
        }
        other => panic!("not a Behind with the retained block: {other:?}"),
    }
    let text = format!("{refusal}");
    let digest_hex = hexs(&block.digest);
    for needle in [
        "recorded a SETTLE at index 0",
        digest_hex.as_str(),
        "reserved balance 5000000 nanoMCM, block-to-live 4242",
        "reorg",
        "does not share this chain",
        "may yet land",
        "only one key 0 may ever give",
        "NO COMMAND",
        "Keep any copy",
        "wait for the spend to land and reconcile again",
        "1 BEHIND local",
    ] {
        assert!(text.contains(needle), "the reverted-settle report does not say {needle:?}:\n{text}");
    }

    // Control 1: a Behind with no retained block.
    let (d1, mut ks1) = store("recon-reverted-none");
    let _ = ks1.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks1);
    let ks1 = reopen("recon reverted none", d1.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r1 = Wallet::open(ks1, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), Some(&m))
        .expect_err("local ahead must refuse");
    assert!(matches!(
        r1.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 3, .. }, reverted_settle: None, .. }
    ), "{:?}", r1.diverged[0]);
    let t1 = format!("{r1}");
    for s in SENTENCES {
        assert!(!t1.contains(s), "control 1 (no retained block) says {s:?}:\n{t1}");
    }

    // Control 2: a retained block with the chain AHEAD.
    let (d2, ks2) = store("recon-reverted-ahead");
    let mut w2 = Wallet::open(ks2, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = reserve_and_settle(&mut w2, 0);
    drop(w2);
    let ks2 = reopen("recon reverted ahead", d2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = Wallet::open(ks2, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 1))])), Some(&m))
        .expect_err("chain ahead must refuse");
    assert!(matches!(
        r2.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 4, .. }, reverted_settle: None, .. }
    ), "{:?}", r2.diverged[0]);
    let t2 = format!("{r2}");
    for s in SENTENCES {
        assert!(!t2.contains(s), "control 2 (chain ahead of a retained block) says {s:?}:\n{t2}");
    }

    // Control 3: a retained block at index 1, the chain back at index 0 --
    // a Behind by two, not the block's index.
    let (d3, mut ks3) = store("recon-reverted-other-index");
    let _ = ks3.persist_advance_to(&TAG, pos(1)).unwrap_or_else(|e| panic!("{e}"));
    let mut w3 = Wallet::open(ks3, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(1), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let block3 = reserve_and_settle(&mut w3, 1);
    assert_eq!(block3.spent_index, pos(1));
    drop(w3);
    let ks3 = reopen("recon reverted other", d3.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = Wallet::open(ks3, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .expect_err("chain two behind must refuse");
    assert!(matches!(
        r3.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 2, .. }, reverted_settle: None, .. }
    ), "the retained block at index 1 was reported for a chain at index 0: {:?}", r3.diverged[0]);
    let t3 = format!("{r3}");
    for s in SENTENCES {
        assert!(!t3.contains(s), "control 3 (retained block at another index) says {s:?}:\n{t3}");
    }
    println!("  reverted settle: Behind by one carries the retained block, its digest and both figures, both causes, both halves; three controls carry none");
}

/// **A reservation is dead when the balance moved or the tip reached the
/// block-to-live** (the diagnosis once filed as debt) --
/// at the wallet layer, each reservation made through `plan` and
/// `reserve_and_sign` so `SpendPlan::balance()` and `figures()` are on the
/// path. The scenarios mirror the CLI marker's and add three: E, an
/// unreadable tip, which is neither dead nor asserted live; H, dead by both
/// causes; and the call counts F/G -- one chain read after `open` for a
/// zero block-to-live, two for a recorded non-zero one -- read immediately
/// after `Wallet::open` and before `settle_if_landed`.
#[test]
fn a_reservation_is_dead_when_the_balance_moved_or_the_tip_reached_the_block_to_live() {
    let m = master();
    // A store with a reservation made through the wallet at `btl`, against a
    // chain holding 5,000,000 at the spent address.
    let reserve = |name: &str, btl: u64| -> ScratchDir {
        let (dir, ks) = store(name);
        let mut w = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
            .unwrap_or_else(|e| panic!("{e}"));
        let plan = w
            .plan(&TAG, &access(&m), vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }], MFEE, btl)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        if btl != 0 {
            w.client().transport().set_tip(btl - 1);
        }
        assert_eq!(plan.figures(), Figures { reserved_balance: 5_000_000, blk_to_live: btl });
        let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("{e}"));
        dir
    };
    struct Case {
        name: &'static str,
        btl: u64,
        balance_after: u64,
        tip_after: Option<u64>,
        dead: bool,
        calls_after_open: usize,
    }
    let cases = [
        Case { name: "A", btl: 0, balance_after: 6_000_000, tip_after: Some(100), dead: true, calls_after_open: 1 },
        Case { name: "B", btl: 4_242, balance_after: 5_000_000, tip_after: Some(4_242), dead: true, calls_after_open: 2 },
        Case { name: "C", btl: 0, balance_after: 5_000_000, tip_after: Some(100), dead: false, calls_after_open: 1 },
        Case { name: "D", btl: 4_242, balance_after: 5_000_000, tip_after: Some(4_241), dead: false, calls_after_open: 2 },
        Case { name: "E", btl: 4_242, balance_after: 5_000_000, tip_after: None, dead: false, calls_after_open: 2 },
        Case { name: "H", btl: 4_242, balance_after: 6_000_000, tip_after: Some(4_242), dead: true, calls_after_open: 2 },
    ];
    let mut driven = 0usize;
    for c in &cases {
        let dir = reserve(&format!("recon-dead-{}", c.name), c.btl);
        let ks = reopen("recon dead", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), c.balance_after))]);
        if let Some(tip) = c.tip_after {
            chain.set_tip(tip);
        }
        let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{}: a dead reservation is still an Ok state, and open refused: {e}", c.name));
        assert_eq!(w.client().transport().calls(), c.calls_after_open, "{}: chain calls after open", c.name);
        let AccountStatus::SpendOutstanding { reservation, .. } = &w.accounts()[0].1 else {
            panic!("{}: not outstanding: {:?}", c.name, w.accounts()[0].1)
        };
        let Reservation::Recorded(d) = reservation else { panic!("{}: figures not recorded", c.name) };
        let d = d.clone();
        assert_eq!(d.figures, Figures { reserved_balance: 5_000_000, blk_to_live: c.btl }, "{}", c.name);
        assert_eq!(d.balance_moved, c.balance_after != 5_000_000, "{}: balance_moved", c.name);
        assert_eq!(d.balance_now, c.balance_after, "{}", c.name);
        let expected_expiry = match (c.btl, c.tip_after) {
            (0, _) => Expiry::NoExpiry,
            (btl, Some(tip)) if tip >= btl => Expiry::Reached { tip },
            (_, Some(tip)) => Expiry::Below { tip },
            (_, None) => match &d.expiry {
                // The cause is the fake's own refusal; what is asserted is the arm.
                Expiry::Unreadable { cause } => Expiry::Unreadable { cause: cause.clone() },
                other => panic!("{}: an unreadable tip was read as {other:?}", c.name),
            },
        };
        assert_eq!(d.expiry, expected_expiry, "{}: expiry", c.name);
        assert_eq!(d.is_dead(), c.dead, "{}: is_dead", c.name);
        // settle carries the same verdict and moves nothing.
        match w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{}: {e}", c.name)) {
            Settlement::StillOutstanding { spent_index, reservation } => {
                assert_eq!(spent_index, WotsIndex::ZERO);
                assert_eq!(reservation, Reservation::Recorded(d), "{}: settle's verdict differs from open's", c.name);
            }
            other => panic!("{}: settle did something with a reservation the chain never confirmed: {other:?}", c.name),
        }
        let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert!(v.wots_index == pos(1) && v.pending.is_some(), "{}: settle moved the store", c.name);
        driven += 1;
    }
    assert_eq!(driven, 6);
    println!("  dead reservations: 6 scenarios -- moved balance, tip reached, two live controls, an unreadable tip, both causes -- classified from the store and the chain alone");
}

/// **A migrated reservation declines to classify**:
/// the captured version-3 reservation opens through the wallet as
/// `SpendOutstanding` with `Reservation::Unrecorded` -- neither live nor
/// dead -- makes no tip read, and `settle_if_landed` neither settles nor
/// writes, so the store stays version 3 on disk.
#[test]
fn a_migrated_reservation_declines_to_classify() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    let m = master();
    let dir = ScratchDir::new("recon-migrated");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    dir.write_snapshot(IMAGE);
    let ks = reopen("recon migrated", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(&w.accounts()[0].1, AccountStatus::SpendOutstanding { reservation: Reservation::Unrecorded, .. }),
        "a version-3 reservation was classified: {:?}",
        w.accounts()[0].1
    );
    assert_eq!(w.client().transport().calls(), 1, "an unrecorded expiry must not read the tip");
    assert!(matches!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::StillOutstanding { reservation: Reservation::Unrecorded, .. }
    ));
    assert_eq!(w.store().upgraded_from(), None, "settle wrote when nothing settled");
    drop(w);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "the version-3 store moved on disk under read-only commands");
    println!("  migrated reservation: outstanding, unclassified, one chain read, nothing written");
}

/// **The recovery for a lost retry artifact, and the reason it has to
/// exist** (as corrected by the audit that retired `abandon_reservation`).
///
/// The audit that found this drove the whole consequence chain: reserve at
/// index 0 with the funds at address(0), lose the artifact, and the index is
/// at 1 while the chain is still at address(0). The balance there is
/// reachable only by the key at 0, the index cannot roll back to it, and
/// `plan` refuses `ChainAddressMismatch`. So a signature from that key is the
/// only way those funds ever move, and with the artifact gone
/// `resign_pending` is the only way to that signature.
///
/// What this asserts:
///  * the rebuilt bytes are **byte-identical** to the ones that were lost —
///    WOTS+ determinism, which is what makes this one
///    signature produced twice rather than two signatures under one key;
///  * a plan that does **not** hash to the reserved digest is refused, which
///    is the property that keeps it from being a second-signature route;
///  * it needs no receipt and persists nothing.
#[test]
fn resigning_a_reservation_reproduces_the_lost_artifact_byte_for_byte() {
    let (_dir, ks) = store("recon-resign");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let dsts = vec![Destination {
        tag: [0x6b; ADDR_TAG_LEN],
        reference: [0; 16],
        amount: 1_000_000,
    }];
    let plan = w
        .plan(&TAG, &access(&m), dsts.clone(), MFEE, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let original = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    let lost = original.wire().to_vec();
    drop(original); // the artifact is lost

    // The recovery: the same parameters a human remembers, nothing else.
    let recovered = w
        .resign_pending(&TAG, &access(&m), dsts.clone(), MFEE, 0)
        .unwrap_or_else(|e| panic!("resign_pending: {e}"));
    assert_eq!(
        recovered.wire(),
        &lost[..],
        "the recovered artifact is not byte-identical to the lost one; the whole safety \
         argument is that this is ONE signature produced twice"
    );

    // It persisted nothing and needed no receipt: the reservation is still
    // open and the index has not moved.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1));
    assert_eq!(v.pending.map(|p| p.spent_index), Some(WotsIndex::ZERO));

    // And it is idempotent -- a third call is the same bytes again.
    let again = w
        .resign_pending(&TAG, &access(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(again.wire(), &lost[..]);
}

/// A plan that is not the reserved one is refused. This is the check that
/// keeps `resign_pending` from being a second-signature route: the digest is
/// not a parameter, and a rebuilt plan that hashes to anything else cannot
/// borrow the reserved key.
#[test]
fn resigning_refuses_a_plan_that_is_not_the_reserved_one() {
    let (_dir, ks) = store("recon-resign-wrong");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let plan = w
        .plan(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }],
            MFEE,
            0,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("{e}"));

    // A different AMOUNT -- everything else identical.
    assert!(
        matches!(
            w.resign_pending(
                &TAG,
                &access(&m),
                vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 2_000_000 }],
                MFEE,
                0,
            ),
            Err(Error::DigestMismatch)
        ),
        "a spend that was never reserved borrowed the reserved key"
    );
    // A different DESTINATION.
    assert!(matches!(
        w.resign_pending(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6c; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }],
            MFEE,
            0,
        ),
        Err(Error::DigestMismatch)
    ));
    // And with nothing reserved at all.
    let (_d2, ks2) = store("recon-resign-none");
    let chain2 = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w2 = Wallet::open(ks2, MeshClient::new(chain2), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        w2.resign_pending(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1 }],
            MFEE,
            0,
        ),
        Err(Error::NothingPending)
    ));
}

/// A reservation with the chain at neither address is divergence, not a
/// spend state: something moved this tag that this wallet did not.
#[test]
fn a_reservation_with_the_chain_at_neither_address_is_divergence() {
    let (_dir, ks) = reserved("recon-unexplained");
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 5))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(matches!(refusal.diverged[0], Divergence::ReservationUnexplained { .. }));
    let text = format!("{refusal}");
    assert!(text.contains("Compare the key stream"), "no action:\n{text}");
    // The position is rendered, not `{:?}`: reserved at 0, so the window
    // is centred on the change index 1, and the chain at 5 is 4 ahead of it.
    assert!(
        text.contains("the chain's address IS this seed's key at index 5 -- 4 ahead of local"),
        "the reservation report does not render where the chain's address sits:\n{text}"
    );
    assert!(!text.contains("Ahead {"), "the reservation report renders the derived Debug:\n{text}");
}

/// **The node's "account not found" is not the ledger's absence, and neither
/// site says it is** (`recon`'s module doc, fact 3).
///
/// For two minutes after the first live recovery's transaction landed, the
/// node answered code 4 for every tag on the chain -- the destination that
/// had just been paid included -- and the reference explains why it can:
/// `callHandler` maps any lookup error to `ErrAccountNotFound`, and
/// `QueryTagResolve` discards zero-amount answers and errors below quorum.
/// Both sites read that answer as the ledger's absence and reasoned from
/// fact 1 to *never funded*; restore's ACTION told the operator to create
/// the account rather than restore it. The reasoning was sound and the
/// premise was never examined. Both texts now name the three readings and
/// prefer none, and neither carries the sentence that asserted one.
#[test]
fn a_node_that_does_not_resolve_a_tag_is_not_reported_as_never_funded() {
    let m = master();

    // The reconcile site, through the wallet's refusal.
    let (_d, ks) = store("recon-unresolved");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        Some(&m),
    )
    .expect_err("an unresolved tag must refuse");
    assert!(
        matches!(refusal.diverged[0], Divergence::TagUnresolved { local: WotsIndex::ZERO, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    let text = format!("{refusal}");
    for needle in ["did not resolve this tag", "ZERO balance", "lookup itself failed", "ask again"] {
        assert!(text.contains(needle), "the refusal does not carry {needle:?}:\n{text}");
    }
    for stale in ["NEVER been funded", "absence means", "create it rather than"] {
        assert!(
            !text.contains(stale),
            "the refusal still asserts {stale:?} -- the node's answer is read as the ledger's \
             absence:\n{text}"
        );
    }

    // The restore site.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)]));
    let err = recon::restore_account_index(&client, &m, 0).expect_err("an unresolved tag must fail");
    assert!(matches!(err, RestoreFailure::TagUnresolved { tag: TAG }), "{err:?}");
    let text = format!("{err}");
    for needle in ["did not resolve this tag", "ZERO balance", "lookup itself failed", "ask again", "not at 0"] {
        assert!(text.contains(needle), "restore's failure does not carry {needle:?}:\n{text}");
    }
    for stale in ["so it has never been funded", "create it rather than restoring it"] {
        assert!(!text.contains(stale), "restore's failure still says {stale:?}:\n{text}");
    }
}

/// The `Ahead` arm excludes the crash cause at every gap, in a sentence that
/// is true at every gap (the live recovery's finding 3).
///
/// A sentence like *"a gap of more than one cannot be a crash between signing
/// and saving"*, printed unconditionally, excludes the cause for gaps the
/// report is not about and says nothing about the gap in front of the
/// operator -- at gap 1 above all. The property that holds is stronger and
/// gap-independent: I2 writes
/// the index and its reservation durably before a signature exists, so a
/// spend interrupted after signing is reported through the reservation arms
/// (`SpendOutstanding`, `SpendLanded`, `ReservationUnexplained`), never as an
/// `IndexMismatch`. Pinned at gap 1 and gap 3 so a gap-conditional wording
/// cannot come back.
#[test]
fn the_ahead_arm_excludes_the_crash_cause_at_every_gap() {
    let one = diagnose("recon-ahead-gap1", 0, 1, &ScanScope::DIAGNOSTIC);
    let three = diagnose("recon-ahead-gap3", 0, 3, &ScanScope::DIAGNOSTIC);
    for (d, gap) in [(&one, 1u32), (&three, 3)] {
        assert!(
            matches!(d, Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: g, .. }, .. } if *g == gap),
            "{d:?}"
        );
        let text = format!("{d}");
        assert!(
            text.contains("cannot leave this state at any gap"),
            "gap {gap}: the crash cause is not excluded:\n{text}"
        );
        assert!(
            !text.contains("more than one cannot be a crash"),
            "gap {gap}: the gap-conditional sentence is back, and at gap 1 it is irrelevant:\n{text}"
        );
    }
}

/// A divergence report names the balance at stake (the live recovery's
/// finding 2): an operator deciding whether to advance past a mismatch, or
/// what moved a reserved tag, could not see the amount until after acting.
/// Two accounts, two distinct non-zero balances, so a constant cannot pass.
#[test]
fn a_divergence_report_names_the_balance_at_stake() {
    let m = master();
    let (_d1, ks) = store("recon-balance-mismatch");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 123_456))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(
        matches!(refusal.diverged[0], Divergence::IndexMismatch { balance: 123_456, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    let text = format!("{refusal}");
    assert!(
        text.contains("123456 nanoMCM"),
        "the index-mismatch report does not name the balance at stake:\n{text}"
    );

    let (_d2, ks2) = reserved("recon-balance-reservation");
    let refusal2 = Wallet::open(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 654_321))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(
        matches!(refusal2.diverged[0], Divergence::ReservationUnexplained { balance: 654_321, .. }),
        "{:?}",
        refusal2.diverged[0]
    );
    let text2 = format!("{refusal2}");
    assert!(
        text2.contains("654321 nanoMCM"),
        "the reservation report does not name the balance at stake:\n{text2}"
    );
}

// ---------------------------------------------------------------------------
// The divergence window, the raised ceiling, and the verified index
// ---------------------------------------------------------------------------

/// A store holding `F-address-widths`' derived account 0 at position `local`,
/// reopened, so the diagnostic reads the index off disk as the wallet would.
fn store_at(name: &str, local: u32) -> (ScratchDir, Keystore) {
    let (dir, mut ks) = store(name);
    if local > 0 {
        let _ = ks.persist_advance_to(&TAG, pos(local)).unwrap_or_else(|e| panic!("{e}"));
    }
    drop(ks);
    let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

/// The diagnostic against a chain holding the tag at `chain`, for a store at
/// `local`, under `scope`.
fn diagnose(name: &str, local: u32, chain: u32, scope: &ScanScope) -> Divergence {
    let (_dir, ks) = store_at(name, local);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(chain), 1))]));
    recon::reconcile_account_with(&ks, &client, &TAG, &access(&master()), scope, &Cancel::NEVER)
        .expect_err("local and chain differ, so this must be a divergence")
}

/// **The diagnostic is a window around the local index, not a walk from
/// zero**. Once `locate` walked `0..20` absolute and
/// passed `local` only to the ahead/behind comparison, so a store at 22 whose
/// chain sat at 24 -- a gap of two, I4's two-instance case -- was reported as
/// *this seed does not own this tag*.
///
/// Both edges of the window are pinned in both directions (the low edge is
/// the one a one-sided window passes), the recovery range is shown to be
/// unioned in (a chain at 3 under a store at 50 is `Behind`, not unlocated),
/// and the unlocated text is read as rendered: it names what was walked and
/// all three causes, and asserts neither of the two the old text preferred.
///
/// # Two scopes, because the window is not observable from the default alone
///
/// At a ceiling of 20, one past the window's edge -- 71 above a local of 50
/// -- falls outside the recovery range too, so a single scope pins the edge.
/// The ceiling is 10,000: 71 is inside it, the union finds it, and the edge
/// is invisible from the default scope. So the edges are pinned
/// under `w`, the window with its ceiling set to **zero**, where what is
/// found is found by the window and nothing else; and the union is driven
/// under `d`, the window over a ceiling of [`WALKED`], which is the shape
/// the default carried before. The default's own reach past the window is
/// `the_diagnostics_ceiling_follows_the_recovery_ceiling`, which is the test
/// that can tell which way that decision went.
#[test]
fn the_divergence_diagnostic_is_a_window_around_local_not_a_walk_from_zero() {
    assert_eq!(DIVERGENCE_WINDOW, 20, "the cases below are written for a window of 20");
    assert_eq!(RECOVERY_CEILING, 10_000, "the ceiling moved; the union cases below assume the old 20 explicitly");
    let w = &ScanScope::DIAGNOSTIC.with_ceiling(0);
    let d = &ScanScope::DIAGNOSTIC.with_ceiling(WALKED);
    let cases: [(u32, u32, &str, &ScanScope); 11] = [
        (22, 24, "ahead 2", d),   // the case the brief is about
        (22, 20, "behind 2", d),
        (50, 70, "ahead 20", w),  // the window's high edge, inside -- the window alone
        (50, 71, "unlocated", w), // one past it, with no ceiling behind it to rescue it
        (50, 30, "behind 20", w), // the window's low edge, inside
        (50, 29, "unlocated", w), // one below it
        (50, 71, "unlocated", d), // one past the high edge and past a ceiling of 20 too
        (50, 29, "unlocated", d), // and 29 is not in 0..20 either
        (50, 3, "behind 47", d),  // found through the recovery range, not the window
        (50, 19, "behind 31", d), // the recovery range's last position
        (0, 2, "ahead 2", d),     // the control every earlier test already drives
    ];
    let mut walked = 0usize;
    for (i, (local, chain, expect, scope)) in cases.iter().enumerate() {
        let div = diagnose(&format!("recon-window-{i}"), *local, *chain, scope);
        let Divergence::IndexMismatch { found, .. } = &div else {
            panic!("case {i}: not an index mismatch: {div:?}");
        };
        let got = match found {
            ChainPosition::Ahead { gap, .. } => format!("ahead {gap}"),
            ChainPosition::Behind { gap, .. } => format!("behind {gap}"),
            ChainPosition::Unlocated { .. } => "unlocated".to_string(),
        };
        assert_eq!(&got, expect, "case {i}: local {local}, chain {chain}: {div:?}");
        walked += 1;
    }
    assert_eq!(walked, cases.len());

    // The unlocated text, as rendered: what was walked, the three
    // causes, the remedy -- and NOT the closed disjunction it replaced.
    let text = format!("{}", diagnose("recon-window-text", 50, 71, d));
    // `d`'s ceiling is 20 here; the default's own render of the same arm
    // would need an exhausted 10,000-position walk, about 7 m 24 s in this
    // profile.
    assert!(text.contains("indices 30 through 70, 20 either side of index 50"), "the window is not named:\n{text}");
    assert!(text.contains("indices 0 through 19"), "the recovery range is not named:\n{text}");
    assert!(text.contains("Three things produce that"), "the three causes are not named:\n{text}");
    assert!(text.contains("second wallet"), "the second-wallet cause is missing:\n{text}");
    assert!(text.contains("raising the scan ceiling"), "the remedy is not named:\n{text}");
    assert!(text.contains("confirm no second wallet holds this seed"), "the two-instance warning is missing:\n{text}");
    assert!(!text.contains("does not own this tag, or"), "the closed disjunction is back:\n{text}");
    assert!(!text.contains("not 'further along"), "the denial is back:\n{text}");
    // And the Behind arm reached through the recovery range names the
    // wrong-node cause, which a gap of 47 makes the likeliest.
    let behind = format!("{}", diagnose("recon-window-behind", 50, 3, d));
    assert!(behind.contains("47 BEHIND local"), "{behind}");
    assert!(behind.contains("spent fewer times"), "the behind arm does not name the wrong-node cause:\n{behind}");

    // A raised ceiling reaches what the window does not: 100 is found under a
    // ceiling of 101 and not under a ceiling of 100 (half-open, like restore's).
    match diagnose("recon-window-raised", 50, 100, &d.with_ceiling(101)) {
        Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 50, .. }, .. } => {}
        other => panic!("a ceiling of 101 did not find index 100: {other:?}"),
    }
    assert!(matches!(
        diagnose("recon-window-raised-edge", 50, 100, &d.with_ceiling(100)),
        Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }
    ), "a ceiling of 100 walked index 100; the ceiling is not half-open");
    println!("  divergence window: {walked} placement(s) diagnosed around the local index");
}

/// **An operator-named index is verified, never trusted**.
/// The number raises the walk's ceiling; the acknowledgement is built from
/// what the walk FOUND, so naming 99 when the chain is at 100 yields no
/// acknowledgement and writes nothing, naming 5000 yields an acknowledgement
/// for 100 and not for 5000, and naming an index the chain confirms below
/// local yields a `Behind` that nothing advances past. Only the confirmed
/// index moves the store, and afterwards the account reconciles.
#[test]
fn an_operator_named_index_is_verified_against_the_chain_never_trusted() {
    let m = master();
    let chain_at_100 = || MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(100), 1))]));

    // A scope that does not reach index 100: unlocated, and nothing to
    // acknowledge. The default scope reaches 100 at a ceiling of 10,000, so
    // it cannot serve here. What the arm is about is a walk that does not
    // find the chain's index, so the scope that does not find it is named
    // rather than assumed; that the DEFAULT does reach it is
    // `the_diagnostics_ceiling_follows_the_recovery_ceiling`'s subject.
    let (dir, mut ks) = store_at("recon-named-default", 0);
    let client = chain_at_100();
    let short = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);
    let d = recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &short, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{d:?}");
    assert!(OperatorAcknowledgement::of(&d).is_none(), "an unlocated address produced an acknowledgement");

    // Naming 99: the walk covers 0..=99, the chain is at 100, nothing found,
    // nothing acknowledged, nothing written.
    let named_99 = ScanScope::DIAGNOSTIC.with_ceiling(100);
    let d99 = recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_99, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d99, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{d99:?}");
    assert!(OperatorAcknowledgement::of(&d99).is_none(), "naming 99 produced an acknowledgement");
    assert!(format!("{d99}").contains("indices 0 through 99"), "the raised walk is not reported:\n{d99}");

    // Naming 5000: the walk finds 100 on its way and the acknowledgement it
    // yields names 100 -- the typed number is not the answer.
    let named_5000 = ScanScope::DIAGNOSTIC.with_ceiling(5001);
    let d5000 =
        recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_5000, &Cancel::NEVER).expect_err("diverged");
    let ack5000 = OperatorAcknowledgement::of(&d5000).unwrap_or_else(|| panic!("100 lies under 5000: {d5000:?}"));
    assert_eq!(ack5000.target(), pos(100), "the acknowledgement names the typed number, not the found index");

    // Naming 100: found, acknowledged, advanced, and the account reconciles.
    let named_100 = ScanScope::DIAGNOSTIC.with_ceiling(101);
    let d100 =
        recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_100, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d100, Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 100, .. }, .. }), "{d100:?}");
    let ack = OperatorAcknowledgement::of(&d100).unwrap_or_else(|| panic!("ahead has a target"));
    assert_eq!(ack.target(), pos(100));
    // The acknowledgement is checked against the LIVE divergence under the
    // scope it is APPLIED with: under a scope too narrow to reach index 100
    // the store is `Unlocated`, there is no live target, and the same
    // acknowledgement is refused. `ScanScope::DIAGNOSTIC` cannot stand in:
    // at a ceiling of 10,000 it reaches 100 itself, under which the same
    // acknowledgement is accepted, because that scope re-confirms the index
    // it names -- the mechanism working rather than failing. What the arm is
    // the re-confirmation, so the narrow scope is named.
    assert!(matches!(
        recon::advance_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &short, &Cancel::NEVER),
        Err(Error::AcknowledgementDoesNotMatch)
    ), "an acknowledgement was applied under a scope that cannot re-confirm its index");
    let r = recon::advance_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &named_100, &Cancel::NEVER)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(100));
    assert!(matches!(
        recon::reconcile_account(&ks, &client, &TAG, &access(&m)),
        Ok(AccountStatus::InSync { .. })
    ));
    drop(ks);
    let ks = reopen("recon named reopen", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(100), "the advance did not reach disk");

    // A foreign address under any ceiling: still unlocated, still nothing.
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let (_d2, ks2) = store_at("recon-named-alien", 0);
    let client2 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))]));
    let da = recon::reconcile_account_with(&ks2, &client2, &TAG, &access(&m), &ScanScope::DIAGNOSTIC.with_ceiling(200), &Cancel::NEVER)
        .expect_err("diverged");
    assert!(matches!(da, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{da:?}");
    assert!(OperatorAcknowledgement::of(&da).is_none());

    // A confirmed index BELOW local: `Behind`, no acknowledgement, and the
    // report says which way it is -- not that the number failed to match.
    let (_d3, ks3) = store_at("recon-named-behind", 22);
    let client3 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(20), 1))]));
    let db = recon::reconcile_account_with(&ks3, &client3, &TAG, &access(&m), &ScanScope::DIAGNOSTIC.with_ceiling(21), &Cancel::NEVER)
        .expect_err("diverged");
    assert!(matches!(db, Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 2, .. }, .. }), "{db:?}");
    assert!(OperatorAcknowledgement::of(&db).is_none(), "a behind divergence produced an acknowledgement");
    assert!(format!("{db}").contains("2 BEHIND local"));
}

/// **Restore's ceiling is a default the operator can set, and setting it
/// finds the exact index or fails again**. The failure text
/// counts the positions as they were walked -- `0 through 19` at a ceiling
/// of 20, never *within 20* -- and names all three causes.
///
/// The scope is explicit here too: the default is 10,000, and taking
/// it would make this one call cost about 7 m 24 s in a debug build, so a
/// ceiling of [`WALKED`] stands in and the text is asserted against that.
/// The **default's** own rendering is pinned, at its real value and without
/// a walk, in `the_recovery_ceiling_is_the_extensions_own_number`.
#[test]
fn restore_finds_a_far_along_index_only_when_the_ceiling_is_raised() {
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 5))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(WALKED), &Cancel::NEVER)
        .expect_err("30 is past a ceiling of 20");
    match &err {
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => assert_eq!(*scanned, WALKED),
        other => panic!("{other:?}"),
    }
    let text = format!("{err}");
    assert!(text.contains("none of key indices 0 through 19"), "the walk is not counted as walked:\n{text}");
    assert!(text.contains("spent 20 or more times"), "the far-along cause is not named:\n{text}");
    assert!(text.contains("does not own this tag"), "the wrong-seed cause is not named:\n{text}");
    assert!(text.contains("another chain"), "the wrong-chain cause is not named:\n{text}");
    assert!(text.contains("higher scan ceiling"), "the remedy is not named:\n{text}");
    assert!(!text.contains("within 20"), "the off-by-one phrasing is back:\n{text}");
    assert!(!text.contains("not 'further along"), "the denial is back:\n{text}");

    // Raised to walk 0..=30: found. Raised to walk 0..=29: still not.
    let found = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(31), &Cancel::NEVER)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(found.index, pos(30));
    assert_eq!(found.balance, 5);
    assert!(matches!(
        recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(30), &Cancel::NEVER),
        Err(RestoreFailure::NoIndexReproducesTheAddress { scanned: 30, .. })
    ), "a ceiling of 30 walked index 30");

    // A foreign address under a raised ceiling: the ceiling does not invent a
    // match, and the report counts what it walked.
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let client2 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    match recon::restore_account_index_with(&client2, &master(), 0, &ScanScope::RESTORE.with_ceiling(60), &Cancel::NEVER) {
        Err(e @ RestoreFailure::NoIndexReproducesTheAddress { scanned: 60, .. }) => {
            assert!(format!("{e}").contains("0 through 59"), "{e}");
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The acknowledgement gate
// ---------------------------------------------------------------------------

/// Advancing past a divergence requires an acknowledgement built **from the
/// divergence itself**, and it is checked against the live state. There is no
/// route from this type to `persist_advance_to` that skips it.
#[test]
fn advancing_requires_an_acknowledgement_of_the_live_divergence() {
    let (dir, ks) = store("recon-ack");
    let m = master();
    // The wallet will not open while diverged, so the report comes from
    // `reconcile_account` directly -- which is what the CLI's `status` and
    // `reconcile` commands do, both of which run before that gate.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(2), 1))]));
    let d = recon::reconcile_account(&ks, &client, &TAG, &access(&m)).expect_err("diverged");
    let ack = OperatorAcknowledgement::of(&d).unwrap_or_else(|| panic!("ahead has a target"));
    assert_eq!(ack.tag(), TAG);
    // The target IS the chain's index, not one past it: the chain's current
    // address for a tag is the address of the key that signs NEXT, so a
    // chain at index 2 means local state belongs at 2. Written as `pos(3)`
    // first and caught by the reconcile-after-advance assertion below.
    assert_eq!(ack.target(), pos(2), "the target is the chain's index");

    // A divergence advancing cannot remedy yields no acknowledgement at all.
    assert!(OperatorAcknowledgement::of(&Divergence::TagUnresolved {
        tag: TAG,
        local: WotsIndex::ZERO
    })
    .is_none());
    assert!(OperatorAcknowledgement::of(&Divergence::ChainUnreachable {
        tag: TAG,
        cause: Error::NoSuchAccount
    })
    .is_none());

    // Now open a wallet over a chain that agrees, and show the advance path
    // refuses when there is nothing to reconcile.
    drop(ks);
    let ks = reopen("recon ack", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let mut w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    match w.advance_after_operator_review(&TAG, &access(&m), ack) {
        Err(Error::NothingToReconcile) => {}
        Err(other) => panic!("a healthy account must refuse an advance by name: {other:?}"),
        Ok(_) => panic!("a healthy account was advanced by a stale acknowledgement"),
    }

    // Point the chain at position 2 and the same acknowledgement applies.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let r = w
        .advance_after_operator_review(&TAG, &access(&m), ack)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(2));
    // And the wallet now reconciles cleanly -- the advance landed the store
    // exactly where the chain is, rather than one past it.
    assert!(matches!(
        w.status(&TAG, &access(&m)),
        Ok(AccountStatus::InSync { .. })
    ));
    // And a second application is refused: the divergence is gone.
    assert!(matches!(
        w.advance_after_operator_review(&TAG, &access(&m), ack),
        Err(Error::NothingToReconcile)
    ));
}

/// An acknowledgement of one account cannot be applied to another.
#[test]
fn an_acknowledgement_is_bound_to_the_account_it_names() {
    let dir = ScratchDir::new("recon-ack-bound");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 1)).unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let other = tag1();
    let other_at_0 = recon::derived_address_at(&master(), 1, WotsIndex::ZERO);
    drop(ks);
    let ks = reopen("ack bound", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));

    let mut w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(0), 1)),
            (other, ChainState::At(other_at_0, 1)),
        ])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    // Diverge the FIRST account and take an acknowledgement of it.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let d = w.status(&TAG, &access(&m)).expect_err("diverged");
    let ack = OperatorAcknowledgement::of(&d).unwrap_or_else(|| panic!("target"));

    // It cannot be applied to the second account, which is not diverged at
    // all -- the tag is checked before anything else.
    assert!(matches!(
        w.advance_after_operator_review(&other, &access(&m), ack),
        Err(Error::AcknowledgementDoesNotMatch)
    ));

    // Diverge the second account too, to a DIFFERENT index, and the first
    // account's acknowledgement is still refused: the target is checked
    // against the live divergence, not merely the tag.
    w.client()
        .transport()
        .set(other, ChainState::At(recon::derived_address_at(&master(), 1, pos(5)), 1));
    assert!(matches!(
        w.advance_after_operator_review(&other, &access(&m), ack),
        Err(Error::AcknowledgementDoesNotMatch)
    ));

    // SAME account, WRONG target: the acknowledgement names index 2 and the
    // chain has since moved to 4, so the divergence it was taken of is not
    // the one the store is in now. Refused -- the check is against the LIVE
    // divergence, not merely against the tag.
    //
    // The reconciliation session's own injection matrix found this case missing: deleting the
    // target comparison left this test green, because every case here
    // differed by tag alone. The row that exposed it was recorded with the
    // session; this assertion is what it was aimed at.
    w.client().transport().set(TAG, ChainState::At(addr_at(4), 1));
    assert!(
        matches!(
            w.advance_after_operator_review(&TAG, &access(&m), ack),
            Err(Error::AcknowledgementDoesNotMatch)
        ),
        "an acknowledgement of a divergence the store has moved past was accepted"
    );

    // And with the chain back where the acknowledgement was taken, it applies.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let r = w
        .advance_after_operator_review(&TAG, &access(&m), ack)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(2));
}

// ---------------------------------------------------------------------------
// The wallet's spend path
// ---------------------------------------------------------------------------

/// The whole flow through the wallet, which is the CLI's `send`: plan,
/// reserve-and-sign, submit — and the signed bytes handed back as **the retry
/// artifact the wallet does not keep**. The caller owns them
/// from here until the reservation resolves; if they are lost,
/// `resign_pending` is the recovery and it burns nothing — it rebuilds the
/// reserved plan and re-signs it with the same key.
#[test]
fn the_wallet_spend_path_hands_the_retry_artifact_to_the_caller() {
    let (_dir, ks) = store("recon-spend");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let plan = w
        .plan(
            &TAG,
            &access(&m),
            vec![Destination {
                tag: [0x6b; ADDR_TAG_LEN],
                reference: [0; 16],
                amount: 1_000_000,
            }],
            MFEE,
            0,
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
    assert_eq!(plan.tag(), TAG, "the plan does not name the account it was built for");
    assert_eq!(plan.position(), WotsIndex::ZERO);

    let signed = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    assert!(!signed.wire().is_empty(), "no artifact was handed back");

    // The store advanced and the reservation is open; nothing in it holds
    // the bytes.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1), "the reservation did not advance the index");
    assert!(v.pending.is_some(), "the reservation is open until it resolves");

    // A second spend is refused while it is open -- the account is not
    // spendable again until the operator settles or re-signs.
    assert!(matches!(
        w.plan(
            &TAG,
            &access(&m),
            vec![Destination {
                tag: [0x6b; ADDR_TAG_LEN],
                reference: [0; 16],
                amount: 1,
            }],
            MFEE,
            0,
        ),
        Err(Error::PendingUnresolved { .. })
    ));
}

/// A changed observation must be refused while the key is still unused.
/// Retrying after a fresh plan remains safe because no reservation exists.
#[test]
fn reservation_preflight_refuses_changed_chain_state_without_writing() {
    let (_dir, ks) = store("preflight-chain");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
    let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    for (observation, expected) in [
        (ChainState::At(addr_at(0), 6_000_000), Error::BalanceChanged { planned: 5_000_000, current: 6_000_000 }),
        (ChainState::At(addr_at(0), 4_000_000), Error::BalanceChanged { planned: 5_000_000, current: 4_000_000 }),
        (ChainState::At(addr_at(1), 5_000_000), Error::ChainAddressMismatch { position: 0 }),
        (ChainState::Absent, Error::Mesh { code: 4, retriable: false }),
        (ChainState::Unreachable, Error::Transport {
            op: "connect",
            kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
        }),
    ] {
        w.client().transport().set(TAG, observation);
        assert_eq!(w.reserve_and_sign(&plan, access(&m)).err(), Some(expected));
        assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
        assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    }
    w.client().transport().set(TAG, ChainState::At(addr_at(0), 6_000_000));
    let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let signed = w.reserve_and_sign(&fresh, access(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(signed.wire().len(), 2_408);
    let view = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(view.wots_index, pos(1));
    assert_eq!(view.pending.map(|p| p.digest), Some(fresh.digest()));
}

/// Both the local key position and the full address pair are checked before
/// reserving. A failed plan cannot consume a different key or redirect change.
#[test]
fn reservation_preflight_binds_plan_to_current_store_keys() {
    let (_dir, ks) = store("preflight-keys");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
    let original = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    for change_only in [false, true] {
        let mut addresses = w.spend_addresses(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}"));
        if change_only {
            addresses.change[20] ^= 1;
        } else {
            addresses.source[20] ^= 1;
        }
        let plan = mochimo_crypto::mesh::spend::SpendPlan::new(
            &addresses,
            &mochimo_crypto::mesh::LedgerEntry { address: addresses.source, balance: 5_000_000 },
            dsts.clone(), MFEE, 0,
        ).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(w.reserve_and_sign(&plan, access(&m)).err(), Some(Error::SpendPlanAddressMismatch));
        assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
        assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    }
    let wrong = mochimo_crypto::Secret::new([0x77; 32]);
    assert!(w.reserve_and_sign(&original, access(&wrong)).is_err());
    assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
    assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    let _signed = w.reserve_and_sign(&original, access(&m)).unwrap_or_else(|e| panic!("{e}"));
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4_000_000));
    assert!(matches!(w.settle_if_landed(&TAG, &access(&m)), Ok(Settlement::Settled { .. })));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.reserve_and_sign(&original, access(&m)).err(), Some(Error::StaleSpendPlan { planned: 0, stored: 1 }));
    assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
    assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let _signed = w.reserve_and_sign(&fresh, access(&m)).unwrap_or_else(|e| panic!("{e}"));
}

/// Non-zero expiry needs a readable tip and a remaining inclusion window.
/// Boundary arithmetic must not wrap near the largest representable block.
#[test]
fn reservation_preflight_checks_expiry_before_writing() {
    let m = master();
    for (tip, expiry, accepted) in [
        (None, 101, false),
        (Some(100), 99, false),
        (Some(100), 100, false),
        (Some(100), 101, true),
        (Some(100), 356, true),
        (Some(100), 357, false),
        (Some(u64::MAX), u64::MAX, false),
        (Some(u64::MAX - 1), u64::MAX, true),
        (None, 0, true),
    ] {
        let (_dir, ks) = store("preflight-expiry");
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
        if let Some(tip) = tip {
            chain.set_tip(tip);
        }
        let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
        let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
        let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, expiry).unwrap_or_else(|e| panic!("{e}"));
        let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
        let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
        let result = w.reserve_and_sign(&plan, access(&m));
        if accepted {
            assert!(result.is_ok(), "tip {tip:?}, expiry {expiry}: {result:?}");
        } else {
            match tip {
                Some(tip) => assert_eq!(result.err(), Some(Error::InvalidExpiry { expiry, tip })),
                None => assert!(matches!(result, Err(Error::MeshResponse { .. }))),
            }
            assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
            assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
            let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
            assert!(w.reserve_and_sign(&fresh, access(&m)).is_ok());
        }
    }
}
