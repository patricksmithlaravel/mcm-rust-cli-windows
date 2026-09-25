#![cfg(not(miri))]
//! The compile-fail partition: every `ui/fail` case is refused by rustc for
//! the reason its pinned `.stderr` records, and every `ui/pass` case builds.
//!
//! Runtime tests cannot reach this. "There is no way to write X" is a statement
//! about programs that must be rejected, and a program that is rejected never
//! runs. Gated on `not(miri)` because trybuild spawns `cargo`, which Miri
//! cannot.
//!
//! # What the partition holds
//!
//! The cases are the compiler's half of several invariants in
//! `docs/specification.md`: I1's (`signing_raw_signer_is_not_reachable`,
//! `signing_internals_are_not_reachable`, the receipt consumed and not
//! `Clone`), I2 and I3's (`account_advance_receipt_is_not_constructible`,
//! `durable_is_not_constructible`, `medium_steps_are_not_reorderable`), I6's
//! (`secret_is_not_partial_eq`, `secret_is_not_partial_ord`), the account
//! model's, the keystore's, and the terminal's. I7's compile-fail half -- the
//! TXENTRY handle's four by-value hazards -- is not among them: the FFI
//! transaction type is not a Rust value here because it does not exist here.
//!
//! # Why the cases live in `ui/` and not under `tests/`
//!
//! `tests/invariants.rs::test_sources()` concatenates every `.rs` under
//! `tests/` and several checks grep the result for symbol names. The files here
//! are deliberately broken code that names `Clone`, `Default` and private paths
//! in order to be rejected. Feeding that into a corpus other checks search would
//! make "this symbol is discussed" indistinguishable from "this symbol is
//! used". They are inputs to a test, not tests, so they sit outside the walk.
//!
//! # Why both directions are present
//!
//! A `compile_fail` case passes when compilation fails. It does not care *why*.
//! Two things are therefore required of every run:
//!
//!   * each fail case has a checked-in `.stderr` naming the **specific type**
//!     and the **specific missing trait**, so a case that starts failing for an
//!     unrelated reason — a typo, a renamed import — goes red instead of green;
//!   * `ui/pass/` must compile. Without it, deleting the dependency or breaking
//!     the feature flags would turn every fail case green at once, and the
//!     suite would report the invariant as most thoroughly enforced at the
//!     moment nothing in the directory builds at all.
//!
//! # One test, several subjects: the headline is the partition's
//!
//! If any case breaks -- someone derives `PartialEq` on `Secret`, or a
//! rendered error moves -- the red arrives under this one test's name, which
//! names no subject. trybuild's output names the offending `.rs` file on the
//! line above the diff, so the information is not lost, but the *headline* is
//! the partition's and not the invariant's: read the file trybuild names. The
//! subject census below is what keeps this honest -- each family is floored
//! separately, so none can quietly vanish behind another's count, and the
//! partition is closed so a case belonging to no family cannot hide.
//!
//! The `.stderr` files pin rustc's exact wording (1.98.0). Regenerate with
//! `TRYBUILD=overwrite cargo test --test compile_fail` and *read the diff* --
//! a case that starts failing for a new reason is the finding, not the noise.

/// The two directions, in one `trybuild` run.
///
/// One `TestCases` value, because trybuild batches everything registered on it
/// into a single `cargo` invocation on drop. Splitting them across two tests
/// would compile the workspace twice for no gain.
#[test]
fn every_ui_case_compiles_or_fails_for_its_pinned_reason() {
    // Before anything is registered: the cases exist, and every fail case has a
    // pinned reason. A glob matching nothing is the vacuous pass this whole
    // file is arranged to prevent, and it would look identical to success.
    let fails = cases("ui/fail");
    let passes = cases("ui/pass");

    // Censused by subject, not counted in aggregate. A bare `fails.len() >= 4`
    // was enough while every case here was a TXENTRY case; it stopped being
    // enough when `ui/fail` became shared (see the module note above), because
    // deleting a case and adding an unrelated one leaves the total untouched.
    // A count is blind to a case that *stopped being carried*, so each
    // subject is floored on its own, and the
    // partition is closed so a case belonging to none cannot hide. The TXENTRY
    // family (four cases: raw deref, Default, Clone, Deref) is gone with the
    // handle it pinned.
    let secret_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("secret_"))
        .count();
    let account_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("account_"))
        .count();
    let keystore_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("keystore_") || stem(p).starts_with("durable_") || stem(p).starts_with("medium_"))
        .count();
    let signing_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("signing_"))
        .count();
    let terminal_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("terminal_"))
        .count();
    assert!(
        secret_cases >= 3,
        "ui/fail holds {secret_cases} `secret_*` case(s); expected the two \
         comparison families (PartialEq, PartialOrd) and the duplication one \
         (Clone, whose named replacement is `Secret::duplicate`). \
         `secret_has_no_equality_and_nothing_enforces_it` in tests/invariants.rs \
         reports itself cleared when ui/fail/secret_is_not_partial_eq.rs exists \
         with a .stderr beside it; if a case was deleted, that marker is green \
         over nothing and this is the only place that would notice."
    );
    // The account model's absences: Clone (a cloned account is two spend
    // paths over one index), Default (an account from nothing at index zero),
    // the struct literal (the bypass around the constructors), a writable
    // wots_index (a rewindable index re-signs a used key), and a forgeable
    // AdvanceReceipt (a durability witness minted by nobody). Deliberately
    // NOT cased, argued here where the siblings are asserted:
    // `account_is_not_copy` -- Copy: Clone is a supertrait, so adding Copy
    // dies at the Clone case first; `imported_root_is_not_extractable` --
    // it would pin a falsehood, since the restore path must hand the root
    // back and `Secret::duplicate` is how it does so. Note what changed and
    // what did not: `Secret` no longer derives `Clone`, and
    // `secret_is_not_clone.rs` pins that, but duplication itself is still
    // there under a name that greps. The root is as extractable as it ever
    // was, so a case claiming otherwise would pin a falsehood today for the
    // same reason it would have before. The mitigation for exposure is the
    // Debug-holder scan and each impl's pinned rendering, not trybuild.
    // Format v2 added two, and the floor moves with them or deleting them is
    // invisible: the removed `import_with_unverified_tag` (a forged imported
    // tag must be unconstructible, not merely discouraged) and the
    // `AccountRecord::Imported` literal missing its first-key components and
    // stream identity (a record without them is an imported account with no
    // path to position 0 -- I8's loss mode).
    assert!(
        account_cases >= 7,
        "ui/fail holds {account_cases} `account_*` cases; expected the five \
         account-model absences (Clone, Default, struct literal, wots_index \
         write, AdvanceReceipt forgery) plus format v2's two (the unverified \
         imported constructor gone, the imported record's new fields \
         required). If one was deleted, the absence it pinned is one derive \
         or one `pub` away from silently returning."
    );
    // The keystore's absences: Clone (a second writer -- the shipped race),
    // Default (an empty store from nothing -- I5's index-zero assumption), a
    // forgeable Durable witness (a receipt for an advance that never reached
    // disk), and a reorderable step sequence (the torn write the typestate
    // exists to make a type error).
    assert!(
        keystore_cases >= 4,
        "ui/fail holds {keystore_cases} keystore/durable/medium cases; expected the \
         four keystore absences (Clone, Default, Durable forgery, step reorder)."
    );
    // The signing path's absences: the raw signer unnameable (`wots::sign` is
    // `pub(crate)` -- the I1 demotion), its internals unnameable (a signer
    // by composition otherwise), the receipt consumed by `sign_spend` (a
    // second call is a use after move), and the receipt not `Clone` (the
    // one derive that reopens I1 while E0382 stays red). Deliberately NOT
    // cased, argued here: `backend::native::wots_sign` -- it
    // COMPILES under the `raw-backend` feature trybuild inherits from the
    // test build's fingerprint, which is why the downstream probe in
    // tests/signing.rs exists; and a two-argument `sign_spend` (E0061,
    // trivial).
    assert!(
        signing_cases >= 4,
        "ui/fail holds {signing_cases} `signing_*` cases; expected the four signing \
         absences (raw signer private, internals private, receipt consumed, receipt \
         not Clone). If one was deleted, the absence it pinned is one `pub` or one \
         derive away from silently returning."
    );
    // The terminal absence, and it is the whole of the confirmation's safety
    // argument. `create`'s three-word confirmation now ECHOES -- the phrase it
    // asks about is three lines above in the same scrollback, so hiding the
    // answer buys no secrecy and costs a real `exit 3`.
    // What keeps the acquisition's property across that change is a signature:
    // `Terminal::read_visible_line` takes `self`, so there is no terminal left
    // to read a secret from afterwards. A convention about statement order
    // would leave nothing to case; a signature leaves exactly this.
    assert!(
        terminal_cases >= 1,
        "ui/fail holds no `terminal_*` case. The claim that no secret read can \
         follow the echoing confirmation is held by ONE `self` in a trait \
         method, and this case is the only thing that would notice it becoming \
         `&mut self` -- after which `create` would compile with the phrase \
         prompt running visibly."
    );
    assert_eq!(
        secret_cases + account_cases + keystore_cases + signing_cases + terminal_cases,
        fails.len(),
        "ui/fail holds {} cases but only {} were recognised by the five \
         subject filters above. An unrecognised case is still compiled by the \
         glob, so it is enforced but uncounted -- give it a floor, or the next \
         deletion is invisible.",
        fails.len(),
        secret_cases + account_cases + keystore_cases + signing_cases + terminal_cases
    );
    assert!(
        !passes.is_empty(),
        "ui/pass is empty. Without a case that must compile, every compile_fail \
         case would pass at the moment nothing in this directory built at all."
    );
    for case in &fails {
        assert!(
            case.with_extension("stderr").is_file(),
            "{} has no .stderr beside it. A compile_fail case without pinned \
             output asserts only that something went wrong -- a typo in the \
             case would satisfy it.",
            case.display()
        );
    }

    // The medium's order pin is per platform, as its steps are: the rename
    // layout's on Unix, the slot layout's on Windows. Each names methods the
    // other platform's `Medium` does not have, so each is compiled only where
    // it pins something, and both are counted above.
    let registered: Vec<&std::path::PathBuf> = fails.iter().filter(|case| pinned_here(case)).collect();
    assert_eq!(
        fails.len() - registered.len(),
        1,
        "exactly one of the two medium order pins is another platform's; {} of {} fail cases \
         are registered here",
        registered.len(),
        fails.len()
    );

    // Evidence for `invariants.rs::census`, which requires this test to run,
    // pass, AND report what it measured -- an empty `#[test]` body runs and
    // passes, so execution alone does not distinguish one. Printed before the
    // `TestCases` is built because trybuild runs on drop; if the cases then
    // fail, the test fails and the census reads the failure, not this line.
    println!(
        "\x20 compile-fail partition: {} fail case(s) registered here of {} ({secret_cases} secret, \
         {account_cases} account, {keystore_cases} keystore, {signing_cases} signing, \
         {terminal_cases} terminal), {} pass case(s), every fail case with a pinned .stderr",
        registered.len(),
        fails.len(),
        passes.len()
    );

    let t = trybuild::TestCases::new();

    // Must compile. Registered first so that when the whole directory is
    // broken, the first thing reported is the reason rather than four
    // misleading successes.
    t.pass("ui/pass/*.rs");

    // Must not compile, each for the reason its .stderr records.
    for case in registered {
        t.compile_fail(std::path::Path::new("ui/fail").join(case.file_name().unwrap_or_default()));
    }
}

/// Whether `case` pins something this platform builds: every case but the
/// medium's two order pins, which belong to one platform's steps each.
fn pinned_here(case: &std::path::Path) -> bool {
    match stem(case).as_str() {
        "medium_steps_are_not_reorderable" => cfg!(unix),
        "medium_slot_steps_are_not_reorderable" => cfg!(windows),
        _ => true,
    }
}

/// A case's file stem, for the subject census above.
fn stem(p: &std::path::Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The `.rs` cases in a `ui/` subdirectory, as absolute paths.
fn cases(dir: &str) -> Vec<std::path::PathBuf> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let entries = std::fs::read_dir(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut out: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}
