#![cfg(all(feature = "native", not(miri)))]
//! The CLI: every command driven against the scriptable chain, every
//! refusal **rendered and read back**, and every exit code asserted.
//!
//! Gated as `recon.rs` is: `native` for the keystore and the derivation,
//! `not(miri)` for WOTS+ time and the filesystem. **What that removes from the
//! Miri claim:** the interpreter never walks these command paths. They are
//! safe Rust over primitives `walk_native` already walks, over `std::fs` that
//! Miri's isolation forbids, and over the same `codec` `tests/mesh.rs` drives
//! under Miri.
//!
//! # Why the assertions read output rather than call the wallet
//!
//! A CLI's product **is** its text. Failure-path text is invisible
//! to a passing suite, so the wording that carries this project's three
//! residues — a submission is not a verdict, `tx_val` never ran, the artifact
//! is losable — is asserted against captured output, never against the source
//! that produced it. If the three notices were deleted the wallet would still
//! work and these tests would go red, which is the point of having them.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/chain.rs"]
mod chain;

use chain::{addr_at, hexs, master, Chain, ChainState, TAG};
use keystore_harness::{reopen, ScratchDir};
use mochimo_crypto::account::Account;
use mochimo_crypto::cli::args::{self, Command, Spend, SpendTo};
use mochimo_crypto::cli::{self, Code};
use mochimo_crypto::consts::{ADDR_REF_LEN, ADDR_TAG_LEN, MFEE};
use mochimo_crypto::keystore::{Figures, KeyAccess, Keystore};
use mochimo_crypto::mesh::MeshClient;
use mochimo_crypto::tx::wire::Destination;
use mochimo_crypto::wallet::Wallet;

const TO: [u8; ADDR_TAG_LEN] = [0x6b; ADDR_TAG_LEN];

/// A store holding `F-address-widths`' derived account 0, at position 0.
fn store(name: &str) -> (ScratchDir, Keystore) {
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    // **The store holds its own master seed**. `cli::run` reads it from the
    // store the password opened, so a store
    // built without one is a store whose derived account nothing can sign for
    // -- `Wallet::open` refuses it with `NoMasterForDerivedAccount`, which is
    // correct and is exactly what every command test saw when this helper
    // stopped adopting.
    let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0))
        .unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

fn spend() -> Spend {
    Spend {
        tag: TAG,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
    }
}

/// [`spend`] carrying a destination reference, laid out as `--ref <text>`
/// lays it out: the ASCII bytes, NUL-padded to the field.
fn spend_with_reference(text: &str) -> Spend {
    assert!(text.is_ascii() && text.len() <= ADDR_REF_LEN, "{text:?} is not a reference this helper lays out");
    let mut s = spend();
    s.dsts[0].reference[..text.len()].copy_from_slice(text.as_bytes());
    s
}

/// The bytes of a hex string, for reading a wire image back.
fn bytes_of(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

/// Run one command over a fresh store and a scripted chain.
fn run_on(name: &str, chain: Chain, cmd: &Command) -> cli::Report {
    let (_dir, ks) = store(name);
    cli::run(ks, MeshClient::new(chain), cmd)
}

/// [`run_on`], keeping the directory so the store can be reopened and READ
/// afterwards. A CLI test that never reads store state after `cli::run`
/// cannot see a `reconcile` that never reached the store.
fn run_on_keeping(name: &str, chain: Chain, cmd: &Command) -> (ScratchDir, cli::Report) {
    let (dir, ks) = store(name);
    let r = cli::run(ks, MeshClient::new(chain), cmd);
    (dir, r)
}

/// The stored index of `TAG`, read back from disk.
fn stored_index(dir: &ScratchDir) -> u32 {
    let ks = reopen("stored index", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    ks.view(&TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the store no longer holds the account"))
        .wots_index
        .get()
}

/// Sign the same spend through the wallet API on a throwaway store, to learn
/// the transaction id the CLI's run will produce.
///
/// The id comes from `SignedTransaction::id()` — the crate's own API — never
/// from anything this file computes. `MeshClient::submit` then compares its own
/// id against the echo, so if the two runs ever diverged the CLI's `send`
/// would fail rather than this assertion passing quietly.
fn id_for_the_spend(name: &str) -> [u8; 32] {
    id_for(name, &spend())
}

/// [`id_for_the_spend`] over any `Spend`, because the block-to-live is inside
/// the digest and a chain scripted to accept a btl-4242 spend needs THAT
/// spend's id, not the default's (`resign` ships what it
/// reproduces, so every test that drives it to success scripts an accepting
/// socket). `id_for_the_spend` stays as the one-line wrapper above so that no
/// existing call site moved when this was added -- the 203 marker's included.
fn id_for(name: &str, s: &Spend) -> [u8; 32] {
    let (_dir, ks) = store(name);
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(
            &TAG,
            &KeyAccess::Master(&m),
            // Every destination, not just the first: a spend of three is
            // three on the wire and its id is over all of them. `None` is
            // the `all` keyword, which resolves against the same 5,000,000
            // this helper's own chain is scripted with.
            s.dsts
                .iter()
                .map(|d| Destination {
                    tag: d.to,
                    reference: d.reference,
                    amount: d.amount.unwrap_or(5_000_000 - s.fee_total),
                })
                .collect(),
            s.fee_total,
            s.blk_to_live,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let signed = w
        .reserve_and_sign(&plan, KeyAccess::Master(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    signed.id().0
}

/// A tag in the machine form the parser now requires: `0x` and forty hex
/// characters. Bare hex is refused so that no forty-character
/// substring of anything this program prints can be taken as a destination.
fn prefixed(tag: &[u8]) -> String {
    format!("0x{}", hexs(tag))
}

/// `create`'s three entropy draws, fixed.
///
/// The phrase entropy is the constant these tests already used; the salt and
/// the nonce seed come from the harness, so a store built here and a store
/// built by `keystore_harness::create` are byte-identical for identical
/// contents -- which is what keeps the flow test's observables comparable.
/// The two password reads `create` makes, in front of whatever the test is
/// scripting.
///
/// `read_new_password` reads twice and requires the two to agree, so every
/// `create` script gains two answers before the one it cared about. Written as
/// a helper rather than pasted so that a change to how many times the password
/// is read is one edit rather than six.
fn password_then(rest: Vec<String>) -> Vec<String> {
    let pw = keystore_harness::TEST_PASSWORD_STR.to_string();
    let mut v = vec![pw.clone(), pw];
    v.extend(rest);
    v
}

fn test_create_entropy() -> create_cmd::CreateEntropy {
    create_cmd::CreateEntropy {
        phrase: ENTROPY,
        salt: keystore_harness::TEST_SALT,
        nonce_seed: keystore_harness::TEST_NONCE_SEED,
    }
}

fn assert_says(report: &cli::Report, needle: &str, what: &str) {
    assert!(
        report.text.contains(needle),
        "{what}: the rendered output does not contain {needle:?}.\n--- output ---\n{}",
        report.text
    );
}

// ---------------------------------------------------------------------------
// The open path: every command reconciles first, or the wallet does not exist
// ---------------------------------------------------------------------------

/// Chain state: in sync at position 0. The wallet opens and `balance` reports.
#[test]
fn balance_reports_every_account_after_reconciliation() {
    let r = run_on(
        "cli-balance",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::Ok, "an in-sync store did not open: {}", r.text);
    // A destination, not a hex tag -- this is the line an operator
    // copies into `settle`, `status` or someone else's wallet.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "balance");
    // Narrowly: THIS line prints one spelling. The claim is deliberately not
    // global -- `recon::Divergence`'s `Display`, which the CLI prints verbatim
    // on a startup refusal, still renders tags through `recon::hex20`, and
    // `a_divergence_refuses_startup_with_code_2_and_names_what_diverged` below
    // pins that hex. Whether a *diagnostic* should speak the payment form is a
    // question left open, recorded rather than asserted here in either
    // direction.
    assert!(
        !r.text.contains(&hexs(&TAG)),
        "balance prints the hex tag beside the destination; two spellings of one identifier on \
         one line is the transcription hazard the destination form removed:\n{}",
        r.text
    );
    assert_says(&r, "5000000", "balance");
    assert_says(&r, "in sync", "balance");
}

/// Chain state: the chain is at position 2 and the store at 0 — local behind.
/// **Exit code 2, and the report is I4's.**
#[test]
fn a_divergence_refuses_startup_with_code_2_and_names_what_diverged() {
    let r = run_on(
        "cli-diverged",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 5_000_000))]),
        &Command::Balance,
    );
    assert_eq!(
        r.code,
        Code::StartupRefused,
        "a divergence did not refuse startup: {}",
        r.text
    );
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
    // I4's message-quality clause: what diverged, both indices, the gap, the action.
    assert_says(&r, "ACTION", "the startup refusal");
    assert_says(&r, &hexs(&TAG), "the startup refusal");
}

/// Chain state: unreachable. Restore fails closed rather than assuming zero,
/// and a wallet cannot open either.
#[test]
fn an_unreachable_chain_refuses_rather_than_assuming() {
    let r = run_on(
        "cli-unreachable",
        Chain::new(&[(TAG, ChainState::Unreachable)]),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::StartupRefused, "output: {}", r.text);
}

// ---------------------------------------------------------------------------
// Reading commands
// ---------------------------------------------------------------------------

/// **The command the deadlock was about.** `address` answers with a transport
/// that refuses every request, on a store whose tag the chain has never held —
/// which is exactly the state an operator is in when they need somewhere to
/// send the first payment.
#[test]
fn address_answers_before_the_tag_is_funded_and_asks_no_node() {
    let (_dir, ks) = store("cli-address-unfunded");
    // Absent from the ledger, and the fake counts every request it is given.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: Some(TAG), account: None },
    );
    assert_eq!(
        r.code,
        Code::Ok,
        "address refused on an unfunded tag -- the deadlock is back: {}",
        r.text
    );
    assert_says(&r, &hexs(&addr_at(0)), "address");
    // The FIRST line is the destination, bare, and the 40-byte ledger
    // address is an indented second thing rather than a second spelling of
    // the first. An operator copies line one; so does a script.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        r.text.lines().next(),
        Some(dest.as_str()),
        "the first line is not the bare destination:\n{}",
        r.text
    );
    assert_says(&r, "DESTINATION", "address");
    assert_says(&r, "It is not a destination: no wallet takes it, and neither does this one", "address");
}

/// A transport that counts, through a handle the test keeps after the client
/// is moved into `cli::run`.
///
/// `Chain` has its own counter and `cli::run` consumes the client, so the
/// count lives behind an `Rc` the test holds. Asserting on the transport's
/// own counter would assert on a value this test cannot read once the client
/// has moved: a `cmd_address` that dialled and tolerated the answer would
/// leave it green.
struct Counting {
    inner: Chain,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
}

impl mochimo_crypto::mesh::Transport for Counting {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        self.inner.post(path, body)
    }
}

/// And it really asked nothing: the transport's counter is zero after both
/// shapes of the command, and the control shows it counts.
#[test]
fn address_makes_no_request_at_all() {
    let mut shapes = 0usize;
    for tag in [Some(TAG), None] {
        let (_dir, ks) = store("cli-address-nonet");
        let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let client = MeshClient::new(Counting {
            inner: Chain::new(&[]),
            calls: std::rc::Rc::clone(&calls),
        });
        let r = cli::run(ks, client, &Command::Address { tag, account: None });
        assert_eq!(r.code, Code::Ok, "{}", r.text);
        assert_eq!(calls.get(), 0, "address (tag {:?}) sent {} request(s) to the node", tag.map(|_| "given"), calls.get());
        shapes += 1;
    }
    assert_eq!(shapes, 2);
    // The control: a command that does ask is counted, so a zero above is a
    // zero and not a counter nothing increments.
    let (_dir, ks) = store("cli-address-nonet-control");
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Balance);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(calls.get() > 0, "balance made no request, so the counter is not counting");
    println!("address requests: 0 across 2 shape(s); balance made {} as the control", calls.get());
}

/// **`address --account N` opens the loop the specification recorded as
/// closed**. End to end, in process:
/// on a fresh store holding account 0, `address --account 1` prints a
/// destination and says the account is not stored, with the snapshot bytes
/// identical before and after and no request made; the scripted chain is
/// then funded at that destination's position-0 address; `restore
/// --account 1` adds the account at position 0; and the tag the store now
/// holds is the tag the printed destination decodes to -- one account,
/// derived, funded, restored, end to end.
#[test]
fn address_account_derives_a_destination_without_storing_and_restore_then_adds_it() {
    let (dir, ks) = store("cli-address-account");
    let before = dir.snapshot_bytes();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Address { tag: None, account: Some(1) });
    assert_eq!(r.code, Code::Ok, "address --account 1 was refused:\n{}", r.text);
    assert_eq!(calls.get(), 0, "address --account made {} request(s)", calls.get());
    assert_eq!(dir.snapshot_bytes(), before, "address --account WROTE to the store");
    assert_says(&r, "NOT STORED", "address --account");
    assert_says(&r, "nothing was written, nothing reserved, no node asked", "address --account");
    assert_says(&r, "restore --account 1", "address --account");
    assert_says(&r, "\n  index    0\n", "address --account");
    let dest = r.text.lines().next().unwrap_or_default().to_owned();
    let printed_tag = mochimo_crypto::addr::tag_from_base58(&dest).unwrap_or_else(|e| panic!("line one is not a destination: {e}"));
    assert_eq!(printed_tag, chain::tag1(), "the printed destination is not account 1's tag");
    let printed_address = r
        .text
        .lines()
        .find_map(|l| l.strip_prefix("  address  "))
        .unwrap_or_else(|| panic!("no address line:\n{}", r.text))
        .to_owned();
    let expected = mochimo_crypto::recon::derived_address_at(&master(), 1, mochimo_crypto::account::WotsIndex::ZERO);
    assert_eq!(printed_address, hexs(&expected), "the printed address is not account 1's position-0 address");

    // Funded at that destination, then restored: the loop closes with the
    // same tag, at position 0, added to the store.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let funded_tag = chain
        .credit_destination(&dest, expected, 7_000)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(funded_tag, printed_tag);
    let ks = reopen("address account restore", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &Command::Restore { account: 1, scan_to: None });
    assert_eq!(r2.code, Code::Ok, "restore --account 1 after funding was refused:\n{}", r2.text);
    assert_says(&r2, "index    0", "restore");
    assert_says(&r2, "added to the store", "restore");
    assert_says(&r2, &dest, "restore");
    let after = reopen("address account after", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let held = after.view(&printed_tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("the restored account is not in the store"));
    assert_eq!(held.wots_index.get(), 0);
    assert_eq!(held.tag, printed_tag, "the restored tag differs from the printed one");
    // And now `address <tag>` answers for it, with the same address.
    let r3 = cli::run(after, MeshClient::new(Chain::new(&[])), &Command::Address { tag: Some(printed_tag), account: None });
    assert_eq!(r3.code, Code::Ok, "{}", r3.text);
    assert_says(&r3, &format!("  address  {}", hexs(&expected)), "address <tag> after the restore");
    println!(
        "  address --account 1: destination {dest}, tag 0x{}; funded at position 0; restore --account 1 added it at index 0 under the same tag; snapshot bytes identical across the derive",
        hexs(&printed_tag)
    );
}

/// The two refusals of `address --account N`: a store holding no master
/// derives nothing (imported accounts only), and an account the store
/// already holds is answered by `address <destination>`, not by position
/// 0's address, which the chain may no longer hold. Both write nothing.
#[test]
fn address_account_refuses_a_masterless_store_and_an_account_already_held() {
    let dir = ScratchDir::new("cli-address-account-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(keystore_harness::imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    let r = cli::run(ks, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: Some(1) });
    assert_eq!(r.code, Code::Refused, "a masterless store derived an account:\n{}", r.text);
    assert_says(&r, "no master seed", "address --account on an imported-only store");
    assert_says(&r, "Nothing was written", "address --account refusal");
    assert_eq!(dir.snapshot_bytes(), before, "the refusal wrote");

    let (dir2, ks2) = store("cli-address-account-held");
    let before2 = dir2.snapshot_bytes();
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks2, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: Some(0) });
    assert_eq!(r2.code, Code::Refused, "an account the store holds was answered at position 0:\n{}", r2.text);
    assert_says(&r2, "already in this store", "address --account on a held account");
    assert_says(&r2, &format!("run `address {dest}`"), "address --account on a held account");
    assert_eq!(dir2.snapshot_bytes(), before2, "the refusal wrote");
    println!("  address --account refusals: no master (imported-only) and an account already held, both without a write");
}

// ---------------------------------------------------------------------------
// discover: a read-only sweep that never asserts absence
// ---------------------------------------------------------------------------

/// **The sweep reports what the node said, index by index, with the extent
/// it searched -- and writes nothing.**
///
/// The store holds account 0; the scripted chain resolves account 0 and
/// account 2 and answers code 4 for the rest. The page must carry the
/// extent, a row for each resolved index, the held marker on account 0, the
/// unresolved indices named as unresolved, and none of it as a claim that
/// an account does not exist. The snapshot bytes are read before and after.
#[test]
fn discover_reports_every_index_the_node_answered_for_and_writes_nothing() {
    let (dir, ks) = store("cli-discover");
    let before = dir.snapshot_bytes();
    let m = master();
    let tag2 = mochimo_crypto::derive::derive_account_tag(&m, 2);
    let addr2 = mochimo_crypto::recon::derived_address_at(&m, 2, mochimo_crypto::account::WotsIndex::ZERO);
    let chain = Chain::new(&[
        (TAG, ChainState::At(addr_at(0), 5_000_000)),
        (tag2, ChainState::At(addr2, 7_000)),
    ]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Discover { to: 4 });
    assert_eq!(r.code, Code::Ok, "discover was refused:\n{}", r.text);
    assert_eq!(dir.snapshot_bytes(), before, "discover WROTE to the store");

    // The extent, every time, found or not -- and it is the extent asked
    // for, not the count of what was found.
    assert_says(&r, "searched account indices 0..=4", "discover");
    assert_says(&r, "5 index(es), one node call each", "discover");
    assert_says(&r, "The node resolved 2 of them.", "discover");

    // The two resolved rows, by destination, with the balance the same
    // `tag_resolve` answer carried -- no second round of calls for it.
    let dest0 = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let dest2 = mochimo_crypto::addr::tag_to_base58(&tag2).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest0, "discover");
    assert_says(&r, &dest2, "discover");
    assert_says(&r, "5000000 nanoMCM (0.005000000 MCM)", "discover");
    assert_says(&r, "7000 nanoMCM (0.000007000 MCM)", "discover");

    // The held account is MARKED, not hidden: a report that omits what you
    // already have is one you cannot check against your own store.
    assert_says(&r, "IN THIS STORE (derived, at key index 0)", "discover");
    assert!(
        !r.text.lines().any(|l| l.contains(&dest2) && l.contains("IN THIS STORE")),
        "an account the store does not hold was marked as held:\n{}",
        r.text
    );

    // The three the node did not resolve, named as indices the node did
    // not resolve.
    assert_says(&r, "the node did not resolve 3 index(es):", "discover");
    for i in [1u32, 3, 4] {
        assert!(
            r.text.split("did not resolve 3 index(es):").nth(1).is_some_and(|t| t.split_whitespace().any(|w| w == i.to_string())),
            "index {i} is missing from the unresolved list:\n{}",
            r.text
        );
    }

    // **And the rule.** Nothing on this page says an account is absent, and
    // the page says why it cannot.
    for forbidden in [
        "does not exist",
        "no such account",
        "you have 2 accounts",
        "has no accounts",
        "never funded at",
    ] {
        assert!(
            !r.text.to_ascii_lowercase().contains(&forbidden.to_ascii_lowercase()),
            "the page asserts absence with {forbidden:?}:\n{}",
            r.text
        );
    }
    assert_says(&r, "does NOT say those accounts do not exist -- it cannot", "discover");
    assert_says(&r, "Nothing was written", "discover");
    assert_says(&r, "restore --account N", "discover");
    println!("  discover: extent 0..=4 printed, 2 resolved, 1 marked held, 3 named unresolved, snapshot bytes identical");
}

/// A sweep that resolves **nothing** is a successful observation: exit 0,
/// the extent printed, and still no claim of absence. A node that cannot be
/// reached is not: exit 3, and the page reports no extent at all for the
/// indices it never asked about.
#[test]
fn discover_finding_nothing_is_exit_zero_and_an_unreachable_node_is_not() {
    let (_d, ks) = store("cli-discover-empty");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Discover { to: 3 },
    );
    assert_eq!(r.code, Code::Ok, "a clean sweep that found nothing was not exit 0:\n{}", r.text);
    assert_says(&r, "searched account indices 0..=3", "discover, nothing found");
    assert_says(&r, "The node resolved 0 of them.", "discover, nothing found");
    // Three, not four: account 0 is IN THIS STORE and the node did not
    // resolve it either, which is the emptied-account window exactly. It
    // keeps its own row, marked held and marked unresolved, rather than
    // disappearing into a list of numbers -- hiding the one account the
    // operator has is the opposite of what this page is for.
    assert_says(&r, "the node did not resolve 3 index(es):", "discover, nothing found");
    assert!(
        r.text.lines().any(|l| l.contains("IN THIS STORE") && l.contains("not resolved by the node")),
        "a held account the node did not resolve lost its row:\n{}",
        r.text
    );
    assert!(!r.text.to_ascii_lowercase().contains("does not exist"), "{}", r.text);

    let (dir2, ks2) = store("cli-discover-down");
    let before = dir2.snapshot_bytes();
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        &Command::Discover { to: 3 },
    );
    assert_eq!(r2.code, Code::Refused, "an unreachable node was reported as a finding:\n{}", r2.text);
    assert_says(&r2, "the sweep stopped at account index 0", "discover, unreachable");
    assert_says(&r2, "0 of 4 index(es) were searched", "discover, unreachable");
    assert_says(&r2, "asserting absence by omission", "discover, unreachable");
    assert_eq!(dir2.snapshot_bytes(), before, "the refusal wrote");
    println!("  discover: a clean sweep finding nothing is exit 0; an unreachable node is exit 3 and reports no extent");
}

/// A store holding no master derives no account index, and says so in the
/// words `address --account N` uses for the same fact. It asks the node
/// nothing at all.
#[test]
fn discover_refuses_a_store_with_no_master_and_asks_the_node_nothing() {
    let dir = ScratchDir::new("cli-discover-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(keystore_harness::imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Discover { to: 8 });
    assert_eq!(r.code, Code::Refused, "a masterless store swept:\n{}", r.text);
    assert_says(&r, "no master seed", "discover on an imported-only store");
    assert_says(&r, "Nothing was written", "discover refusal");
    assert_eq!(calls.get(), 0, "the refusal made {} node call(s)", calls.get());
    assert_eq!(dir.snapshot_bytes(), before, "the refusal wrote");
    println!("  discover: a masterless store is refused before any call, 0 request(s) made");
}

/// A tag the store does not hold is refused, not answered.
#[test]
fn address_refuses_a_tag_the_store_does_not_hold() {
    let r = run_on(
        "cli-address-unknown",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 7))]),
        &Command::Address { tag: Some(TO), account: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "no account", "address");
}

/// `status` reconciles now and reports without refusing.
#[test]
fn status_reports_without_refusing() {
    let r = run_on(
        "cli-status",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 42))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    // Rendered, not the derived `Debug`. It printed
    // `InSync { address: [5, 255, 15, ...], .. }` -- a decimal byte array for
    // the same 40-byte object `address` shows in hex, agreeing with nothing.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.text.lines().next(), Some(dest.as_str()), "status: {}", r.text);
    assert_says(&r, "in sync", "status");
    assert_says(&r, &hexs(&addr_at(0)), "status");
    assert!(
        !r.text.contains("InSync {"),
        "status still prints the derived Debug:\n{}",
        r.text
    );
}

// ---------------------------------------------------------------------------
// send: the artifact, and the two residues printed beside it
// ---------------------------------------------------------------------------

/// The whole spend path, and **the three residues as they actually render**.
#[test]
fn send_prints_the_artifact_and_says_a_submission_is_not_a_verdict() {
    let id = id_for_the_spend("cli-send-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let r = run_on("cli-send", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Ok, "the spend did not go through: {}", r.text);

    // Residue 1: the retry artifact, labelled before it is emitted.
    assert_says(&r, "RETRY ARTIFACT", "send");
    assert_says(&r, "`resign` is the only recovery", "send");
    assert_says(&r, "SAME destination, amount, fee, block-to-live and reference", "send");

    // Residue 2: tx_val has never run offline.
    assert_says(&r, "passed every check that can be run offline", "send");
    assert_says(&r, "a rejection there is silent to this program", "send");

    // Residue 3: submission is a socket write.
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "send");
    assert_says(&r, "computed locally", "send");
    assert_says(&r, "not the node's", "send");
}

/// A failed submission leaves the reservation open and says the artifact is
/// the only copy — exit code 3, because the command did not happen.
#[test]
fn a_failed_submission_is_refused_and_says_the_artifact_is_the_only_copy() {
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let r = run_on("cli-send-fail", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "RETRY ARTIFACT", "a failed submit");
    assert_says(&r, "the only copy", "a failed submit");
}

/// More than the balance is refused before anything is reserved.
#[test]
fn send_refuses_more_than_the_balance_with_code_3() {
    let mut s = spend();
    s.dsts[0].amount = Some(9_000_000);
    let r = run_on(
        "cli-send-broke",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 1_000))]),
        &Command::Send(s),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
}

// ---------------------------------------------------------------------------
// settle and resign: the reservation's two resolutions
// ---------------------------------------------------------------------------

/// Chain state: the tag has moved to the change key. Settling clears the
/// reservation.
#[test]
fn settle_clears_the_reservation_when_the_chain_shows_the_change_key() {
    let id = id_for_the_spend("cli-settle-id");
    let (_dir, ks) = store("cli-settle");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let sent = cli::run(ks, MeshClient::new(chain), &Command::Send(spend()),
    );
    assert_eq!(sent.code, Code::Ok, "{}", sent.text);

    // The store is at position 1 now; move the chain to the change key.
    let (_dir2, ks2) = store("cli-settle-2");
    let mut ks2 = ks2;
    let receipt = ks2
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let r = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_000_000))])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "settled", "settle");
}

/// Chain state: the tag is still at the key that signed. Settling does not
/// settle, and says why in the operator's terms.
#[test]
fn settle_says_not_settled_while_the_chain_still_holds_the_spent_key() {
    let (_dir, ks) = store("cli-settle-out");
    let mut ks = ks;
    let receipt = ks
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "NOT settled", "settle");
    assert_says(&r, "socket write, not a verdict", "settle");
    assert_says(&r, "`resign` rebuilds it", "settle");
}

/// `resign` on a plan that is not the reserved one is refused by name, and the
/// message says what to do — nothing was signed.
#[test]
fn resign_refuses_a_different_spend_and_says_nothing_was_signed() {
    let (_dir, ks) = store("cli-resign-wrong");
    let mut ks = ks;
    let receipt = ks
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let mut s = spend();
    s.dsts[0].amount = Some(999); // not what was reserved
    // The socket is held, not only the page: `resign`
    // ships what it reproduces, so the property this test carries is that a
    // plan that is not the reserved one puts NOTHING on the socket. The log
    // assertion sits between the code and the needles on purpose -- under
    // injection (a fault row with the digest comparison deleted) the
    // panic must name this line, not a needle the wrong page still carries.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_eq!(
        log.borrow().len(),
        0,
        "a resign of a plan that is not the reserved one put {} body(ies) on the socket:\n{}",
        log.borrow().len(),
        r.text
    );
    assert_says(&r, "not the spend that was reserved", "resign");
    assert_says(&r, "Nothing was signed", "resign");
}

/// **`resign` after the spend it reserved has already landed names `settle`,
/// and is not I4's divergence.**
///
/// A run against mainnet reached this state by the commonest mistaken route
/// to the verb -- `resign` after a `send` that actually worked -- and got the
/// chain-address guard's page: I4's divergence, three causes, "do not advance
/// the index by hand; reconcile". **None of the three applied.** The spend
/// had settled; `settle` handled the identical state one command later in a
/// single line, which is what demonstrated the finding rather than arguing it.
///
/// No test in the board could reach it: every `resign` test scripts the chain
/// at the key that signed, because that is the state the verb is *for*. This
/// one scripts the change key instead.
///
/// The three needles it forbids are quoted from the page it replaces. The one
/// about what was NOT established is the other half: the classifier says
/// `SpendLanded` from one observation, and a change address follows the
/// position rather than the transaction, so the chain standing here does not
/// name which transaction put it there -- the page must not trade one
/// over-confident answer for another.
#[test]
fn resign_after_the_spend_landed_names_settle_and_not_a_divergence() {
    let (dir, _artifact) = send_that_never_left("cli-resign-landed");
    // The chain has moved to the change key: what a landed spend looks like,
    // and the state `settle` resolves.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_998_500))]);
    let log = chain.submit_log();
    let ks = reopen("resign landed", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_eq!(
        log.borrow().len(),
        0,
        "a resign over a landed spend put {} body(ies) on the socket:\n{}",
        log.borrow().len(),
        r.text
    );

    // What the page says, in the order it says it: the observation first, the
    // classification second, the verb third, the limit last. The opening
    // sentence is what the chain was seen to do, not what that is concluded
    // to mean. `settle`'s own page is entitled to lead with the conclusion,
    // because acting on it is its job; this one is refusing.
    assert_says(&r, "the chain has moved past the key this reservation holds", "resign over a landed spend");
    assert_says(&r, "the state reconciliation calls a landed spend", "resign over a landed spend");
    assert_says(&r, "at the key at position 1", "resign over a landed spend");
    assert_says(&r, "the reservation at position 0", "resign over a landed spend");
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &format!("`settle {src}`"), "resign over a landed spend");

    // What it does not claim: the observation, not a settlement.
    assert_says(&r, "not which transaction put it there", "resign over a landed spend");

    // And it is not the page it replaces. Each needle is a claim that does
    // not hold in this state.
    for wrong in ["three causes", "do not advance the index by hand", "reconcile"] {
        assert!(
            !r.text.contains(wrong),
            "the landed page still carries the divergence page's {wrong:?}:\n{}",
            r.text
        );
    }

    // The store is untouched: index 1 with the reservation still open, which
    // is `settle`'s to clear and not this verb's.
    assert_eq!(stored_index(&dir), 1, "a refused resign moved the stored index");
    let ks = reopen("resign landed after", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).is_some_and(|v| v.pending.is_some()),
        "a refused resign resolved the reservation"
    );
}

/// **`send` over the same chain state is unchanged: it refuses as a
/// divergence and never reaches the landed page.**
///
/// The pair to the test above, and the one that goes red if the landed-spend
/// refusal is ever moved down into `SpendPlan::new` where both verbs would
/// inherit it. With no reservation open, a chain standing one key on is an
/// account some other signer moved -- I4's case exactly -- and the wallet
/// refuses at startup before `send` lays anything out. The planner's own half
/// of this claim is in `tests/spend.rs`.
#[test]
fn send_over_a_chain_one_key_on_is_still_a_divergence_and_never_the_landed_page() {
    let r = run_on(
        "cli-send-one-on",
        Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_998_500))]),
        &Command::Send(spend()),
    );
    assert_eq!(r.code, Code::StartupRefused, "output: {}", r.text);
    assert_says(&r, "WALLET WILL NOT START", "send over a chain one key on");
    assert_says(&r, "a second wallet live on this seed", "send over a chain one key on");
    for wrong in ["already landed", "nothing left to reproduce", "`settle"] {
        assert!(
            !r.text.contains(wrong),
            "`send` was given `resign`'s landed page ({wrong:?}), which no `send` state can be:\n{}",
            r.text
        );
    }
}

/// A `send` whose socket write failed, in process: the reservation is open
/// and the page carries the artifact. The two `resign` tests below start
/// here; the recovery markers have their own child-process form of it
/// (`p10_send_that_never_left`).
fn send_that_never_left(name: &str) -> (ScratchDir, String) {
    send_that_never_left_with(name, &spend())
}

/// [`send_that_never_left`] over any `Spend`, for the reference tests.
fn send_that_never_left_with(name: &str, s: &Spend) -> (ScratchDir, String) {
    let (dir, ks) = store(name);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s.clone()));
    assert_eq!(r.code, Code::Refused, "premise: a send through a refusing socket did not exit 3:\n{}", r.text);
    let artifact = r
        .text
        .lines()
        .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("premise: send's page carries no artifact line:\n{}", r.text))
        .to_owned();
    (dir, artifact)
}

/// **`submit` ships the artifact it is given, as it is, and touches nothing
/// else**. The refusals first, with the chain's
/// submit log read after each: not hex, hex that is no transaction, and the
/// artifact one byte short -- a length `from_wire` accepts and zero-extends,
/// which is exactly the case the byte-identity check exists for -- each exit
/// 3 saying nothing was written, with the log still empty. Then the artifact
/// `send` printed, through `cli::run` with a store handed in as the child
/// probe drives it: exit 0, the log holding that artifact byte for byte as
/// its `signed_transaction`, the page carrying `send`'s `submitted:` block
/// naming `settle` with the SOURCE, and the store as `send` left it -- index
/// 1, the reservation open -- because the verb writes nothing.
#[test]
fn submit_ships_a_saved_artifact_as_it_is_and_refuses_what_is_not_one_before_the_socket() {
    let (dir, artifact) = send_that_never_left("cli-submit");
    let id = id_for_the_spend("cli-submit-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);
    let truncated = artifact[..artifact.len() - 2].to_owned();
    let cases: [(&str, &str); 3] = [
        ("zz", "is not hex"),
        ("00ff", "does not parse as a transaction"),
        (truncated.as_str(), "is not a whole transaction image"),
    ];
    for (input, why) in cases {
        let shown = &input[..input.len().min(16)];
        let r = cli::run_submit(&client, input);
        assert_eq!(r.code, Code::Refused, "`submit {shown}...` did not exit 3:\n{}", r.text);
        assert!(r.text.contains(why), "the refusal for `{shown}...` does not say the artifact {why}:\n{}", r.text);
        assert!(
            r.text.contains("Nothing was written to the socket"),
            "the refusal for `{shown}...` does not say nothing was written:\n{}",
            r.text
        );
        assert!(
            log.borrow().is_empty(),
            "a refused artifact reached the socket: {} body(ies) after `{shown}...`",
            log.borrow().len()
        );
    }

    let settle_arg = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let ks = reopen("submit", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, client, &Command::Submit { artifact: artifact.clone() });
    assert_eq!(r.code, Code::Ok, "submit of the artifact send printed did not exit 0:\n{}", r.text);
    assert_says(&r, "submitted: the node accepted the SOCKET WRITE", "submit");
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "submit");
    assert_says(&r, &format!("Run `settle {settle_arg}`"), "submit");
    assert_says(&r, "No store was opened and no password asked", "submit");
    let bodies = log.borrow().clone();
    assert_eq!(bodies.len(), 1, "the chain saw {} submit body(ies), not one", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&hexs(&bodies[0])).as_deref(),
        Some(artifact.as_str()),
        "the submit body does not carry the artifact byte for byte"
    );
    assert_eq!(stored_state(&dir), (1, true), "submit changed the store; it writes nothing");
    println!("  submit: three refusals with the socket untouched, then one body carrying the artifact");
}

/// `send` writes a zero destination reference, byte for byte, at the offset
/// the wire layout documents: bytes 20..36 of the one destination, which
/// begins at image offset 116. Pinned because a `--ref` flag was asked for
/// and deferred: the node's reference grammar is
/// restated nowhere in this repository and the corpus records its verdict
/// on one accepted and one rejected value only, so the flag cannot be
/// validated offline against the reference. Until it can, the field is
/// zero and this says so.
#[test]
fn send_writes_a_zero_destination_reference_at_the_documented_offset() {
    let (_dir, artifact) = send_that_never_left("cli-zero-ref");
    let mut bytes = Vec::with_capacity(artifact.len() / 2);
    for i in (0..artifact.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&artifact[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")));
    }
    let tx = mochimo_crypto::tx::wire::Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.dsts().len(), 1);
    assert_eq!(tx.dsts()[0].reference, [0u8; 16], "send wrote a non-zero destination reference");
    assert_eq!(&bytes[116 + 20..116 + 36], &[0u8; 16], "the reference bytes at image offset 136..152 are not zero");
    assert_eq!(&bytes[116..116 + 20], &TO[..], "the destination tag is not at image offset 116");
    println!("  zero reference: send's one destination carries sixteen zero reference bytes at image offset 136..152");
}

/// `send --ref AB-00-EF` lays the reference out at the offset the wire
/// layout documents, bytes 20..36 of the one destination at image offset
/// 116, NUL-padded: the twin of the zero-reference pin above, which still
/// holds for a `send` without the flag.
#[test]
fn send_with_a_reference_lays_it_out_at_the_documented_offset() {
    let s = spend_with_reference("AB-00-EF");
    let (_dir, artifact) = send_that_never_left_with("cli-ref-offset", &s);
    let bytes = bytes_of(&artifact);
    let tx = mochimo_crypto::tx::wire::Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.dsts().len(), 1);
    assert_eq!(tx.dsts()[0].reference, *b"AB-00-EF\0\0\0\0\0\0\0\0", "the destination does not carry the reference NUL-padded");
    assert_eq!(&bytes[116 + 20..116 + 36], b"AB-00-EF\0\0\0\0\0\0\0\0", "the reference is not at image offset 136..152");
    assert_eq!(&bytes[116..116 + 20], &TO[..], "the destination tag is not at image offset 116");
    println!("  reference offset: send --ref AB-00-EF carries the field at image offset 136..152, NUL-padded, the tag at 116");
}

/// A reference the node's rule refuses is a usage error at parse time,
/// naming the flag, the value and the rule's words -- before any prompt,
/// store or socket, as every argv refusal is -- and `--ref` given twice is
/// the repeated-flag refusal. The rule's own accepted examples parse to the
/// NUL-padded field.
#[test]
fn a_refused_reference_is_a_usage_error_with_the_rules_words() {
    let tag = format!("0x{}", hexs(&TAG));
    let to = format!("0x{}", hexs(&TO));
    let with = |extra: &[&str]| {
        let mut a = vec!["--dir", "/d", "--node", "n", "send", &tag, &to, "1000"];
        a.extend_from_slice(extra);
        args::parse(&argv(&a))
    };
    let mut refused = 0usize;
    for value in ["AB-CD-EF", "123-456-789", "ABC-", "-123", "ab-00-ef", "AB 00", "AB--00", "AB-12-CD-34-EF-56"] {
        match with(&["--ref", value]) {
            Err(u) => {
                assert!(u.0.starts_with("--ref: `") && u.0.contains(value), "--ref {value}: the refusal does not name the flag and the value: {}", u.0);
                assert!(u.0.contains(args::REFERENCE_RULE), "--ref {value}: the refusal does not carry the rule's words: {}", u.0);
                assert!(u.0.contains("AB-00-EF") && u.0.contains("single dashes"), "--ref {value}: the rule's words are not the rule: {}", u.0);
                refused += 1;
            }
            Ok(other) => panic!("--ref {value} was accepted: {other:?}"),
        }
    }
    match with(&["--ref", "AB", "--ref", "CD"]) {
        Err(u) => assert_eq!(u.0, "--ref given twice"),
        Ok(other) => panic!("--ref twice was accepted: {other:?}"),
    }
    let mut accepted = 0usize;
    for (value, field) in [("AB-00-EF", *b"AB-00-EF\0\0\0\0\0\0\0\0"), ("123-CDE-789", *b"123-CDE-789\0\0\0\0\0"), ("ABC", *b"ABC\0\0\0\0\0\0\0\0\0\0\0\0\0"), ("123", *b"123\0\0\0\0\0\0\0\0\0\0\0\0\0")] {
        match with(&["--ref", value]) {
            Ok(args::ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => assert_eq!(s.dsts[0].reference, field, "--ref {value} did not lay out NUL-padded"),
                other => panic!("--ref {value} parsed to {other:?}"),
            },
            other => panic!("--ref {value} was refused or read as help: {other:?}"),
        }
        accepted += 1;
    }
    println!("  reference refusals: {refused} values refused at parse time with the rule's words, `--ref` twice refused by name, {accepted} of the node's own examples laid out NUL-padded");
}

/// `resign --ref` reproduces the artifact `send --ref` printed, byte for
/// byte on the socket, and `resign` without the reference is refused as a
/// different transaction by the digest check that already exists, the page
/// naming the reference among the figures to retype, with nothing on the
/// socket and the store untouched.
#[test]
fn resign_with_the_reference_reproduces_the_artifact_and_without_it_is_refused() {
    let s = spend_with_reference("AB-00-EF");
    let (dir, artifact) = send_that_never_left_with("cli-ref-resign", &s);
    let id = id_for("cli-ref-resign-id", &s);

    // With the reference: reproduced and shipped.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign with ref", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s.clone()));
    assert_eq!(r.code, Code::Ok, "resign with the reference did not exit 0:\n{}", r.text);
    assert_says(&r, "       ref AB-00-EF", "resign's page");
    assert_says(&r, &artifact, "resign's page");
    let shipped: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(shipped.len(), 1, "resign with the reference put {} body(ies) on the socket", shipped.len());
    assert_eq!(p10_signed_transaction_of(&shipped[0]).as_deref(), Some(artifact.as_str()), "the body is not the artifact send --ref printed");
    assert_eq!(&bytes_of(&artifact)[136..152], b"AB-00-EF\0\0\0\0\0\0\0\0", "the reproduced artifact does not carry the reference");

    // Without it: a different transaction, refused before the socket.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign without ref", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "resign without the reference did not exit 3:\n{}", r.text);
    assert_says(&r, "not the spend that was reserved", "resign without the reference");
    assert_says(&r, "block-to-live or reference differs", "resign without the reference");
    assert_says(&r, "`--ref` included if one was given", "resign without the reference");
    assert_says(&r, "Nothing was signed", "resign without the reference");
    assert!(log.borrow().is_empty(), "resign without the reference put {} body(ies) on the socket", log.borrow().len());
    assert_eq!(stored_state(&dir), (1, true), "the store moved");
    println!("  resign with the reference: one body, the artifact byte for byte, `reference AB-00-EF` on the page; without it: refused as a different transaction naming the reference, nothing on the socket");
}

/// The index and whether a reservation is open, read back from disk.
fn stored_state(dir: &ScratchDir) -> (u32, bool) {
    let ks = reopen("stored state", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks
        .view(&TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the store no longer holds the account"));
    (v.wots_index.get(), v.pending.is_some())
}

/// **`resign` submits what it reproduces**, and says of
/// the write exactly what `send` says.
///
/// What is asserted here is the socket, then the page, then the store, and
/// the artifact compared against is the one `send` printed -- two
/// productions of one signature, not one value looked for in itself. The
/// chain's submit log holds exactly one body and its `signed_transaction`
/// is that artifact byte for byte; the page carries it, the SAME-bytes
/// sentence, and the three lines of `send`'s Ok arm -- the socket write is
/// not a verdict, the id was computed locally, `settle <src>` is what comes
/// next, with the SOURCE destination (a fault row hands it the
/// destination's); `HELP` says the verb submits; and the store is unchanged
/// by the write, index 1 with the reservation still open, because `settle`
/// is what clears it and `resign` writes nothing
/// (`Keystore::resign_reserved` takes `&self`).
#[test]
fn resign_submits_what_it_reproduces_and_says_a_submission_is_not_a_verdict() {
    let (dir, artifact) = send_that_never_left("cli-resign-ships");
    let id = id_for_the_spend("cli-resign-ships-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign ships", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);

    // The socket.
    let bodies: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(bodies.len(), 1, "the chain saw {} submit body(ies); resign writes the socket once", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&bodies[0]).as_deref(),
        Some(artifact.as_str()),
        "the body on the socket does not carry the artifact send printed"
    );

    // The page.
    assert_says(&r, &artifact, "resign");
    assert_says(&r, "SAME bytes the original signing produced", "resign");
    assert_says(&r, "submitted: the node accepted the SOCKET WRITE", "resign");
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "resign");
    assert_says(&r, "computed locally", "resign");
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &format!("Run `settle {src}`"), "resign");
    assert_says(&r, &format!("id {}", hexs(&id)), "resign");

    // The help, where the verb's behaviour is described (`settle`'s text is
    // kept out of it, on purpose).
    assert!(
        args::HELP.contains("rebuild a lost retry artifact and submit it"),
        "HELP's resign entry does not say the verb submits:\n{}",
        args::HELP
    );

    // The store.
    assert_eq!(stored_state(&dir), (1, true), "resign moved the store; settle is what clears the reservation");

    // The body itself, on the green path, so the board log carries what
    // went on the socket rather than a sentence about it (failure-path text
    // is invisible to a passing suite). It is byte-identical to the body the recovery marker's child chain
    // records: same store seed, same spend, one deterministic signature,
    // and `request_submit`'s only other field is a constant.
    println!(
        "  submit body on the socket ({} bytes): {}",
        log.borrow()[0].len(),
        String::from_utf8_lossy(&log.borrow()[0])
    );
}

/// A refused socket write under `resign` is exit 3, the artifact is on the
/// page, the sentence is `resign`'s own -- the bytes are NOT the only copy,
/// because this command reproduces them, and whether they reached the node
/// is not known here -- and the store is untouched.
///
/// The exit code is `send`'s for the reason `Code` gives: the command's
/// purpose now includes the write, and a write that did not happen is a
/// command that did not happen. The refused write is still a
/// write the chain saw, so the log holds it, and it carries the artifact.
///
/// What this cannot see is the STREAM: `cli::run` returns a `Report`, and
/// `mcm-wallet.rs::main` puts an exit-3 report on stderr. The composition
/// -- this test's exit 3, and the pty suite's exit-3 pages landing on stderr
/// with stdout empty -- is made directly by
/// `pty::resign_on_a_real_pty_completes_the_recovery_send_could_not`.
#[test]
fn resign_through_a_refusing_socket_is_refused_and_keeps_the_reservation() {
    let (dir, artifact) = send_that_never_left("cli-resign-refused");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let log = chain.submit_log();
    let ks = reopen("resign refused", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, &artifact, "a refused resign");
    assert_says(&r, "submission FAILED", "a refused resign");
    assert_says(&r, "not known here", "a refused resign");
    assert_says(&r, "tries the socket again", "a refused resign");
    assert!(
        !r.text.contains("the only copy"),
        "resign's refusal borrowed send's sentence; after resign the artifact is not the only copy:\n{}",
        r.text
    );
    assert!(!r.text.contains("submitted:"), "a refused write said submitted:\n{}", r.text);
    let bodies: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(bodies.len(), 1, "the refused write is still a write the chain saw; it saw {}", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&bodies[0]).as_deref(),
        Some(artifact.as_str()),
        "the refused body does not carry the artifact"
    );
    assert_eq!(stored_state(&dir), (1, true), "a refused resign moved the store");
}

// ---------------------------------------------------------------------------
// reconcile: the acknowledgement gate, from the operator's side
// ---------------------------------------------------------------------------

/// The number the operator types must be the number the report named --
/// asserted as the rendered refusal and the untouched store.
///
/// Asserting `Code::StartupRefused` here would assert what a RIGHT number
/// produces too: behind `Wallet::open` the command refuses on the divergence
/// it was started to reconcile, and the mismatch check never runs.
#[test]
fn reconcile_refuses_an_advance_to_that_does_not_match_the_report() {
    let (dir, r) = run_on_keeping(
        "cli-reconcile-wrong",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Reconcile {
            tag: TAG,
            advance_to: 7,
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "--advance-to 7 does not match the index this divergence reports (2)", "reconcile");
    assert_says(&r, "Nothing was written", "reconcile");
    assert_eq!(stored_index(&dir), 0, "a refused reconcile moved the index");

    // The sibling arm: a number that is not a mismatch against a report but
    // a divergence advancing cannot remedy -- local ahead of the chain.
    let (dir2, ks) = store("cli-reconcile-behind");
    let mut ks = ks;
    let _ = ks.persist_advance_to(&TAG, mochimo_crypto::account::WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("behind", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))])),
        &Command::Reconcile { tag: TAG, advance_to: 0 },
    );
    assert_eq!(r2.code, Code::Refused, "output: {}", r2.text);
    assert_says(&r2, "no advance to acknowledge", "reconcile behind");
    assert_says(&r2, "1 BEHIND local", "reconcile behind");
    assert_eq!(stored_index(&dir2), 1, "a behind divergence moved the index");
}

/// **The acknowledged path exists**: the number the report
/// named advances the store, the report is printed before the write, and
/// the store then reconciles -- an acknowledged advance that ends in the
/// startup refusal it was invoked to clear is a path with no exit.
#[test]
fn reconcile_with_the_number_the_report_named_advances_the_store() {
    let (dir, r) = run_on_keeping(
        "cli-reconcile-right",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Reconcile {
            tag: TAG,
            advance_to: 2,
        },
    );
    assert_eq!(r.code, Code::Ok, "THE ACKNOWLEDGED PATH IS NOT REACHABLE: {}", r.text);
    assert_says(&r, "THE STORE BEFORE THIS DECISION: 1 of 1 account(s) diverged", "reconcile");
    assert_says(&r, "key at index 2 -- 2 ahead of local", "reconcile");
    assert_says(&r, "SECOND WALLET", "reconcile");
    assert_says(&r, &format!("advanced account 0x{} to index 2", hexs(&TAG)), "reconcile");
    assert_eq!(stored_index(&dir), 2, "the advance did not reach disk");

    // And the store now opens: `balance` is in sync at index 2.
    let ks = reopen("after reconcile", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let b = cli::run(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))])), &Command::Balance);
    assert_eq!(b.code, Code::Ok, "balance after the advance: {}", b.text);
    assert_says(&b, "index 2", "balance");
    assert_says(&b, "in sync", "balance");
}

/// **An index the operator names is derived and compared, never trusted**
///. The chain at 100, past the window and the ceiling:
/// naming 99 is refused with nothing written; naming 5000 is refused naming
/// the index the walk actually found; naming 100 advances.
#[test]
fn reconcile_refuses_an_index_the_chain_does_not_confirm_and_writes_nothing() {
    let far = || Chain::new(&[(TAG, ChainState::At(addr_at(100), 9))]);
    let (d1, r1) = run_on_keeping("cli-reconcile-99", far(), &Command::Reconcile { tag: TAG, advance_to: 99 });
    assert_eq!(r1.code, Code::Refused, "99 was accepted: {}", r1.text);
    assert_says(&r1, "no advance to acknowledge", "reconcile 99");
    assert_says(&r1, "indices 0 through 99", "reconcile 99");
    assert_eq!(stored_index(&d1), 0, "naming 99 moved the index");

    let (d2, r2) = run_on_keeping("cli-reconcile-5000", far(), &Command::Reconcile { tag: TAG, advance_to: 5000 });
    assert_eq!(r2.code, Code::Refused, "5000 was accepted: {}", r2.text);
    assert_says(&r2, "--advance-to 5000 does not match the index this divergence reports (100)", "reconcile 5000");
    assert_eq!(stored_index(&d2), 0, "naming 5000 moved the index");

    let (d3, r3) = run_on_keeping("cli-reconcile-100", far(), &Command::Reconcile { tag: TAG, advance_to: 100 });
    assert_eq!(r3.code, Code::Ok, "the confirmed index was refused: {}", r3.text);
    assert_says(&r3, "key at index 100 -- 100 ahead of local", "reconcile 100");
    assert_eq!(stored_index(&d3), 100, "the confirmed advance did not reach disk");
}

/// **The whole store is read before the write, and a spend this wallet did
/// not make on ANY account refuses the advance**: a second
/// account with a reservation the chain explains at neither of its keys is
/// the live-second-wallet signal, and advancing the first would hand that
/// wallet the key at the named index too.
#[test]
fn reconcile_refuses_to_advance_while_another_account_shows_a_spend_this_wallet_did_not_make() {
    let m = master();
    let other = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let other_at = |i: u32| mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(i));
    let two_accounts = |name: &str| -> (ScratchDir, Keystore) {
        let (dir, mut ks) = store(name);
        ks.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("{e}"));
        // Account 1 reserves a spend at index 0.
        // The figures match the balance of 1 the control arm scripts for this
        // account, so its reservation reads live there.
        let _ = ks
            .persist_advance(&other, &[0xD1; 32], Figures { reserved_balance: 1, blk_to_live: 0 })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(ks);
        let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        (dir, ks)
    };

    // Account 1's chain address is at neither its spent key (0) nor its
    // change key (1): something else spent from this seed.
    let (dir, ks) = two_accounts("cli-second-wallet");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(2), 9)),
            (other, ChainState::At(other_at(5), 1)),
        ])),
        &Command::Reconcile { tag: TAG, advance_to: 2 },
    );
    assert_eq!(r.code, Code::Refused, "advanced past a second-wallet signal: {}", r.text);
    assert_says(&r, "NOT ADVANCED", "reconcile");
    assert_says(&r, "SECOND WALLET", "reconcile");
    assert_says(&r, &format!("Account 0x{}", hexs(&other)), "reconcile");
    assert_says(&r, "2 of 2 account(s) diverged", "reconcile");
    assert_eq!(stored_index(&dir), 0, "the advance went through despite the signal");

    // The control: account 1's reservation still outstanding on the chain
    // (its spent key's address) is a known state, and the advance proceeds.
    let (dir2, ks2) = two_accounts("cli-second-wallet-control");
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(2), 9)),
            (other, ChainState::At(other_at(0), 1)),
        ])),
        &Command::Reconcile { tag: TAG, advance_to: 2 },
    );
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_eq!(stored_index(&dir2), 2);
}

// ---------------------------------------------------------------------------
// status: before the gate
// ---------------------------------------------------------------------------

/// `status` reports a divergence rather than stopping on it -- exit 0, the
/// report and the in-program next step, nothing written -- and with
/// `--scan-to` it finds a far-along index the default walk does not reach.
/// Behind the gate, as it once was, every case here was the startup refusal.
#[test]
fn status_reports_a_divergence_without_opening_a_wallet() {
    let (dir, r) = run_on_keeping(
        "cli-status-diverged",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "status on a divergence did not report: {}", r.text);
    assert_says(&r, "DIVERGED", "status");
    assert_says(&r, "key at index 2 -- 2 ahead of local", "status");
    assert_says(&r, &format!("reconcile 0x{} --advance-to 2", hexs(&TAG)), "status");
    assert!(!r.text.contains("WALLET WILL NOT START"), "status rendered the startup refusal:\n{}", r.text);
    assert_eq!(stored_index(&dir), 0, "status wrote to the store");

    // Far along, out of reach of the walk: what was walked is said, and the
    // remedy is named. `--scan-to 19` sets the ceiling to 20, which is what
    // a ceiling of 10,000 finds a chain at 30 by itself (the case below), so
    // the out-of-reach rendering
    // needs a ceiling that is named. A target past the default instead
    // would cost an exhausted ten-thousand-position walk, about 7 m 24 s in
    // this profile.
    let r2 = run_on(
        "cli-status-far",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: Some(19) },
    );
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "NO key index this scan walked", "status far");
    assert_says(&r2, "indices 0 through 19", "status far");
    assert_says(&r2, &format!("status 0x{} --scan-to <M>", hexs(&TAG)), "status far");
    assert!(!r2.text.contains("does not own this tag, or"), "the closed disjunction:\n{}", r2.text);

    // And what the raised ceiling is FOR: with no `--scan-to` at all, the
    // default of 10,000 reaches index 30 and names it.
    let r2d = run_on(
        "cli-status-far-default",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r2d.code, Code::Ok, "{}", r2d.text);
    assert_says(&r2d, "key at index 30 -- 30 ahead of local", "status at the default ceiling");
    assert!(!r2d.text.contains("NO key index this scan walked"), "the default ceiling did not reach index 30:\n{}", r2d.text);
    let r3 = run_on(
        "cli-status-far-raised",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: Some(40) },
    );
    assert_eq!(r3.code, Code::Ok, "{}", r3.text);
    assert_says(&r3, "key at index 30 -- 30 ahead of local", "status --scan-to");
    assert_says(&r3, &format!("reconcile 0x{} --advance-to 30", hexs(&TAG)), "status --scan-to");
}

/// The access is chosen per account, before the gate too: a derived account
/// in a store with no master is told so by name, not "could not compare".
#[test]
fn status_names_the_missing_master_for_a_derived_account() {
    let dir = ScratchDir::new("cli-status-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))])),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "no master seed was supplied", "status without a master");
    assert!(!r.text.contains("could not compare"), "the generic failure, not the named one:\n{}", r.text);
}

/// A tag the store does not hold is refused by name, for `status` and
/// `reconcile` alike -- the arm `address` had and these two lacked.
#[test]
fn status_and_reconcile_refuse_a_tag_the_store_does_not_hold_by_name() {
    let other = mochimo_crypto::derive::derive_account_tag(&master(), 1);
    let chain = || Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))]);
    let r = run_on("cli-status-notheld", chain(), &Command::Status { tag: other, scan_to: None });
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "no account for the tag", "status");
    assert!(!r.text.contains("could not ask the question"), "{}", r.text);
    let r2 = run_on("cli-reconcile-notheld", chain(), &Command::Reconcile { tag: other, advance_to: 1 });
    assert_eq!(r2.code, Code::Refused, "{}", r2.text);
    assert_says(&r2, "no account for the tag", "reconcile");
}

/// **The startup refusal names the in-program next step per account**, only
/// on the arms one exists for: the `reconcile` line for an `Ahead`, the
/// search and then the line for an unlocated address, nothing for the rest.
#[test]
fn the_startup_refusal_names_the_next_step_only_where_one_exists() {
    let r = run_on("cli-next-ahead", Chain::new(&[(TAG, ChainState::At(addr_at(3), 9))]), &Command::Balance);
    assert_eq!(r.code, Code::StartupRefused);
    assert_says(&r, &format!("reconcile 0x{} --advance-to 3", hexs(&TAG)), "refusal, ahead");
    // Far ahead, and the default diagnostic reaches it: the startup page
    // names the advance for index 30 rather than a wider search.
    // `Wallet::open` takes no scope, so the UNLOCATED arm
    // cannot be reached here at any affordable cost -- the default ceiling
    // is 10,000 and an address no index reproduces walks all of them, about
    // 7 m 24 s in this profile. What that arm needs proved is split in two
    // and both halves are held: `next_steps`'s unlocated line is asserted
    // on the `status` page, which calls the same function, in
    // `status_reports_a_divergence_without_opening_a_wallet`; and that the
    // STARTUP page calls `next_steps` and respects its silence is the arm
    // above and the arm below.
    let r2 = run_on("cli-next-far", Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]), &Command::Balance);
    assert_eq!(r2.code, Code::StartupRefused);
    assert_says(&r2, &format!("reconcile 0x{} --advance-to 30", hexs(&TAG)), "refusal, far ahead");
    let r3 = run_on("cli-next-absent", Chain::new(&[(TAG, ChainState::Absent)]), &Command::Balance);
    assert_eq!(r3.code, Code::StartupRefused);
    assert!(!r3.text.contains("In this program"), "a next step was printed for an arm that has none:\n{}", r3.text);
}

// ---------------------------------------------------------------------------
// restore: the one command that holds a mutable store
// ---------------------------------------------------------------------------

/// The index comes from the chain. Position 0 is a match like any other.
#[test]
fn restore_takes_the_index_from_the_chain_and_says_so() {
    let dir = ScratchDir::new("cli-restore");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    // `restore` derives from the master, and the master comes out
    // of the store rather than off the terminal -- so a store that has not
    // adopted one refuses, correctly, with the no-master message.
    let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 11))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "index    3", "restore");
    assert_says(&r, "(from the chain, never assumed)", "restore");
    assert_says(&r, "a match like any other, never a default", "restore");
    assert_says(&r, "added to the store", "restore");
}

/// **`restore` never moves an account the store already holds**. It once
/// advanced one whenever the chain was ahead --
/// no report, no acknowledgement, exit 0 -- which is the silent advance I4
/// makes unrepresentable everywhere else.
#[test]
fn restore_does_not_touch_an_account_the_store_already_holds() {
    let (dir, r) = run_on_keeping(
        "cli-restore-held",
        Chain::new(&[(TAG, ChainState::At(addr_at(3), 11))]),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "index    3", "restore");
    assert_says(&r, "ALREADY IN THE STORE, at index 0 -- and NOT moved", "restore");
    assert_says(&r, &format!("reconcile 0x{} --advance-to 3", hexs(&TAG)), "restore");
    assert_eq!(stored_index(&dir), 0, "restore advanced an account the store already held");
}

/// **A raised ceiling restores a far-along account, in one write**.
#[test]
fn restore_with_a_raised_ceiling_finds_a_far_along_account() {
    let fresh = |name: &str| -> (ScratchDir, Keystore) {
        let dir = ScratchDir::new(name);
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
        (dir, ks)
    };
    // A ceiling the account is past: refused, counting what it walked.
    // `--scan-to 19` is a ceiling of 20; a target past the DEFAULT would
    // need an exhausted ten-thousand-position walk, about 7 m 24 s in this
    // profile.
    let (_d1, ks1) = fresh("cli-restore-far-bounded");
    let r1 = cli::run(
        ks1,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: Some(19) },
    );
    assert_eq!(r1.code, Code::Refused, "output: {}", r1.text);
    assert_says(&r1, "none of key indices 0 through 19", "restore far");
    assert_says(&r1, "restore --account 0 --scan-to <M>", "restore far");

    // And what the raised ceiling is FOR: with no `--scan-to`, the default
    // of 10,000 finds index 30 and stores the account there, where a lower
    // one makes an operator who has spent thirty times pass a flag.
    let (d1d, ks1d) = fresh("cli-restore-far-default");
    let r1d = cli::run(
        ks1d,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r1d.code, Code::Ok, "the default ceiling did not restore an account at index 30: {}", r1d.text);
    assert_says(&r1d, "index    30", "restore at the default ceiling");
    assert_eq!(stored_index(&d1d), 30, "the restored account is not at the found index");

    let (d2, ks2) = fresh("cli-restore-far-raised");
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: Some(40) },
    );
    assert_eq!(r2.code, Code::Ok, "output: {}", r2.text);
    assert_says(&r2, "index    30", "restore --scan-to");
    assert_says(&r2, "added to the store at that index, in one write", "restore --scan-to");
    assert_eq!(stored_index(&d2), 30, "the restored account is not at the found index");
}

/// A tag the ledger does not hold has no index to derive. Fail, never zero.
#[test]
fn restore_refuses_a_tag_the_chain_does_not_hold() {
    let dir = ScratchDir::new("cli-restore-absent");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
}

/// An unreachable chain during restore fails closed — I5's clause is
/// unconditional.
#[test]
fn restore_fails_closed_when_the_chain_is_unreachable() {
    let dir = ScratchDir::new("cli-restore-down");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
}

/// Restore needs the master by definition, and says so rather than guessing.
#[test]
fn restore_without_a_master_is_refused() {
    let dir = ScratchDir::new("cli-restore-nomaster");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "master seed", "restore");
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

fn argv(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

#[test]
fn the_parser_accepts_the_recorded_flow() {
    let inv = match args::parse(&argv(&[
        "--dir", "/tmp/d", "--node", "https://n", "send", &prefixed(&TAG), &prefixed(&TO), "1000",
    ]))
    .unwrap_or_else(|e| panic!("{e}"))
    {
        args::ParsedArgv::Run(i) => i,
        args::ParsedArgv::Help => panic!("a send invocation parsed as help"),
    };
    assert_eq!(inv.dir, "/tmp/d");
    assert_eq!(inv.node.as_deref(), Some("https://n"));
    assert_eq!(
        inv.command,
        Command::Send(Spend {
            tag: TAG,
            dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1000) }],
            fee_total: MFEE,
            blk_to_live: 0,
        })
    );
}

#[test]
fn the_parser_refuses_what_it_cannot_read() {
    let cases: [(&[&str], &str); 9] = [
        (&["--dir", "/d", "--node", "n"], "no command"),
        (&["--node", "n", "balance"], "--dir is required"),
        (&["--dir", "/d", "balance"], "--node is required"),
        (&["--dir", "/d", "--node", "n", "fly"], "unknown command"),
        // A short argument is diagnosed as a destination, because it
        // is not `0x`-prefixed. The hex arm keeps its own rows, reached only
        // through the prefix.
        (&["--dir", "/d", "--node", "n", "address", "zz"], "is not a destination"),
        (&["--dir", "/d", "--node", "n", "address", "0x00"], "hex characters"),
        (
            &["--dir", "/d", "--node", "n", "address", "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
            "not hexadecimal",
        ),
        // **Bare forty-hex is refused and told exactly what to do.** The
        // second half of the 80-character ledger address `address` prints is
        // also forty hex characters -- a tag nobody holds, and accepting the
        // bare form takes it without complaint.
        (
            &["--dir", "/d", "--node", "n", "address", "05ff0f69d4c1cd682ed3341c0b7773054b58800f"],
            "is a bare hex tag. Write it as `0x",
        ),
        (&["--dir", "/d", "--node", "n", "restore"], "--account"),
    ];
    for (a, needle) in cases {
        match args::parse(&argv(a)) {
            Ok(v) => panic!("{a:?} parsed to {v:?}; it should not have"),
            Err(u) => assert!(
                format!("{u}").contains(needle),
                "{a:?} was refused, but not for {needle:?}: {u}"
            ),
        }
    }
}

/// `--scan-to` on `status` and `restore`, `--advance-to` on `reconcile`: read
/// as key indices, the last index refused, and a flag where the tag should
/// be diagnosed as the missing tag.
#[test]
fn the_parser_reads_scan_to_and_refuses_the_last_index() {
    let tag = prefixed(&TAG);
    let run = |a: &[&str]| -> Command {
        match args::parse(&argv(a)).unwrap_or_else(|e| panic!("{a:?}: {e}")) {
            args::ParsedArgv::Run(i) => i.command,
            args::ParsedArgv::Help => panic!("{a:?} parsed as help"),
        }
    };
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "status", &tag, "--scan-to", "5"]),
        Command::Status { tag: TAG, scan_to: Some(5) }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "status", &tag]),
        Command::Status { tag: TAG, scan_to: None }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "restore", "--account", "0", "--scan-to", "7"]),
        Command::Restore { account: 0, scan_to: Some(7) }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "reconcile", &tag, "--advance-to", "4294967294"]),
        Command::Reconcile { tag: TAG, advance_to: u32::MAX - 1 }
    );
    let refused: [(&[&str], &str); 5] = [
        (&["--dir", "/d", "--node", "n", "reconcile", &tag, "--advance-to", "4294967295"], "out of range"),
        (&["--dir", "/d", "--node", "n", "status", &tag, "--scan-to", "4294967295"], "out of range"),
        (&["--dir", "/d", "--node", "n", "status", "--scan-to", "5"], "status needs <tag>"),
        (&["--dir", "/d", "--node", "n", "reconcile", "--advance-to", "5"], "reconcile needs <tag>"),
        (&["--dir", "/d", "--node", "n", "reconcile", &tag, "--scan-to", "5"], "unexpected argument"),
    ];
    for (a, needle) in refused {
        match args::parse(&argv(a)) {
            Ok(v) => panic!("{a:?} parsed to {v:?}; it should not have"),
            Err(u) => assert!(u.0.contains(needle), "{a:?} was refused, but not for {needle:?}: {}", u.0),
        }
    }
}

/// A typo'd flag is a usage error, not a silently ignored argument.
#[test]
fn the_parser_refuses_an_unknown_flag_rather_than_ignoring_it() {
    let r = args::parse(&argv(&[
        "--dir", "/d", "--node", "n", "send", &prefixed(&TAG), &prefixed(&TO), "1", "--fee-total", "9",
    ]));
    match r {
        Ok(v) => panic!("a typo'd flag was accepted: {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("unexpected argument"),
            "wrong refusal: {u}"
        ),
    }
}

/// Help is an outcome, not an error. All three spellings, and none of them
/// needs `--dir` or `--node` — asking for help before you know the flags is
/// the case that matters. It is recognised where a verb or a global flag is
/// -- before the verb, or as the verb -- and nowhere else: after the verb a
/// help spelling is a stray token like any other, refused by name. Winning
/// from anywhere in argv makes `send <tag> -h 5` print the help and exit 0.
#[test]
fn help_is_reachable_without_making_a_mistake() {
    for spelling in [vec!["-h"], vec!["--help"], vec!["help"]] {
        match args::parse(&argv(&spelling)) {
            Ok(args::ParsedArgv::Help) => {}
            Ok(args::ParsedArgv::Run(i)) => panic!("{spelling:?} parsed as a command: {i:?}"),
            Err(u) => panic!("{spelling:?} was a usage error, not help: {u}"),
        }
    }
    // And it survives being asked for alongside a real invocation, before
    // the verb.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "--help", "balance"])) {
        Ok(args::ParsedArgv::Help) => {}
        other => panic!("--help before a verb did not ask for help: {other:?}"),
    }
    // After the verb it is a stray token, refused by name.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "balance", "--help"])) {
        Err(u) => assert!(u.0.contains("unexpected argument `--help`"), "wrong refusal: {}", u.0),
        other => panic!("--help after the verb was not refused: {other:?}"),
    }
    assert!(
        args::HELP.contains("create") && args::HELP.contains("address"),
        "the help text does not mention the two commands that work before funding"
    );
    println!("CLI help: 4 spelling(s) reachable without a usage error");
}

/// The number of variants of the `enum` whose header is `header` in `src`:
/// lines at exactly four spaces of indent beginning with an uppercase letter
/// inside its brace-matched block. Fields sit at eight, doc comments start
/// with `/`, and the closing brace is not a letter, so nothing else counts.
fn enum_variants(src: &str, header: &str) -> usize {
    let start = src.find(header).unwrap_or_else(|| panic!("{header:?} not found in the source"));
    let rest = &src[start..];
    let open = rest.find('{').unwrap_or(0);
    let mut depth = 0usize;
    let mut end = rest.len();
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    rest[open..end]
        .lines()
        .filter(|l| l.starts_with("    ") && !l.starts_with("     "))
        .filter(|l| l[4..].starts_with(|c: char| c.is_ascii_uppercase()))
        .count()
}

/// `--node` is required exactly where a node is used, and the help says so.
///
/// # The finding this pins
///
/// An unconditional `--node is required` at the end of `parse`, reached by
/// every verb, contradicts three operator-facing texts saying `create` and
/// `address` need no node -- true of the socket, false of argv -- and both
/// commands then exit 1 without touching the store, so an operator following
/// the help can run neither. The rule lives in one place,
/// `Command::needs_node`, whose `match` has no wildcard, so an eleventh
/// verb is a compile error there rather than a silent default.
///
/// # The domain
///
/// Every verb, typed here with the least argv each accepts. The list is
/// an allow-list and cannot be derived from the artifact -- there is no way to
/// enumerate an enum's variants at runtime -- so the tie is the other way:
/// `needs_node`'s exhaustive `match` forces a decision for any new verb, and
/// the floor below makes an omission from this list a red rather than a
/// narrower check.
///
/// Both directions are walked for every verb: without `--node` the thirteen
/// refuse and the two parse to `node: None`; with it all fifteen parse and
/// keep it, because a supplied node is never refused, only an absent one.
/// Then the two texts an operator reads are held to the same rule.
#[test]
fn only_create_and_address_parse_without_a_node() {
    let tag = prefixed(&TAG);
    let to = prefixed(&TO);
    let hash = "0x18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
    let verbs: [(&str, Vec<&str>, bool); 15] = [
        ("create", vec!["create"], false),
        ("address", vec!["address"], false),
        ("balance", vec!["balance"], true),
        ("send", vec!["send", &tag, &to, "1"], true),
        ("settle", vec!["settle", &tag], true),
        ("resign", vec!["resign", &tag, &to, "1"], true),
        ("reconcile", vec!["reconcile", &tag, "--advance-to", "1"], true),
        ("restore", vec!["restore", "--account", "0"], true),
        ("status", vec!["status", &tag], true),
        ("submit", vec!["submit", "00"], true),
        // The four read-only verbs. They need a node like every other verb
        // that asks one anything; what is different about them is that they
        // open no store, which `opens_no_store` says and the pty test drives.
        ("transaction", vec!["transaction", hash], true),
        ("recent-transactions", vec!["recent-transactions", &tag], true),
        ("block", vec!["block", "1078535"], true),
        ("blocks", vec!["blocks"], true),
        // `discover` opens a store -- the master is in it -- so it is not one
        // of `opens_no_store`'s five; it asks a node once per index, so it
        // needs one.
        ("discover", vec!["discover"], true),
    ];
    // The domain, derived twice from the artifact so the typed table above
    // can be wrong: `Command`'s variants counted out of `args.rs`, and the
    // command lines of `HELP`. A new verb added to either without a row
    // here is a red here, which a count over the table alone could never be.
    // (It said "a tenth verb" while there were ten; the sentence is about
    // any new one.)
    let variants = enum_variants(include_str!("../src/cli/args.rs"), "pub enum Command {");
    assert_eq!(
        variants,
        verbs.len(),
        "`Command` has {variants} variant(s) and this table lists {}; add the verb here",
        verbs.len()
    );
    // Distinct VERBS, not usage lines: `send` and `resign` each spell two
    // forms (positional pairs, and `--destinations <path>`), and a
    // count of lines would call that a missing row.
    let help_verbs: std::collections::BTreeSet<&str> = args::HELP
        .lines()
        .filter(|l| l.starts_with("  ") && l.chars().nth(2).is_some_and(|c| c.is_ascii_lowercase()))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(
        help_verbs.len(),
        verbs.len(),
        "HELP names {} verb(s) {help_verbs:?} and this table {}",
        help_verbs.len(),
        verbs.len()
    );
    let mut walked = 0usize;
    let mut without = 0usize;
    for (verb, rest, needs) in &verbs {
        walked += 1;
        let mut a = vec!["--dir", "/d"];
        a.extend(rest.iter().copied());
        match args::parse(&argv(&a)) {
            Err(u) => {
                assert!(
                    *needs,
                    "`{verb}` without --node was refused, but it needs no node: {u}"
                );
                // `u.0`, the bare message, and not the rendered `Usage`: its
                // `Display` appends `HELP`, which names every verb, so a needle
                // on the rendered text would be true of any usage error at
                // all -- including the unconditional one this test exists to
                // rule out (a refutation panel's finding).
                assert!(
                    u.0.contains(&format!("--node is required for `{verb}`")),
                    "`{verb}` without --node was refused for the wrong reason, or the refusal \
                     does not name the verb: {}",
                    u.0
                );
            }
            Ok(args::ParsedArgv::Run(inv)) => {
                assert!(
                    !*needs,
                    "`{verb}` parsed WITHOUT --node, and it reconciles against a node first: \
                     the binary would dial nothing and the command would refuse later, or \
                     worse, not refuse"
                );
                assert_eq!(inv.node, None);
                assert!(!inv.command.needs_node(), "`{verb}` parsed without a node but says it needs one");
                without += 1;
            }
            Ok(args::ParsedArgv::Help) => panic!("`{verb}` parsed as help"),
        }
        // A loopback node, so every verb also shows that the plaintext gate
        // does not fire on the local case.
        let mut b = vec!["--dir", "/d", "--node", "http://127.0.0.1:8080"];
        b.extend(rest.iter().copied());
        match args::parse(&argv(&b)) {
            Ok(args::ParsedArgv::Run(inv)) => {
                assert_eq!(inv.node.as_deref(), Some("http://127.0.0.1:8080"), "`{verb}` dropped a supplied --node");
                assert_eq!(inv.command.needs_node(), *needs, "`{verb}`'s needs_node disagrees with this table");
            }
            other => panic!("`{verb}` with --node did not parse to a command: {other:?}"),
        }
    }
    assert_eq!(walked, verbs.len(), "the walk did not cover every verb");
    assert_eq!(without, 2, "exactly create and address run without a node");

    // The texts the operator reads, held to the parser. The usage line must
    // mark the flag optional and the closing sentence must name the two
    // commands and say the others require it. A text true of the socket and
    // false of argv misleads, and a parser that changes under a help text
    // that does not is the same defect from the other side.
    let usage = args::HELP.lines().next().unwrap_or_default();
    assert!(
        usage.contains("[--node <URL>]"),
        "the usage line does not mark --node optional: {usage:?}"
    );
    assert!(
        args::HELP.contains("create and address need no `--node`"),
        "the help's closing sentence no longer says which two commands run without a node"
    );
    println!("CLI node requirement: {walked} verb(s) walked, {without} run without a node");
}

/// Exit codes are distinct and a refusal is never 0.
#[test]
fn every_exit_code_is_distinct_and_no_refusal_is_zero() {
    let codes = [
        Code::Ok,
        Code::Usage,
        Code::StartupRefused,
        Code::Refused,
    ];
    let nums: Vec<i32> = codes.iter().map(|c| *c as i32).collect();
    assert_eq!(nums, vec![0, 1, 2, 3], "the exit codes moved");
    for c in &codes[1..] {
        assert_ne!(*c as i32, 0, "a refusal code is 0");
    }
    println!(
        "CLI exit codes: {} distinct, {} of them refusals, none zero",
        nums.len(),
        nums.len() - 1
    );
}

// ---------------------------------------------------------------------------
// create: the store, and the phrase
// ---------------------------------------------------------------------------

use mochimo_crypto::cli::create::{self as create_cmd, ENTROPY_LEN};

const ENTROPY: [u8; ENTROPY_LEN] = [0x5a; ENTROPY_LEN];

/// The phrase `ENTROPY` encodes, generated the way `orchestrate` generates it.
///
/// `create` takes a phrase -- generating one is the caller's step,
/// taken and confirmed before the write -- so the library-level tests below
/// generate it here, from the same entropy, and hand it in.
fn test_phrase() -> String {
    mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"))
        .expose()
        .to_string()
}

/// `create` over the test constants, on `dir`.
fn create_here(dir: &std::path::Path, words: &str) -> mochimo_crypto::Result<create_cmd::Created> {
    create_cmd::create(
        dir,
        words,
        keystore_harness::TEST_PASSWORD_STR,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
}

// ---------------------------------------------------------------------------
// The password floor: measured in characters, asked at the library entry
// point and at the prompt (the debt an audit filed)
// ---------------------------------------------------------------------------

/// An `MIN_PASSWORD_LEN - 1`-character password whose UTF-8 is at least
/// `MIN_PASSWORD_LEN` bytes: the input that tells a character count from a
/// byte count. Every test below that must discriminate uses it, so that the
/// byte-counting floor that once shipped reds all of them rather than none.
fn one_short_but_wide() -> String {
    let p = format!("{}é", "a".repeat(create_cmd::MIN_PASSWORD_LEN - 2));
    assert_eq!(p.chars().count(), create_cmd::MIN_PASSWORD_LEN - 1, "premise: one character short");
    assert!(p.len() >= create_cmd::MIN_PASSWORD_LEN, "premise: not short in bytes");
    p
}

/// **The floor counts characters, not bytes, and says so**.
///
/// `password_refusal` once compared `.len()` on the UTF-8 bytes
/// while its message said *character(s)* and interpolated the byte count.
/// The boundary from both sides in ASCII, where the two units agree; then
/// the discriminators, where they do not: one character short but twelve
/// bytes wide, three emoji, four CJK characters -- each refused, each with
/// the CHARACTER count rendered -- and twelve accented characters accepted,
/// because encoding raises the floor no more than it lowers it.
///
/// The number twelve is asserted by itself and the assertion names the
/// decision: the floor moving is a decision, and the red that
/// reports it should say where the decision lives. The boundary cases are
/// built from the constant, so they follow it.
#[test]
fn the_password_floor_counts_characters_not_bytes() {
    use create_cmd::{password_refusal, MIN_PASSWORD_LEN};
    assert_eq!(
        MIN_PASSWORD_LEN,
        12,
        "the password floor moved. Twelve is the encryption decision's floor (a floor under the search \
         space, no character-class rule); change it at cli::create::MIN_PASSWORD_LEN first, then here"
    );
    let at_floor = "a".repeat(MIN_PASSWORD_LEN);
    let one_short = "a".repeat(MIN_PASSWORD_LEN - 1);
    assert!(
        password_refusal(&at_floor).is_none(),
        "{MIN_PASSWORD_LEN} ASCII characters were refused; the floor is not inclusive"
    );
    let why = password_refusal(&one_short)
        .unwrap_or_else(|| panic!("{} ASCII characters were accepted", MIN_PASSWORD_LEN - 1));
    for needle in [
        format!("{} character", MIN_PASSWORD_LEN - 1),
        format!("fewer than {MIN_PASSWORD_LEN}"),
        "Nothing was created".to_string(),
    ] {
        assert!(why.contains(&needle), "the refusal does not say {needle:?} (the count, its unit as character, the floor): {why}");
    }

    // The discriminators: short in characters, not short in bytes.
    let wide = one_short_but_wide();
    let why = password_refusal(&wide).unwrap_or_else(|| {
        panic!(
            "{} characters were accepted because their UTF-8 is {} bytes: the floor counts bytes \
             while the message says character(s), and eleven characters with one accented \
             letter pass a twelve-character floor",
            wide.chars().count(),
            wide.len()
        )
    });
    assert!(
        why.contains(&format!("{} character", MIN_PASSWORD_LEN - 1)),
        "the count rendered is not the character count ({}): the message says character and \
         measures something else: {why}",
        MIN_PASSWORD_LEN - 1
    );
    for (label, pw) in [("three emoji", "🔑🔑🔑"), ("four CJK characters", "鍵鍵鍵鍵")] {
        assert!(pw.len() >= MIN_PASSWORD_LEN, "premise: {label} is not short in bytes");
        let why = password_refusal(pw).unwrap_or_else(|| {
            panic!("{label} ({} bytes, {} characters) were accepted", pw.len(), pw.chars().count())
        });
        assert!(
            why.contains(&format!("{} character", pw.chars().count())),
            "{label}: the character count is not what the refusal renders: {why}"
        );
    }
    // And encoding does not raise the floor either: twelve accented characters
    // are twelve characters.
    let wide_enough = "é".repeat(MIN_PASSWORD_LEN);
    assert!(
        password_refusal(&wide_enough).is_none(),
        "{MIN_PASSWORD_LEN} accented characters were refused; the floor counts something other \
         than characters"
    );
    println!(
        "  password floor: {MIN_PASSWORD_LEN} characters inclusive; {} chars/{} bytes, three \
         emoji and four CJK refused with the character count rendered; {} accented chars accepted",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN
    );
}

/// **The library entry point asks the floor, and asks it before anything is
/// written**.
///
/// `create_cmd::create` took the password as bytes and sealed with it from
/// a time; only `orchestrate`'s prompt asked the floor, and every
/// test came in here with the harness's password -- the control enforced
/// exactly where no test looked. Both halves, as every `create`
/// refusal has both: the error by variant with its count and floor, and the
/// directory absent, because an error code cannot say whether a store was
/// written. The control seals under exactly the floor in accented
/// characters, so a byte-counting floor and a character-counting one give
/// different answers to both arms.
#[test]
fn create_refuses_a_short_password_and_writes_nothing() {
    use create_cmd::MIN_PASSWORD_LEN;
    let dir = ScratchDir::new("cli-create-short-pw");
    let target = dir.path().to_path_buf();
    let wide = one_short_but_wide();
    let err = create_cmd::create(
        &target,
        &test_phrase(),
        &wide,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
    .err();
    assert!(
        matches!(
            err,
            Some(mochimo_crypto::Error::PasswordTooShort { chars, min })
                if chars == MIN_PASSWORD_LEN - 1 && min == MIN_PASSWORD_LEN
        ),
        "the library entry point sealed a store under {} characters ({} bytes), or refused it \
         under another name than PasswordTooShort {{ chars: {}, min: {MIN_PASSWORD_LEN} }}: \
         {err:?}. Only the prompt asked the floor once",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN - 1
    );
    assert!(
        !target.exists(),
        "a store was written before the floor was asked -- {} exists after the refusal. The \
         floor must be asked before Keystore::create makes the directory",
        target.display()
    );
    let rendered = format!("{}", err.unwrap_or_else(|| panic!("checked above")));
    for needle in [
        format!("{} character", MIN_PASSWORD_LEN - 1),
        format!("fewer than {MIN_PASSWORD_LEN}"),
        "MIN_PASSWORD_LEN".to_string(),
    ] {
        assert!(rendered.contains(&needle), "the rendered error does not say {needle:?}: {rendered}");
    }

    // The control: exactly the floor, in characters wider than bytes would
    // need, seals a store.
    let dir2 = ScratchDir::new("cli-create-floor-pw");
    let at_floor = "é".repeat(MIN_PASSWORD_LEN);
    create_cmd::create(
        dir2.path(),
        &test_phrase(),
        &at_floor,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
    .unwrap_or_else(|e| panic!("{MIN_PASSWORD_LEN} accented characters were refused by the library entry point: {e}"));
    assert!(dir2.path().join("accounts.mks").exists(), "the control wrote no store");
    println!(
        "  create: {} chars/{} bytes refused as PasswordTooShort with nothing written; {} accented \
         chars sealed a store",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN
    );
}

/// **The prompt refuses a short password before a phrase exists** -- the
/// clearing condition the audit wrote for this debt, verbatim: `orchestrate`
/// driven with a password below the floor, the refusal asserted, no store
/// written, and the rendered message naming the floor.
///
/// Three more things the order makes checkable, each the thing the early
/// copy is FOR: nothing was shown, no entropy was drawn, and the password was
/// read exactly once -- a refusal after a second read, a phrase or a
/// confirmation would be `create`'s authoritative refusal arriving late, with
/// the operator's phrase on screen for a store that will never exist. The
/// discriminating password again, so a byte-counting prompt reds here too.
#[test]
fn orchestrate_refuses_a_short_password_before_a_phrase_exists() {
    use create_cmd::MIN_PASSWORD_LEN;
    let dir = ScratchDir::new("cli-create-short-orch");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let reads = Rc::new(RefCell::new(Vec::new()));
    let rl = Rc::clone(&reads);
    let entropy_taken = Rc::new(RefCell::new(false));
    let taken = Rc::clone(&entropy_taken);
    let wide = one_short_but_wide();
    let r = create_cmd::orchestrate(
        &target,
        false,
        || {
            *taken.borrow_mut() = true;
            Ok(zeroize::Zeroizing::new(test_create_entropy()))
        },
        || Ok(Recorder::watching(log, vec![wide.clone(), wide.clone(), "never asked".into()], rl)),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, &format!("{} character", MIN_PASSWORD_LEN - 1), "the short-password refusal");
    assert_says(&r, &format!("fewer than {MIN_PASSWORD_LEN}"), "the short-password refusal");
    assert_says(&r, "Nothing was created", "the short-password refusal");
    assert!(
        !target.exists(),
        "a store was written under a password below the floor: {} exists",
        target.display()
    );
    assert!(
        shown.borrow().is_empty(),
        "a phrase was shown before the password was refused: {:?}. The early copy exists so \
         the operator is told before a phrase exists for a store that never will",
        shown.borrow()
    );
    assert!(!*entropy_taken.borrow(), "entropy was drawn before the password was refused");
    assert_eq!(
        reads.borrow().len(),
        1,
        "the password was read {} time(s); a password below the floor is read once and refused, \
         not confirmed: {:?}",
        reads.borrow().len(),
        reads.borrow()
    );
    println!(
        "  orchestrate: {} chars/{} bytes refused at the first read; nothing shown, no entropy \
         drawn, nothing written",
        wide.chars().count(),
        wide.len()
    );
}

/// `create` makes the store from a phrase and derives account 0 of it.
/// Deterministic because the entropy behind the phrase is a parameter.
///
/// This was `create_makes_a_store_and_returns_the_phrase_once` until
/// `create` stopped generating -- and therefore stopped returning -- a phrase:
/// the phrase is now shown and confirmed before the write, so the write takes
/// it as an input and hands nothing secret back.
#[test]
fn create_makes_a_store_holding_account_0_of_the_phrase() {
    let dir = ScratchDir::new("cli-create");
    let phrase = test_phrase();
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "32 bytes of entropy is BIP39's 24-word case"
    );
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    // The account is really in the store, and it is account 0 of that phrase.
    let ks = reopen("cli flow 1", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let view = ks
        .view(&c.tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("account 0 is not in the store"));
    assert_eq!(view.wots_index.get(), 0, "a fresh account is at position 0");
    let m = mochimo_crypto::mnemonic::master_seed_from_phrase(&phrase, "")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        c.tag,
        mochimo_crypto::derive::derive_account_tag(&m, 0),
        "the tag is not account 0 of the phrase that was shown"
    );
}

/// One phrase, two stores, one account 0 -- the determinism the
/// confirm-before-write order rests on: a phrase whose store was refused
/// or never written is one `create --from-phrase` from the same wallet.
///
/// This was `create_from_a_supplied_phrase_does_not_return_it`; the
/// property it held -- that `create` hands no phrase back -- is now true by
/// type, since `Created` has no phrase field, and what remains worth
/// asserting is the identity.
#[test]
fn the_same_phrase_makes_the_same_account_0_in_any_store() {
    let dir = ScratchDir::new("cli-create-supplied");
    let seed = ScratchDir::new("cli-create-supplied-src");
    let phrase = test_phrase();
    let src = create_here(seed.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.tag, src.tag, "the same phrase produced a different account 0");
}

/// An existing store is refused, and `Keystore::create` is what refuses it.
#[test]
fn create_refuses_an_existing_store() {
    let dir = ScratchDir::new("cli-create-twice");
    let phrase = test_phrase();
    create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    // **The refusal must come from `Keystore::create`'s snapshot check**, not
    // from `add` refusing a duplicate tag further in. Both are `Error::Exists`
    // and differ only in `what`, so a needle on "exists" passes either way --
    // so a needle on "exists" alone stays green under an injection replacing
    // `Keystore::create` with `create().or_else(open)`.
    match create_here(dir.path(), &phrase) {
        Ok(_) => panic!("a second create over the same directory succeeded"),
        Err(mochimo_crypto::Error::Exists { what: "snapshot" }) => {}
        Err(e) => panic!(
            "the second create was refused, but not by Keystore::create's snapshot check: \
             {e:?}. A refusal from `add` means the store was opened rather than refused."
        ),
    }
}

/// The confirmation checks the words it says it checks, and nothing more.
#[test]
fn the_confirmation_wants_those_three_words_and_no_others() {
    let _dir = ScratchDir::new("cli-create-confirm");
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<&str> = phrase.expose().split_whitespace().collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    let right = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
    assert!(create_cmd::confirmation_matches(phrase.expose(), &right));
    assert!(
        create_cmd::confirmation_matches(phrase.expose(), &right.to_uppercase()),
        "case should not matter for a transcribed word"
    );
    assert!(!create_cmd::confirmation_matches(phrase.expose(), "abandon abandon abandon"));
    assert!(
        !create_cmd::confirmation_matches(phrase.expose(), &format!("{right} extra")),
        "a fourth word should not pass"
    );
    assert!(!create_cmd::confirmation_matches(phrase.expose(), ""));
    println!(
        "create confirmation: {} position(s) checked, {} rejection case(s)",
        p.len(),
        4
    );
}

// ---------------------------------------------------------------------------
// The flow the deadlock made impossible
// ---------------------------------------------------------------------------

/// **The session's proof.** create -> address -> the chain funds that address
/// -> balance -> send -> settle, in one test, with no step reaching around the
/// CLI. Once this could not begin: no verb made a store, and `address`
/// went through `Wallet::open`, which refuses a tag the ledger has never held.
#[test]
fn the_whole_flow_from_an_empty_directory_to_a_settled_spend() {
    let dir = ScratchDir::new("cli-flow");

    // 1. create -- no chain involved at all. The phrase is generated here,
    //    as `orchestrate` generates it, and handed to the write.
    let phrase = test_phrase();
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    let m = mochimo_crypto::mnemonic::master_seed_from_phrase(&phrase, "")
        .unwrap_or_else(|e| panic!("{e}"));
    let tag = c.tag;

    // 2. address -- before the tag exists on any chain.
    let ks = reopen("cli flow 2", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let unfunded = Chain::new(&[(tag, ChainState::Absent)]);
    let r = cli::run(ks, MeshClient::new(unfunded), &Command::Address { tag: Some(tag), account: None });
    assert_eq!(r.code, Code::Ok, "address failed on an unfunded tag: {}", r.text);
    let addr0 = mochimo_crypto::recon::derived_address_at(
        &m,
        0,
        mochimo_crypto::account::WotsIndex::ZERO,
    );
    assert_says(&r, &hexs(&addr0), "the address to fund");

    // **The destination as an operator gets it: the first line, copied.**
    // Nothing here reaches into the store for it -- if the CLI stopped
    // printing a destination on line one, this is the string that would go
    // wrong, and step 3 is where it would be refused.
    let printed = r.text.lines().next().unwrap_or("").to_string();

    // 3. the chain funds THAT STRING, through a door that takes only the
    //    reference form. Funding `tag` here instead -- a Rust value the test
    //    already holds -- lets the flow walk six steps without ever looking
    //    at what `address` rendered, over a string no other wallet accepts.
    let funded = || {
        let c = Chain::new(&[]);
        let credited = c
            .credit_destination(&printed, addr0, 5_000_000)
            .unwrap_or_else(|e| panic!("{e}"));
        // And the round trip closes: what came back out of the printed string
        // is the tag the store holds. Two degrees of freedom -- the CLI
        // encoded, the fake decoded -- so a composition wrong in one direction
        // only cannot survive here. One wrong in BOTH directions survives,
        // which is what the group C KAT below is for.
        assert_eq!(
            credited, tag,
            "the destination the CLI printed (`{printed}`) decodes to a different tag than the \
             store holds; funds sent to it would be irrecoverable"
        );
        c
    };

    // 4. balance -- the first command that opens a Wallet, and it opens.
    let ks = reopen("cli flow 3", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(funded()), &Command::Balance);
    assert_eq!(r.code, Code::Ok, "balance refused after funding: {}", r.text);
    assert_says(&r, "5000000", "balance");

    // 5. send. The id comes from a dry run on THIS store -- which the dry run
    // then advances -- so the CLI's own send runs on a second store made from
    // the same entropy. Two handles on one store is a held lock, not a test
    // detail.
    let spend = Spend { tag, dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }], fee_total: MFEE, blk_to_live: 0 };
    let id = {
        let ks2 = reopen("cli flow 5", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let mut w = Wallet::open(ks2, MeshClient::new(funded()), Some(&m))
            .unwrap_or_else(|e| panic!("{e}"));
        let plan = w
            .plan(
                &tag,
                &KeyAccess::Master(&m),
                vec![Destination { tag: TO, reference: [0; 16], amount: 1_000 }],
                MFEE,
                0,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        w.reserve_and_sign(&plan, KeyAccess::Master(&m))
            .unwrap_or_else(|e| panic!("{e}"))
            .id()
            .0
    };
    // That dry run advanced its own copy of the store; take a fresh one.
    let dir2 = ScratchDir::new("cli-flow-send");
    let c2 = create_here(dir2.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c2.tag, tag, "the same entropy made a different account");
    let ks = reopen("cli flow 6", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = funded();
    chain.accepts_submit(id);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend));
    assert_eq!(r.code, Code::Ok, "send failed: {}", r.text);
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "send");
    // The destination read back in the checksummed form, whichever form was
    // typed -- the operator's one chance to compare against the payee.
    let to_dest = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &to_dest, "send's destination read-back");

    // **The loop neither the KAT nor the fake can see: this program's own
    // renderer against this program's own parser.** Everything else in this
    // test hands a Rust value to the next step. Here the `settle` argument is
    // taken out of the rendered text exactly as an operator would copy it and
    // run back through `args::parse`, so a rendering site that drifted from
    // the parser would be caught by the program disagreeing with itself.
    let settle_arg = r
        .text
        .split("Run `settle ")
        .nth(1)
        .and_then(|t| t.split('`').next())
        .unwrap_or_else(|| panic!("send did not print a `settle` hint:\n{}", r.text))
        .trim()
        .to_string();
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &settle_arg])) {
        Ok(args::ParsedArgv::Run(i)) => assert_eq!(
            i.command,
            Command::Settle { tag },
            "the `settle` argument this program printed parses to a different tag than the \
             store holds: {settle_arg}"
        ),
        other => panic!("the printed `settle {settle_arg}` did not parse: {other:?}"),
    }

    // 6. settle -- the chain has moved to the change key.
    let addr1 = mochimo_crypto::recon::derived_address_at(
        &m,
        0,
        mochimo_crypto::account::WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")),
    );
    let ks = reopen("cli flow 7", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(tag, ChainState::At(addr1, 4_000_000))])),
        &Command::Settle { tag },
    );
    assert_eq!(r.code, Code::Ok, "settle failed: {}", r.text);
    assert_says(&r, "settled", "settle");

    // 7. send again. The settled block is retained in
    //    the record and must not freeze the account. Through a refusing
    //    socket, so no second id is needed: the property is that the plan was
    //    built and the reservation made -- exit 3 with the artifact on the
    //    page, and the store read back at index 2 with a reservation open. A
    //    freeze (`PendingUnresolved` before anything is reserved) fails all
    //    three; an ordinary refused write passes them, which is why the exit
    //    code alone would not discriminate.
    let ks = reopen("cli flow 8", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(tag, ChainState::At(addr1, 4_000_000))]);
    chain.refuses_submit();
    let r = cli::run(
        ks,
        MeshClient::new(chain),
        &Command::Send(Spend { tag, dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }], fee_total: MFEE, blk_to_live: 0 }),
    );
    assert_eq!(r.code, Code::Refused, "step 7: a send through a refusing socket exits 3:\n{}", r.text);
    assert_says(&r, "RETRY ARTIFACT", "step 7: the second spend was planned, reserved and signed");
    let ks = reopen("cli flow 9", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("step 7: the store no longer holds the account"));
    assert_eq!(
        (v.wots_index.get(), v.pending.is_some(), v.settled.is_some()),
        (2, true, false),
        "step 7: the second send did not advance the store past the retained settled block and \
         release it -- the freeze the retained block must not cause"
    );
    drop(ks);

    println!(
        "CLI flow: 7 step(s) from an empty directory to a settled spend and a second spend, 0 \
         reaching around the CLI"
    );
}

// ---------------------------------------------------------------------------
// The absent terminal
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::rc::Rc;

/// A terminal that records what it was shown and answers from a script.
///
/// The `shown` log is shared with the test through an `Rc`, so the assertion
/// *no phrase was displayed* is made against what the code actually did rather
/// than against a stream nobody captured.
struct Recorder {
    shown: Rc<RefCell<Vec<String>>>,
    answers: Vec<String>,
    /// Which read each prompt went through, in order: `"secret"` for the
    /// echo-off read and `"visible"` for the echoing one.
    ///
    /// Recorded because *which* read the confirmation uses is the whole of
    /// that finding, and it is invisible from the answer: both methods return
    /// a string from the same script. A test that only checked the answer
    /// would pass identically before and after the change.
    reads: Rc<RefCell<Vec<(&'static str, String)>>>,
}

impl Recorder {
    fn new(shown: Rc<RefCell<Vec<String>>>, answers: Vec<String>) -> Recorder {
        Recorder {
            shown,
            answers,
            reads: Rc::new(RefCell::new(Vec::new())),
        }
    }
    fn watching(
        shown: Rc<RefCell<Vec<String>>>,
        answers: Vec<String>,
        reads: Rc<RefCell<Vec<(&'static str, String)>>>,
    ) -> Recorder {
        Recorder {
            shown,
            answers,
            reads,
        }
    }
}

impl create_cmd::Terminal for Recorder {
    fn show(&mut self, text: &str) -> Result<(), String> {
        self.shown.borrow_mut().push(text.to_string());
        Ok(())
    }
    fn read_secret_line(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.reads.borrow_mut().push(("secret", prompt.to_string()));
        if self.answers.is_empty() {
            return Err("test: the script ran out of answers".into());
        }
        Ok(zeroize::Zeroizing::new(self.answers.remove(0)))
    }
    /// The confirmation's read, which the trait takes by value.
    ///
    /// The double answers from the same script: what a *terminal* does with
    /// echo is the binary's business. What is recorded is *which* read ran,
    /// because that is the finding; and the property that nothing can read
    /// again afterwards is held by the signature and cased in
    /// `ui/fail/terminal_cannot_read_a_secret_after_the_visible_read.rs`,
    /// where a program that tries it is rejected by the compiler.
    fn read_visible_line(mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.reads.borrow_mut().push(("visible", prompt.to_string()));
        if self.answers.is_empty() {
            return Err("test: the script ran out of answers".into());
        }
        Ok(zeroize::Zeroizing::new(self.answers.remove(0)))
    }
}

/// **The session's property.** With no controlling terminal, `create` writes
/// nothing and shows no phrase.
///
/// Both halves, because either alone passes over the defect: an exit code says
/// the command failed, which it always did — what the first `create` got wrong was that it
/// failed *after* writing a store and printing a mnemonic.
#[test]
fn create_without_a_terminal_writes_nothing_and_shows_no_phrase() {
    let dir = ScratchDir::new("cli-create-no-tty");
    let target = dir.path().to_path_buf();
    assert!(!target.exists(), "the target must not exist beforehand");

    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let entropy_taken = Rc::new(RefCell::new(false));
    let taken = Rc::clone(&entropy_taken);

    let r = create_cmd::orchestrate(
        &target,
        false,
        || {
            *taken.borrow_mut() = true;
            Ok(zeroize::Zeroizing::new(test_create_entropy()))
        },
        || {
            Err::<Recorder, String>(
                "cannot open /dev/tty: Device not configured (os error 6)".into(),
            )
        },
    );

    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    // Half one, and the one the first `create` failed: the store must not exist.
    assert!(
        !target.exists(),
        "THE STORE WAS WRITTEN BEFORE THE TERMINAL WAS ACQUIRED -- {} exists after a refusal \
         that had nowhere to confirm a phrase. This is the store-before-terminal defect.",
        target.display()
    );
    // Half two: nothing was displayed.
    assert!(
        shown.borrow().is_empty(),
        "something was shown despite there being no terminal: {:?}",
        shown.borrow()
    );
    // And the entropy was never drawn, because acquisition precedes it.
    assert!(
        !*entropy_taken.borrow(),
        "entropy was drawn before the terminal was acquired"
    );
    assert!(
        r.text.contains("/dev/tty"),
        "the refusal does not name the cause: {}",
        r.text
    );
    // The promise every refusal from `create` keeps is appended at the seam,
    // so an acquisition that fails in its own words still ends with it and
    // no caller has to remember to add it.
    assert_says(&r, "Nothing was created", "the no-terminal refusal");
    // **The bound on half two.** `shown` sees only what went through the
    // `Terminal` seam; a bare `println!` in the create path would reach stdout
    // and be invisible to it. That gap is closed in
    // `invariants.rs::the_cli_cannot_reach_around_the_wallet`, which reads
    // `cli/create.rs` through the project's comment stripper and forbids the
    // print constructs there. The stripper is why: without it the check
    // fires on the word `println!` inside a doc comment.
    println!(
        "create without a terminal: store absent, {} thing(s) shown, entropy drawn: {}",
        shown.borrow().len(),
        *entropy_taken.borrow()
    );
}

/// **`create --from-phrase` says that one derivation scheme restores, before
/// it reads anything.**
///
/// Several Mochimo wallets turn one phrase into different seeds. A phrase from
/// another scheme is accepted here and derives a well-formed store whose
/// accounts are empty, and an empty store is what a genuinely unfunded wallet
/// looks like too -- so the operator sees no error and has nothing to notice.
///
/// The ordering is the half that matters, and this drives it rather than
/// asserting it: the script carries **no answers at all**, so the first read
/// fails. Whatever reached the terminal before that failure was shown before
/// any read could be answered -- before the password, and therefore before the
/// twenty-four words.
#[test]
fn create_from_phrase_warns_about_the_derivation_scheme_before_any_read() {
    let dir = ScratchDir::new("cli-create-scheme-warning");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);

    let r = create_cmd::orchestrate(
        dir.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, Vec::new())),
    );
    assert_eq!(r.code, Code::Refused, "the empty script should have refused: {}", r.text);

    let first = shown
        .borrow()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("nothing was shown before the first read; the warning cannot be read after the phrase is typed"));

    for needle in [
        "one derivation scheme",
        "browser extension",
        "no error",
        "empty",
    ] {
        assert!(
            first.contains(needle),
            "the scheme warning does not carry {needle:?}:\n{first}"
        );
    }
    // What it must NOT say: that the phrase is rejected. Nothing refuses it,
    // and an operator told to expect a refusal will wait for one.
    for stale in ["unsupported", "invalid phrase", "will fail"] {
        assert!(!first.contains(stale), "the warning promises an error the operator will not see: {first}");
    }
    assert!(
        !dir.path().join("accounts.mks").exists(),
        "a store was written by a run whose reads all failed"
    );
    println!("  create --from-phrase: the scheme warning is shown before the first read");
}

/// The positive control: with a terminal, the same call *does* write and *does*
/// show — otherwise the assertions above would pass over a `create` that never
/// worked at all.
#[test]
fn create_with_a_terminal_writes_the_store_and_shows_the_phrase_once() {
    let dir = ScratchDir::new("cli-create-tty");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);

    // The confirmation is answered from the phrase the run itself produces:
    // derive it the same way `create` does, from the same entropy.
    let expected = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<&str> = expected.expose().split_whitespace().collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);

    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Recorder::new(log, password_then(vec![answer])))
        },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert!(target.join("accounts.mks").exists(), "no store was written");
    assert_eq!(shown.borrow().len(), 1, "the phrase should be shown exactly once");
    assert!(
        shown.borrow()[0].contains("WRITE THIS DOWN"),
        "what was shown is not the phrase notice: {:?}",
        shown.borrow()[0]
    );
    assert_says(&r, "confirmed", "create");
    // `create` prints a DESTINATION, and does not also print the tag as
    // hex beside it. Recomputed here from the entropy rather than read out of
    // the report, so the two sides can disagree.
    let tag = mochimo_crypto::mnemonic::master_seed_from_phrase(expected.expose(), "")
        .map(|m| mochimo_crypto::derive::derive_account_tag(&m, 0))
        .unwrap_or_else(|e| panic!("{e}"));
    let dest = mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "create");
    assert!(
        !r.text.contains(&hexs(&tag)),
        "create prints the hex tag beside the destination -- two spellings of one identifier \
         is what the shipped wallet refused:\n{}",
        r.text
    );
}

/// A wrong confirmation refuses **and leaves nothing on disk**.
///
/// Leaving `accounts.mks` present after the refusal turns a display defect
/// into a fund-loss one -- exit 3, a real store, a phrase nobody has seen --
/// and the argument for it (an operator who wrote the phrase down should not
/// lose the store to three mistyped words) is answered by
/// `create --from-phrase` rebuilding the identical store, which
/// `the_same_phrase_makes_the_same_account_0_in_any_store` and the pty
/// harness both measure.
///
/// Both halves, as the absent-terminal test has both: the exit code, and
/// the directory -- an exit code cannot say whether a store was written.
#[test]
fn a_wrong_confirmation_refuses_and_leaves_nothing_on_disk() {
    let dir = ScratchDir::new("cli-create-badconfirm");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Recorder::new(log, password_then(vec!["abandon abandon abandon".into()])))
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !target.exists(),
        "THE STORE WAS WRITTEN BEFORE THE CONFIRMATION -- {} exists after a refused \
         confirmation. The exit code says refused and the filesystem says created, which is \
         the pair the confirm-before-write order removed.",
        target.display()
    );
    assert_eq!(shown.borrow().len(), 1, "the phrase is shown before the confirmation");
    assert_says(&r, "Nothing was created", "a wrong confirmation");
    assert_says(&r, "create --from-phrase", "a wrong confirmation's route back");
    assert!(
        !r.text.contains("WAS created"),
        "the refusal claims a store exists:\n{}",
        r.text
    );
}

/// A display that fails refuses before anything is written.
///
/// A trait whose `show` returns nothing lets a write to a read-only
/// descriptor be discarded. With `show` returning a `Result`, a terminal
/// whose display fails is refused at the seam, and --
/// because the write now follows the confirmation -- refused with nothing on
/// disk and no phrase on any screen.
#[test]
fn a_display_that_fails_refuses_with_nothing_written() {
    struct Mute {
        inner: Recorder,
    }
    impl create_cmd::Terminal for Mute {
        fn show(&mut self, _text: &str) -> Result<(), String> {
            Err("cannot write to /dev/tty: Bad file descriptor (os error 9)".into())
        }
        fn read_secret_line(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
            self.inner.read_secret_line(prompt)
        }
        fn read_visible_line(self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
            self.inner.read_visible_line(prompt)
        }
    }
    let dir = ScratchDir::new("cli-create-mute");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let confirmed = Rc::new(RefCell::new(Vec::new()));
    let reads = Rc::clone(&confirmed);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Mute {
                inner: Recorder::watching(log, password_then(vec!["never asked".into()]), reads),
            })
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !target.exists(),
        "a store was written although the phrase could not be shown: {}",
        target.display()
    );
    assert_says(&r, "Bad file descriptor", "a failed display");
    assert_says(&r, "Nothing was created", "a failed display");
    assert!(
        !confirmed.borrow().iter().any(|(kind, _)| *kind == "visible"),
        "the confirmation was asked after the display failed: {:?}",
        confirmed.borrow()
    );
}

/// A phrase the parser refuses leaves nothing on disk.
///
/// Predicted from source and not run until here: `create` called
/// `Keystore::create` -- which makes the directory and seals and commits an
/// EMPTY image -- BEFORE `mnemonic::master_seed_from_phrase` parsed the
/// words, so a mistyped phrase exited 3 with `bip39: checksum mismatch`, no
/// "Nothing was created", and a 112-byte store plus a lock file behind it;
/// the retry into the same directory was then refused as an existing store
/// whose only advice was to run another command against it. The
/// write-before-validate order found at the terminal, one prompt along. Both halves, as the
/// wrong-confirmation test has them: the result, and the directory -- an
/// error value cannot say whether a store was written.
#[test]
fn a_refused_phrase_leaves_nothing_on_disk() {
    // Twenty-four valid words whose checksum is wrong: the well-known
    // 24 x "abandon" vector ends in "art", so 24 x "abandon" fails the
    // checksum and nothing else.
    let bad = ["abandon"; 24].join(" ");

    // The library entry point.
    let dir = ScratchDir::new("cli-create-badphrase");
    let err = match create_here(dir.path(), &bad) {
        Ok(_) => panic!("a bad checksum must refuse"),
        Err(e) => e,
    };
    assert!(
        matches!(err, mochimo_crypto::Error::Mnemonic { what: "checksum mismatch" }),
        "refused for the wrong reason: {err:?}"
    );
    assert!(
        !dir.path().exists(),
        "A STORE EXISTS after a refused phrase: {} holds {:?}. The keystore was sealed before \
         the words were parsed, so a typo in twenty-four words leaves an empty store that \
         refuses the retry as `already exists`.",
        dir.path().display(),
        dir.listing()
    );

    // The orchestrated path, `--from-phrase`: the same property through the
    // seam, with the text the operator reads.
    let dir2 = ScratchDir::new("cli-create-badphrase-orchestrated");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        dir2.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, password_then(vec![bad.clone()]))),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !dir2.path().exists(),
        "A STORE EXISTS after a refused phrase through --from-phrase: {} holds {:?}",
        dir2.path().display(),
        dir2.listing()
    );
    assert_says(&r, "checksum mismatch", "a refused phrase");
    assert_says(&r, "Nothing was created", "a refused phrase");
    // The one thing shown on this path is the derivation-scheme warning, which
    // is written before any read. The phrase itself is never displayed back.
    let shown = shown.borrow();
    assert_eq!(shown.len(), 1, "more than the scheme warning was shown: {shown:?}");
    assert!(shown[0].starts_with("BEFORE YOU TYPE:"), "what was shown is not the scheme warning: {shown:?}");
    assert!(
        !shown[0].contains(bad.split_whitespace().next().unwrap_or("?")),
        "the supplied phrase reached the screen: {shown:?}"
    );
}

// ---------------------------------------------------------------------------
// The destination identifier
// ---------------------------------------------------------------------------
//
// A program that prints a bare 40-hex tag is unusable by its intended
// operator: the shipped Chrome wallet refuses that outright (*"Tag must be
// between 22 and 31 characters"*), so the wallet cannot be funded from its
// own output. It fails in the other direction too -- a `send <to>` taking
// 40-hex when every other wallet hands you Base58.
//
// # Why these live in the CLI's file
//
// The codec is `addr::{tag_to_base58, tag_from_base58}` and is not CLI-shaped,
// but the *question* is: it exists because a human could not use this program,
// and the checks that matter are the round trip through what the CLI printed
// and the KAT against what the reference emits. Putting them beside the flow
// test keeps the three within one file's reading. It also adds no test binary,
// which would move `invariants.rs::census` and Miri's per-binary counts for a
// file that is a fixture walk.
//
// # Two mechanisms, and they fail on different faults
//
// * the **round trip** (in the flow test above, through `credit_destination`)
//   catches a *composition* error: the encoder and the decoder are separate
//   code, so a checksum dropped, computed over the wrong bytes, or written in
//   the wrong order in one direction alone cannot survive it;
// * the **KAT** below catches a *primitive* error, including one the encoder
//   and the decoder would make together. Group C's strings came out of the C;
//   `C9`'s is additionally crosschecked against executed TypeScript
//   (`crosscheck_typescript_expected`, `tag-utils.test.ts`), so one of the four
//   is anchored outside this reference entirely.
//
// Neither alone is enough and that is why both are here.

/// Group C, embedded rather than read at runtime, as `tests/derive.rs` embeds
/// group F: the walk then has no filesystem in it and cannot silently measure
/// a scratch copy.
const GROUP_C: &str = include_str!("../../../fixtures/group_c_addr.json");

/// Group CX: the **executed** crosscheck. Its values are what
/// `TagUtils.addrTagToBase58`, `bs58.decode`, `validateBase58Tag` and
/// `base58ToAddrTag` returned when the generator ran them, not what anybody
/// read out of an upstream test file.
///
/// The distinction -- an executed second implementation against a transcribed
/// literal -- is the whole of the independence
/// claim: group C's own `crosscheck_typescript_expected` is a **transcribed
/// literal**, so asserting against it establishes what the person doing the
/// transcribing believed -- which beside an assertion against the C's string
/// in the same vector is two byte-identical copies of one value, where no
/// input can make the second red while the first is green.
const GROUP_CX: &str = include_str!("../../../fixtures/group_c_crosscheck.json");

fn group_c() -> serde_json::Value {
    serde_json::from_str(GROUP_C).unwrap_or_else(|e| panic!("group_c_addr.json parses: {e}"))
}

fn group_cx() -> serde_json::Value {
    serde_json::from_str(GROUP_CX)
        .unwrap_or_else(|e| panic!("group_c_crosscheck.json parses: {e}"))
}

fn unhex_tag(s: &str) -> [u8; ADDR_TAG_LEN] {
    let mut out = [0u8; ADDR_TAG_LEN];
    let b = s.as_bytes();
    assert_eq!(b.len(), ADDR_TAG_LEN * 2, "not a 20-byte hex tag: {s}");
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("bad hex in {s}: {e}"));
    }
    out
}

/// **The KAT.** Every group C vector that records a Base58 encoding of a
/// 22-byte tag payload, plus the thousand-entry corpus, replayed through
/// `addr::tag_to_base58` and back through `addr::tag_from_base58`.
///
/// The expected values are the reference's own output, recorded from
/// `crc16 + put16 + base58_encode`. This file computes nothing: a wrong
/// composition here disagrees with a string a C program emitted, which is the
/// only kind of disagreement worth having.
#[test]
fn the_destination_matches_every_group_c_vector() {
    let root = group_c();
    let mut vectors = 0usize;
    let mut crosschecked = 0usize;
    for v in root["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("group C has a vectors array"))
    {
        let (Some(tag_hex), Some(expected)) = (
            v.get("tag").and_then(|t| t.as_str()),
            v.get("base58_of_tag22").and_then(|t| t.as_str()),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let tag = unhex_tag(tag_hex);
        let got = mochimo_crypto::addr::tag_to_base58(&tag)
            .unwrap_or_else(|e| panic!("{id}: tag_to_base58: {e}"));
        assert_eq!(
            got, expected,
            "{id}: the destination this crate renders is not the one the reference emitted for \
             tag {tag_hex}"
        );
        let back = mochimo_crypto::addr::tag_from_base58(expected)
            .unwrap_or_else(|e| panic!("{id}: the reference's own string was refused: {e}"));
        assert_eq!(back, tag, "{id}: the reference's string decodes to a different tag");
        vectors += 1;
    }
    // The corpus: 1000 tags, each the first 20 bytes of a reference sha256,
    // with the reference's own crc16 and base58 beside them.
    let entries = root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("group C carries crc16_base58_corpus.entries"));
    let mut walked = 0usize;
    for e in entries {
        let tag = unhex_tag(e["tag"].as_str().unwrap_or_else(|| panic!("corpus entry has a tag")));
        let expected = e["base58"].as_str().unwrap_or_else(|| panic!("corpus entry has base58"));
        let got = mochimo_crypto::addr::tag_to_base58(&tag)
            .unwrap_or_else(|e| panic!("corpus tag_to_base58: {e}"));
        assert_eq!(got, expected, "corpus entry {}: destination", e["i"]);
        assert_eq!(
            mochimo_crypto::addr::tag_from_base58(expected).unwrap_or_else(|e| panic!("{e}")),
            tag,
            "corpus entry {}: round trip", e["i"]
        );
        walked += 1;
    }
    // Vacuity floors, and they are floors over the artifact rather than over
    // an expectation: group C carries four `base58_of_tag22` vectors (C7, C8,
    // C9, C10) and the corpus declares its own count.
    assert_eq!(
        vectors, 4,
        "expected the four group C vectors carrying base58_of_tag22 (C7, C8, C9, C10); walked \
         {vectors}. A walk that shrank is a walk that stopped checking."
    );
    // **The independence leg, and it is a different file on purpose.**
    // `crosscheck_typescript_executed` in group CX is what
    // `TagUtils.addrTagToBase58` RETURNED. Group C's
    // `crosscheck_typescript_expected` is a literal somebody typed in from the
    // upstream test file; both are kept -- the literal is the only thing that
    // checks the transcription -- but only the executed one can disagree with
    // this crate for a reason that is about the algorithm.
    for v in group_cx()["vectors"].as_array().unwrap_or(&Vec::new()) {
        let (Some(hex), Some(executed)) = (
            v.get("input_hex").and_then(|t| t.as_str()),
            v.get("crosscheck_typescript_executed").and_then(|t| t.as_str()),
        ) else {
            continue;
        };
        if hex.len() != ADDR_TAG_LEN * 2 || !v["source"].as_str().unwrap_or("").contains("addrTagToBase58") {
            continue;
        }
        let id = v["id"].as_str().unwrap_or("?");
        let got = mochimo_crypto::addr::tag_to_base58(&unhex_tag(hex))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            got, executed,
            "{id}: this crate disagrees with what TagUtils.addrTagToBase58 RETURNED for {hex}"
        );
        crosschecked += 1;
    }
    assert!(
        crosschecked >= 4,
        "only {crosschecked} executed-TypeScript encodings were replayed; expected CX-C7, \
         CX-C8, CX-C9 and CX-C10. Without them every value here traces to the same C and the \
         agreement is a self-comparison."
    );
    let declared = root["crc16_base58_corpus"]["count"].as_u64().unwrap_or(0) as usize;
    assert_eq!(
        walked, declared,
        "the corpus declares {declared} entries and the walk saw {walked}"
    );
    assert!(walked >= 1000, "the corpus shrank to {walked}");
    println!(
        "  destination KAT: {vectors} group C vector(s), {crosschecked} replayed against \
         EXECUTED TypeScript return values, {walked} corpus entries"
    );
}

/// **Where this crate deliberately diverges from the shipped TypeScript, and
/// by how much** — walked against the executed record rather than described.
///
/// `tag-utils.ts` splits the question in two: `validateBase58Tag` compares the
/// CRC16, and `base58ToAddrTag` checks only that the payload is twenty-two
/// bytes and **hands the tag back unvalidated**. `addr::tag_from_base58` fuses
/// them and refuses on a mismatch.
///
/// That is a strengthening, and by this project's own rule a decision is not
/// made until it is written down. It is also measurable: group
/// CX ran both TypeScript functions on the same strings the C was given and
/// recorded `validate_base58_tag` beside `base58_to_addr_tag`, so the walk
/// below says exactly where the two implementations agree and where they do
/// not — rather than leaving a reader to compare two files and guess.
#[test]
fn the_decoder_agrees_with_the_shipped_typescript_except_where_it_deliberately_does_not() {
    let mut agreed = 0usize;
    let mut diverged = 0usize;
    for v in group_cx()["vectors"].as_array().unwrap_or(&Vec::new()) {
        let (Some(input), Some(valid)) = (
            v.get("input_base58").and_then(|t| t.as_str()),
            v.get("validate_base58_tag").and_then(serde_json::Value::as_bool),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let ours = mochimo_crypto::addr::tag_from_base58(input);
        if valid {
            // Where the TypeScript validates, we must accept AND return the
            // same twenty bytes it returned.
            let want = v["base58_to_addr_tag"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: validate_base58_tag is true with no tag beside it"));
            let got = ours.unwrap_or_else(|e| {
                panic!("{id}: the TypeScript validated `{input}` and this crate refused it: {e}")
            });
            assert_eq!(
                hexs(&got), want,
                "{id}: both accept `{input}` and they return different tags"
            );
            agreed += 1;
        } else {
            // Where it does not validate, we must refuse -- even though
            // `base58ToAddrTag` still returns a tag for some of these. That is
            // the divergence, and CX-C12 is the vector that carries it.
            assert!(
                ours.is_err(),
                "{id}: `{input}` fails validateBase58Tag and this crate accepted it. The CRC16 \
                 is the only thing between a mistyped destination and a payment nobody can \
                 recover; fusing validate with decode is the whole point."
            );
            if v.get("base58_to_addr_tag").and_then(|t| t.as_str()).is_some() {
                diverged += 1;
            }
        }
    }
    assert!(
        agreed >= 3,
        "only {agreed} vector(s) had both implementations accepting; the agreement half of this \
         walk is nearly empty and the divergence half then proves only that we refuse things"
    );
    assert!(
        diverged >= 1,
        "no vector recorded the TypeScript RETURNING a tag for a string it did not validate. \
         CX-C12 is that vector, and without it this test does not measure the divergence it is \
         named for -- it just agrees with the reference."
    );
    println!(
        "  decoder vs shipped TypeScript: {agreed} agreement(s), {diverged} recorded divergence(s) \
         (validateBase58Tag false, base58ToAddrTag returns a tag, we refuse)"
    );
}

/// **The two accepted forms cannot collide**, which is what makes accepting
/// both safe rather than merely convenient.
///
/// A bare hex tag is forty characters; `addr::TAG_BASE58_MAX_CHARS` is
/// thirty-one. That is asserted three ways here, because the interesting half
/// is not the constant but the claim behind it — *no forty-character Base58
/// string decodes to twenty-two bytes* — and a constant cannot say that.
#[test]
fn the_two_destination_forms_cannot_collide() {
    use mochimo_crypto::addr::{TAG_BASE58_MAX_CHARS, TAG_BASE58_MIN_CHARS};

    // 1. The window is the one the fixtures witness, at BOTH ends. C7's
    //    all-zero tag is the shortest a 22-byte payload can be (one '1' per
    //    leading zero byte) and C8's all-ff tag is the longest.
    let root = group_c();
    let mut shortest = usize::MAX;
    let mut longest = 0usize;
    let mut seen = 0usize;
    for v in root["vectors"].as_array().unwrap_or(&Vec::new()) {
        if let Some(s) = v.get("base58_of_tag22").and_then(|t| t.as_str()) {
            shortest = shortest.min(s.chars().count());
            longest = longest.max(s.chars().count());
            seen += 1;
        }
    }
    for e in root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or(&Vec::new())
    {
        if let Some(s) = e["base58"].as_str() {
            shortest = shortest.min(s.chars().count());
            longest = longest.max(s.chars().count());
            seen += 1;
        }
    }
    assert!(seen >= 1004, "the length walk saw only {seen} recorded encodings");
    assert_eq!(
        (shortest, longest),
        (TAG_BASE58_MIN_CHARS, TAG_BASE58_MAX_CHARS),
        "the declared window is [{TAG_BASE58_MIN_CHARS}, {TAG_BASE58_MAX_CHARS}] but the \
         reference's own strings run [{shortest}, {longest}]"
    );
    // **Statically**, because the property is static and
    // a static property asserted at runtime is asserted in the weaker
    // place. A `const` block is evaluated when this function is compiled, so
    // widening the window past a hex tag's length is a build failure here
    // rather than a red test -- which is a stronger outcome than the runtime
    // form, and is why injection A7 is declared as NOBUILD rather than RED.
    const {
        assert!(
            TAG_BASE58_MAX_CHARS < ADDR_TAG_LEN * 2,
            "a destination can be as long as a hex tag, so the two accepted forms overlap and \
             the parser's length dispatch is ambiguous"
        );
    }

    // 2. The claim the window rests on, walked rather than asserted: build
    //    forty-character Base58 strings across the whole leading-zero axis --
    //    the place the intuition is weakest, and the class the reference
    //    decoder mishandles -- and confirm not one of them is a tag.
    //
    //    The family is chosen to MINIMISE the decoded length for each
    //    leading-zero count, so the walk states the bound rather than sampling
    //    it. With `z` leading `'1'`s the decoded length is `z` plus the byte
    //    length of the value the remaining `40 - z` digits carry; that byte
    //    length is monotone in the value, so the minimum over all
    //    forty-character strings with `z` leading `'1'`s is reached by the
    //    smallest such value -- first digit `'2'` (one) and the rest `'1'`
    //    (zero). Showing the minimum exceeds twenty-two for every `z` covers
    //    the whole forty-character space, not one family in it.
    let mut probed = 0usize;
    let mut smallest = usize::MAX;
    for zeros in 0..=40usize {
        let s: String = if zeros == 40 {
            "1".repeat(40)
        } else {
            "1".repeat(zeros) + "2" + &"1".repeat(39 - zeros)
        };
        assert_eq!(s.chars().count(), 40);
        let decoded = mochimo_crypto::base58::decode(&s)
            .unwrap_or_else(|e| panic!("40-char probe with {zeros} leading '1's: {e}"));
        assert_ne!(
            decoded.len(),
            ADDR_TAG_LEN + 2,
            "a 40-character Base58 string ({s}) decoded to a {}-byte payload -- the two \
             accepted forms CAN collide and the parser's dispatch is unsound",
            ADDR_TAG_LEN + 2
        );
        assert!(
            mochimo_crypto::addr::tag_from_base58(&s).is_err(),
            "a 40-character string was accepted as a destination: {s}"
        );
        smallest = smallest.min(decoded.len());
        probed += 1;
        // The second family, kept as a sample beside the bound: the same
        // leading-zero axis with the tail maximised rather than minimised.
        let big: String = "1".repeat(zeros) + &"z".repeat(40 - zeros);
        let d2 = mochimo_crypto::base58::decode(&big).unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(d2.len(), ADDR_TAG_LEN + 2, "40-char probe (max tail): {big}");
    }
    assert_eq!(probed, 41, "the 40-character probe walked {probed} of 41 cases");
    assert!(
        smallest > ADDR_TAG_LEN + 2,
        "the SHORTEST payload any forty-character Base58 string can decode to is {smallest} \
         bytes, which is not more than the {} a destination carries. The two accepted forms \
         can overlap.",
        ADDR_TAG_LEN + 2
    );

    // 3. And operationally, over the corpus: the hex form of every tag is
    //    refused as a destination, and the destination form is refused as hex.
    let mut both = 0usize;
    for e in root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .take(64)
    {
        let hex = e["tag"].as_str().unwrap_or_default();
        let b58 = e["base58"].as_str().unwrap_or_default();
        assert!(
            mochimo_crypto::addr::tag_from_base58(hex).is_err(),
            "the hex form of a tag was accepted as a destination: {hex}"
        );
        assert!(b58.chars().count() != ADDR_TAG_LEN * 2, "a destination is hex-tag length: {b58}");
        both += 1;
    }
    assert_eq!(both, 64);
    println!(
        "  form disjointness: {seen} recorded encodings in [{shortest},{longest}], {probed} \
         forty-character minima (shortest {smallest} bytes, a destination is {}), {both} \
         corpus pairs", ADDR_TAG_LEN + 2
    );
}

/// **The checksum is what earns the encoding**, and fixture `C12` is the
/// recorded proof that the codec alone would not refuse a typo.
///
/// `C12` is `C9`'s string with its last character altered. The reference's
/// `base58_decode` returns `rc == 0` on it and hands back twenty-two bytes —
/// the fixture records both, and records `checksum_would_reject: true` beside
/// them. So this is not "our parser rejects a bad string"; it is *the
/// reference accepts it, and the CRC16 is the only thing that does not.*
#[test]
fn a_mistyped_destination_is_refused_by_its_checksum() {
    let root = group_c();
    let c12 = root["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .cloned()
        .unwrap_or_else(|| panic!("group C carries C12, the altered-character negative"));
    let altered = c12["in"].as_str().unwrap_or_else(|| panic!("C12 has `in`"));
    assert_eq!(
        c12["rc"].as_i64(),
        Some(0),
        "C12 no longer records the codec ACCEPTING the altered string; without that this test \
         asserts nothing about the checksum"
    );
    assert_eq!(c12["checksum_would_reject"].as_bool(), Some(true));

    // The codec accepts it, exactly as the fixture says.
    let raw = mochimo_crypto::base58::decode(altered)
        .unwrap_or_else(|e| panic!("C12's string was refused by the codec: {e}"));
    assert_eq!(raw.len(), ADDR_TAG_LEN + 2, "C12 decodes to a 22-byte payload");

    // And the checksum does not.
    let refusal = match mochimo_crypto::addr::tag_from_base58(altered) {
        Ok(t) => panic!(
            "an altered destination was ACCEPTED, as tag {}. Funds sent to it are \
             irrecoverable.",
            hexs(&t)
        ),
        Err(e) => format!("{e}"),
    };
    // Rendered and read back: the refusal only ever appears on
    // this path, so a green suite is otherwise silent about its wording.
    assert!(
        refusal.contains("checksum does not match"),
        "the refusal does not say what is wrong: {refusal}"
    );
    assert!(
        refusal.contains("One character is wrong"),
        "the refusal does not tell the operator what to do: {refusal}"
    );
    println!("  checksum refusal: {refusal}");
}

/// **`send <to>` takes a destination from another wallet**, which is the
/// direction that was broken and is the reason the program could not be used
/// in an ecosystem it belongs to.
#[test]
fn send_accepts_a_destination_and_a_hex_tag_and_agrees_with_itself() {
    let dest = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));

    let parse = |tag: &str, to: &str| -> Command {
        match args::parse(&argv(&[
            "--dir", "/d", "--node", "n", "send", tag, to, "1000",
        ]))
        .unwrap_or_else(|e| panic!("`send {tag} {to} 1000` was refused: {e}"))
        {
            args::ParsedArgv::Run(i) => i.command,
            args::ParsedArgv::Help => panic!("a send parsed as help"),
        }
    };

    let want = Command::Send(Spend {
        tag: TAG,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1000) }],
        fee_total: MFEE,
        blk_to_live: 0,
    });
    // Base58 both sides -- what every other wallet hands you.
    assert_eq!(parse(&src, &dest), want, "a Base58 send did not parse to the same spend");
    // `0x` hex both sides -- the machine form the Mesh endpoints use and the
    // form this project's fixtures record. Refusing it would make the
    // project's own values unpasteable into its own wallet.
    assert_eq!(parse(&prefixed(&TAG), &prefixed(&TO)), want, "a 0x-hex send stopped parsing");
    // And mixed, because an operator will do this: their own tag from an
    // own records, the payee's from a wallet.
    assert_eq!(parse(&prefixed(&TAG), &dest), want);
    assert_eq!(parse(&src, &prefixed(&TO)), want);
    // Whitespace is trimmed, as both shipped clients trim: a pasted
    // destination with a trailing newline is 31 characters, inside the window,
    // and would otherwise reach the codec and be refused with a backend error
    // whose text differs between the C and C-free builds.
    assert_eq!(parse(&format!("  {src}\n"), &format!("\t{dest} ")), want, "whitespace");
    // `0x` says "this is hex" whatever its length, so a short one is refused
    // as bad hex rather than as a bad destination.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "status", "0x1234"])) {
        Ok(v) => panic!("`0x1234` parsed: {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("hex characters"),
            "a 0x-prefixed argument was diagnosed as a destination: {u}"
        ),
    }
    // And a Base58 destination can never be captured by the hex arm, because
    // the alphabet has no `0` -- so no destination begins `0x`.
    assert!(
        !src.starts_with('0') && !dest.starts_with('0'),
        "a destination began with `0`, which the Base58 alphabet excludes"
    );
}

/// **The one destination the checksum provably cannot refuse**, refused by
/// name instead.
///
/// `crc16` of twenty zero bytes is zero (group C's `C7` records it), so the
/// all-zero tag's own checksum matches and `addr::tag_from_base58` returns it
/// on the happy path -- correctly, because that function is a codec and the
/// reference encodes and decodes this value like any other. Nothing downstream
/// refuses it either: `SpendPlan` has no zero-tag rule, `mdst_val` refuses a
/// zero *amount* and a destination equal to the source but not a zero tag, and
/// the ledger creates the account on credit. So a payment to it settles, and
/// nothing can ever spend it again.
///
/// It is what an uninitialised field or a truncated column produces, which
/// makes it the one twenty-byte value likeliest to arrive by accident.
#[test]
fn the_all_zero_destination_is_refused_although_its_checksum_verifies() {
    let zero: [u8; ADDR_TAG_LEN] = [0u8; ADDR_TAG_LEN];
    let encoded = mochimo_crypto::addr::tag_to_base58(&zero).unwrap_or_else(|e| panic!("{e}"));
    // It is `C7`'s recorded string, so this is the reference's own value and
    // not one this test made up.
    assert_eq!(encoded, "1".repeat(ADDR_TAG_LEN + 2), "C7's encoding moved");
    // The codec accepts it -- checksum and all. That is the premise.
    assert_eq!(
        mochimo_crypto::addr::tag_from_base58(&encoded).unwrap_or_else(|e| panic!("{e}")),
        zero,
        "the codec must agree with the reference here; the refusal is a policy one layer up"
    );
    // The CLI does not, in either form, and says why.
    for form in [encoded.clone(), format!("0x{}", hexs(&zero))] {
        let u = match args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &form])) {
            Ok(v) => panic!("the all-zero tag `{form}` parsed to {v:?}"),
            Err(u) => format!("{u}"),
        };
        assert!(
            u.contains("all-zero tag"),
            "`{form}`: refused, but not as the zero tag:\n{u}"
        );
        assert!(
            u.contains("cannot refuse this one"),
            "`{form}`: the refusal does not say why the checksum is no help here:\n{u}"
        );
    }
    // The control: one bit away, and it is accepted. Without this the two rows
    // above are satisfied by a parser that refuses everything.
    let mut nearly = zero;
    nearly[ADDR_TAG_LEN - 1] = 1;
    let near = mochimo_crypto::addr::tag_to_base58(&nearly).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(near, "1111111111111111111Nzs", "C10's encoding moved");
    assert!(
        args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &near])).is_ok(),
        "a tag one bit from zero was refused too, so the zero-tag rows establish nothing"
    );
}

/// The parser's refusals for a destination, **rendered and read from a real
/// parse** rather than from the source that produces them.
#[test]
fn the_parser_refuses_a_destination_it_cannot_take() {
    let good = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    // C12: valid Base58, decodes to 22 bytes, checksum wrong.
    let altered = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .and_then(|v| v["in"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C12"));
    // C13's 21-byte payload: valid Base58, decodes to the wrong length.
    let short_payload = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C13")
        .and_then(|v| v["base58_21"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C13"));

    let cases: [(String, &str, &str); 5] = [
        (altered, "checksum does not match", "one character altered"),
        (short_payload, "byte(s); a destination is 22", "a 21-byte payload"),
        ("0OIl0OIl0OIl0OIl0OIl0OIl".to_string(), "not Base58", "outside the alphabet"),
        (String::new(), "character(s); a destination is", "the empty string"),
        ("1".repeat(80), "character(s); a destination is", "eighty characters"),
    ];
    let mut rendered = 0usize;
    for (input, needle, what) in cases {
        let r = args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &input]));
        let u = match r {
            Ok(v) => panic!("{what} (`{input}`) parsed to {v:?}"),
            Err(u) => format!("{u}"),
        };
        assert!(
            u.contains(needle),
            "{what}: refused, but not for {needle:?}.\n--- rendered ---\n{u}"
        );
        assert!(
            u.contains("is not a destination"),
            "{what}: the refusal does not say what kind of thing was expected:\n{u}"
        );
        rendered += 1;
    }
    // The control: the good one is not refused, or every row above is a
    // refusal of everything rather than of these five things.
    assert!(
        args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &good])).is_ok(),
        "a well-formed destination was refused, so the five refusals above establish nothing"
    );
    assert_eq!(rendered, 5);
}

/// **The fake's own control** (the more valuable half of the first-contact finding).
///
/// `Chain::credit_destination` exists so the flow test cannot be funded by a
/// string no other client would take. A door that accepted everything would be
/// worth exactly what the old flow test was, so what it refuses is asserted
/// here — including the two forms a CLI is most likely to print.
#[test]
fn the_fake_refuses_every_form_but_the_reference_one() {
    let good = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let altered = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .and_then(|v| v["in"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C12"));

    let short_payload = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C13")
        .and_then(|v| v["base58_21"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C13"));

    // **Each row carries its own needle**, because "it was refused" is
    // satisfied by a door that refuses everything, and four of these five
    // would otherwise land on one arm. Three arms are reached below and each
    // one is distinguishable in the message.
    let refused: [(String, &str, &str); 6] = [
        // The bare tag.
        (hexs(&TAG), "the 40-hex tag", "character(s); a destination is"),
        // The ledger address.
        (hexs(&addr_at(0)), "the 80-hex ledger address", "character(s); a destination is"),
        (altered, "a destination with one character altered", "checksum does not match"),
        (short_payload, "Base58 over a 21-byte payload", "byte(s); a destination is 22"),
        (String::new(), "the empty string", "character(s); a destination is"),
        ("0OIl0OIl0OIl0OIl0OIl0OIl".to_string(), "characters outside the alphabet", "not Base58"),
    ];
    let mut seen = 0usize;
    let mut arms: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (input, what, needle) in refused {
        let c = Chain::new(&[]);
        match c.credit_destination(&input, addr_at(0), 5_000_000) {
            Ok(t) => panic!(
                "the chain accepted {what} (`{input}`) as a destination, crediting tag {}. \
                 With this door open the flow test cannot catch a CLI that prints an \
                 identifier no other client takes.",
                hexs(&t)
            ),
            Err(e) => {
                assert!(
                    e.contains("refuses it"),
                    "{what}: the refusal does not say what happened:\n{e}"
                );
                assert!(
                    e.contains(needle),
                    "{what}: refused, but not for {needle:?} -- so this row is \
                     indistinguishable from the others:\n{e}"
                );
                arms.insert(needle);
                seen += 1;
            }
        }
    }
    assert_eq!(seen, 6);
    assert_eq!(
        arms.len(),
        4,
        "the six rows reached {} distinct refusal(s); rows that all land on one arm test one \
         arm six times",
        arms.len()
    );
    // And the positive control: the reference form IS accepted, and credits
    // the tag it names. Without this every row above is satisfied by a door
    // that refuses everything.
    let c = Chain::new(&[]);
    assert_eq!(
        c.credit_destination(&good, addr_at(0), 7).unwrap_or_else(|e| panic!("{e}")),
        TAG,
        "the reference form was refused, or credited the wrong tag"
    );
}

/// **Finding B: the route back to the destination.** `address` with no
/// argument lists the store — no node, and **no master seed**, which is the
/// half that matters: the operator who needs this is the one who just mistyped
/// three words of their phrase.
#[test]
fn address_with_no_argument_lists_the_store_with_no_node_and_no_seed() {
    let (_dir, ks) = store("cli-address-list");
    // Every request refused, and no master supplied at all.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: None, account: None });
    assert_eq!(
        r.code,
        Code::Ok,
        "listing the store needed something it should not: {}",
        r.text
    );
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "the listing");
    assert_says(&r, "index 0", "the listing");
    assert_says(&r, "derived", "the listing");
    // **The first line is a HEADER, and that is deliberate.** `address <tag>`
    // puts a bare destination on line one, so a script reads line one. If the
    // listing did too, a script whose tag argument went missing -- an unquoted
    // empty shell variable -- would silently receive a well-formed destination
    // for whatever account sorts first and publish it as an invoice. The
    // header makes that failure loud.
    let first = r.text.lines().next().unwrap_or("");
    assert!(
        first.starts_with("1 account(s)"),
        "the listing's first line is not a header: {first:?}"
    );
    assert!(
        mochimo_crypto::addr::tag_from_base58(first.split_whitespace().next().unwrap_or(""))
            .is_err(),
        "the listing's first line parses as a destination, so a script that lost its tag \
         argument would read one instead of failing: {first:?}"
    );
    // And the account lines really are usable: the strict door takes what was
    // printed, taken the way an operator takes it -- the first field of the
    // line that names their account.
    let line = r
        .text
        .lines()
        .find(|l| l.trim_start().starts_with(&dest))
        .unwrap_or_else(|| panic!("no account line:\n{}", r.text));
    let c = Chain::new(&[]);
    assert_eq!(
        c.credit_destination(line.split_whitespace().next().unwrap_or(""), addr_at(0), 1)
            .unwrap_or_else(|e| panic!("{e}")),
        TAG
    );
}

/// An empty store lists as empty rather than refusing.
#[test]
fn address_with_no_argument_on_an_empty_store_says_so() {
    let dir = ScratchDir::new("cli-address-list-empty");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[])),
        &Command::Address { tag: None, account: None },
    );
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "no accounts in this store", "the empty listing");
}

/// `address` still takes one tag, and two arguments are still a usage error
/// rather than a listing that ignored both.
#[test]
fn address_takes_one_tag_or_none_and_never_two() {
    let a = hexs(&TAG);
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "address", &a, &a])) {
        Ok(v) => panic!("`address <tag> <tag>` parsed to {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("takes one tag, or none at all"),
            "wrong refusal: {u}"
        ),
    }
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "address"])) {
        Ok(args::ParsedArgv::Run(i)) => {
            assert_eq!(i.command, Command::Address { tag: None, account: None })
        }
        other => panic!("bare `address` did not parse to a listing: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Findings B and C at `create`'s own confirmation
// ---------------------------------------------------------------------------

/// The phrase and the answer the run's own entropy produces, so the
/// confirmation can be answered right or wrong on purpose.
fn expected_confirmation() -> String {
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<String> = phrase
        .expose()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    format!(
        "{} {} {}",
        words[p[0] - 1],
        words[p[1] - 1],
        words[p[2] - 1]
    )
}

/// **The route back, re-decided.** A wrong confirmation exits 3 and the way
/// back is named -- and now the way back is `create --from-phrase`,
/// because there is no store to point at.
///
/// The first-contact finding was that the exit-3 refusal carried no route to the
/// account it had just made: the tag was printed only on the exit-0 path, and
/// recovering the tag then means reading `accounts.mks` at offset 22. That
/// is answered by printing the destination in the refusal. With the write
/// behind the confirmation, a refused
/// confirmation leaves no account to find and no destination to print; what
/// the refusal must still carry is the route -- the phrase on the screen
/// rebuilds the identical store through `--from-phrase`, measured by
/// `the_same_phrase_makes_the_same_account_0_in_any_store` and by the pty
/// harness -- and the instruction to record the phrase before funding.
///
/// # What this does *not* change about the confirmation
///
/// It is still one attempt. A retry path was considered and rejected in
/// the same session: a confirmation you may answer until you get it right establishes
/// nothing, and the phrase is on the same screen as the answer. Exit 3 still
/// means *you did not read it back*; now it also means, uniformly with
/// every other refusal, *and nothing was written*.
#[test]
fn a_wrong_confirmation_names_the_route_back_and_no_destination() {
    let dir = ScratchDir::new("cli-create-badconfirm-dest");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, password_then(vec!["abandon abandon abandon".into()]))),
    );
    assert_eq!(r.code, Code::Refused, "a wrong confirmation did not exit 3: {}", r.text);
    assert!(!target.exists(), "a refused confirmation left {} on disk", target.display());

    // The destination the phrase WOULD have produced must not be offered:
    // everything on a refusal screen that looks payable invites funding an
    // account whose backup was just shown not to have been read.
    let expected = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .map(|p| {
            mochimo_crypto::mnemonic::master_seed_from_phrase(p.expose(), "")
                .map(|m| mochimo_crypto::derive::derive_account_tag(&m, 0))
        })
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    let dest = mochimo_crypto::addr::tag_to_base58(&expected).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !r.text.contains(&dest) && !r.text.contains("destination"),
        "the refusal offers a destination for a store that does not exist:\n{}",
        r.text
    );
    assert_says(&r, "Nothing was created", "the exit-3 refusal");
    assert_says(&r, "create --from-phrase", "the exit-3 refusal's route back");
    assert_says(&r, "write the phrase down", "the exit-3 refusal");
}

/// **Finding C.** The three-word confirmation is read **with echo**; the
/// phrase, when one is supplied, is not.
///
/// Echo was off for the confirmation while the phrase sat in full three lines
/// above in the same scrollback — a protection whose subject was already
/// exposed, paid at the moment an operator is most likely to fumble. It cost a
/// real exit 3.
///
/// # Why this asserts the read *kind* and not the answer
///
/// Both reads return a string from the same script, so an assertion on the
/// answer passes identically before and after the change. What is checked is
/// which method ran, which is the only observable difference.
///
/// The other half of C — that no echo-off read can follow the echoing one — is
/// not assertable at runtime, because the program that would violate it does
/// not compile. It is cased in
/// `ui/fail/terminal_cannot_read_a_secret_after_the_visible_read.rs` with a
/// pinned `.stderr` naming `read_visible_line`'s `self`.
#[test]
fn the_confirmation_is_read_visibly_and_a_supplied_phrase_is_not() {
    // Generate: one visible read, and it is the confirmation.
    let dir = ScratchDir::new("cli-create-visible");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let reads: Rc<RefCell<Vec<(&'static str, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let (log, rl) = (Rc::clone(&shown), Rc::clone(&reads));
    let r = create_cmd::orchestrate(
        dir.path(),
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::watching(log, password_then(vec![expected_confirmation()]), rl)),
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    let got = reads.borrow().clone();

    // **The whole read sequence, in order**. It was one read; it is
    // three, and the shape is what preserves both earlier sessions'
    // properties across the password:
    //
    //   1-2. the new password, twice, ECHO OFF. The argument for echoing
    //        the confirmation deliberately does not transfer -- a password
    //        being created is on no screen and in no scrollback, which is
    //        exactly what the mnemonic prompt's argument is about, and typing it twice replaces
    //        seeing it.
    //     3. the three-word confirmation, VISIBLE, and LAST. The seam made the
    //        echoing read take `self`, so it can be called once and nothing
    //        can read after it -- the compiler holds that, and
    //        `ui/fail/terminal_cannot_read_a_secret_after_the_visible_read.rs`
    //        is the case. This assertion is what would notice if the password
    //        reads ever moved AFTER it, which the type system permits (they
    //        would simply never run) and which would put a secret read on the
    //        wrong side of the echo restore.
    assert_eq!(
        got.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        vec!["secret", "secret", "visible"],
        "create's terminal reads are not two echo-off password reads followed by the visible \
         confirmation: {got:?}"
    );
    assert!(
        got[0].1.contains("password") && got[1].1.contains("again"),
        "the first two reads are not the password and its confirmation: {got:?}"
    );
    assert!(
        got[2].1.contains("type words"),
        "the visible read is not the confirmation prompt: {:?}",
        got[2].1
    );

    // Supplied: one read, and it is the SECRET one. The mnemonic prompt's argument
    // holds unchanged there -- that phrase is not on screen.
    let dir2 = ScratchDir::new("cli-create-visible-supplied");
    let shown2: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let reads2: Rc<RefCell<Vec<(&'static str, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let (log2, rl2) = (Rc::clone(&shown2), Rc::clone(&reads2));
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let r2 = create_cmd::orchestrate(
        dir2.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::watching(log2, password_then(vec![phrase.expose().to_string()]), rl2)),
    );
    assert_eq!(r2.code, Code::Ok, "output: {}", r2.text);
    let got2 = reads2.borrow().clone();
    // Three reads here too, and **all three echo-off**: the password twice and
    // then the phrase. There is no visible read on this path at all, because
    // nothing is displayed to read back -- the mnemonic prompt's argument holds for
    // every one of them unchanged, which is the point the confirmation was careful to
    // make about which secrets are already on screen and which are not.
    assert_eq!(
        got2.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        vec!["secret", "secret", "secret"],
        "--from-phrase read something visibly; a phrase the operator types is not on any screen \
         and the mnemonic prompt's argument applies to it in full: {got2:?}"
    );
    assert!(
        got2[2].1.contains("recovery phrase"),
        "the third read is not the phrase prompt: {got2:?}"
    );
    // Only the scheme warning, which is written before the first read; the
    // phrase the operator typed is never echoed.
    assert_eq!(
        shown2.borrow().len(),
        1,
        "the --from-phrase path showed something besides the scheme warning: {:?}",
        shown2.borrow()
    );
}

/// **The listing needs no node and no seed** — the half of
/// `the_seed_is_read_only_for_the_commands_that_use_it` that survived encryption at rest.
///
/// # What replaced what
///
/// That test was a six-row table over `Command`, asserting which invocations
/// needed the operator to type twenty-four words. Its subject is gone: the
/// store is encrypted, so **nothing** can be read out of it without the
/// password, and there is no per-command arm to get right. `cli::needs_master`
/// went with it.
///
/// What did not go is the property that made the listing worth having in the
/// first place: it answers from records, so it derives
/// nothing and asks no node. It needs the password because the bytes are
/// encrypted, not because it needs a key — and those are different claims,
/// which is why this test drives it with a transport that refuses everything.
#[test]
fn the_listing_needs_no_node_and_no_seed() {
    let (_dir, ks) = store("cli-listing-no-node");
    // Every request refused. If the listing reached the chain, this is where
    // it would show.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: None, account: None });
    assert_eq!(
        r.code,
        Code::Ok,
        "listing the store reached for something it should not: {}",
        r.text
    );
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "the listing");

    // And the seed. `store()` adopts a master, so this arm builds
    // one that has NOT -- deliberately, because a listing that quietly needed
    // a seed would be indistinguishable from one that did not if every store
    // in this file had one. The premise is asserted before it is used; when
    // `store()` changed under it, the assertion below is what said so.
    let dir2 = ScratchDir::new("cli-listing-no-master");
    let mut bare = Keystore::create(dir2.path(), &keystore_harness::init())
        .unwrap_or_else(|e| panic!("{e}"));
    bare.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        bare.master().unwrap_or_else(|e| panic!("{e}")).is_none(),
        "this test's premise is that the store holds no master; if it does, the assertion below \
         no longer distinguishes a listing that derives from one that does not"
    );
    let r2 = cli::run(bare, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: None });
    assert_eq!(
        r2.code,
        Code::Ok,
        "the listing refused a store with no master, so it derives after all: {}",
        r2.text
    );
    assert_says(&r2, &dest, "the seedless listing");
}

// ---------------------------------------------------------------------------
// The shipped binary, on a real pseudo-terminal
// ---------------------------------------------------------------------------
//
// Every test above drives `cli::Report` through a double. None executed the
// binary, and the binary is where `create` can show the operator nothing:
// `/dev/tty` opened read-only, every write failing with `EBADF`, every
// result discarded, and a source scan standing in for a test asking only
// whether the impl *names* the descriptor.
// Naming a descriptor is a text property; writing to it is a runtime one. This
// module is the runtime one.
//
// # What it spawns, and how it gets a terminal
//
// It builds the shipped binary -- `cargo build -p mochimo-crypto --features
// mesh-https --bin mcm-wallet`, as a subprocess, exactly as the census in
// `invariants.rs` spawns `cargo test --no-run` -- and runs it under
// `script(1)`, which allocates a pseudo-terminal, makes it the child's
// controlling terminal, forwards its own stdin into the pty and its own stdout
// out of it. No `unsafe`, no `libc::forkpty`, no pty crate: the binary already
// shells out to `stty` rather than calling `termios`, and this is the same
// precedent one tool over. `script` is BSD's on this host (`script -q
// /dev/null cmd args`); util-linux's `-c` form is written in too and marked
// unmeasured, because only macOS has run this.
//
// The binary's own stdout and stderr are redirected to files INSIDE the pty,
// so the transcript holds exactly what the operator's terminal would show and
// the two files hold exactly what a shell redirect would capture. That is the
// terminal property -- no redirection can separate the phrase from the question
// about it -- asserted by executing it rather than by scanning for `println!`.
//
// # Why it is on the board, and why only in the default configuration
//
// A check that lives behind a command nobody runs is a check nobody runs.
// So this is a `#[test]` in
// the board's own `cli` binary and it BUILDS its subject rather than skipping
// when the subject is absent -- a skipping test is green while asserting
// nothing. It is gated on `not(miri)` because it spawns `cargo` and
// `script(1)`, which Miri cannot; the subject links `ring`'s C through
// rustls, in a subprocess, which is the one place the shipped binary's
// C-free property does not reach and never claimed to. Under Miri the module
// is absent, not skipping: nothing there can build the subject.
//
// # What it establishes, and what it cannot
//
// That the shipped binary, given a terminal, shows a password prompt with echo
// off, shows a phrase, asks about it with echo on, writes a store the typed
// password opens, and that the phrase it showed reproduces the store's
// destination both in-process and through `create --from-phrase`. It cannot
// see a terminal emulator's scrollback policy, a `SIGKILL` inside the
// echo-off window, or util-linux `script`'s behaviour.
#[cfg(all(unix, not(miri)))]
mod pty {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use super::create_cmd;
    use super::keystore_harness::ScratchDir;
    use super::{addr_at, hexs, master, TAG};
    use mochimo_crypto::keystore::{Keystore, Unlock, NONCE_SEED_LEN};

    /// How long one step may take before the session is killed and the test
    /// fails with the transcript. The slow step is Argon2id at
    /// `Kdf::RECOMMENDED` in the debug profile, paid once per store written.
    const STEP: Duration = Duration::from_secs(300);

    /// Twelve characters is the floor; this is the suite's usual password.
    const PASSWORD: &str = "harness-password-not-for-real-use";

    /// A node the binary never dials: `create` needs the flag and not the
    /// socket.
    const NODE: &str = "http://127.0.0.1:1";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives at <repo>/crates/mochimo-crypto")
            .to_path_buf()
    }

    /// The shipped binary, built once per test process.
    ///
    /// Everything here is a panic rather than a skip. A harness that cannot
    /// build its subject must say so: returning "absent" would arrive at the
    /// assertions as a pass over nothing, which is the shape this module
    /// exists to end.
    fn wallet_binary() -> &'static Path {
        static EXE: OnceLock<PathBuf> = OnceLock::new();
        EXE.get_or_init(|| {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| {
                panic!(
                    "CARGO is unset. Cargo sets it for every test process it runs, so this \
                     test is not being run by cargo and cannot build the binary it tests. Run \
                     the board with `cargo test`, not by invoking the test binary."
                )
            });
            // Match the profile the outer run is using, as the census does.
            let me = std::env::current_exe().expect("current_exe");
            let release = me.components().any(|c| c.as_os_str() == "release");
            let mut cmd = Command::new(&cargo);
            cmd.current_dir(repo_root()).args([
                "build",
                "-p",
                "mochimo-crypto",
                "--features",
                "mesh-https",
                "--bin",
                "mcm-wallet",
                "--message-format=json",
            ]);
            if release {
                cmd.arg("--release");
            }
            // **The nested cargo must not inherit the variables cargo set for
            // THIS test process**, and this was measured rather than reasoned
            //. `ring`'s build script declares
            // `rerun-if-env-changed=CARGO_MANIFEST_DIR`; cargo sets that
            // variable for every test binary it runs, a nested `cargo build`
            // inherits it, and cargo's fingerprint reads the value out of its
            // own environment -- so a build from inside a test and a build from
            // a shell (or a clippy run, which also runs build scripts) disagree,
            // and every alternation recompiles ring, rustls, webpki, ureq and
            // this crate: 45 to 70 seconds, reported by cargo as
            // `EnvVarChanged { name: "CARGO_MANIFEST_DIR", .. }`. Scrubbing the
            // per-test variables makes the nested build's fingerprint the
            // shell's. `CARGO` and the toolchain selection stay.
            for (k, _) in std::env::vars_os() {
                let k = k.to_string_lossy();
                let injected = matches!(
                    k.as_ref(),
                    "CARGO_MANIFEST_DIR"
                        | "CARGO_MANIFEST_PATH"
                        | "CARGO_CRATE_NAME"
                        | "CARGO_PRIMARY_PACKAGE"
                        | "CARGO_TARGET_TMPDIR"
                        | "OUT_DIR"
                ) || k.starts_with("CARGO_PKG_")
                    || k.starts_with("CARGO_BIN_EXE_");
                if injected {
                    cmd.env_remove(k.as_ref());
                }
            }
            let out = cmd
                .output()
                .unwrap_or_else(|e| panic!("could not run `{cargo} build --bin mcm-wallet`: {e}"));
            assert!(
                out.status.success(),
                "`cargo build --features mesh-https --bin mcm-wallet` failed ({}), so the pty \
                 harness has no subject. This is a build failure of the shipped binary, not a \
                 finding about its terminal handling.\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            let mut exe: Option<PathBuf> = None;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if v["reason"] != "compiler-artifact" || v["target"]["name"] != "mcm-wallet" {
                    continue;
                }
                let is_bin = v["target"]["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|x| x == "bin"));
                if !is_bin {
                    continue;
                }
                if let Some(p) = v["executable"].as_str() {
                    exe = Some(PathBuf::from(p));
                }
            }
            let exe = exe.unwrap_or_else(|| {
                panic!(
                    "cargo built without reporting an executable for the `mcm-wallet` bin \
                     target. The harness reads the path from cargo's own JSON rather than \
                     guessing `target/debug/mcm-wallet`, so a renamed target or a moved target \
                     directory fails here rather than running a stale binary."
                )
            });
            assert!(exe.is_file(), "cargo named {} and it is not a file", exe.display());
            // No path in this line on purpose: whatever this test prints is
            // inside a censused block, and a digit in a path would be an
            // integer the census's floor could read.
            println!(
                "pty harness: built the shipped binary in the {} profile",
                if release { "release" } else { "debug" }
            );
            exe
        })
    }

    /// One shell-quoted word, for the util-linux form that goes through `sh -c`.
    fn quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }

    /// `script(1)` around `wrapper exe args...`, in the host's dialect.
    ///
    /// BSD (macOS) `script` takes the command as trailing arguments and execs
    /// it directly; util-linux takes one string after `-c` and hands it to a
    /// shell, and `-e` makes it return the child's status (BSD's always does).
    /// **Both forms have run.** The BSD one runs on every board on macOS. The
    /// Linux one runs unchanged in the Windows fork's board workflow, on
    /// GitHub's `ubuntu-24.04` runner and that runner's own `script`, which
    /// Ubuntu takes from util-linux: all eighteen `pty::` tests passed on
    /// Linux in each of that workflow's eight runs on 2026-09-24 and 25, on
    /// image versions 20260907.300.1 and 20260920.314.1. The latest is run
    /// 36188984261 in `patricksmithlaravel/mcm-rust-cli-windows`, and
    /// `gh run view --repo patricksmithlaravel/mcm-rust-cli-windows --job
    /// 108249252162 --log | grep -c 'test pty::.* ok'` prints 18 for its
    /// Linux job. The log names no `script` version, so none is claimed. Any
    /// other host fails here rather than passing with no terminal.
    fn script_command(wrapper: &Path, exe: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("script");
        if cfg!(target_os = "macos") {
            cmd.args(["-q", "/dev/null"]).arg(wrapper).arg(exe).args(args);
        } else if cfg!(target_os = "linux") {
            let mut words = vec![quote(&wrapper.to_string_lossy()), quote(&exe.to_string_lossy())];
            words.extend(args.iter().map(|a| quote(a)));
            cmd.args(["-q", "-e", "-c", &words.join(" "), "/dev/null"]);
        } else {
            panic!(
                "the pty harness knows BSD and util-linux `script(1)` and this host is \
                 neither ({}). It does not skip: without a pseudo-terminal nothing here is \
                 measured.",
                std::env::consts::OS
            );
        }
        cmd
    }

    /// What one driven run of the binary left behind.
    pub struct Outcome {
        /// The process's exit code, or `None` if a signal took it.
        pub code: Option<i32>,
        /// Everything the pty carried, `\r` stripped: the operator's screen.
        pub screen: String,
        /// The binary's stdout, as a shell redirect would have captured it.
        pub stdout: String,
        /// The binary's stderr, likewise.
        pub stderr: String,
        /// Prompts this session waited for and answered.
        pub prompts: usize,
    }

    /// A binary running under a pty, with its stdin held by the test.
    ///
    /// Answers are sent only after their prompt has appeared, because the pty
    /// echoes input at the moment it arrives: a password typed ahead of `stty
    /// -echo` would be echoed, and the assertion that it is not would then be
    /// about the harness's timing rather than the binary's echo handling.
    pub struct Session {
        child: Child,
        stdin: Option<ChildStdin>,
        rx: Receiver<Vec<u8>>,
        script_stderr: Arc<Mutex<Vec<u8>>>,
        transcript: Vec<u8>,
        cursor: usize,
        stdout_file: PathBuf,
        stderr_file: PathBuf,
        prompts: usize,
        started: Instant,
    }

    impl Session {
        /// Spawn `mcm-wallet args...` under a pty, with its own stdout and
        /// stderr redirected to files inside `io`.
        pub fn spawn(io: &Path, args: &[&str]) -> Session {
            std::fs::create_dir_all(io).unwrap_or_else(|e| panic!("cannot create {}: {e}", io.display()));
            let wrapper = io.join("run.sh");
            let stdout_file = io.join("stdout");
            let stderr_file = io.join("stderr");
            // The redirect happens INSIDE the pty, so the binary's process-wide
            // streams go to files and only what it writes to /dev/tty reaches
            // the transcript. Redirecting `script` itself would capture both.
            std::fs::write(
                &wrapper,
                "#!/bin/sh\nexec \"$@\" > \"$MCM_PTY_STDOUT\" 2> \"$MCM_PTY_STDERR\"\n",
            )
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", wrapper.display()));
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))
                    .unwrap_or_else(|e| panic!("chmod {}: {e}", wrapper.display()));
            }
            let mut cmd = script_command(&wrapper, wallet_binary(), args);
            cmd.env("MCM_PTY_STDOUT", &stdout_file)
                .env("MCM_PTY_STDERR", &stderr_file)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap_or_else(|e| {
                panic!(
                    "cannot spawn `script`: {e}. The pty harness needs script(1) on PATH and \
                     does not skip without it."
                )
            });
            let stdin = child.stdin.take().expect("piped stdin");
            let mut stdout = child.stdout.take().expect("piped stdout");
            let mut stderr = child.stderr.take().expect("piped stderr");
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            let script_stderr = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&script_stderr);
            std::thread::spawn(move || {
                let mut all = Vec::new();
                let _ = stderr.read_to_end(&mut all);
                sink.lock().unwrap_or_else(|p| p.into_inner()).extend(all);
            });
            Session {
                child,
                stdin: Some(stdin),
                rx,
                script_stderr,
                transcript: Vec::new(),
                cursor: 0,
                stdout_file,
                stderr_file,
                prompts: 0,
                started: Instant::now(),
            }
        }

        fn screen(&self) -> String {
            String::from_utf8_lossy(&self.transcript).replace('\r', "")
        }

        fn diagnostics(&mut self) -> String {
            let status = match self.child.try_wait() {
                Ok(Some(s)) => format!("{s}"),
                Ok(None) => "still running (killed by the harness)".to_string(),
                Err(e) => format!("unknown ({e})"),
            };
            let file = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
            format!(
                "--- status: {status}\n--- the operator's screen ---\n{}\n--- the binary's stdout \
                 ---\n{}\n--- the binary's stderr ---\n{}\n--- script's own stderr ---\n{}",
                self.screen(),
                file(&self.stdout_file),
                file(&self.stderr_file),
                String::from_utf8_lossy(&self.script_stderr.lock().unwrap_or_else(|p| p.into_inner()))
            )
        }

        fn find_from_cursor(&self, needle: &[u8]) -> Option<usize> {
            let hay = &self.transcript[self.cursor..];
            hay.windows(needle.len()).position(|w| w == needle).map(|i| self.cursor + i)
        }

        /// Wait until `needle` appears on the screen after everything already
        /// consumed, and return the text that came before it. Kills the
        /// session and fails the test on timeout or on the pty closing first.
        pub fn expect(&mut self, needle: &str) -> String {
            let deadline = Instant::now() + STEP;
            loop {
                if let Some(at) = self.find_from_cursor(needle.as_bytes()) {
                    let before = String::from_utf8_lossy(&self.transcript[self.cursor..at])
                        .replace('\r', "");
                    self.cursor = at + needle.len();
                    return before;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                match self.rx.recv_timeout(left.max(Duration::from_millis(1))) {
                    Ok(chunk) => self.transcript.extend(chunk),
                    Err(RecvTimeoutError::Disconnected) => {
                        let d = self.diagnostics();
                        panic!(
                            "THE OPERATOR WAS NEVER SHOWN {needle:?}: the pty closed without it. \
                             This is the shape of the read-only-descriptor defect -- the binary reached the end \
                             of a path whose prompt never appeared.\n{d}"
                        );
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let _ = self.child.kill();
                        let d = self.diagnostics();
                        panic!(
                            "THE OPERATOR WAS NEVER SHOWN {needle:?}: nothing more appeared on the \
                             pty in {:?} (session age {:?}). A binary waiting on an answer to a \
                             question it never asked looks exactly like this.\n{d}",
                            STEP,
                            self.started.elapsed()
                        );
                    }
                }
            }
        }

        /// `expect`, counted: the needle is a prompt the harness will answer.
        pub fn expect_prompt(&mut self, needle: &str) -> String {
            let s = self.expect(needle);
            self.prompts += 1;
            s
        }

        /// End of input at the prompt: one `0x04` byte (VEOF), no newline.
        /// The pty's line discipline is canonical -- the binary turns echo
        /// off and nothing else -- so a VEOF at the start of a line makes the
        /// binary's first `read` of the line return zero bytes, which
        /// `read_scrubbed_line` reports as end of input, keeping `read_line`'s
        /// contract; that is the case the third parse defect was about.
        pub fn send_eof(&mut self) {
            let stdin = self.stdin.as_mut().expect("stdin is held until finish");
            stdin
                .write_all(b"\x04")
                .and_then(|()| stdin.flush())
                .unwrap_or_else(|e| panic!("cannot send end-of-file into the pty: {e}"));
        }

        /// Type a line, Enter included.
        pub fn send(&mut self, line: &str) {
            let stdin = self.stdin.as_mut().expect("stdin is held until finish");
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .unwrap_or_else(|e| panic!("cannot type into the pty: {e}"));
        }

        /// Wait for the binary to exit on its own, then collect everything.
        pub fn finish(mut self) -> Outcome {
            let deadline = Instant::now() + STEP;
            let status = loop {
                match self.child.try_wait() {
                    Ok(Some(s)) => break s,
                    Ok(None) if Instant::now() < deadline => {
                        // Keep draining so a chatty child cannot fill the pipe.
                        while let Ok(chunk) = self.rx.try_recv() {
                            self.transcript.extend(chunk);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Ok(None) => {
                        let _ = self.child.kill();
                        let d = self.diagnostics();
                        panic!(
                            "the binary did not exit within {STEP:?} of its last answer. A \
                             process still waiting for input after the confirmation is a \
                             process that asked a question the harness did not see.\n{d}"
                        );
                    }
                    Err(e) => panic!("waiting for script: {e}"),
                }
            };
            // The child is gone; closing stdin now lets `script` finish and
            // its reader thread hit EOF.
            drop(self.stdin.take());
            while let Ok(chunk) = self.rx.recv_timeout(Duration::from_secs(5)) {
                self.transcript.extend(chunk);
            }
            let file = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
            Outcome {
                code: status.code(),
                screen: self.screen(),
                stdout: file(&self.stdout_file),
                stderr: file(&self.stderr_file),
                prompts: self.prompts,
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // A test that panicked mid-session must not leave `script` and the
            // binary parked on a pty waiting for an answer that will not come.
            if let Ok(None) = self.child.try_wait() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    /// The twenty-four words: the first line after `WRITE THIS DOWN` with
    /// exactly that many lowercase words on it.
    fn phrase_after_notice(s: &mut Session) -> Vec<String> {
        s.expect("WRITE THIS DOWN");
        // The phrase is the next line with 24 tokens; wait for the sentence
        // that follows it so the whole line is guaranteed to have arrived.
        let block = s.expect("It is the ONLY backup of this wallet.");
        let words: Vec<String> = block
            .lines()
            .map(str::split_whitespace)
            .map(|ws| ws.map(str::to_owned).collect::<Vec<_>>())
            .find(|ws| ws.len() == 24)
            .unwrap_or_else(|| panic!("no 24-word line between the notice and its explanation:\n{block}"));
        for w in &words {
            assert!(
                !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()),
                "a shown word is not a lowercase word: {w:?}"
            );
        }
        words
    }

    /// The positions the question asks for, read off the screen and checked
    /// against the constant the binary was built with -- two sources, so a
    /// question asking for different words than the code confirms fails here.
    fn positions_asked(s: &mut Session) -> [usize; 3] {
        s.expect("type words ");
        let text = s.expect_prompt(", separated by spaces: ");
        let nums: Vec<usize> = text
            .split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .map(|t| t.parse().unwrap_or_else(|e| panic!("{t:?} in {text:?}: {e}")))
            .collect();
        let got: [usize; 3] = nums
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("the question names {} position(s), not 3: {text:?}", nums.len()));
        assert_eq!(
            got,
            create_cmd::CONFIRM_POSITIONS,
            "the question on the screen asks for different positions than the code confirms"
        );
        got
    }

    /// Account 0's destination for a phrase, computed in this process from
    /// the crate's own derivation -- the second route to the value the binary
    /// prints, so the two can disagree.
    fn destination_of(phrase: &str) -> String {
        let m = mochimo_crypto::mnemonic::master_seed_from_phrase(phrase, "")
            .unwrap_or_else(|e| panic!("{e}"));
        let tag = mochimo_crypto::derive::derive_account_tag(&m, 0);
        mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"))
    }

    /// **The harness's property.** The shipped binary, on a terminal, shows a
    /// phrase, and the phrase it shows recovers the store it writes.
    ///
    /// Every assertion here went red under the defect this test exists for:
    /// with `/dev/tty` opened read-only the first `expect` times out, because
    /// the password prompt never reaches the screen.
    #[test]
    fn create_on_a_real_pty_shows_a_phrase_that_recovers_the_store() {
        let io = ScratchDir::new("pty-create-io");
        let store = ScratchDir::new("pty-create");
        let dir = store.path().to_string_lossy().into_owned();

        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "create"]);
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(&mut s);
        let p = positions_asked(&mut s);
        let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
        s.send(&answer);
        let o = s.finish();
        let phrase = words.join(" ");

        assert_eq!(o.code, Some(0), "create did not exit 0.\n--- screen ---\n{}\n--- stdout ---\n{}\n--- stderr ---\n{}", o.screen, o.stdout, o.stderr);

        // The screen: the phrase once, the password never, the answer echoed.
        assert_eq!(o.screen.matches(&phrase).count(), 1, "the phrase is not on the screen exactly once:\n{}", o.screen);
        assert!(!o.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the terminal:\n{}", o.screen);
        assert_eq!(
            o.screen.matches(&answer).count(),
            1,
            "the confirmation answer was not echoed exactly once -- either echo was not restored \
             before the question or the echo landed twice:\n{}",
            o.screen
        );

        // The streams: the report on stdout, the phrase on neither.
        assert!(!o.stdout.contains(&phrase) && !o.stderr.contains(&phrase), "THE PHRASE LEFT THE TERMINAL through a process-wide stream -- `create > file` would have written the words to disk.\n--- stdout ---\n{}\n--- stderr ---\n{}", o.stdout, o.stderr);
        assert!(!o.screen.contains("destination"), "the report went to the terminal rather than to stdout:\n{}", o.screen);
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        let expected = destination_of(&phrase);
        assert!(o.stdout.contains("created "), "no `created` line on stdout:\n{}", o.stdout);
        assert!(o.stdout.contains(&format!("destination  {expected}")), "stdout does not carry the destination this process derived from the shown phrase.\n--- stdout ---\n{}\n--- expected ---\n{expected}", o.stdout);
        assert!(o.stdout.contains("confirmed    3 words read back"), "stdout does not say the confirmation happened:\n{}", o.stdout);

        // The store: on disk, opened by the password that was typed, holding
        // account 0 of the phrase that was shown.
        let ks = Keystore::open(
            store.path(),
            &Unlock { password: PASSWORD.as_bytes(), nonce_seed: [7u8; NONCE_SEED_LEN] },
        )
        .unwrap_or_else(|e| panic!("the store the binary wrote does not open with the password that was typed: {e}"));
        let tags = ks.tags().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tags.len(), 1, "the store should hold exactly account 0");
        assert_eq!(
            mochimo_crypto::addr::tag_to_base58(&tags[0]).unwrap_or_else(|e| panic!("{e}")),
            expected,
            "the store holds a different account than the phrase on the screen derives"
        );
        drop(ks);

        // The phrase recovers the store: `create --from-phrase`, typed on a
        // second pty with echo off, into a fresh directory, lands on the same
        // destination. This is the measurement the confirm-before-write
        // decision rests on.
        let io2 = ScratchDir::new("pty-restore-io");
        let store2 = ScratchDir::new("pty-restore");
        let dir2 = store2.path().to_string_lossy().into_owned();
        let mut s2 = Session::spawn(io2.path(), &["--dir", &dir2, "--node", NODE, "create", "--from-phrase"]);
        s2.expect_prompt("choose a password for this wallet");
        s2.send(PASSWORD);
        s2.expect_prompt("type it again: ");
        s2.send(PASSWORD);
        s2.expect_prompt("existing recovery phrase (12 or 24 words): ");
        s2.send(&phrase);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(0), "create --from-phrase did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(!o2.screen.contains(&phrase), "THE TYPED PHRASE WAS ECHOED on the --from-phrase path:\n{}", o2.screen);
        assert!(o2.stdout.contains(&format!("destination  {expected}")), "the phrase the first run showed did not reproduce its destination through --from-phrase.\n--- stdout ---\n{}\n--- expected ---\n{expected}", o2.stdout);

        println!(
            "tty create: {} prompt(s) answered on a pseudo-terminal by the shipped binary",
            o.prompts + o2.prompts
        );
    }

    /// A wrong answer on a real terminal exits 3 with nothing on disk.
    ///
    /// The double-driven twin above holds the same property at the seam; this
    /// one holds it for the binary, where the exit code is a process's and
    /// the directory is a real one.
    #[test]
    fn a_wrong_confirmation_on_a_real_pty_leaves_nothing_on_disk() {
        let io = ScratchDir::new("pty-badconfirm-io");
        let store = ScratchDir::new("pty-badconfirm");
        let dir = store.path().to_string_lossy().into_owned();

        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "create"]);
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(&mut s);
        let _ = positions_asked(&mut s);
        s.send("abandon abandon abandon");
        let o = s.finish();

        assert_eq!(o.code, Some(3), "a wrong confirmation did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(
            !store.path().exists(),
            "THE STORE WAS WRITTEN BEFORE THE CONFIRMATION: {} exists after exit 3. The exit \
             code says refused and the filesystem says created.",
            store.path().display()
        );
        assert!(o.stderr.contains("those are not words 1, 12 and 24"), "the refusal is not on stderr:\n{}", o.stderr);
        assert!(o.stderr.contains("Nothing was created"), "the refusal does not say nothing was created:\n{}", o.stderr);
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-3 path:\n{}", o.stdout);
        assert_eq!(o.screen.matches(&words.join(" ")).count(), 1, "the phrase is not on the screen exactly once:\n{}", o.screen);
        println!(
            "tty refusal: {} prompt(s) answered on a pseudo-terminal by the shipped binary",
            o.prompts
        );
    }

    /// Drive `create`'s prompts on an open session and return the words it
    /// showed. Shared by the tests that need a store made through the binary.
    fn drive_create(s: &mut Session) -> Vec<String> {
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(s);
        let p = positions_asked(s);
        let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
        s.send(&answer);
        words
    }

    /// The two commands that need no node run without `--node`, and the
    /// shared password prompt reaches the terminal, not stderr.
    ///
    /// # Two defects, one run, because the second is only reachable past
    /// # the first
    ///
    /// `create` and `address` exiting 1 with `usage: --node is required`
    /// contradicts a help that says they need no node. And a free
    /// `read_secret_line` writing its prompt with `eprint!` makes
    /// `address 2>file` ask for a password on no screen -- the same defect
    /// `create` has, one impl over. The harness redirects the
    /// binary's stderr to a file INSIDE the pty, so the assertion that the
    /// prompt is on the screen and not in that file is exactly the property
    /// `eprint!` cannot have.
    ///
    /// What makes it red: `--node` required for either command (the first
    /// `expect` sees the pty close on exit 1); the prompt written to stderr
    /// (the screen never shows it and the stderr file does); `/dev/tty` opened
    /// read-only (the write fails and the binary refuses); anything at all on
    /// stderr on the exit-0 path.
    #[test]
    fn address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr() {
        let io = ScratchDir::new("pty-nonode-create-io");
        let store = ScratchDir::new("pty-nonode");
        let dir = store.path().to_string_lossy().into_owned();

        // `create`, with no `--node` on argv at all.
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "create"]);
        let words = drive_create(&mut s);
        let o = s.finish();
        assert_eq!(o.code, Some(0), "create without --node did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        let expected = destination_of(&words.join(" "));
        assert!(o.stdout.contains(&format!("destination  {expected}")), "create's stdout lacks the destination:\n{}", o.stdout);
        assert!(!o.stderr.contains("--node"), "create without --node complained about the node:\n{}", o.stderr);
        // The third of the three texts -- `created_text` -- is read back
        // here; the parser test holds the two in `HELP`.
        assert!(
            o.stdout.contains("both need no `--node`"),
            "create's report no longer says the two commands need no --node:\n{}",
            o.stdout
        );

        // `address`, with no `--node`, its stderr going to a file. The prompt
        // must be on the screen; the password must not be.
        let io2 = ScratchDir::new("pty-nonode-address-io");
        let mut s2 = Session::spawn(io2.path(), &["--dir", &dir, "address"]);
        s2.expect_prompt("password: ");
        s2.send(PASSWORD);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(0), "address without --node did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert_eq!(
            o2.screen.matches("password: ").count(),
            1,
            "the password prompt is not on the operator's screen exactly once:\n{}",
            o2.screen
        );
        assert!(
            !o2.stderr.contains("password"),
            "THE PASSWORD PROMPT WENT TO STDERR: `address 2>file` would ask for a password on no \
             screen. The prompt must go to the terminal the binary acquired, as `create`'s \
             does.\n--- stderr file ---\n{}",
            o2.stderr
        );
        assert!(!o2.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the terminal:\n{}", o2.screen);
        assert!(o2.stderr.is_empty(), "stderr is not empty on address's exit-0 path:\n{}", o2.stderr);
        assert!(o2.stdout.contains("1 account(s) in this store:"), "address did not list the store:\n{}", o2.stdout);
        assert!(o2.stdout.contains(&expected), "the listing lacks the destination create printed:\n--- stdout ---\n{}\n--- expected ---\n{expected}", o2.stdout);
        assert!(!o2.screen.contains(&expected), "the listing went to the terminal rather than to stdout:\n{}", o2.screen);

        println!(
            "tty password: {} prompt(s) answered on a pseudo-terminal by the shipped binary with no node",
            o.prompts + o2.prompts
        );
    }

    /// A command that reconciles refuses at argv without `--node`, before
    /// any prompt -- the direction the relaxation must not have widened.
    ///
    /// `balance` is the representative: the parser test walks all seven. Here
    /// the point is the ordering an operator meets -- exit 1 with the usage
    /// on stderr, nothing on the screen, no password asked, no directory
    /// made -- which is what an earlier-than-the-prompt refusal looks like
    /// from outside the process.
    #[test]
    fn balance_without_a_node_is_a_usage_error_before_any_prompt() {
        let io = ScratchDir::new("pty-nonode-balance-io");
        let store = ScratchDir::new("pty-nonode-balance");
        let dir = store.path().to_string_lossy().into_owned();
        let s = Session::spawn(io.path(), &["--dir", &dir, "balance"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "balance without --node did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        // The exact phrase, because the usage text that follows it names
        // every verb and "balance" alone would match any usage error.
        assert!(
            o.stderr.contains("usage: --node is required for `balance`"),
            "the refusal is not the usage error naming the verb:\n{}",
            o.stderr
        );
        assert!(o.screen.trim().is_empty(), "something reached the terminal before the usage refusal:\n{}", o.screen);
        // The needle is the prompt, not the word: the usage text on stderr
        // says "prompts for its password" and this first read as a prompt.
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "a password was asked for before argv was refused.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o.screen,
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-1 path:\n{}", o.stdout);
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty usage: exit 1 with no prompt for balance without a node");
    }


    /// A help spelling after the verb is a usage error through the binary:
    /// `send <tag> -h 5` exits 1 with the usage naming `-h`, nothing on the
    /// screen, no prompt, no directory made -- the same shape as every other
    /// stray token, refused before the store is read.
    #[test]
    fn a_help_spelling_in_an_argument_position_is_a_usage_error_not_help() {
        let io = ScratchDir::new("pty-help-position-io");
        let store = ScratchDir::new("pty-help-position");
        let dir = store.path().to_string_lossy().into_owned();
        let tag = format!("0x{}", hexs(&TAG));
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "send", &tag, "-h", "5"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "`send <tag> -h 5` did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}", o.screen, o.stderr, o.stdout);
        assert!(
            o.stderr.contains("usage: unexpected argument `-h` after `send`"),
            "the refusal is not the usage error naming the token:\n{}",
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-1 path (the help was printed?):\n{}", o.stdout);
        assert!(o.screen.trim().is_empty(), "something reached the terminal before the usage refusal:\n{}", o.screen);
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty help position: exit 1 naming `-h` for send <tag> -h 5, no prompt, no help printed");
    }

    /// A repeated flag is a usage error through the binary: `send ... --fee
    /// 500 --fee 600` exits 1 naming `--fee`, before any prompt.
    #[test]
    fn a_repeated_flag_is_a_usage_error_before_any_prompt() {
        let io = ScratchDir::new("pty-repeated-flag-io");
        let store = ScratchDir::new("pty-repeated-flag");
        let dir = store.path().to_string_lossy().into_owned();
        let tag = format!("0x{}", hexs(&TAG));
        let to = format!("0x{}", hexs(&super::TO));
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "send", &tag, &to, "1", "--fee", "500", "--fee", "600"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "a repeated --fee did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("usage: --fee given twice"), "the refusal does not name the repeated flag:\n{}", o.stderr);
        assert!(!o.screen.contains("password: ") && !o.stderr.contains("password: "), "a password was asked before argv was refused");
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty repeated flag: exit 1 naming --fee, no prompt");
    }

    /// **Ctrl-D at the password prompt is end of input, refused in its own
    /// words before the store is read**. The read returns zero bytes and
    /// `read_scrubbed_line` hands them back as end of input; reading them as
    /// an empty line instead, trimming that to an empty password and handing
    /// it to the store, reports a wrong password. Delivered as one
    /// `0x04` byte with no newline into the pty; that the binary saw it as
    /// end-of-file rather than an empty line is what the refusal text
    /// shows -- the wrong-password text is absent, the end-of-input text is
    /// present, exit 2 (nothing ran), and the snapshot bytes are untouched
    /// with the lock released. Then `create`'s first prompt, the same byte:
    /// exit 3 in `create`'s own class with "Nothing was created" and no
    /// directory made.
    #[test]
    fn end_of_input_at_a_prompt_is_refused_before_anything_is_compared() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-eof");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let io = ScratchDir::new("pty-eof-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "balance"]);
        s.expect_prompt("password: ");
        s.send_eof();
        let o = s.finish();
        assert_eq!(o.code, Some(2), "end of input at the password prompt did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("end of input at the prompt"), "the refusal is not the end-of-input text:\n{}", o.stderr);
        assert!(
            !o.stderr.contains("did not decrypt") && !o.stderr.contains("password is wrong"),
            "END OF INPUT WAS REPORTED AS A WRONG PASSWORD: the binary read Ctrl-D as an empty line and compared it:\n{}",
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-2 path:\n{}", o.stdout);
        assert_eq!(store.snapshot_bytes(), before, "the store was touched by a refused prompt");
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("the lock was not released after the refusal: {e}"));
        drop(ks);

        let fresh = ScratchDir::new("pty-eof-create");
        let fresh_dir = fresh.path().to_string_lossy().into_owned();
        let io2 = ScratchDir::new("pty-eof-create-io");
        let mut s2 = Session::spawn(io2.path(), &["--dir", &fresh_dir, "create"]);
        s2.expect_prompt("choose a password for this wallet");
        s2.send_eof();
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(3), "end of input at create's first prompt did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(o2.stderr.contains("end of input at the prompt"), "create's refusal is not the end-of-input text:\n{}", o2.stderr);
        // Both halves: the sentence and the directory. A `create` whose
        // password-read refusals lack the sentence its phrase-read refusals
        // carry passes an arm that asserts the absent directory alone.
        assert!(o2.stderr.contains("Nothing was created"), "create's end-of-input refusal does not say nothing was created:\n{}", o2.stderr);
        assert!(!fresh.path().exists(), "end of input at create's prompt made the directory {}", fresh.path().display());
        println!("tty end of input: one 0x04 byte at the password prompt -> exit 2 in the prompt's own words, store untouched; at create's prompt -> exit 3 saying nothing was created, and nothing was");
    }

    /// `address --account 1` through the shipped binary: no `--node`, the
    /// password answered, exit 0 with a destination on line one and NOT
    /// STORED on the page, nothing on stderr, and the snapshot bytes
    /// identical before and after.
    #[test]
    fn address_account_on_a_real_pty_needs_no_node_and_writes_nothing() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-address-account");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let io = ScratchDir::new("pty-address-account-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "address", "--account", "1"]);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        let o = s.finish();
        assert_eq!(o.code, Some(0), "address --account 1 did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        let expected = mochimo_crypto::addr::tag_to_base58(&super::chain::tag1()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(o.stdout.lines().next().unwrap_or_default(), expected, "line one is not account 1's destination:\n{}", o.stdout);
        assert!(o.stdout.contains("NOT STORED"), "the page does not say the account is not stored:\n{}", o.stdout);
        assert_eq!(store.snapshot_bytes(), before, "address --account WROTE to the store through the binary");
        println!("tty address --account: {} prompt(s), no node, exit 0, snapshot bytes identical", o.prompts);
    }

    /// A failed open leaves `keystore.lock` behind, and the leftover
    /// is inert: `create` refuses on the snapshot while it is there, and
    /// proceeds through the lock once it is not.
    ///
    /// # The scenario, replayed through the binary
    ///
    /// A copied store (its lock deleted from the copy, its version word set
    /// to 2) has its lock recreated by the failed open, and `create` then
    /// refuses the directory. A refusal naming the lock file, and advising
    /// running any other command against the
    /// store, every one of which refuses `Missing`: a loop with no exit that
    /// either message named. The side effect itself is kept and
    /// measured here through the binary, at the second step.
    ///
    /// What makes it red: the lock no longer left by the failed open (step
    /// two's listing); `create` overwriting a snapshot it cannot read (step
    /// three's exit code, or the bytes moving); `create` refusing a directory
    /// holding only an unheld lock (step four's exit code).
    #[test]
    fn a_failed_open_leaves_an_inert_lock_and_create_proceeds_once_the_snapshot_is_gone() {
        let store = ScratchDir::new("pty-leftover-lock");
        let dir = store.path().to_string_lossy().into_owned();
        let has = |name: &str| store.listing().iter().any(|n| n == name);

        // A real store, then a copy of it: version word 2, no lock. The
        // fresh word is 4 (3 before format version 4); 2 stays the
        // refused version this test needs, since the version-3 word is READ
        // and would open.
        let ks = Keystore::create(store.path(), &super::keystore_harness::init())
            .unwrap_or_else(|e| panic!("{e}"));
        drop(ks);
        let mut image = store.snapshot_bytes();
        assert_eq!(
            u16::from_le_bytes([image[8], image[9]]),
            4,
            "premise: a fresh store's version word is 4; the flip below assumes the layout"
        );
        image[8..10].copy_from_slice(&2u16.to_le_bytes());
        store.write_snapshot(&image);
        std::fs::remove_file(store.path().join("keystore.lock")).unwrap_or_else(|e| panic!("{e}"));
        assert!(!has("keystore.lock"), "premise: the copy has no lock");

        // 1. `balance` prompts, opens, is refused on the version word -- and
        //    the lock is back.
        let io = ScratchDir::new("pty-leftover-balance-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "balance"]);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        let o = s.finish();
        assert_eq!(o.code, Some(2), "balance on a version-2 file did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("format version 2"), "the refusal does not name the version:\n{}", o.stderr);
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-2 path:\n{}", o.stdout);
        assert!(
            has("keystore.lock"),
            "the failed open did NOT leave keystore.lock: `open_with` no longer takes the lock \
             before the read, and the keystore module doc's \"The lock\" recording the side \
             effect is now false. Listing: {:?}",
            store.listing()
        );

        // 2. `create` over the unreadable snapshot: refused on the SNAPSHOT,
        //    before any prompt, with the bytes untouched. Not an overwrite path.
        let io2 = ScratchDir::new("pty-leftover-create-refused-io");
        let s2 = Session::spawn(io2.path(), &["--dir", &dir, "create"]);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(3), "create over an existing snapshot did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(o2.stderr.contains("a keystore already exists") && o2.stderr.contains("snapshot is present"), "the refusal does not name the snapshot:\n{}", o2.stderr);
        assert!(
            o2.stderr.contains("use a different --dir") && o2.stderr.contains("restore --account N"),
            "the refusal names no next step:\n{}",
            o2.stderr
        );
        assert!(!o2.stderr.contains("lock file"), "the refusal named the lock file rather than the snapshot:\n{}", o2.stderr);
        assert!(o2.screen.trim().is_empty(), "create over an existing store showed the operator something:\n{}", o2.screen);
        assert_eq!(store.snapshot_bytes(), image, "THE UNREADABLE SNAPSHOT WAS REWRITTEN by a refused create");

        // 3. The operator removes the snapshot; the lock stays; and
        //    `create` walks through it.
        std::fs::remove_file(store.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.listing(), vec!["keystore.lock".to_string()], "premise: only the lock remains");
        let io3 = ScratchDir::new("pty-leftover-create-io");
        let mut s3 = Session::spawn(io3.path(), &["--dir", &dir, "create"]);
        let words = drive_create(&mut s3);
        let o3 = s3.finish();
        assert_eq!(
            o3.code,
            Some(0),
            "create REFUSED a directory holding only an unheld keystore.lock -- the stale-lock \
             semantics the lock design chose flock to avoid.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o3.screen,
            o3.stderr
        );
        let expected = destination_of(&words.join(" "));
        assert!(o3.stdout.contains(&format!("destination  {expected}")), "create's stdout lacks the destination:\n{}", o3.stdout);
        let ks = Keystore::open(
            store.path(),
            &Unlock { password: PASSWORD.as_bytes(), nonce_seed: [7u8; NONCE_SEED_LEN] },
        )
        .unwrap_or_else(|e| panic!("the store created through the leftover lock does not open: {e}"));
        assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")).len(), 1);
        drop(ks);

        println!(
            "tty leftover lock: {} prompt(s) answered on a pseudo-terminal across the refused open, the refused create and the create that proceeded",
            o.prompts + o2.prompts + o3.prompts
        );
    }


    /// A `--node` this program cannot use is refused before any prompt, for
    /// every command alike -- including the two that never dial.
    ///
    /// Validation after the password read and the store's open would make
    /// `address --node localhost:8080` prompt, run Argon2id, take the keystore
    /// lock and THEN say `cannot use node`, exit 2, for a command the help
    /// says needs no node -- while `create --node localhost:8080` is accepted
    /// silently, dispatched before any transport exists. The transport is
    /// built first for all ten verbs, and it opens no
    /// socket, so a bad URL costs nothing and asks nothing.
    #[test]
    fn a_malformed_node_is_refused_before_any_prompt_whatever_the_command() {
        let store = ScratchDir::new("pty-badnode");
        let dir = store.path().to_string_lossy().into_owned();
        let mut refused = 0usize;
        for verb in ["create", "address", "balance"] {
            let io = ScratchDir::new("pty-badnode-io");
            let s = Session::spawn(io.path(), &["--dir", &dir, "--node", "localhost:8080", verb]);
            let o = s.finish();
            assert_eq!(o.code, Some(2), "`{verb} --node localhost:8080` did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
            assert!(o.stderr.contains("cannot use node localhost:8080"), "`{verb}`'s refusal does not name the node:\n{}", o.stderr);
            assert!(o.screen.trim().is_empty(), "`{verb}` showed the operator something before refusing the node:\n{}", o.screen);
            assert!(!o.screen.contains("password: ") && !o.stderr.contains("password: "), "`{verb}` asked for a password before refusing the node");
            assert!(o.stdout.is_empty(), "`{verb}` wrote to stdout on the exit-2 path:\n{}", o.stdout);
            assert!(!store.path().exists(), "`{verb}` made the directory {} before refusing the node", store.path().display());
            refused += 1;
        }
        println!("tty malformed node: {refused} command(s) refused before any prompt");
    }
    // ---------------------------------------------------------------------
    // The acknowledged path, through the shipped binary
    // ---------------------------------------------------------------------

    /// A loopback Mesh endpoint that answers every `/call` with one ledger
    /// entry, switchable between requests, and records how many it answered.
    ///
    /// The binary's transport is the real `UreqTransport` over a real socket;
    /// only the far end is ours, as in `tests/mesh_http.rs`. It answers the
    /// same BALANCE and the same hash half whatever tag is asked for, and
    /// splices the asked-for tag into the answer's tag half -- `"tag"` is
    /// the one 40-hex field a `/call` body carries. That splice arrived at
    /// `discover` is the first verb that asks about more than one
    /// tag: the codec checks that a resolved address begins with the tag it
    /// asked about, so a fixed answer made every index after the first a
    /// parse failure. It changes nothing for the tests that came before,
    /// which all ask about `TAG` alone and whose configured addresses
    /// already begin with it.
    /// What the loopback answers `/construction/submit` with.
    #[derive(Clone, Copy)]
    enum Submit {
        /// As every other path: the ledger entry, which `parse_submit`
        /// refuses -- the state every earlier pty test ran in, kept so
        /// their call counts and pages are what they were.
        AsLedger,
        /// HTTP 503, the first live recovery's lever: the reservation is written and
        /// the write fails.
        Refuse,
        /// Echo this id, bare hex -- the live endpoint's shape, as the
        /// scripted `Chain` answers it.
        Accept([u8; 32]),
    }

    /// The 20 bytes of the one `"tag": "0x<40 hex>"` field a `/call` body
    /// carries, if it carries one. `None` for every other path, whose
    /// bodies name no tag -- `/block`, `/network/status`, a submit.
    fn asked_tag(body: &[u8]) -> Option<[u8; 20]> {
        let text = String::from_utf8_lossy(body);
        let at = text.find("\"tag\"")?;
        let rest = &text[at..];
        let start = rest.find("0x")? + 2;
        let hex: String = rest[start..].chars().take(40).collect();
        if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }

    struct Ledger {
        url: String,
        entry: Arc<Mutex<(mochimo_crypto::addr::Address, u64)>>,
        answered: Arc<Mutex<usize>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        submit: Arc<Mutex<Submit>>,
        /// Every `/construction/submit` body, whatever was answered.
        submits: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Ledger {
        fn serve(address: mochimo_crypto::addr::Address, balance: u64) -> Ledger {
            use std::io::{Read as _, Write as _};
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
            listener.set_nonblocking(true).unwrap_or_else(|e| panic!("nonblocking: {e}"));
            let port = listener.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}")).port();
            let entry = Arc::new(Mutex::new((address, balance)));
            let answered = Arc::new(Mutex::new(0usize));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let submit = Arc::new(Mutex::new(Submit::AsLedger));
            let submits: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let (e2, a2, s2) = (Arc::clone(&entry), Arc::clone(&answered), Arc::clone(&stop));
            let (m2, b2) = (Arc::clone(&submit), Arc::clone(&submits));
            std::thread::spawn(move || {
                while !s2.load(std::sync::atomic::Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(c) => c,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => panic!("accept: {e}"),
                    };
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    // Read one request: headers, then Content-Length bytes.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let header_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(i + 4);
                        }
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let Some(header_end) = header_end else { continue };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < header_end + len {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let (mut address, balance) = *e2.lock().unwrap_or_else(|p| p.into_inner());
                    // The tag the body asked about, spliced over the answer's
                    // tag half so the codec's own check passes for any tag.
                    if let Some(asked) = asked_tag(&buf[header_end.min(buf.len())..]) {
                        address[..20].copy_from_slice(&asked);
                    }
                    // The request line's path, from the head this loop already
                    // lower-cased; the Mesh paths carry no upper case.
                    let path = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("").to_owned();
                    let mode = *m2.lock().unwrap_or_else(|p| p.into_inner());
                    if path == "/construction/submit" {
                        let end = (header_end + len).min(buf.len());
                        b2.lock().unwrap_or_else(|p| p.into_inner()).push(buf[header_end..end].to_vec());
                    }
                    let (status, body) = match (path.as_str(), mode) {
                        ("/construction/submit", Submit::Refuse) => (
                            "503 Service Unavailable",
                            r#"{"error":"test: the lever refuses the write after the reservation is written"}"#.to_string(),
                        ),
                        ("/construction/submit", Submit::Accept(id)) => (
                            "200 OK",
                            format!(r#"{{"transaction_identifier":{{"hash":"{}"}}}}"#, hexs(&id)),
                        ),
                        // One row for the explorer verbs, in the shape
                        // `/search/transactions` records (source debited
                        // GROSS, the change back as its own destination,
                        // metadata as JSON numbers). The captured bodies
                        // themselves are replayed in `tests/mesh.rs`; this
                        // is the loopback a pty test drives.
                        ("/search/transactions", _) => (
                            "200 OK",
                            format!(
                                r#"{{"transactions":[{{"block_identifier":{{"index":1078535,"hash":"0x{h}"}},"transaction_identifier":{{"hash":"0x{t}"}},"timestamp":1788500208000,"operations":[{{"operation_identifier":{{"index":0}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag}"}},"amount":{{"value":"-50000000","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":1}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":"PTY-1"}}}}],"metadata":{{"block_to_live":0,"change_total":39999500,"fee_total":500,"send_total":10000000}}}}],"total_count":1}}"#,
                                h = "36".repeat(32),
                                t = "18".repeat(32),
                                tag = hexs(&TAG),
                            ),
                        ),
                        _ => (
                            "200 OK",
                            format!(
                                r#"{{"result":{{"address":"0x{}","amount":{balance}}},"idempotent":true}}"#,
                                hexs(&address)
                            ),
                        ),
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    *a2.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                }
            });
            Ledger { url: format!("http://127.0.0.1:{port}"), entry, answered, stop, submit, submits }
        }

        fn set(&self, address: mochimo_crypto::addr::Address, balance: u64) {
            *self.entry.lock().unwrap_or_else(|p| p.into_inner()) = (address, balance);
        }

        fn answered(&self) -> usize {
            *self.answered.lock().unwrap_or_else(|p| p.into_inner())
        }

        /// Answer every `/construction/submit` with HTTP 503.
        fn refuse_submits(&self) {
            *self.submit.lock().unwrap_or_else(|p| p.into_inner()) = Submit::Refuse;
        }

        /// Echo `id` from `/construction/submit`. The id is the
        /// caller's, from `SignedTransaction::id()` on a dry run, never
        /// computed here (the scripted `Chain`'s rule).
        fn accept_submits(&self, id: [u8; 32]) {
            *self.submit.lock().unwrap_or_else(|p| p.into_inner()) = Submit::Accept(id);
        }

        /// Every submit body the loopback received, in order.
        fn submits(&self) -> Vec<Vec<u8>> {
            self.submits.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    impl Drop for Ledger {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// One command against the ledger, its password answered, its outcome.
    fn run_reconciling(io: &Path, dir: &str, url: &str, args: &[&str]) -> Outcome {
        let mut argv = vec!["--dir", dir, "--node", url];
        argv.extend_from_slice(args);
        let mut s = Session::spawn(io, &argv);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        s.finish()
    }

    /// **The recovery `resign` exists for completes through the shipped
    /// binary, without a hand-built POST** (the recovery marker's condition on
    /// the binary itself, under the decision that `resign` ships).
    ///
    /// The first live recovery's shape, on a loopback instead of mainnet: `send` through a Mesh
    /// that answers `/construction/submit` with HTTP 503 (that recovery's lever), so
    /// the reservation is written and the write fails -- exit 3, stdout
    /// EMPTY, the whole page including the artifact on stderr, which is the
    /// shape the first live recovery recorded for `send` and which no test asserted until
    /// now. Then `resign` with the same values through the same loopback,
    /// now echoing the id -- exit 0, stderr empty, the artifact and
    /// `submitted:` on stdout. The loopback holds two bodies, both carrying
    /// the artifact byte for byte; the second is the recovery. The store
    /// afterwards is at index 1 with the reservation open: `settle` clears
    /// it, and the chain here never moves.
    ///
    /// This is the one harness that sees a STREAM -- `main` routes by the
    /// exit code -- so it is where the decision's accepted cost is measured on
    /// `send`'s half: the artifact of a refused write is on stderr. A refused
    /// `resign` is not driven here; the in-process test holds its exit 3 and
    /// its body, and `main`'s routing is uniform across commands.
    #[test]
    fn resign_on_a_real_pty_completes_the_recovery_send_could_not() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-resign");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let to_arg = format!("0x{}", hexs(&super::TO));
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.refuse_submits();

        // 1. `send`: the socket refuses after the reservation is written.
        let io1 = ScratchDir::new("pty-resign-io1");
        let o1 = run_reconciling(io1.path(), &dir, &ledger.url, &["send", &tag_arg, &to_arg, "1000"]);
        assert_eq!(
            o1.code,
            Some(3),
            "send through a refusing socket did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o1.screen, o1.stderr, o1.stdout
        );
        assert!(o1.stdout.is_empty(), "send's exit-3 page reached stdout:\n{}", o1.stdout);
        let artifact = o1
            .stderr
            .lines()
            .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("send's stderr carries no artifact line:\n{}", o1.stderr))
            .to_owned();
        assert!(o1.stderr.contains("submission FAILED"), "send's refusal is not on stderr:\n{}", o1.stderr);
        assert!(o1.stderr.contains("the only copy"), "send's refusal does not say the page is the only copy:\n{}", o1.stderr);

        // 2. `resign`: the same values, the socket now accepts.
        ledger.accept_submits(super::id_for_the_spend("pty-resign-id"));
        let io2 = ScratchDir::new("pty-resign-io2");
        let o2 = run_reconciling(io2.path(), &dir, &ledger.url, &["resign", &tag_arg, &to_arg, "1000"]);
        assert_eq!(
            o2.code,
            Some(0),
            "THE RECOVERY DID NOT COMPLETE THROUGH THE BINARY: resign with the exact values, against \
             a socket that accepts, did not exit 0. The first live recovery finished this step on mainnet with a hand-built \
             POST; the decision since is that resign ships what it reproduces.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o2.screen, o2.stderr, o2.stdout
        );
        assert!(o2.stderr.is_empty(), "resign wrote to stderr on the exit-0 path:\n{}", o2.stderr);
        assert!(o2.stdout.contains(&artifact), "resign's stdout does not carry the artifact send printed:\n{}", o2.stdout);
        assert!(
            o2.stdout.contains("submitted: the node accepted the SOCKET WRITE"),
            "resign's stdout does not say the bytes were written, as send's does:\n{}",
            o2.stdout
        );
        assert!(o2.stdout.contains("Run `settle"), "resign's stdout does not name settle as the next step:\n{}", o2.stdout);

        // 3. The socket: two bodies, both the artifact; the second is the
        //    recovery.
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 2, "the loopback saw {} submit body(ies); send's refused write and resign's are two", bodies.len());
        for (i, b) in bodies.iter().enumerate() {
            assert_eq!(
                super::p10_signed_transaction_of(&hexs(b)).as_deref(),
                Some(artifact.as_str()),
                "submit body {i} does not carry the artifact byte for byte"
            );
        }

        // 4. The store, read in this process rather than through the binary's
        //    report of itself: index 1, the reservation still open.
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(
            (v.wots_index.get(), v.pending.is_some()),
            (1, true),
            "the store after the recovery is not index 1 with the reservation open; settle is what clears it"
        );
        drop(ks);
        assert!(ledger.answered() >= 4, "the loopback answered {} request(s); two commands each resolve and submit", ledger.answered());
        let digest = |b: &[u8]| hexs(&mochimo_crypto::backend::selected::sha256(b));
        println!(
            "tty resign: send refused at the socket (exit 3, the artifact on stderr), resign shipped the same bytes (exit 0, on stdout); {} prompt(s); bodies {} and {} bytes, sha256 {} and {}; artifact sha256 {}",
            o1.prompts + o2.prompts,
            bodies[0].len(),
            bodies[1].len(),
            digest(&bodies[0]),
            digest(&bodies[1]),
            digest(artifact.as_bytes())
        );
    }

    /// `send --ref AB-00-EF` through the shipped binary against the
    /// loopback: exit 0, the page carrying `ref  AB-00-EF` beside the other
    /// figures, and the one submit body on the socket carrying the artifact
    /// the page printed, with the reference at bytes 20..36 of its
    /// destination, NUL-padded.
    #[test]
    fn send_with_a_reference_on_a_real_pty_ships_it() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-ref");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let to_arg = format!("0x{}", hexs(&super::TO));
        let s = super::spend_with_reference("AB-00-EF");
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for("pty-ref-id", &s));
        let io = ScratchDir::new("pty-ref-io");
        let o = run_reconciling(io.path(), &dir, &ledger.url, &["send", &tag_arg, &to_arg, "1000", "--ref", "AB-00-EF"]);
        assert_eq!(
            o.code,
            Some(0),
            "send --ref through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stderr.is_empty(), "send --ref wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(o.stdout.contains("       ref AB-00-EF"), "the page does not carry the reference line:\n{}", o.stdout);
        assert!(o.stdout.contains("submitted: the node accepted the SOCKET WRITE"), "the page does not say the bytes were written:\n{}", o.stdout);
        let artifact = o
            .stdout
            .lines()
            .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("the page carries no artifact line:\n{}", o.stdout))
            .to_owned();
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies); one send is one", bodies.len());
        let shipped = super::p10_signed_transaction_of(&hexs(&bodies[0])).unwrap_or_else(|| panic!("the body carries no signed_transaction"));
        assert_eq!(shipped, artifact, "the body is not the artifact the page printed");
        let bytes = super::bytes_of(&shipped);
        assert_eq!(&bytes[136..152], b"AB-00-EF\0\0\0\0\0\0\0\0", "the shipped destination reference is not AB-00-EF NUL-padded at image offset 136..152");
        assert_eq!(&bytes[116..136], &super::TO[..], "the shipped destination tag is not at image offset 116");
        println!(
            "tty send --ref: exit 0, {} prompt(s), one body of {} bytes whose destination reference is AB-00-EF NUL-padded at image offset 136..152",
            o.prompts,
            bodies[0].len()
        );
    }

    /// **`discover` through the shipped binary**: a node, a password, exit
    /// 0, the extent on the page, the held account marked, and the store
    /// untouched.
    ///
    /// The loopback answers the same ledger entry for every tag it is
    /// asked about -- it does not read the tag out of the body -- so every
    /// index in this sweep resolves. That is not a realistic chain and it
    /// does not need to be: what a pty test adds over the in-process ones
    /// is that the verb reaches the socket through the real transport,
    /// prompts once, exits 0, and writes nothing to a real directory. A
    /// node answering identically for every tag is also a fair reminder of
    /// why the page reports answers and not accounts.
    #[test]
    fn discover_on_a_real_pty_sweeps_and_writes_nothing() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-discover");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let ledger = Ledger::serve(addr_at(0), 4_200);
        let io = ScratchDir::new("pty-discover-io");
        let o = run_reconciling(io.path(), &dir, &ledger.url, &["discover", "--to", "2"]);
        assert_eq!(
            o.code,
            Some(0),
            "discover through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        assert!(o.stdout.contains("searched account indices 0..=2"), "the extent is not on the page:\n{}", o.stdout);
        assert!(o.stdout.contains("3 index(es), one node call each"), "{}", o.stdout);
        assert!(
            o.stdout.contains("IN THIS STORE (derived, at key index 0)"),
            "the held account is not marked:\n{}",
            o.stdout
        );
        assert!(
            !o.stdout.to_ascii_lowercase().contains("does not exist"),
            "the page asserts absence:\n{}",
            o.stdout
        );
        assert_eq!(store.snapshot_bytes(), before, "discover WROTE to the store through the binary");
        assert!(ledger.answered() >= 3, "the loopback answered {} request(s); three indices are three calls", ledger.answered());
        println!(
            "tty discover: {} prompt(s), exit 0, {} loopback answer(s) for 3 indices, snapshot bytes identical",
            o.prompts,
            ledger.answered()
        );
    }

    /// **A three-destination `send` through the shipped binary**: the
    /// positional pairs reach the wire as three destinations, the fee is the
    /// floor for three, and the image is the length three destinations give.
    /// `options[2]` is the destination count minus one, so three reads as 2.
    #[test]
    fn send_to_three_destinations_on_a_real_pty_ships_all_three() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-multi");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tags = [[0x6bu8; 20], [0x7cu8; 20], [0x9cu8; 20]];
        let args: Vec<String> = tags.iter().map(|t| format!("0x{}", hexs(t))).collect();
        let tag_arg = format!("0x{}", hexs(&TAG));
        let mut s = super::spend();
        s.dsts = tags
            .iter()
            .zip([1_000u64, 2_000, 3_000])
            .map(|(t, a)| super::SpendTo { to: *t, reference: [0; 16], amount: Some(a) })
            .collect();
        s.fee_total = super::MFEE * 3;
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for("pty-multi-id", &s));
        let io = ScratchDir::new("pty-multi-io");
        let o = run_reconciling(
            io.path(),
            &dir,
            &ledger.url,
            &["send", &tag_arg, &args[0], "1000", &args[1], "2000", &args[2], "3000"],
        );
        assert_eq!(
            o.code,
            Some(0),
            "a three-destination send through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stdout.contains("sending 6000 nanoMCM to 3 destination(s)"), "{}", o.stdout);
        assert!(
            o.stdout.contains("fee    1500 total (the node's floor is 500 per destination, 1500 here)"),
            "the page does not state the floor for three:\n{}",
            o.stdout
        );
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies)", bodies.len());
        let shipped = super::p10_signed_transaction_of(&hexs(&bodies[0]))
            .unwrap_or_else(|| panic!("the body carries no signed_transaction"));
        let bytes = super::bytes_of(&shipped);
        assert_eq!(bytes.get(2), Some(&2u8), "options[2] is not `three destinations minus one`");
        assert_eq!(bytes.len(), 2364 + 44 * 3, "the image is not the length three destinations give");
        println!(
            "tty send x3: exit 0, one body of {} bytes, options[2] = 2, fee 1500 = 500 x 3",
            bodies[0].len()
        );
    }

    /// **`submit` ships a saved artifact through the shipped binary and opens
    /// no store**.
    ///
    /// The artifact comes from an in-process `send` whose socket write was
    /// refused -- the page the operator holds. The store it came from is
    /// then LOCKED by this process for the whole run, and the binary is
    /// driven with `--dir` naming it: no password prompt reaches the screen
    /// or the stderr file, the lock is not contended, exit 0, `send`'s
    /// `submitted:` block on stdout, nothing on stderr; the loopback saw one
    /// request, a `/construction/submit` whose `signed_transaction` is the
    /// artifact byte for byte; and the store afterwards is what `send` left,
    /// index 1 with the reservation open. What makes it red: a password
    /// asked, the lock contended (the open refuses), a second request, a
    /// body that is not the artifact, a store that moved.
    #[test]
    fn submit_on_a_real_pty_ships_a_saved_artifact_and_opens_no_store() {
        let (store, artifact) = super::send_that_never_left("pty-submit");
        // **The hold is taken through the harness's `reopen`, not
        // `Keystore::open`.** The in-process `send` above dropped this store's
        // handle an instant ago, and this binary runs its tests on parallel
        // threads that spawn children -- `cargo`, `script`, and itself for the
        // child sessions. `flock` belongs to the open file description, and a
        // child keeps a copy of this process's descriptor table from its
        // creation until its `exec` closes it, so a child that a sibling is
        // spawning at that instant holds the old description's lock until its
        // `exec`. A fresh open's `try_lock` then meets a live holder, and
        // `Locked` is the truth. `reopen` retries `Locked` alone, bounded, and
        // says so on file descriptor 2 whenever it had to; the mechanism, the
        // bound and the two tests that pin it are at its doc, and every reopen
        // outside this module -- twenty-nine calls -- goes through it.
        //
        // Two alternatives, refused. A retry written here would be a second
        // definition of that rule, with its own bound and neither the pinning
        // tests nor the announcement. A process-wide gate held around every
        // spawn and across this release would close the window by
        // construction, but only for the sites wrapped in it and only while
        // every spawn in this file remembers to take it, which nothing checks;
        // the other reopens here would still rest on `reopen`, so the file
        // would carry two mechanisms for one hazard.
        //
        // The bound, measured on one macOS host and not on a CI runner, by
        // probes outside this repository. `Keystore::open` itself, dropping
        // and re-opening one store beside two threads spawning `/usr/bin/true`,
        // met `Locked` in 18,117 of 271,730 cycles and in none of 199,321
        // without them, and every block cleared within five retries of 100 µs.
        // A bare `try_lock` loop with every core saturated or three times
        // oversubscribed needed at most 39 of `reopen`'s 50. `std` spawned
        // through `posix_spawn` there, both for those children and for spawns
        // shaped like this file's three; only a `pre_exec` closure forced a
        // fork.
        let held = super::reopen("pty submit hold", store.path())
            .result
            .unwrap_or_else(|e| panic!("cannot hold the store's lock: {e}"));
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for_the_spend("pty-submit-id"));
        let dir = store.path().to_string_lossy().into_owned();
        let io = ScratchDir::new("pty-submit-io");
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "submit", &artifact]);
        let o = s.finish();
        assert_eq!(
            o.code,
            Some(0),
            "submit through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "submit asked for a password; it opens no store.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o.screen, o.stderr
        );
        assert!(o.stderr.is_empty(), "submit wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(
            o.stdout.contains("submitted: the node accepted the SOCKET WRITE"),
            "submit's stdout does not say the bytes were written, as send's does:\n{}",
            o.stdout
        );
        assert!(o.stdout.contains("Run `settle"), "submit's stdout does not name settle as the next step:\n{}", o.stdout);
        assert!(o.stdout.contains("No store was opened"), "submit's page does not say no store was opened:\n{}", o.stdout);
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies); the artifact needs one", bodies.len());
        assert_eq!(
            super::p10_signed_transaction_of(&hexs(&bodies[0])).as_deref(),
            Some(artifact.as_str()),
            "the submit body does not carry the artifact byte for byte"
        );
        assert_eq!(ledger.answered(), 1, "submit made {} request(s); it resolves nothing and submits once", ledger.answered());
        drop(held);
        // Released and re-taken at once: the same instant as the hold above,
        // for the same reason.
        let ks = super::reopen("pty submit after", store.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(
            (v.wots_index.get(), v.pending.is_some()),
            (1, true),
            "the store after submit is not what send left; submit writes nothing"
        );
        drop(ks);
        let digest = |b: &[u8]| hexs(&mochimo_crypto::backend::selected::sha256(b));
        println!(
            "tty submit: the artifact of a refused send shipped by the binary with the store locked and no prompt (exit 0, on stdout); {} prompt(s); body {} bytes, sha256 {}; artifact sha256 {}",
            o.prompts,
            bodies[0].len(),
            digest(&bodies[0]),
            digest(artifact.as_bytes())
        );
    }

    /// **`submit` refuses what is not an artifact before any socket is
    /// opened, and needs no store directory at all.** Three inputs against
    /// a loopback that would accept: text that is not hex, hex that is no
    /// transaction, and a real artifact one byte short (a length `from_wire`
    /// accepts and zero-extends). Each exits 3 with the refusal on stderr
    /// naming what the artifact is not and saying nothing was written; the
    /// loopback answered nothing; no password was asked; and `--dir`, which
    /// names a directory that does not exist, is still absent afterwards.
    /// What makes it red: a body on the socket (the parse or the identity
    /// check moved after the write), a prompt, a directory made.
    #[test]
    fn submit_on_a_real_pty_refuses_what_is_not_an_artifact_before_the_socket() {
        let (_store, artifact) = super::send_that_never_left("pty-submit-refuse");
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for_the_spend("pty-submit-refuse-id"));
        let absent = ScratchDir::new("pty-submit-absent");
        let dir = absent.path().to_string_lossy().into_owned();
        let truncated = artifact[..artifact.len() - 2].to_owned();
        let cases: [(&str, &str); 3] = [
            ("zz", "is not hex"),
            ("00ff", "does not parse as a transaction"),
            (truncated.as_str(), "is not a whole transaction image"),
        ];
        let mut refused = 0usize;
        for (input, why) in cases {
            let shown = &input[..input.len().min(16)];
            let io = ScratchDir::new("pty-submit-refuse-io");
            let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "submit", input]);
            let o = s.finish();
            assert_eq!(
                o.code,
                Some(3),
                "`submit {shown}...` did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
                o.screen, o.stderr, o.stdout
            );
            assert!(o.stderr.contains(why), "the refusal for `{shown}...` does not say the artifact {why}:\n{}", o.stderr);
            assert!(
                o.stderr.contains("Nothing was written to the socket"),
                "the refusal for `{shown}...` does not say nothing was written:\n{}",
                o.stderr
            );
            assert!(o.stdout.is_empty(), "stdout is not empty on the exit-3 path:\n{}", o.stdout);
            assert!(
                !o.screen.contains("password: ") && !o.stderr.contains("password: "),
                "`submit {shown}...` asked for a password"
            );
            assert!(!absent.path().exists(), "`submit {shown}...` made the store directory {}", absent.path().display());
            refused += 1;
        }
        assert_eq!(ledger.submits().len(), 0, "a refused artifact reached the socket: {} body(ies)", ledger.submits().len());
        assert_eq!(ledger.answered(), 0, "the loopback answered {} request(s); a refused artifact opens no socket", ledger.answered());
        println!("tty submit refusals: {refused} inputs refused before the socket, no prompt, no directory made");
    }

    /// **`recent-transactions` through the shipped binary opens no store and
    /// asks no password**, with the store directory absent throughout.
    ///
    /// The same shape as `submit`'s no-store test, for the same reason: the
    /// node is the whole input, so there is nothing to unlock. `--dir` names
    /// a directory that does not exist and is still absent afterwards.
    /// What makes it red: a prompt, a directory made, or a verb that reached
    /// `Wallet::open`.
    #[test]
    fn recent_transactions_on_a_real_pty_opens_no_store_and_asks_no_password() {
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        let absent = ScratchDir::new("pty-recent-absent");
        let dir = absent.path().join("no-wallet-here").to_string_lossy().into_owned();
        let tag_arg = format!("0x{}", hexs(&TAG));
        let io = ScratchDir::new("pty-recent-io");
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "recent-transactions", &tag_arg]);
        let o = s.finish();
        assert_eq!(
            o.code,
            Some(0),
            "recent-transactions through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "recent-transactions asked for a password; it opens no store.\n--- screen ---\n{}",
            o.screen
        );
        assert!(o.stderr.is_empty(), "recent-transactions wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(
            !std::path::Path::new(&dir).exists(),
            "recent-transactions made the store directory {dir}"
        );
        assert!(o.stdout.contains("1 of 1 row(s), newest first"), "{}", o.stdout);
        assert!(o.stdout.contains("block   1078535"), "{}", o.stdout);
        assert!(o.stdout.contains("memo PTY-1"), "the memo is not on the page:\n{}", o.stdout);
        assert!(o.stdout.contains("/search/transactions"), "the page does not name the endpoint:\n{}", o.stdout);
        assert_eq!(ledger.answered(), 1, "recent-transactions made {} request(s); it asks one", ledger.answered());
        println!(
            "tty recent-transactions: exit 0, {} prompt(s), the store directory never made, one request to the node",
            o.prompts
        );
    }

    /// **The acknowledged path exists in the shipped binary, and it verifies
    /// the index it is given**.
    ///
    /// The whole path has to work in the shipped binary and not only in the
    /// library: `reconcile` is a pre-gate command precisely so that it is not
    /// behind a constructor that refuses on the divergence it exists to
    /// clear, and a binary that reached the wallet gate here would answer
    /// step 2 with step 1's report and offer the operator nothing.
    #[test]
    fn reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-reconcile");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let mut prompts = 0usize;

        // The chain sits at index 2; the store at 0. Local behind, gap 2.
        let ledger = Ledger::serve(addr_at(2), 9);

        // 1. `balance` refuses with I4's report and names the path.
        let io1 = ScratchDir::new("pty-reconcile-io1");
        let o1 = run_reconciling(io1.path(), &dir, &ledger.url, &["balance"]);
        prompts += o1.prompts;
        assert_eq!(o1.code, Some(2), "balance on a diverged store did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o1.screen, o1.stderr);
        assert!(o1.stderr.contains("key at index 2 -- 2 ahead of local"), "the report does not name the chain's index and the gap:\n{}", o1.stderr);
        assert!(o1.stderr.contains(&format!("reconcile {tag_arg} --advance-to 2")), "the report does not print the command that takes the acknowledged path:\n{}", o1.stderr);

        // 2. The WRONG number is refused by the acknowledgement check -- exit
        //    3, the mismatch named, nothing written.
        let io2 = ScratchDir::new("pty-reconcile-io2");
        let o2 = run_reconciling(io2.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "7"]);
        prompts += o2.prompts;
        assert_eq!(o2.code, Some(3), "reconcile with the wrong index did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}", o2.screen, o2.stderr, o2.stdout);
        assert!(o2.stderr.contains("--advance-to 7 does not match the index this divergence reports (2)"), "the mismatch is not named:\n{}", o2.stderr);

        // 3. The number the report named advances the store: exit 0.
        let io3 = ScratchDir::new("pty-reconcile-io3");
        let o3 = run_reconciling(io3.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "2"]);
        prompts += o3.prompts;
        assert_eq!(
            o3.code,
            Some(0),
            "THE ACKNOWLEDGED PATH IS NOT REACHABLE: reconcile with the exact index the report \
             named did not exit 0, which leaves a divergence with no way out of it.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o3.screen, o3.stderr, o3.stdout
        );
        assert!(o3.stdout.contains("to index 2 after operator review"), "reconcile's stdout does not say what it did:\n{}", o3.stdout);
        assert!(o3.stdout.contains("THE STORE BEFORE THIS DECISION"), "the report was not printed before the write:\n{}", o3.stdout);

        // 4. `balance` now opens: in sync at index 2.
        let io4 = ScratchDir::new("pty-reconcile-io4");
        let o4 = run_reconciling(io4.path(), &dir, &ledger.url, &["balance"]);
        prompts += o4.prompts;
        assert_eq!(o4.code, Some(0), "balance after the advance did not open.\n--- stderr ---\n{}", o4.stderr);
        assert!(o4.stdout.contains("index 2") && o4.stdout.contains("in sync"), "balance does not show index 2 in sync:\n{}", o4.stdout);

        // 5. FAR ALONG: the chain moves to index 30, past the window.
        //    `status --scan-to 19` -- a ceiling of 20, which is what the
        //    DEFAULT is not -- reports it out of reach: exit 0, the
        //    report on stdout, a report being an answer and not a refusal,
        //    and what to do said without deciding among the three causes.
        //    The flag is passed rather than relying on the default because
        //    the default ceiling is 10,000 now and finds index 30 (step 5b);
        //    an address past the default would cost an exhausted
        //    ten-thousand-position walk here, minutes on a pty.
        ledger.set(addr_at(30), 11);
        let io5 = ScratchDir::new("pty-reconcile-io5");
        let o5 = run_reconciling(io5.path(), &dir, &ledger.url, &["status", &tag_arg, "--scan-to", "19"]);
        prompts += o5.prompts;
        assert_eq!(o5.code, Some(0), "status on a far-along divergence did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o5.stderr, o5.stdout);
        assert!(o5.stdout.contains("NO key index this scan walked"), "status does not report the unlocated address on stdout:\n{}", o5.stdout);
        assert!(o5.stdout.contains("indices 0 through 19"), "status does not say what it walked:\n{}", o5.stdout);
        assert!(!o5.stdout.contains("does not own this tag, or"), "status still asserts the closed disjunction:\n{}", o5.stdout);
        assert!(o5.stderr.is_empty(), "status wrote to stderr on the exit-0 path:\n{}", o5.stderr);

        // 5b. And with no flag at all, through the shipped binary: the
        //     default ceiling reaches index 30 and names it. This is the
        //     raised ceiling is for, driven end to end on a pty.
        let io5b = ScratchDir::new("pty-reconcile-io5b");
        let o5b = run_reconciling(io5b.path(), &dir, &ledger.url, &["status", &tag_arg]);
        prompts += o5b.prompts;
        assert_eq!(o5b.code, Some(0), "status at the default ceiling did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o5b.stderr, o5b.stdout);
        assert!(o5b.stdout.contains("key at index 30 -- 28 ahead of local"), "the DEFAULT ceiling did not reach index 30:\n{}", o5b.stdout);

        // 6. `status --scan-to 40` finds the exact index by searching further.
        let io6 = ScratchDir::new("pty-reconcile-io6");
        let o6 = run_reconciling(io6.path(), &dir, &ledger.url, &["status", &tag_arg, "--scan-to", "40"]);
        prompts += o6.prompts;
        assert_eq!(o6.code, Some(0), "status --scan-to on a divergence did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o6.stderr, o6.stdout);
        assert!(o6.stdout.contains("key at index 30 -- 28 ahead of local"), "the raised ceiling did not find index 30:\n{}", o6.stdout);
        assert!(o6.stdout.contains(&format!("reconcile {tag_arg} --advance-to 30")), "status does not print the command that follows:\n{}", o6.stdout);

        // 7. A far-along index the operator names is VERIFIED: 29 is refused
        //    with nothing written, 30 advances.
        let io7 = ScratchDir::new("pty-reconcile-io7");
        let o7 = run_reconciling(io7.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "29"]);
        prompts += o7.prompts;
        assert_eq!(o7.code, Some(3), "a wrong far-along index was not refused.\n--- stderr ---\n{}\n--- stdout ---\n{}", o7.stderr, o7.stdout);
        assert!(o7.stderr.contains("indices 0 through 29"), "the refusal does not say the named index was walked:\n{}", o7.stderr);
        assert!(o7.stderr.contains("no advance to acknowledge"), "the refusal does not say why:\n{}", o7.stderr);
        let io8 = ScratchDir::new("pty-reconcile-io8");
        let o8 = run_reconciling(io8.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "30"]);
        prompts += o8.prompts;
        assert_eq!(o8.code, Some(0), "a verified far-along index did not advance.\n--- stderr ---\n{}\n--- stdout ---\n{}", o8.stderr, o8.stdout);
        assert!(o8.stdout.contains("to index 30 after operator review"), "reconcile's stdout does not name the index:\n{}", o8.stdout);
        let io9 = ScratchDir::new("pty-reconcile-io9");
        let o9 = run_reconciling(io9.path(), &dir, &ledger.url, &["balance"]);
        prompts += o9.prompts;
        assert_eq!(o9.code, Some(0), "balance after the far-along advance did not open.\n--- stderr ---\n{}", o9.stderr);
        assert!(o9.stdout.contains("index 30") && o9.stdout.contains("in sync"), "balance does not show index 30 in sync:\n{}", o9.stdout);

        // The store on disk agrees, read in this process rather than through
        // the binary's own report of itself.
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(v.wots_index.get(), 30, "the store is not at the index the binary said it advanced to");
        drop(ks);

        assert!(ledger.answered() >= 9, "the ledger answered {} request(s); fewer than the nine commands means a command never dialed", ledger.answered());
        println!(
            "tty reconcile: {prompts} prompt(s) answered on a pseudo-terminal across the refusal, the acknowledged advance, the far-along search and the verified advance"
        );
    }

}

// ===========================================================================
// The recovery surface. Three of the four debts the first live recovery
// filed are given markers here (the fourth is in tests/keystore.rs). Each is red
// until the condition its entry states is met, and each drives the shipped
// command layer over a store the operator comes back to in a FRESH PROCESS.
// ===========================================================================

/// The operator's NEXT session, as a separate process.
///
/// Every marker below models an operator who ran `send`, lost the page, and
/// comes back later holding the store, the password and the phrase. The
/// shipped binary is one-shot, so "later" means a fresh process: nothing
/// survives but the file on disk and what the chain answers. An in-process
/// reopen would let a value carried in process memory -- a static set by
/// `send`, say -- satisfy a marker whose condition is that the STORE carries
/// it, and nothing in the marker could tell the two apart. So the parent
/// re-executes this test binary (`std::env::current_exe`) with this one test
/// selected, and the child runs one command over the same directory against a
/// chain scripted from the environment, printing what the operator would see
/// between markers the parent parses. No cargo, no network, no pty.
///
/// In the parent run this test does nothing but say so: it answers the
/// environment and nothing else. The `--exact` selection is what keeps a
/// child from running the whole file.
///
/// The environment, all set by [`p10_child_session_run`]:
/// `P10_CHILD_STORE` (the directory), `P10_CHILD_CMD` (`status`, `balance`,
/// `settle`, `resign:<btl>`, or `argv:` followed by argv words joined by
/// `\x1f`), `P10_CHILD_BALANCE` and `P10_CHILD_ADDR_INDEX` (the ledger's
/// entry for `TAG`: `addr_at(index)` with that balance), `P10_CHILD_TIP`
/// (what `/network/status` answers -- always scripted, so a fix that reads
/// the tip is not refused by the fake), and `P10_CHILD_ACCEPT_ID` (a hex id
/// `/construction/submit` echoes; absent, the socket refuses).
#[test]
fn p10_child_session() {
    let Ok(dir) = std::env::var("P10_CHILD_STORE") else {
        println!("  child session: not invoked as a child; nothing to do here");
        return;
    };
    let need = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("child: {k} is unset"));
    let cmd = need("P10_CHILD_CMD");
    let balance: u64 = need("P10_CHILD_BALANCE").parse().expect("child: P10_CHILD_BALANCE");
    let addr_index: u32 = std::env::var("P10_CHILD_ADDR_INDEX").ok().map_or(0, |s| s.parse().expect("child: P10_CHILD_ADDR_INDEX"));
    let tip: u64 = need("P10_CHILD_TIP").parse().expect("child: P10_CHILD_TIP");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(addr_index), balance))]);
    chain.set_tip(tip);
    match std::env::var("P10_CHILD_ACCEPT_ID") {
        Ok(h) => {
            let mut id = [0u8; 32];
            for (i, b) in id.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("child: P10_CHILD_ACCEPT_ID hex");
            }
            chain.accepts_submit(id);
        }
        Err(_) => chain.refuses_submit(),
    }
    let log = chain.submit_log();
    let path = std::path::Path::new(&dir);
    let ks = reopen("p10 child", path).result.unwrap_or_else(|e| panic!("child: cannot open the store: {e}"));
    let client = MeshClient::new(chain);

    let report = match cmd.as_str() {
        "status" => cli::run(ks, client, &Command::Status { tag: TAG, scan_to: None }),
        "balance" => cli::run(ks, client, &Command::Balance),
        "settle" => cli::run(ks, client, &Command::Settle { tag: TAG }),
        s if s.starts_with("resign:") => {
            let mut sp = spend();
            sp.blk_to_live = s["resign:".len()..].parse().expect("child: resign:<btl>");
            cli::run(ks, client, &Command::Resign(sp))
        }
        s if s.starts_with("argv:") => {
            let mut argv: Vec<String> = vec!["--dir".into(), dir.clone(), "--node".into(), "http://127.0.0.1:1".into()];
            argv.extend(s["argv:".len()..].split('\x1f').map(str::to_owned));
            match args::parse(&argv) {
                Ok(args::ParsedArgv::Run(inv)) => cli::run(ks, client, &inv.command),
                Ok(args::ParsedArgv::Help) => cli::Report { text: "help".into(), code: Code::Ok },
                Err(u) => {
                    // Nothing consumed the store on this path; release the
                    // lock before the read-back below reopens it.
                    drop(ks);
                    drop(client);
                    println!("<<<CHILD USAGE>>>{}", u.0);
                    cli::Report { text: format!("{u}"), code: Code::Usage }
                }
            }
        }
        other => panic!("child: unknown P10_CHILD_CMD {other:?}"),
    };
    println!("<<<CHILD CODE>>>{}", report.code as i32);
    println!("<<<CHILD REPORT>>>\n{}\n<<<CHILD END>>>", report.text);
    for body in log.borrow().iter() {
        println!("<<<CHILD SUBMIT>>>{}", hexs(body));
    }
    // The store after the command, read back from disk: the index and
    // whether a reservation is still open.
    let after = reopen("p10 child after", path).result.unwrap_or_else(|e| panic!("child: cannot reopen the store: {e}"));
    let view = after
        .view(&TAG)
        .unwrap_or_else(|e| panic!("child: {e}"))
        .unwrap_or_else(|| panic!("child: the store no longer holds TAG"));
    println!("<<<CHILD INDEX>>>{}", view.wots_index.get());
    println!("<<<CHILD PENDING>>>{}", u8::from(view.pending.is_some()));
}

/// What a child session printed, parsed back.
struct P10Child {
    code: i32,
    text: String,
    /// Every `/construction/submit` body the chain saw, hex-encoded.
    submits: Vec<String>,
    /// The usage error, when argv did not parse.
    usage: Option<String>,
    index: u32,
    pending: bool,
}

/// Run one command in a child session over `dir`; see [`p10_child_session`].
///
/// A child that prints no report is a failure here, never an empty result:
/// the marker that called this cannot say anything about a page it never
/// saw (a guard that passed over nothing).
fn p10_child_session_run(dir: &std::path::Path, cmd: &str, balance: u64, addr_index: u32, tip: u64, accept: Option<[u8; 32]>) -> P10Child {
    let me = std::env::current_exe().expect("current_exe");
    let mut c = std::process::Command::new(me);
    c.args(["--exact", "p10_child_session", "--nocapture", "--test-threads", "1"])
        .env("P10_CHILD_STORE", dir)
        .env("P10_CHILD_CMD", cmd)
        .env("P10_CHILD_BALANCE", balance.to_string())
        .env("P10_CHILD_ADDR_INDEX", addr_index.to_string())
        .env("P10_CHILD_TIP", tip.to_string());
    match accept {
        Some(id) => {
            c.env("P10_CHILD_ACCEPT_ID", hexs(&id));
        }
        None => {
            c.env_remove("P10_CHILD_ACCEPT_ID");
        }
    }
    let out = c.output().unwrap_or_else(|e| panic!("cannot spawn the child session: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the child session for `{cmd}` failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
    // Anywhere in a line, not at its start: under `--nocapture` libtest
    // prints `test p10_child_session ... ` and the child's first line lands
    // on the same line. Caught by this helper's own empty-result guard on
    // its first run.
    let after = |marker: &str| -> Option<String> {
        stdout
            .lines()
            .find_map(|l| l.find(marker).map(|i| l[i + marker.len()..].to_owned()))
    };
    let code: i32 = after("<<<CHILD CODE>>>")
        .unwrap_or_else(|| panic!("the child session for `{cmd}` printed no report:\n{stdout}\n--- stderr ---\n{stderr}"))
        .parse()
        .expect("child code");
    let start = stdout.find("<<<CHILD REPORT>>>\n").expect("report start") + "<<<CHILD REPORT>>>\n".len();
    let end = stdout[start..].find("\n<<<CHILD END>>>").expect("report end") + start;
    let text = stdout[start..end].to_owned();
    let submits: Vec<String> = stdout.lines().filter_map(|l| l.strip_prefix("<<<CHILD SUBMIT>>>").map(str::to_owned)).collect();
    let usage = after("<<<CHILD USAGE>>>");
    let index: u32 = after("<<<CHILD INDEX>>>").expect("child index").parse().expect("child index");
    let pending = after("<<<CHILD PENDING>>>").expect("child pending") == "1";
    P10Child { code, text, submits, usage, index, pending }
}

/// A `send` whose submission the socket refused: the reservation is open,
/// the artifact was printed once, and this is the page the operator loses.
struct P10Sent {
    dir: ScratchDir,
    artifact_hex: String,
}

fn p10_send_that_never_left(name: &str, blk_to_live: u64, tip: u64) -> P10Sent {
    let (dir, ks) = store(name);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(tip);
    chain.refuses_submit();
    let mut s = spend();
    s.blk_to_live = blk_to_live;
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(r.code, Code::Refused, "premise: a send through a refusing socket did not exit 3:\n{}", r.text);
    let artifact_hex = r
        .text
        .lines()
        .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("premise: send's page carries no artifact line:\n{}", r.text))
        .to_owned();
    let ks = reopen("p10 sent", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("no TAG"));
    assert!(v.pending.is_some() && v.wots_index.get() == 1, "premise: the refused send left no reservation at index 0");
    drop(ks);
    P10Sent { dir, artifact_hex }
}

/// The `signed_transaction` field of a submit body the chain recorded.
fn p10_signed_transaction_of(body_hex: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(body_hex.len() / 2);
    for i in (0..body_hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(body_hex.get(i..i + 2)?, 16).ok()?);
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("signed_transaction")?.as_str().map(str::to_owned)
}

/// **The shipped binary submits a reproduced artifact** -- green
/// under this name; red as `the_binary_cannot_submit_a_reproduced_artifact`
/// if it stopped shipping. Two routes are named and the first taken:
/// `resign` ships what it reproduces. The body probes both routes and is
/// green on the first, and the two route (ii) probes spawn a child each on
/// every green run -- so
/// the name is the condition, route-neutral, rather than the route
/// taken: a later tree that shipped a `submit` verb instead would pass under
/// it without the name becoming false. What follows is the
/// comment as it stood red, with two corrections marked as such.
///
/// The first live recovery ran the recovery `resign` exists for on mainnet: a send whose socket
/// write failed, the page lost, `resign` reproducing the bytes -- and then the
/// reservation cleared only because the agent POSTed the artifact to
/// `/construction/submit` by hand, with the crate's own body shape, because
/// no verb of the nine ships bytes it did not just sign. *"A recovery that
/// ends at 'resign printed it' is not a recovery."*
///
/// # The condition, verbatim from the entry that filed it
///
/// > the shipped binary can submit a reproduced artifact, so the recovery
/// > `resign` exists for can be completed without a hand-built POST.
///
/// # What this measures, and the two routes it accepts
///
/// A send through a refusing socket leaves a reservation and a page. In a
/// fresh process the operator runs `resign` with the same values against a
/// chain that now accepts; what is checked is not the page but **what the
/// binary put on the socket**: the chain records every `/construction/submit`
/// body, and the marker is green when one of them carries the reproduced
/// artifact as its `signed_transaction`. Two routes reach that, and either
/// clears it (the acceptance set was decided and recorded so
/// the marker's interface is not a guess):
///
/// * **(i)** `resign` submits what it reproduces -- which changes `resign`'s
///   observed contract (reproduce, write nothing, ship nothing) and so needs
///   its own decision entry before it ships;
/// * **(ii)** a `submit` verb takes the artifact hex: `submit <hex>` or
///   `submit <tag> <hex>` -- both shapes are probed, because the artifact
///   already carries its source (`TXHDR.src_addr`, `types.h`) and a verb may
///   reasonably not ask for the tag twice. A verb that reads the artifact
///   from a file or stdin is not probed; a session shipping that shape files
///   a superseding decision first, and only then moves this probe.
///
/// What route (ii) owes, stated so the discharging session does not
/// discover it at the end: the crate has no path from wire bytes to a
/// submission -- `MeshClient::submit` takes a `SignedTransaction`, whose
/// only constructor is `attach(plan, sig)`, and `Transaction::from_wire`
/// yields the unsigned type -- so a verb needs a re-verifying
/// `SignedTransaction::from_wire` or a `MeshClient::submit_wire`; and
/// `needs_node`, `HELP`, the nine-verb table in this file and the two "nine
/// verbs" comments (`mcm-wallet.rs::run_from_argv`, the pty malformed-node
/// test) all move with a tenth verb. (Corrected: this said "the pty ledger floor"
/// until the rename; that floor counts nine COMMANDS inside one pty test,
/// not verbs, and does not move.)
///
/// # Controls
///
/// `resign` must reproduce the artifact byte for byte in the child (the
/// recovery itself works; if it did not, a red here would be about the
/// wrong thing), and the accepting chain's id comes from
/// `SignedTransaction::id()` on a dry run, never from the fake. (Corrected: since
/// `resign` ships, the first control -- `resigned.code == 0` -- is a conjunction,
/// `resign` reproduced AND the scripted socket accepted the write, and its
/// message names only the first half; the `contains(artifact_hex)`
/// assertion after it is the discriminator. Reported here rather than
/// reordered: a marker's body is not edited in the session that clears it.)
#[test]
fn the_binary_submits_a_reproduced_artifact() {
    const TIP: u64 = 1_080_711;
    let sent = p10_send_that_never_left("p10-203", 0, TIP);
    let id = id_for_the_spend("p10-203-id");
    let shipped = |run: &P10Child| {
        run.submits
            .iter()
            .any(|body| p10_signed_transaction_of(body).as_deref() == Some(sent.artifact_hex.as_str()))
    };

    // Route (i): the recovery verb itself.
    let resigned = p10_child_session_run(sent.dir.path(), "resign:0", 5_000_000, 0, TIP, Some(id));
    assert_eq!(resigned.code, 0, "control: resign did not reproduce the artifact:\n{}", resigned.text);
    assert!(
        resigned.text.contains(&sent.artifact_hex),
        "control: resign's page does not carry the lost artifact byte for byte:\n{}",
        resigned.text
    );
    let route_i = shipped(&resigned);

    // Route (ii): a verb that takes the artifact.
    let tag = prefixed(&TAG);
    let mut route_ii: Option<String> = None;
    let mut refusals: Vec<String> = Vec::new();
    for argv in [vec!["submit", sent.artifact_hex.as_str()], vec!["submit", tag.as_str(), sent.artifact_hex.as_str()]] {
        let run = p10_child_session_run(sent.dir.path(), &format!("argv:{}", argv.join("\x1f")), 5_000_000, 0, TIP, Some(id));
        if shipped(&run) {
            route_ii = Some(format!("submit {}", if argv.len() == 2 { "<hex>" } else { "<tag> <hex>" }));
            break;
        }
        refusals.push(run.usage.unwrap_or_else(|| run.text.lines().next().unwrap_or("").to_owned()));
    }

    if route_i || route_ii.is_some() {
        println!(
            "  reproduced artifact submitted by the binary: route (i) resign ships it = {route_i}; route (ii) verb = {}",
            route_ii.as_deref().unwrap_or("none")
        );
        return;
    }
    panic!(
        "THE SHIPPED BINARY CANNOT SUBMIT A REPRODUCED ARTIFACT. `resign` reproduced the lost \
         artifact byte for byte in a fresh process against a chain that would have accepted it, and \
         the chain saw {} submit body(ies) -- none carrying it. The first live recovery finished on mainnet \
         with a hand-built POST; the product cannot.\n\
         \n\
         The condition: \"the shipped binary can submit a reproduced artifact, so the \
         recovery `resign` exists for can be completed without a hand-built POST.\"\n\
         \n\
         What clears it (the acceptance set): (i) `resign` ships what it reproduces -- its \
         contract changes, so that route needs its own decision entry first -- or (ii) a `submit` verb \
         taking the artifact as `submit <hex>` or `submit <tag> <hex>`, which the chain then sees on \
         the socket. The probes here got: {refusals:?}. A verb of another shape is filed as a \
         superseding decision before this probe moves; it is not edited to fit.",
        resigned.submits.len()
    );
}

/// `send` and `resign` print the block-to-live they signed over (the
/// block-to-live finding's first mitigation).
///
/// `resign` needs the value and no page carried it: an operator following
/// the first live recovery's rule wrote it down by hand before the send, and the record says
/// every other operator would not. Both verbs now print it beside the
/// artifact, in decimal with what it means, and the notice says to record
/// it. Since format version 4 the value is also in the record and rendered by `status`
/// and `balance` from the store, which is what
/// `the_block_to_live_is_recovered_from_the_store_without_knowing_the_value`
/// performs; this test holds the page half. Its
/// `resign` chain scripts a tip below the value, because a
/// recorded non-zero block-to-live is compared to the tip at open.
#[test]
fn send_and_resign_print_the_block_to_live_they_signed_over() {
    // Zero, through an accepting socket: the default, and the one that
    // never expires.
    let id = id_for_the_spend("cli-btl-zero-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let r = run_on("cli-btl-zero", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "  btl    0 (never expires", "send with the default block-to-live");
    assert_says(&r, "record it with the bytes", "send's notice");

    // Non-zero, through a refusing socket, then reproduced.
    let (dir, ks) = store("cli-btl-4242");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let mut s = spend();
    s.blk_to_live = 4_242;
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s.clone()));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "  btl    4242 (the node accepts it only while the tip is at or below 4242", "send with --btl 4242");
    assert_says(&r, "refuses it on arrival if 4242 is below the tip", "send's page, the lower bound of the window");
    let ks = reopen("cli btl resign", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    // `resign` ships what it reproduces, so the chain it
    // reproduces against is told to accept THIS spend's id -- the btl-4242
    // id, not the default's, because the value is in the digest. The page is
    // asserted first and the code after, so a socket regression reds this
    // test under a message that names it rather than under the btl line's.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(4_000);
    chain.accepts_submit(id_for("cli-btl-4242-id", &s));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
    assert_says(&r, "block-to-live 4242 (the node accepts it only while the tip is at or below 4242", "resign's page");
    assert_eq!(
        r.code,
        Code::Ok,
        "resign exits 0 only when the socket accepted the write; this chain was scripted to:\n{}",
        r.text
    );
    println!("  block-to-live rendered: send (0 and 4242) and resign (4242)");
}

/// The state `balance` and `status` render for a live reservation --
/// `cli::state_of`'s `SpendOutstanding` arm. The first live recovery recorded that this
/// line was asserted by no test; it is now the control's needle.
const P10_LIVE_LINE: &str = "SPEND OUTSTANDING at index 0 -- not yet seen on the chain";
/// The words a dead reservation's page must carry, taken from the dead-reservation
/// finding's own condition ("can no longer be accepted") and recorded as the marker's
/// mechanical wording rather than left as a guess.
const P10_DEAD_PHRASE: &str = "can no longer be accepted";
/// The dead-reservation sentence: the specification's
/// own words, then that no command offers a second signature on purpose.
const P10_NO_ROUTE_OUT: &str = "A dead reservation has no route out: the whole balance at the reserved key is reachable only by a signature from that key, and the only signature this wallet will ever produce from that key is the one already produced. No command offers a second one, on purpose";

/// **A dead reservation is reported as dead, from the store and the chain
/// alone** -- green under this name; red as
/// `a_dead_reservation_is_reported_as_a_live_one` before format version 4
/// recorded the figures. What follows is
/// the comment as it stood red.
///
/// A deposit that lands while a reservation is open and unlanded credits the
/// tag in place, and `tx_val` demands `send + change + fee == balance`
/// exactly, so the signed bytes can never be accepted again; a non-zero
/// block-to-live the tip has reached does the same by another first step.
/// The wallet then reports `SPEND OUTSTANDING … not yet seen
/// on the chain`, `settle` says *not settled … `resign` rebuilds it*, and
/// nothing says the artifact is dead: literally true, and useless.
///
/// # The condition, verbatim from the entry that filed it
///
/// > an operator whose reserved artifact can no longer be accepted -- the
/// > balance moved, or the block-to-live passed -- is told so by the binary,
/// > from the store and the chain alone, without retyping the original
/// > arguments.
///
/// # What is driven
///
/// Four stores, each with a send the socket refused, each read back in a
/// fresh process by `status`, `balance` and `settle` -- commands that take no
/// spend parameter, which is "without retyping" by construction:
///
/// | | reserved | chain afterwards | expected |
/// | --- | --- | --- | --- |
/// | A | btl 0 | balance 5,000,000 -> 6,000,000 | dead: the balance moved |
/// | B | btl 4,242 | tip 4,242 | dead: the block-to-live passed |
/// | C | btl 0 | unchanged, tip 100 | live (control) |
/// | D | btl 4,242 | unchanged, tip 4,241 | live (control) |
///
/// B sits exactly on the boundary: block N is the last block that can carry
/// btl N (`cmp64(txe->tx_btl, bnum) < 0` refuses against the block's own
/// number), and `txclean` drops it against `Cblocknum + 1`,
/// so a reservation is dead once the tip REACHES its value, not once it
/// passes it. A fix comparing `tip > btl` is red here. D is the control that
/// keeps a fix from calling every non-zero block-to-live dead. Neither
/// boundary has an offline oracle -- the check is inside `tx_val`, which
/// needs a ledger -- so this is the crate's reading of those
/// lines, and an `EMCM_TXBTL` vector stays owed to whatever can run it.
///
/// # What a dead page must carry
///
/// The live state text must be gone (a fix replaces it rather than extending
/// it -- the old words are literally true and useless beside a dead reservation),
/// [`P10_DEAD_PHRASE`] must be present, and so must the figure the store had
/// to carry to know: the reserved balance in A (the ledger now says
/// 6,000,000, so 5,000,000 can only come from the record), the reserved
/// block-to-live in B. `settle` must stop prescribing `resign` for dead bytes
/// and must not advance the store. `Pending` carries the reserved balance
/// and the block-to-live since format version 4, which
/// is what made this possible; before version 4 it held `spent_index` and the
/// digest alone, the same need the block-to-live marker had.
///
/// # Excluded, and why
///
/// `reconcile` is not driven: it is the acknowledgement gate for divergences,
/// and a dead reservation is not a divergence -- whether the gate should
/// mention one is undecided. The route OUT is the open question, and
/// is not asserted in either direction. What this does not establish: any
/// wording beyond the phrase, and the rendering of the expiry against the
/// tip (the block-to-live finding's route (a) names it; no marker asserts it). Since `resign` ships,
/// `resign` is a fourth page that misleads in scenario B: it reproduces an
/// expired reservation -- the block-to-live is in no plan input, so the
/// digest matches -- and, shipping what it reproduces, writes
/// the dead bytes to the socket under `submitted:`. This marker does not
/// drive it; widening a red marker's interface inside the session that
/// benefits from another marker closing is the shape this project avoids, so the page is
/// named here and handed to the 5c session.
#[test]
fn a_dead_reservation_is_reported_as_dead_from_the_store_and_the_chain_alone() {
    struct Scenario {
        name: &'static str,
        btl: u64,
        tip_at_send: u64,
        balance_after: u64,
        tip_after: u64,
        dead: bool,
        figure: &'static str,
    }
    let scenarios = [
        Scenario { name: "A", btl: 0, tip_at_send: 100, balance_after: 6_000_000, tip_after: 100, dead: true, figure: "5000000" },
        Scenario { name: "B", btl: 4_242, tip_at_send: 4_000, balance_after: 5_000_000, tip_after: 4_242, dead: true, figure: "4242" },
        Scenario { name: "C", btl: 0, tip_at_send: 100, balance_after: 5_000_000, tip_after: 100, dead: false, figure: "" },
        Scenario { name: "D", btl: 4_242, tip_at_send: 4_000, balance_after: 5_000_000, tip_after: 4_241, dead: false, figure: "" },
    ];
    let mut failures: Vec<String> = Vec::new();
    let mut live_state_text: Option<String> = None;
    for sc in &scenarios {
        let sent = p10_send_that_never_left(&format!("p10-205-{}", sc.name), sc.btl, sc.tip_at_send);
        let run = |cmd: &str| p10_child_session_run(sent.dir.path(), cmd, sc.balance_after, 0, sc.tip_after, None);
        let status = run("status");
        let balance = run("balance");
        let settle = run("settle");
        // The state text as `status` renders it, recovered from the page.
        let state_text = status
            .text
            .lines()
            .find_map(|l| l.strip_prefix("  state    "))
            .map(str::to_owned)
            .unwrap_or_default();
        if !sc.dead {
            // The controls, and the vacuity floor: a control that is not a
            // live reservation means the scenario setup broke, not that the
            // subject is fine.
            for (what, page) in [("status", &status.text), ("balance", &balance.text)] {
                assert!(
                    page.contains(P10_LIVE_LINE),
                    "control {}: `{what}` does not render the live reservation {P10_LIVE_LINE:?}; the scenario is not the state this marker is about:\n{page}",
                    sc.name
                );
            }
            assert!(settle.text.contains("NOT settled"), "control {}: settle did not say NOT settled:\n{}", sc.name, settle.text);
            assert!(settle.index == 1 && settle.pending, "control {}: settle moved the store", sc.name);
            assert_eq!(state_text, P10_LIVE_LINE, "control {}: the typed needle and the rendered state disagree", sc.name);
            live_state_text = Some(state_text);
            continue;
        }
        let live = live_state_text.clone().unwrap_or_else(|| P10_LIVE_LINE.to_owned());
        for (what, page) in [("status", &status.text), ("balance", &balance.text), ("settle", &settle.text)] {
            if page.contains(&live) {
                failures.push(format!("{} `{what}`: still renders the live state {live:?}", sc.name));
            }
            if !page.contains(P10_DEAD_PHRASE) {
                failures.push(format!("{} `{what}`: does not say {P10_DEAD_PHRASE:?}", sc.name));
            }
            // The decided route out: none, on purpose, stated beside the
            // price. The sentence is the specification's.
            if !page.contains(P10_NO_ROUTE_OUT) {
                failures.push(format!("{} `{what}`: does not say {P10_NO_ROUTE_OUT:?}", sc.name));
            }
        }
        for (what, page) in [("status", &status.text), ("balance", &balance.text)] {
            if !page.split(|c: char| !c.is_ascii_digit()).any(|t| t == sc.figure) {
                failures.push(format!("{} `{what}`: does not carry the reserved figure {} the store had to hold", sc.name, sc.figure));
            }
        }
        if settle.text.contains("`resign` rebuilds it") {
            failures.push(format!("{} `settle`: prescribes `resign` for bytes that can never be accepted", sc.name));
        }
        if !(settle.index == 1 && settle.pending) {
            failures.push(format!("{} `settle`: advanced the store past a reservation the chain never confirmed", sc.name));
        }
    }
    assert!(live_state_text.is_some(), "no control ran");
    if failures.is_empty() {
        println!("  dead reservations diagnosed: 2 dead scenario(s) told, 2 live controls untouched");
        return;
    }
    panic!(
        "A DEAD RESERVATION IS REPORTED AS A LIVE ONE. In {} scenario/page pair(s) the binary told an \
         operator whose signed artifact can never be accepted again that the spend was `not yet seen \
         on the chain`, and `settle` went on prescribing `resign` for bytes the ledger will refuse:\n\
         \x20 - {}\n\
         \n\
         The condition: \"an operator whose reserved artifact can no longer be accepted \
         -- the balance moved, or the block-to-live passed -- is told so by the binary, from the store \
         and the chain alone, without retyping the original arguments.\"\n\
         \n\
         What that needs: `Pending` carrying the reserved balance and the block-to-live beside the \
         index and the digest (format.rs::Pending carries them since format version 4), so that \
         reconciliation can compare them to the ledger entry and the tip; a state that renders \
         {P10_DEAD_PHRASE:?} with the reserved figure (the wording was recorded as this \
         marker's interface); and a `settle` that stops naming `resign`. Format version 4's figures \
         are what discharged this; item 5c's signed bytes were rejected on \
         width. The route out of the dead state is decided: \
         there is none, on purpose, and the page says so beside the price.",
        failures.len(),
        failures.join("\n  - ")
    );
}

/// **The block-to-live is recovered from the store, without knowing the
/// value** -- green under this name; red as
/// `the_block_to_live_cannot_be_recovered_from_the_store` before format
/// version 4 recorded the value: `status` and `balance` render it from the
/// record on its own line. The body performs the recovery rather than a
/// proxy for it.
/// What follows is the comment as it stood red.
///
/// `blk_to_live` is the last field of `TXHDR` and inside the digest; `send`
/// once printed nothing about it, `Pending` does not hold it, and
/// `resign` refuses with one text whether it is omitted or wrong. An
/// operator who ran `send … --btl N`, lost the page and did not write N down
/// is holding a reservation nothing can reproduce, settle or abandon.
///
/// # The condition, verbatim from the entry that filed it
///
/// > an operator holding the store, the password and the phrase can recover a
/// > reservation made with a non-zero block-to-live without knowing the value.
///
/// # What is driven: the recovery itself, not a proxy for it
///
/// Two stores, two values (the first live recovery's 1,080,961 and its double), each with a send
/// the socket refused and a page the operator loses. A script-operator who
/// holds the store, the password and the phrase -- and not the value --
/// comes back in fresh processes and runs the three commands that take no
/// value: `status`, `balance`, and `resign` with the block-to-live omitted.
/// Every decimal token those pages carry is then tried, each as `--btl` to
/// `resign` in its own process, and the marker is green when one attempt
/// reproduces the lost artifact byte for byte -- for BOTH stores, so a
/// constant printed somewhere cannot pass. That is the finding's route (a)
/// (`status`/`balance` render the value) and its route (b) read the way
/// the acknowledged path reads it: the refusal names the value it derived.
/// A refusal that names only the FIELD that differed leaves the value
/// unknown and this red; that resolution of the finding's own wording was
/// recorded. Printing the value on `send`'s page (the first mitigation) does not
/// clear this either: the page is what was lost.
///
/// # Controls
///
/// The reserved value sits in the artifact's little-endian bytes at hex
/// `[216..232)` (byte `[108..116)`, the finding's measurement); `resign` WITH
/// the value reproduces the artifact (the route exists when the value is
/// known); and a pre-send `status` page carries neither value, so a token
/// found later came from the reservation and not from a coincidence. The
/// chain scripts a tip below each value throughout, so a fix that renders
/// the expiry against the tip (route (a)'s second half, asserted by no
/// marker) is not refused by the fake; and it accepts the
/// submission `resign` now makes (the decision records why the control had
/// to move with the verb's contract, and two fault rows of its landing are the
/// demonstrations that it had to and that the clearing path survived).
#[test]
fn the_block_to_live_is_recovered_from_the_store_without_knowing_the_value() {
    let mut verdicts: Vec<(u64, bool, usize)> = Vec::new();
    for (name, b) in [("p10-206-a", 1_080_961u64), ("p10-206-b", 2_161_922u64)] {
        let tip = b - 250;
        // The coincidence guard, on a store with nothing reserved.
        let (fresh, ks) = store(&format!("{name}-fresh"));
        drop(ks);
        let before = p10_child_session_run(fresh.path(), "status", 5_000_000, 0, tip, None);
        assert!(
            !before.text.split(|c: char| !c.is_ascii_digit()).any(|t| t == b.to_string()),
            "premise: the value {b} appears on a page with nothing reserved:\n{}",
            before.text
        );

        let sent = p10_send_that_never_left(name, b, tip);
        // `TXHDR` is options[4] | src_addr[40] | chg_addr[40] | send_total[8]
        // | change_total[8] | fee_total[8] | blk_to_live[8] (types.h), so the
        // block-to-live is byte [108..116) of the artifact: hex [216..232),
        // Reading that hex offset as a byte offset doubles it to [432..464)
        // and refuses the correct artifact, so the entry is not to be
        // "corrected" into one.
        let le: String = b.to_le_bytes().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(
            &sent.artifact_hex[216..232],
            le,
            "the block-to-live finding's measurement no longer holds: the block-to-live is not at hex [216..232) of the artifact"
        );
        // `resign` ships what it reproduces, so every child
        // run is given the accepting id for THIS store's spend -- btl b is in
        // the digest -- and a right value reproduces AND ships, exit 0; a
        // wrong one is DigestMismatch before any write. `status`/`balance`
        // never submit. This scripts the socket OUT of the verdict, not into
        // it: the fake echoes the scripted id for any body, and the only
        // attempt that can carry the artifact is the byte-identical
        // reproduction whose id this is. Without it the control below would
        // red the marker at its control, not its verdict (a fault row of the
        // landing showed it), and a rendered value could never produce exit 0 -- the
        // clearing path would be gone (row I9 shows it is not).
        let mut with_b = spend();
        with_b.blk_to_live = b;
        let id = id_for(&format!("{name}-id"), &with_b);
        let run = |cmd: &str| p10_child_session_run(sent.dir.path(), cmd, 5_000_000, 0, tip, Some(id));
        let known = run(&format!("resign:{b}"));
        // Two assertions, the artifact first, so a reproduction failure keeps
        // reporting as one and a socket failure reports as itself.
        assert!(
            known.text.contains(&sent.artifact_hex),
            "control: resign WITH the value did not reproduce the artifact:\n{}",
            known.text
        );
        assert_eq!(
            known.code,
            0,
            "control: resign WITH the value reproduced it but the write was not accepted:\n{}",
            known.text
        );

        // The operator who lost the page: three commands that need no value.
        let pages = [run("status"), run("balance"), run("resign:0")];
        let mut tokens: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for p in &pages {
            for t in p.text.split(|c: char| !c.is_ascii_digit()) {
                if let Ok(n) = t.parse::<u64>() {
                    tokens.insert(n);
                }
            }
        }
        assert!(tokens.len() <= 64, "the harvest is too wide to try ({} tokens); the pages changed shape", tokens.len());
        let recovered = tokens
            .iter()
            .any(|t| {
                let attempt = run(&format!("resign:{t}"));
                attempt.code == 0 && attempt.text.contains(&sent.artifact_hex)
            });
        verdicts.push((b, recovered, tokens.len()));
    }
    if verdicts.iter().all(|(_, ok, _)| *ok) {
        println!("  block-to-live recovered without the value: {} store(s), from the pages alone", verdicts.len());
        return;
    }
    panic!(
        "THE BLOCK-TO-LIVE CANNOT BE RECOVERED FROM THE STORE. An operator holding the store, the \
         password and the phrase, and not the value, ran `status`, `balance` and `resign` without \
         it and tried every number those pages showed as `--btl`; the lost artifact was reproduced \
         in {} of {} store(s) ({}).\n\
         \n\
         The condition: \"an operator holding the store, the password and the phrase \
         can recover a reservation made with a non-zero block-to-live without knowing the value.\"\n\
         \n\
         Either route clears it: the store carries the reserved block-to-live and `status`/`balance` \
         render it beside the SPEND OUTSTANDING line (with its expiry against the tip, which no marker \
         asserts), or `resign`'s refusal names the value it derived and compared (the acknowledged path's shape; \
         naming only the FIELD leaves the value unknown). Both need `Pending` to carry \
         more than the index and the digest; abandonment is not a route, and printing the \
         value on `send`'s page does not reach an operator who lost the page. Format version \
         4's figures are what discharged this; 5c's signed bytes were rejected \
         on width.",
        verdicts.iter().filter(|(_, ok, _)| *ok).count(),
        verdicts.len(),
        verdicts
            .iter()
            .map(|(b, ok, n)| format!("btl {b}: {} after {n} token(s)", if *ok { "recovered" } else { "NOT recovered" }))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

/// **`status` and `balance` render the reserved figures on their own lines
/// beside the pinned state line**. The live state line
/// stays byte for byte what the red marker asserted by equality; the figures the record
/// carries -- the reserved balance and the block-to-live, with the tip it
/// was compared to -- go on lines of their own under it, in the same words
/// on both pages; and a page with nothing reserved carries none of them.
#[test]
fn status_and_balance_render_the_reserved_figures_on_their_own_lines_beside_the_pinned_state_line() {
    let sent = p10_send_that_never_left("p13-figures", 4_242, 4_000);
    let status = p10_child_session_run(sent.dir.path(), "status", 5_000_000, 0, 4_000, None);
    let state = status
        .text
        .lines()
        .find_map(|l| l.strip_prefix("  state    "))
        .unwrap_or_default();
    assert_eq!(state, P10_LIVE_LINE, "the state line is not byte for byte the live line:\n{}", status.text);
    for needle in [
        "\n  reserved balance  5000000 nanoMCM when the spend was built",
        "\n  block-to-live     4242 (the node accepts it only while the tip is at or below 4242, and refuses it if 4242 is below the tip when it arrives; the tip is 4000",
    ] {
        assert!(status.text.contains(needle), "`status` does not carry {needle:?} on its own line:\n{}", status.text);
    }
    let balance = p10_child_session_run(sent.dir.path(), "balance", 5_000_000, 0, 4_000, None);
    assert!(balance.text.contains(P10_LIVE_LINE), "`balance` lost the live line:\n{}", balance.text);
    for needle in [
        "\n    reserved balance  5000000 nanoMCM when the spend was built",
        "\n    block-to-live     4242 (the node accepts it only while the tip is at or below 4242, and refuses it if 4242 is below the tip when it arrives; the tip is 4000",
    ] {
        assert!(balance.text.contains(needle), "`balance` does not carry {needle:?} under the account's row:\n{}", balance.text);
    }
    // And nothing reserved, nothing rendered.
    let (fresh, ks) = store("p13-figures-fresh");
    drop(ks);
    let before = p10_child_session_run(fresh.path(), "status", 5_000_000, 0, 4_000, None);
    assert!(!before.text.contains("reserved balance"), "a page with nothing reserved renders a reserved balance:\n{}", before.text);
    assert!(!before.text.contains("block-to-live"), "a page with nothing reserved renders a block-to-live:\n{}", before.text);
    println!("  reserved figures: rendered on their own lines by status and balance, the state line pinned");
}

/// **A migrated store says its figures were not recorded, and its first
/// write re-seals it as version 4**. The captured
/// version-3 reservation as a store: `status` and `balance` say the figures
/// were not recorded under format version 3, print no upgrade line, and
/// leave the file byte for byte; the `settle` that lands it is the first
/// write and its page says the store was written in format version 4 and an
/// older build will no longer open it; the file's version word is 4; and a
/// following `status` carries no upgrade line. Every command runs in a
/// fresh process, as the operator's would.
#[test]
fn a_migrated_store_says_its_figures_were_not_recorded_and_is_resealed_by_its_first_write() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    const UPGRADE: &str = "written in format version 4";
    let dir = ScratchDir::new("p13-migrated");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    dir.write_snapshot(IMAGE);

    let status = p10_child_session_run(dir.path(), "status", 5_000_000, 0, 100, None);
    assert_eq!(status.code, 0, "{}", status.text);
    let state = status.text.lines().find_map(|l| l.strip_prefix("  state    ")).unwrap_or_default();
    assert_eq!(state, P10_LIVE_LINE, "a migrated reservation is neither live nor dead and keeps the live line:\n{}", status.text);
    assert!(status.text.contains("not recorded") && status.text.contains("format version 3"), "`status` does not say the figures were not recorded under version 3:\n{}", status.text);
    assert!(!status.text.contains(UPGRADE), "`status` printed the upgrade line without writing:\n{}", status.text);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "`status` rewrote a version-3 store");

    let balance = p10_child_session_run(dir.path(), "balance", 5_000_000, 0, 100, None);
    assert_eq!(balance.code, 0, "{}", balance.text);
    assert!(balance.text.contains("not recorded"), "`balance` does not say the figures were not recorded:\n{}", balance.text);
    assert!(!balance.text.contains(UPGRADE), "`balance` printed the upgrade line without writing:\n{}", balance.text);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "`balance` rewrote a version-3 store");

    // The first write: the chain at the change key, and settle lands it.
    let settle = p10_child_session_run(dir.path(), "settle", 4_000_000, 1, 100, None);
    assert_eq!(settle.code, 0, "{}", settle.text);
    assert!(settle.text.contains("settled"), "{}", settle.text);
    assert!(settle.text.contains(UPGRADE) && settle.text.contains("older build"), "the command that made the first write did not announce the crossing:\n{}", settle.text);
    assert!(settle.index == 1 && !settle.pending, "settle left the store in the wrong state");
    let after = dir.snapshot_bytes();
    assert_eq!(u16::from_le_bytes([after[8], after[9]]), 4, "the first write did not re-seal the store as version 4");
    assert_eq!(after.len(), 51 + 45 + 195 + 16, "one version-4 record");

    let again = p10_child_session_run(dir.path(), "status", 4_000_000, 1, 100, None);
    assert_eq!(again.code, 0, "{}", again.text);
    assert!(again.text.contains("in sync"), "{}", again.text);
    assert!(!again.text.contains(UPGRADE), "a store opened at version 4 printed the upgrade line:\n{}", again.text);
    println!("  migrated store: status and balance say not recorded and write nothing; settle makes the first write, announces version 4; the next status is quiet");
}

// ---------------------------------------------------------------------------
// The four read-only verbs
// ---------------------------------------------------------------------------

/// A transport scripted for the explorer endpoints alone.
///
/// The replies are built **in the shapes group N recorded**, not copied from
/// it: the captured bodies themselves are replayed byte for byte in
/// `tests/mesh.rs`, which is where the codec is held to the server. This
/// double exists to drive the pages, so its bodies are the smallest that
/// carry the fields a page prints. Two of the request shapes it answers --
/// a search by account, and a block by hash -- have no group N vector at
/// all, and are pinned only by the Go at the commit the corpus names.
struct Explorer {
    tip: u64,
    /// Every path posted to, in order.
    paths: RefCell<Vec<String>>,
    /// Every body posted, in order.
    bodies: RefCell<Vec<Vec<u8>>>,
    /// When set, `/search/transactions` answers the middleware's internal
    /// error -- what a deployment with no indexer returns.
    no_indexer: bool,
    /// When set, `/search/transactions` answers an empty page.
    empty: bool,
}

impl Explorer {
    fn new(tip: u64) -> Explorer {
        Explorer { tip, paths: RefCell::new(Vec::new()), bodies: RefCell::new(Vec::new()), no_indexer: false, empty: false }
    }
    fn without_indexer(mut self) -> Explorer {
        self.no_indexer = true;
        self
    }
    fn with_no_rows(mut self) -> Explorer {
        self.empty = true;
        self
    }
    /// One transaction in `/search/transactions`' own rendering: the source
    /// debited GROSS and the change back as its own destination, metadata as
    /// JSON numbers.
    fn search_row(index: u64, tag_hex: &str) -> String {
        format!(
            r#"{{"block_identifier":{{"index":{index},"hash":"0x{h}"}},"transaction_identifier":{{"hash":"0x{t}"}},"timestamp":1788500208000,"operations":[{{"operation_identifier":{{"index":0}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag_hex}"}},"amount":{{"value":"-50000000","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":1}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":"INVOICE-7"}}}},{{"operation_identifier":{{"index":2}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag_hex}"}},"amount":{{"value":"39999500","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":3}},"type":"FEE","status":"SUCCESS","account":{{"address":"0x7b33270a98d2e6b188aedcdf10b7867b16cd9b0b"}},"amount":{{"value":"500","currency":{{"symbol":"MCM","decimals":9}}}}}}],"metadata":{{"block_to_live":0,"change_total":39999500,"fee_total":500,"send_total":10000000}}}}"#,
            h = "36".repeat(32),
            t = "18".repeat(32),
        )
    }
    /// One block in `/block`'s own rendering: a reward transaction, then one
    /// spend whose source is debited NET with no change operation, and
    /// metadata as decimal strings.
    fn block_body(index: u64) -> String {
        format!(
            r#"{{"block":{{"block_identifier":{{"index":{index},"hash":"0x{h}"}},"parent_block_identifier":{{"index":{p},"hash":"0x{ph}"}},"timestamp":1788500198000,"transactions":[{{"transaction_identifier":{{"hash":"0x{r}"}},"operations":[{{"operation_identifier":{{"index":0}},"type":"REWARD","status":"SUCCESS","account":{{"address":"0x9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c"}},"amount":{{"value":"12065840589","currency":{{"symbol":"MCM","decimals":9}}}}}}]}},{{"transaction_identifier":{{"hash":"0x{t}"}},"operations":[{{"operation_identifier":{{"index":0}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":""}}}},{{"operation_identifier":{{"index":1}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x371c388eba10f265c648008e1ad2c94e680c0f4a"}},"amount":{{"value":"-10000500","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"change_amount":"39999500","source_amount":"50000000"}}}},{{"operation_identifier":{{"index":2}},"type":"FEE","status":"SUCCESS","account":{{"address":"0x7b33270a98d2e6b188aedcdf10b7867b16cd9b0b"}},"amount":{{"value":"500","currency":{{"symbol":"MCM","decimals":9}}}}}}],"metadata":{{"block_to_live":"0"}}}}]}}}}"#,
            h = "36".repeat(32),
            p = index - 1,
            ph = "72".repeat(32),
            r = "ab".repeat(32),
            t = "18".repeat(32),
        )
    }
}

impl mochimo_crypto::mesh::Transport for Explorer {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.paths.borrow_mut().push(path.to_owned());
        self.bodies.borrow_mut().push(body.to_vec());
        match path {
            "/network/status" => Ok(format!(
                r#"{{"current_block_identifier":{{"index":{},"hash":"0x{}"}}}}"#,
                self.tip,
                "ab".repeat(32)
            )
            .into_bytes()),
            "/block" => {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let index = v["block_identifier"]["index"].as_u64().unwrap_or(self.tip);
                Ok(Explorer::block_body(index).into_bytes())
            }
            "/search/transactions" => {
                if self.no_indexer {
                    // `giveError(w, ErrInternalError)`: HTTP 200 with a code.
                    return Ok(br#"{"code":1,"message":"Internal general error","retriable":true}"#.to_vec());
                }
                if self.empty {
                    return Ok(br#"{"transactions":[],"total_count":0}"#.to_vec());
                }
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let tag_hex = v["account_identifier"]["address"]
                    .as_str()
                    .map(|s| s.trim_start_matches("0x").to_owned())
                    .unwrap_or_else(|| "37".repeat(20));
                Ok(format!(
                    r#"{{"transactions":[{}],"total_count":1}}"#,
                    Explorer::search_row(1_078_535, &tag_hex)
                )
                .into_bytes())
            }
            other => panic!("the explorer double was asked for {other}"),
        }
    }
}

/// **`transaction <hash>`**: the indexer's rendering of one transaction, and
/// the page that says which endpoint it read.
#[test]
fn transaction_prints_the_indexers_rendering_and_names_the_endpoint() {
    let hash = [0x18u8; 32];
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::LookupTransaction { hash });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("transaction 1818"), "{}", r.text);
    assert!(r.text.contains("in block 1078535"), "{}", r.text);
    assert!(r.text.contains("4 operation(s)"), "{}", r.text);
    assert!(r.text.contains("SOURCE_TRANSFER"), "{}", r.text);
    assert!(r.text.contains("-50000000 nanoMCM (-0.050000000 MCM)"), "the gross debit is not rendered:\n{}", r.text);
    assert!(r.text.contains("memo INVOICE-7"), "{}", r.text);
    assert!(r.text.contains("block_to_live = 0"), "{}", r.text);
    assert!(r.text.contains("send_total = 10000000"), "{}", r.text);
    assert!(r.text.contains("/search/transactions"), "the page does not name the endpoint:\n{}", r.text);
    assert!(r.text.contains("GROSS"), "the page does not state the convention:\n{}", r.text);
    println!("  transaction: 4 operations, the gross debit, the memo, the metadata, the endpoint named");
}

/// **`recent-transactions <tag>`**: one row per transaction, newest first,
/// with the direction as the tag sees it.
#[test]
fn recent_transactions_prints_a_row_per_transaction_with_its_direction() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::RecentTransactions { tag: TAG, count: 5 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("1 of 1 row(s), newest first"), "{}", r.text);
    assert!(r.text.contains("block   1078535"), "{}", r.text);
    // The scripted row debits the tag 50,000,000 and returns 39,999,500 to
    // it, so the tag is on both sides and the net it felt is -10,000,500.
    assert!(r.text.contains("both"), "the direction is not both:\n{}", r.text);
    assert!(r.text.contains("-10000500 nanoMCM"), "the amount that touched the tag is wrong:\n{}", r.text);
    println!("  recent-transactions: one row, direction `both`, the tag's own net -10,000,500");
}

/// A tag the index has never seen prints an empty table and exits 0; a
/// deployment with no indexer is a refusal that says so.
#[test]
fn recent_transactions_is_empty_on_no_history_and_refuses_with_no_indexer() {
    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).with_no_rows()),
        &Command::RecentTransactions { tag: TAG, count: 5 },
    );
    assert_eq!(r.code, Code::Ok, "an empty history is not a refusal:\n{}", r.text);
    assert!(r.text.contains("0 of 0 row(s)"), "{}", r.text);
    assert!(r.text.contains("(none:"), "{}", r.text);

    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).without_indexer()),
        &Command::RecentTransactions { tag: TAG, count: 5 },
    );
    assert_eq!(r.code, Code::Refused, "a missing indexer is not an ok page:\n{}", r.text);
    assert!(r.text.contains("indexer database"), "the refusal does not name the indexer:\n{}", r.text);
    assert!(r.text.contains("no store was opened"), "{}", r.text);
    println!("  recent-transactions: an empty index is exit 0 with an empty table; no indexer is exit 3 naming it");
}

/// **`block <number>`**: the reward reported on its own and excluded from
/// what moved.
#[test]
fn block_reports_its_reward_apart_from_what_it_moved() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::Block { at: args::BlockAt::Index(1_078_535) });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("block 1078535"), "{}", r.text);
    assert!(r.text.contains("parent   1078534"), "{}", r.text);
    assert!(r.text.contains("reward   12065840589 nanoMCM"), "{}", r.text);
    assert!(r.text.contains("spends   1"), "{}", r.text);
    // The reward is 12,065,840,589 and the one spend delivers 10,000,000.
    // `moved` is the second, never the sum.
    assert!(r.text.contains("moved    10000000 nanoMCM"), "the reward leaked into what moved:\n{}", r.text);
    assert!(r.text.contains("fees     500 nanoMCM"), "{}", r.text);
    assert!(r.text.contains("/block, which re-parses the wire"), "{}", r.text);
    println!("  block: reward 12,065,840,589 on its own line, moved 10,000,000, fees 500");
}

/// **`blocks`**: the tip, then one row per block below it.
#[test]
fn blocks_walks_down_from_the_tip_one_row_each() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::Blocks { count: 3 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("the tip is 1078600"), "{}", r.text);
    for i in ["1078600", "1078599", "1078598"] {
        assert!(r.text.contains(i), "block {i} is not on the page:\n{}", r.text);
    }
    assert!(!r.text.contains("1078597"), "a fourth block was fetched:\n{}", r.text);
    // Two: the reward transaction and the one spend. `/block`'s
    // `transactions[]` carries the reward like any other, which is why
    // `block <n>` counts "spends" separately from this row's figure.
    assert!(r.text.contains("2 transaction(s)"), "the row does not carry a transaction count:\n{}", r.text);
    println!("  blocks: the tip and the two below it, one row each, one /block call per row");
}

// ---------------------------------------------------------------------------
// The partition: a diverged account is refused, its siblings are not
// ---------------------------------------------------------------------------

/// Account 1, funded and in sync, beside account 0 swept to zero.
///
/// The emptied account reads as `Absent`: the Mesh answers code 4 for a tag it
/// holds at zero balance, because its quorum discards zero-amount answers. The
/// ledger entry is still there and reappears the moment the tag is paid, which
/// is why the recovery below works at all.
fn emptied_and_funded(name: &str) -> (ScratchDir, Keystore, mochimo_crypto::addr::Tag, Chain) {
    let m = master();
    let sibling = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let (dir, mut ks) = store(name);
    ks.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("{e}"));
    // Account 0 swept itself to zero: the key at 0 signed and the store
    // advanced to the change key at 1, with the reservation still open.
    let _ = ks
        .persist_advance(&TAG, &[0xD1; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let sibling_at = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(0));
    let chain = Chain::new(&[
        (TAG, ChainState::Absent),
        (sibling, ChainState::At(sibling_at, 9_000_000)),
    ]);
    (dir, ks, sibling, chain)
}

/// The id a spend from `tag` will carry, taken from a dry run on a throwaway
/// store built from the same entropy. The dry run advances its own copy, which
/// is why the caller uses a fresh one.
fn submit_id_for(name: &str, tag: mochimo_crypto::addr::Tag, dsts: Vec<Destination>) -> [u8; 32] {
    let m = master();
    let (_dir, ks, _sibling, chain) = emptied_and_funded(name);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&tag, &KeyAccess::Master(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    w.reserve_and_sign(&plan, KeyAccess::Master(&m))
        .unwrap_or_else(|e| panic!("{e}"))
        .id()
        .0
}

/// **A sibling that reconciles spends while another account is diverged.**
///
/// The emptied account's key stream and the sibling's share nothing: a
/// confirmed index on the sibling says the node returned exactly the address
/// this store derived at the stored position, which no wrong seed, wrong chain
/// or lying node can produce. The next key is provably unused, so signing it is
/// not reuse, and none of the machinery that prevents reuse consults a sibling.
#[test]
fn a_reconciling_account_spends_while_a_sibling_is_diverged() {
    let m = master();
    let sibling = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let id = submit_id_for(
        "cli-partition-send-dry",
        sibling,
        vec![Destination { tag: TO, reference: [0; 16], amount: 1_000 }],
    );
    let (_dir, ks, _s, chain) = emptied_and_funded("cli-partition-send");
    chain.accepts_submit(id);
    let s = Spend {
        tag: sibling,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
    };
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(
        r.code,
        Code::Ok,
        "a funded account could not spend while a sibling was diverged:\n{}",
        r.text
    );
    assert_says(&r, "sending 1000 nanoMCM", "send from the reconciling account");
    // The page still carries the diverged sibling's report: the spend went
    // through and the store is still not whole.
    assert_says(&r, "THIS STORE IS NOT WHOLE", "send from the reconciling account");
}

/// **The diverged account's own `send` refuses, by name, with its report.**
///
/// Nothing is reclassified: the sibling's health is evidence of nothing about
/// this account, and the page an operator reads here carries the same three
/// readings of code 4 that the startup refusal carried.
#[test]
fn the_diverged_accounts_own_send_refuses_by_name_with_its_report() {
    let (_dir, ks, _sibling, chain) = emptied_and_funded("cli-partition-refuse");
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend()));
    assert_ne!(r.code, Code::Ok, "a diverged account spent:\n{}", r.text);
    assert_says(&r, &format!("account {}", hexs(&TAG)), "the refusal names the account");
    assert_says(&r, "did not resolve this tag", "the refusal carries the report");
    assert_says(&r, "ZERO balance", "the report keeps the three readings");
    assert_says(&r, "lookup itself failed", "the report keeps the three readings");
    // It is THIS ACCOUNT that is refused, not the store. The wallet opened:
    // the sibling reconciled, so the whole-store refusal is the wrong page and
    // the wrong exit code for a command that reached a running wallet.
    assert!(
        !r.text.contains("WALLET WILL NOT START"),
        "a per-account refusal rendered the whole-store page:\n{}",
        r.text
    );
    assert_eq!(
        r.code,
        Code::Refused,
        "the command was refused by a wallet that started, which is exit 3 and not startup:\n{}",
        r.text
    );
}

/// **Every command that opens the wallet renders every diverged report.**
///
/// A diverged account is a standing condition, not a footnote found by an
/// operator who happens to address it. `balance` shows the reconciled accounts
/// and the diverged ones together, so the page cannot read as a whole store.
#[test]
fn every_command_that_opens_the_wallet_renders_the_diverged_report() {
    for (what, command) in [
        ("balance", Command::Balance),
        ("settle", Command::Settle { tag: mochimo_crypto::derive::derive_account_tag(&master(), 1) }),
    ] {
        let (_dir, ks, _sibling, chain) = emptied_and_funded(&format!("cli-partition-notice-{what}"));
        let r = cli::run(ks, MeshClient::new(chain), &command);
        assert_says(&r, &format!("account {}", hexs(&TAG)), what);
        assert_says(&r, "did not resolve this tag", what);
    }
    // `balance` shows both halves: the sibling's funds and the diverged report.
    let (_dir, ks, _sibling, chain) = emptied_and_funded("cli-partition-balance");
    let r = cli::run(ks, MeshClient::new(chain), &Command::Balance);
    assert_eq!(r.code, Code::Ok, "balance refused a store with one good account:\n{}", r.text);
    assert_says(&r, "9000000", "balance lists the reconciled account's funds");
    assert_says(&r, "did not resolve this tag", "balance lists the diverged account");
}

/// **A store where NO account reconciles still refuses outright.**
///
/// A wallet with nothing operable is not a wallet, and that is the job
/// `StartupRefusal` keeps.
#[test]
fn a_store_where_no_account_reconciles_still_refuses_outright() {
    let (_dir, ks) = store("cli-partition-none");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::StartupRefused, "a store with no operable account opened:\n{}", r.text);
    assert_says(&r, "WALLET WILL NOT START", "the whole-store refusal");
}

/// **Paying the emptied account from its sibling restores it, and it settles.**
///
/// The end-to-end proof. The ledger keeps a zero-balance entry and keeps
/// rehashing it, so a paid tag reappears at exactly the address this store
/// expects -- the change key of the spend that emptied it -- and `settle` then
/// resolves the reservation normally.
///
/// The stand-in node does not mine, so the ledger state after the payment is
/// scripted rather than produced by the submit above it. What the test drives
/// is the wallet's half: that the sibling can pay while the account is
/// diverged, and that the account settles once the entry is visible again.
#[test]
fn paying_the_emptied_account_from_its_sibling_lets_it_settle() {
    let m = master();
    let (dir, ks, sibling, chain) = emptied_and_funded("cli-partition-recover");

    // 1. The emptied account cannot settle while the chain will not show it.
    let r = cli::run(ks, MeshClient::new(chain), &Command::Settle { tag: TAG });
    assert_ne!(r.code, Code::Ok, "an invisible account settled:\n{}", r.text);
    assert_says(&r, "did not resolve this tag", "settle on the diverged account");

    // 2. The sibling pays it. This is the step the old whole-store refusal
    //    made unreachable: the remedy required the wallet to open.
    let ks = reopen("cli-partition-recover-2", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let sibling_at = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(0));
    let id = submit_id_for(
        "cli-partition-recover-dry",
        sibling,
        vec![Destination { tag: TAG, reference: [0; 16], amount: 2_000_000 }],
    );
    let pay = Spend {
        tag: sibling,
        dsts: vec![SpendTo { to: TAG, reference: [0; ADDR_REF_LEN], amount: Some(2_000_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
    };
    let paying = Chain::new(&[
        (TAG, ChainState::Absent),
        (sibling, ChainState::At(sibling_at, 9_000_000)),
    ]);
    paying.accepts_submit(id);
    let r = cli::run(ks, MeshClient::new(paying), &Command::Send(pay));
    assert_eq!(r.code, Code::Ok, "the sibling could not pay the emptied account:\n{}", r.text);

    // 3. The entry reappears at the change key of the spend that emptied it,
    //    which is the address this store already holds as its position.
    let ks = reopen("cli-partition-recover-3", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(1), 2_000_000)),
            (sibling, ChainState::At(sibling_at, 6_999_000)),
        ])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "the re-funded account did not settle:\n{}", r.text);
    assert_says(&r, "settled", "settle after the account was paid");
}
