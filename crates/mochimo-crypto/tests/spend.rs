#![cfg(all(feature = "native", not(miri)))]
//! The spend path: the addresses a spend is built for, the plan's
//! refusals, the signature attached and re-validated, the reference's own
//! acceptance images reproduced byte for byte, and the whole flow over a
//! recording transport.
//!
//! Gated as `signing.rs` is: `native` for the keystore and the derivation,
//! `not(miri)` for WOTS+ time. Not gated on `ffi-oracle`; the arms that hand
//! this crate's bytes to the C validators are, and each says so on its
//! evidence line.
//!
//! No test here spawns a process and none drops and reopens a keystore, so
//! the bounded reopen helper has no site to be used at; the scan
//! in `tests/keystore.rs` holds that no bare `Keystore::open` appears here
//! either.
//!
//! # What the byte-identity proof establishes
//!
//! `attach_reproduces_the_reference_acceptance_images` builds a `SpendPlan`
//! from each `Ds6-N*` image's own header and destinations, signs the plan's
//! digest with the identity key through the raw native signer from an
//! address whose last twelve bytes are ZEROED, and requires `attach` to
//! reproduce the image through the nonce byte for byte. The mandated tail
//! therefore arrives on the wire from `pk_from_sig` alone -- nothing in the
//! crate spells it -- and in the default build the C's `tx_val__wots` and
//! `mdst_val` judge the assembled bytes. What it cannot establish: `tx_val`'s
//! ledger arms, which have never judged any image (the residue at
//! `mesh::spend`).

#[path = "support/keystore_harness.rs"]
mod keystore_harness;
// Only the loaders are used here; the walk itself belongs to `txwire.rs`.
#[allow(dead_code)]
#[path = "support/wire_images.rs"]
mod wire_images;
// The scriptable chain, for the two command-layer cases at the end of this
// file: a store holding both kinds of account is unreachable from the
// command line, so the case is driven here through `cli::run`.
#[path = "support/chain.rs"]
mod chain;

use std::cell::RefCell;

use chain::{Chain, ChainState};
use keystore_harness::{
    derived_account, imported_account, reopen, ScratchDir, DERIVED_MASTER, DERIVED_POSITION, DERIVED_TAG, FIGURES,
    IMPORTED_TAG, ROOT,
};
use mochimo_crypto::account::{Account, AccountKind, WotsIndex};
use mochimo_crypto::backend;
use mochimo_crypto::cli::args::{Command, Spend, SpendTo};
use mochimo_crypto::cli::{self, Code};
use mochimo_crypto::consts::{ADDR_TAG_LEN, HASHLEN, MFEE, PK_LEN, SEED_LEN};
use mochimo_crypto::keystore::{Figures, KeyAccess, Keystore, SpendAddresses, SpendSignature};
use mochimo_crypto::mesh::spend::{reference_is_valid, verify_wots, SignedTransaction, SpendPlan};
use mochimo_crypto::mesh::{codec, hex, LedgerEntry, MeshClient, Transport};
use mochimo_crypto::tx::wire::{Destination, Transaction};
use mochimo_crypto::recon;
use mochimo_crypto::wallet::Wallet;
use mochimo_crypto::wots::Adrs;
use mochimo_crypto::{addr, derive, Error, Secret};

const F_FILE: &str = "group_f_derivation.json";
const ANCHOR_ID: &str = "F-address-widths";
/// For the evidence lines: this crate has no transaction validator, and the
/// reference's are not here to ask.
const VALIDATORS: &str = "none (this crate has no transaction validator)";

fn repo_root() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixture_vector(file: &str, id: &str) -> serde_json::Value {
    let p = repo_root().join("fixtures").join(file);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()));
    json["vectors"]
        .as_array()
        .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some(id)).cloned())
        .unwrap_or_else(|| panic!("{file} has no vector {id}"))
}

fn hexf(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("no string field {key}")), "fixture field")
        .unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn arr<const N: usize>(bytes: &[u8], what: &str) -> [u8; N] {
    bytes.try_into().unwrap_or_else(|_| panic!("{what}: {} bytes, expected {N}", bytes.len()))
}

/// The fixture's account 0: master, tag, and the TypeScript-recorded address
/// of the shipped `wotsIndex 0` -- our position 1.
struct Anchor {
    master: Secret<SEED_LEN>,
    tag: [u8; ADDR_TAG_LEN],
    address_at_1: [u8; 40],
}

fn anchor() -> Anchor {
    let v = fixture_vector(F_FILE, ANCHOR_ID);
    Anchor {
        master: Secret::<SEED_LEN>::from_slice(&hexf(&v, "master_seed")).unwrap_or_else(|e| panic!("{e}")),
        tag: arr(&hexf(&v, "account_tag"), "account_tag"),
        address_at_1: arr(&hexf(&v, "wots_address"), "wots_address"),
    }
}

fn dst(tag_byte: u8, amount: u64) -> Destination {
    Destination {
        tag: [tag_byte; ADDR_TAG_LEN],
        reference: [0; 16],
        amount,
    }
}

/// A fresh store holding the anchor's account at position 0, and its
/// spend addresses.
fn anchored_store(name: &str) -> (ScratchDir, Keystore, Anchor, SpendAddresses) {
    let a = anchor();
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&a.master, 0)).unwrap_or_else(|e| panic!("{e}"));
    let addresses = ks
        .spend_addresses(&a.tag, &KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("spend_addresses: {e}"));
    (dir, ks, a, addresses)
}

// ---------------------------------------------------------------------------
// spend_addresses
// ---------------------------------------------------------------------------

/// Both kinds at both positions, anchored on `F-address-widths`: position 0
/// of a derived account is the implicit first address (tag half equal to
/// hash half) and its change is the recorded `wots_address`;
/// after one spend settles, position 1's source IS that recorded address.
/// An imported account spends from position 0 through the first-key
/// components its record carries (format v2) and derives from its root
/// above it. Every refusal `sign_spend` makes, made here first.
#[test]
fn spend_addresses_follow_the_recorded_positions_for_both_kinds() {
    let (_dir, mut ks, a, at0) = anchored_store("spend-addresses");
    assert_eq!(at0.tag, a.tag);
    assert_eq!(at0.position, WotsIndex::ZERO);
    assert_eq!(at0.source, addr::from_implicit(&a.tag), "position 0's source is the implicit first address");
    assert_eq!(at0.change, a.address_at_1, "position 0's change is the recorded wotsIndex-0 address");

    let mut refusals = 0usize;
    // A reservation outstanding: refused before any network round trip.
    let _r = ks.persist_advance(&a.tag, &[0xD1; 32], FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.spend_addresses(&a.tag, &KeyAccess::Master(&a.master)).err(),
        Some(Error::PendingUnresolved { spent_index: 0 })
    );
    refusals += 1;
    ks.persist_settled(&a.tag).unwrap_or_else(|e| panic!("{e}"));

    let at1 = ks.spend_addresses(&a.tag, &KeyAccess::Master(&a.master)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(at1.position, WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(at1.source, a.address_at_1, "position 1's source is the recorded wotsIndex-0 address");
    assert_eq!(addr::tag_of(&at1.change), &a.tag[..], "the change keeps the tag");
    assert_ne!(addr::hash_of(&at1.change), addr::hash_of(&at1.source), "the change rotates the hash");
    assert_ne!(at1.change, at0.change, "position 2's key is not position 1's");

    // The wrong master, the wrong access shape, an unknown tag.
    let other = Secret::new([0x77; SEED_LEN]);
    assert_eq!(
        ks.spend_addresses(&a.tag, &KeyAccess::Master(&other)).err(),
        Some(Error::DerivedTagNotReproduced { account_index: 0 })
    );
    refusals += 1;
    assert_eq!(
        ks.spend_addresses(&a.tag, &KeyAccess::StoredRoot).err(),
        Some(Error::KeyAccessMismatch {
            kind: AccountKind::Derived
        })
    );
    refusals += 1;
    assert_eq!(
        ks.spend_addresses(&[0x01; ADDR_TAG_LEN], &KeyAccess::Master(&a.master)).err(),
        Some(Error::NoSuchAccount)
    );
    refusals += 1;

    // Imported: position 0 comes from the components the record carries
    // since format v2 (it was `Err(FirstKeyUnavailable)` before that, so a
    // never-spent imported account could not be spent from at all); position
    // 1 derives from the root -- the same derivation `sign_spend` uses, a
    // consistency check on the kind arm, stated as such.
    let dir2 = ScratchDir::new("spend-addresses-imported");
    let mut ks2 = Keystore::create(dir2.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks2.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let imp0 = ks2
        .spend_addresses(&IMPORTED_TAG, &KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("imported position 0: {e}"));
    // The source is the stored first address under the account tag, and the
    // change is rotation 0 -- the pair a first spend from an imported
    // account uses, and where its imported funds actually sit.
    let root = Secret::new(ROOT);
    assert_eq!(
        imp0.source,
        derive::first_key_from_components(
            root.duplicate(),
            keystore_harness::IMPORTED_FIRST_ADDRESS[PK_LEN..PK_LEN + SEED_LEN]
                .try_into()
                .unwrap_or_else(|_| panic!("pub_seed width")),
            mochimo_crypto::wots::Adrs::from_le_image(
                keystore_harness::IMPORTED_FIRST_ADDRESS[PK_LEN + SEED_LEN..]
                    .try_into()
                    .unwrap_or_else(|_| panic!("adrs width"))
            ),
        )
        .address(&IMPORTED_TAG)
    );
    assert_eq!(imp0.change, derive::derive_wots_key(&root, 0).address(&IMPORTED_TAG));
    assert_eq!(
        ks2.spend_addresses(&IMPORTED_TAG, &KeyAccess::Master(&a.master)).err(),
        Some(Error::KeyAccessMismatch {
            kind: AccountKind::Imported
        })
    );
    refusals += 1;
    let _r = ks2.persist_advance(&IMPORTED_TAG, &[0xD1; 32], FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks2.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let imp1 = ks2.spend_addresses(&IMPORTED_TAG, &KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(imp1.source, derive::derive_wots_key(&root, 0).address(&IMPORTED_TAG));
    assert_eq!(imp1.change, derive::derive_wots_key(&root, 1).address(&IMPORTED_TAG));
    // Position 0's change IS position 1's source: the spend chain is one
    // stream, and the two calls agree about where it goes next.
    assert_eq!(imp0.change, imp1.source);

    println!(
        "  spend addresses: derived positions 0 and 1 anchored on {ANCHOR_ID}, imported positions 0 \
         and 1 both derived, {refusals} refusals by name"
    );
}

// ---------------------------------------------------------------------------
// SpendPlan
// ---------------------------------------------------------------------------

/// Every refusal `SpendPlan::new` makes, one input each, and the totals it
/// lays out. Each refusal mirrors a `mdst_val`/`tx_val` arm at the line the
/// error's doc cites; the boundary cases (fee exactly the floor, send plus
/// fee exactly the balance) are accepted.
#[test]
fn spend_plan_refuses_each_shape_the_reference_rejects() {
    let (_dir, _ks, a, at0) = anchored_store("spend-plan");
    let entry = |balance: u64| LedgerEntry {
        address: at0.source,
        balance,
    };
    let mut refusals = 0usize;

    // 1. the chain holds the tag at some other key
    let wrong = LedgerEntry {
        address: at0.change,
        balance: 1_000_000,
    };
    assert_eq!(
        SpendPlan::new(&at0, &wrong, vec![dst(0x6b, 1)], MFEE, 0).err(),
        Some(Error::ChainAddressMismatch { position: 0 })
    );
    refusals += 1;
    // 2. the count bound, both ends
    assert!(matches!(
        SpendPlan::new(&at0, &entry(1_000_000), vec![], MFEE, 0),
        Err(Error::Range {
            what: "destination count",
            ..
        })
    ));
    assert!(matches!(
        SpendPlan::new(&at0, &entry(1_000_000), vec![dst(0x6b, 1); 257], MFEE, 0),
        Err(Error::Range {
            what: "destination count",
            ..
        })
    ));
    refusals += 2;
    // 3. a zero amount, at the index it sits at after sorting
    assert_eq!(
        SpendPlan::new(&at0, &entry(1_000_000), vec![dst(0x6b, 1), dst(0x6c, 0)], 2 * MFEE, 0).err(),
        Some(Error::ZeroAmount { index: 1 })
    );
    refusals += 1;
    // 4. a destination that is the source's own tag
    let mut to_self = dst(0, 1);
    to_self.tag = a.tag;
    assert_eq!(
        SpendPlan::new(&at0, &entry(1_000_000), vec![to_self], MFEE, 0).err(),
        Some(Error::DestinationIsSource { index: 0 })
    );
    refusals += 1;
    // 5. the amount tally overflowing
    assert_eq!(
        SpendPlan::new(&at0, &entry(u64::MAX), vec![dst(0x6b, u64::MAX), dst(0x6c, 1)], 2 * MFEE, 0).err(),
        Some(Error::Overflow { what: "send total" })
    );
    refusals += 1;
    // 6. the fee floor is one MFEE per destination
    assert_eq!(
        SpendPlan::new(&at0, &entry(1_000_000), vec![dst(0x6b, 1), dst(0x6c, 1)], 2 * MFEE - 1, 0).err(),
        Some(Error::FeeBelowMinimum {
            fee: 2 * MFEE - 1,
            min: 2 * MFEE
        })
    );
    refusals += 1;
    assert!(SpendPlan::new(&at0, &entry(1_000_000), vec![dst(0x6b, 1), dst(0x6c, 1)], 2 * MFEE, 0).is_ok());
    // 7. the balance
    assert_eq!(
        SpendPlan::new(&at0, &entry(MFEE + 99), vec![dst(0x6b, 100)], MFEE, 0).err(),
        Some(Error::InsufficientBalance {
            balance: MFEE + 99,
            needed: MFEE + 100
        })
    );
    refusals += 1;
    let exact = SpendPlan::new(&at0, &entry(MFEE + 100), vec![dst(0x6b, 100)], MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(exact.change_total(), 0, "send plus fee equal to the balance leaves no change");
    // 8. send plus fee overflowing
    assert_eq!(
        SpendPlan::new(&at0, &entry(u64::MAX), vec![dst(0x6b, u64::MAX)], MFEE, 0).err(),
        Some(Error::Overflow {
            what: "send plus fee"
        })
    );
    refusals += 1;

    // The totals and fields of an accepted plan.
    let plan = SpendPlan::new(&at0, &entry(10_000), vec![dst(0x6c, 7), dst(0x6b, 5)], 2 * MFEE, 77).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.position(), WotsIndex::ZERO);
    assert_eq!(plan.source(), &at0.source);
    assert_eq!(plan.change(), &at0.change);
    assert_eq!(plan.send_total(), 12);
    assert_eq!(plan.fee_total(), 2 * MFEE);
    assert_eq!(plan.change_total(), 10_000 - 12 - 2 * MFEE);
    assert_eq!(plan.blk_to_live(), 77);
    assert_eq!(plan.dsts()[0].tag, [0x6b; ADDR_TAG_LEN], "sorted by the MDST image");
    assert_eq!(plan.dsts()[1].tag, [0x6c; ADDR_TAG_LEN]);
    // The digest is TX_HASH_MESSAGE over the image these fields describe.
    let mut tx = Transaction::new(plan.dsts().to_vec()).unwrap_or_else(|e| panic!("{e}"));
    tx.src_addr = *plan.source();
    tx.chg_addr = *plan.change();
    tx.send_total = plan.send_total();
    tx.change_total = plan.change_total();
    tx.fee_total = plan.fee_total();
    tx.blk_to_live = plan.blk_to_live();
    assert_eq!(plan.digest(), tx.message_digest());

    println!("  spend plan refusals: {refusals} shapes refused by name, 2 boundaries accepted, totals laid out");
}

/// **The planner calls a chain at the change address a divergence, and that
/// is `send`'s rule.**
///
/// `resign`'s landed-spend refusal lives in `Wallet::resign_pending` and
/// deliberately not here. `SpendPlan::new`'s rules are the node's and nothing
/// else -- the same argument that put the duplicate-destination refusal in
/// the parser, because the node accepts duplicates -- and a refusal about
/// this wallet's reservation state is not one of the node's. The planner does
/// not know what a reservation is: for `send`, whose source is the key the
/// store signs with NEXT, a chain standing at the change address is an
/// account some other signer has moved, which is I4's divergence and the
/// three-cause page is the right one.
///
/// This is the test that goes red if the refusal is ever moved down here,
/// where `send` would inherit it. Its CLI-level half is
/// `send_over_a_chain_one_key_on_is_still_a_divergence_and_never_the_landed_page`.
#[test]
fn the_planner_calls_the_change_address_a_divergence_and_not_a_landed_spend() {
    let (_dir, _ks, _a, at0) = anchored_store("spend-plan-change");
    let at_change = LedgerEntry {
        address: at0.change,
        balance: 1_000_000,
    };
    assert_eq!(
        SpendPlan::new(&at0, &at_change, vec![dst(0x6b, 1)], MFEE, 0).err(),
        Some(Error::ChainAddressMismatch { position: 0 }),
        "the planner answered a chain at the change address with something other than the \
         spend-time guard"
    );
    let page = format!("{}", Error::ChainAddressMismatch { position: 0 });
    assert!(page.contains("three causes"), "the guard's page is no longer the three-cause page: {page}");
    let landed = format!(
        "{}",
        Error::ReservationLanded {
            spent_index: 0,
            settled_index: 1
        }
    );
    assert!(landed.contains("`settle`"), "the landed refusal does not name the verb: {landed}");
    assert_ne!(page, landed, "the two refusals render the same text");
    println!("  planner: a chain at the change address is ChainAddressMismatch with the three causes; the landed-spend refusal is a different error and is not here");
}

/// The plan's destination order is the order the reference accepts:
/// `D12-sorted`'s four destinations fed in reverse come out in the image's
/// order, and in the default build the C's `mdst_val` accepts the plan's
/// order and rejects the reversed one with `EMCM_TXMDSTSORT`.
#[test]
fn spend_plan_orders_destinations_as_the_reference_accepts() {
    let (_dir, _ks, _a, at0) = anchored_store("spend-plan-sort");
    let sorted = Transaction::from_wire(&wire_images::fixture_bytes("D12-sorted_tx.bin")).unwrap_or_else(|e| panic!("{e:?}"));
    let unsorted = Transaction::from_wire(&wire_images::fixture_bytes("D12-unsorted_tx.bin")).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sorted.dsts().len(), 4);
    assert_ne!(sorted.dsts(), unsorted.dsts(), "the two images differ in order");
    let mut reversed = sorted.dsts().to_vec();
    reversed.reverse();
    let count = reversed.len() as u64;
    let entry = LedgerEntry {
        address: at0.source,
        balance: u64::MAX / 2,
    };
    let plan = SpendPlan::new(&at0, &entry, reversed, MFEE * count, 0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.dsts(), sorted.dsts(), "the plan's order is D12-sorted's");
    println!("  spend plan order: 4 destinations reversed come out as D12-sorted; validators: {VALIDATORS}");
}

// ---------------------------------------------------------------------------
// attach and verify_wots
// ---------------------------------------------------------------------------

/// The identity block's signing key, and a start address whose last twelve
/// bytes are zeroed so nothing about the mandated tail is fed in.
struct Identity {
    secret: [u8; SEED_LEN],
    pub_seed: [u8; SEED_LEN],
    terminal_adrs: [u8; 32],
    start_adrs: [u8; 32],
    pk: Box<[u8; PK_LEN]>,
}

fn identity() -> Identity {
    let file = wire_images::fixture_json("group_d_tx.json");
    let id = &file["identity"];
    let terminal: [u8; 32] = arr(&hexf(id, "adrs"), "identity.adrs");
    let mut start = terminal;
    for b in &mut start[20..] {
        *b = 0;
    }
    Identity {
        secret: arr(&hexf(id, "secret"), "identity.secret"),
        pub_seed: arr(&hexf(id, "pub_seed"), "identity.pub_seed"),
        terminal_adrs: terminal,
        start_adrs: start,
        pk: Box::new(arr(&wire_images::fixture_bytes("D_identity_pk.bin"), "D_identity_pk.bin")),
    }
}

/// `SpendPlan` + the raw native signer + `attach` reproduce the four
/// `Ds6-N*` images -- the corpus's "THE ACCEPTANCE TEST" entries, signed by
/// the reference end to end -- byte for byte through the nonce. The tail on
/// the wire comes from `pk_from_sig` alone: the signer starts from an
/// address whose last twelve bytes are zero.
#[test]
fn attach_reproduces_the_reference_acceptance_images() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let idn = identity();
    let mut reproduced = 0usize;
    for id in ["Ds6-N1", "Ds6-N2", "Ds6-N3", "Ds6-N256"] {
        let v = file["vectors"]
            .as_array()
            .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some(id)))
            .unwrap_or_else(|| panic!("no {id}"));
        let image = wire_images::fixture_bytes(v["wire_file"].as_str().unwrap_or(""));
        let tx = Transaction::from_wire(&image).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let tag: [u8; ADDR_TAG_LEN] = arr(addr::tag_of(&tx.src_addr), "tag");
        let addresses = SpendAddresses::unverified(tag, WotsIndex::ZERO, tx.src_addr, tx.chg_addr);
        let balance = tx
            .send_total
            .checked_add(tx.change_total)
            .and_then(|s| s.checked_add(tx.fee_total))
            .unwrap_or_else(|| panic!("{id}: totals overflow"));
        let entry = LedgerEntry {
            address: tx.src_addr,
            balance,
        };
        let plan = SpendPlan::new(&addresses, &entry, tx.dsts().to_vec(), tx.fee_total, tx.blk_to_live)
            .unwrap_or_else(|e| panic!("{id}: plan: {e}"));
        assert_eq!(plan.digest(), tx.message_digest(), "{id}: the plan lays out a different signed prefix");
        assert_eq!(plan.change_total(), tx.change_total, "{id}: change");

        let mut words = Adrs::from_le_image(&idn.start_adrs).0;
        let signature = backend::native::wots_sign(&plan.digest(), &idn.secret, &idn.pub_seed, &mut words);
        let sig = SpendSignature {
            spent_index: WotsIndex::ZERO,
            signature,
            pub_seed: idn.pub_seed,
            adrs: Adrs::from_le_image(&idn.start_adrs),
            public_key: idn.pk.clone(),
        };
        let signed = SignedTransaction::attach(&plan, &sig).unwrap_or_else(|e| panic!("{id}: attach: {e}"));
        let wire = signed.wire();
        let through_nonce = tx.tlr_off() + 8;
        assert_eq!(wire.len(), image.len(), "{id}: length");
        assert_eq!(&wire[..through_nonce], &image[..through_nonce], "{id}: not byte-identical through the nonce");
        assert_eq!(&wire[through_nonce..], &signed.id().0[..], "{id}: the trailer id is not the id digest");
        let back = Transaction::from_wire(&wire).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(back.wots.adrs, idn.terminal_adrs, "{id}: the wire adrs is not the identity's terminal state");
        assert_ne!(idn.start_adrs, idn.terminal_adrs, "{id}: the start address was not zeroed");
        verify_wots(&back).unwrap_or_else(|e| panic!("{id}: verify_wots on the reproduced image: {e}"));

        reproduced += 1;
    }
    assert_eq!(reproduced, 4);
    println!(
        "  attach byte-identity: {reproduced} Ds6 images reproduced through SpendPlan and attach, tail from \
         pk_from_sig alone; validators: {VALIDATORS}"
    );
}

/// `verify_wots` against every image the reference judged with
/// `tx_val__wots`: the accepted ones pass and the two refusal classes map to
/// the two comparisons -- `EMCM_TXADRS` (Ds7, the tail one byte off) to the
/// address scheme, `EMCM_TXWOTS` (Ds8-Ds11) to the source hash. The count is
/// stated: 24 verdicts in the corpus.
#[test]
fn verify_wots_reproduces_every_recorded_verdict() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let mut checked = 0usize;
    let mut accepted = 0usize;
    for v in file["vectors"].as_array().expect("vectors") {
        let Some(rc) = v.get("tx_val__wots_rc_name").and_then(|x| x.as_str()) else { continue };
        let id = v["id"].as_str().unwrap_or("?");
        let image_key = if v.get("wire_file").is_some() { "wire_file" } else { "validated_wire_file" };
        let image = wire_images::fixture_bytes(v[image_key].as_str().unwrap_or_else(|| panic!("{id}: no image")));
        let tx = Transaction::from_wire(&image).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let got = verify_wots(&tx);
        if rc == "VEOK" {
            assert_eq!(got, Ok(()), "{id}: the reference accepted, this crate refused");
            accepted += 1;
        } else {
            let errno = v["tx_val__wots_errno_name"].as_str().unwrap_or("?");
            let want = match errno {
                "EMCM_TXADRS" => "address scheme",
                "EMCM_TXWOTS" => "source address hash",
                other => panic!("{id}: a tx_val__wots errno this test does not map: {other}"),
            };
            assert_eq!(
                got,
                Err(Error::SignatureDoesNotRecover { what: want }),
                "{id}: the reference said {errno}"
            );
        }
        checked += 1;
    }
    // 24 until the bulk corpus appended the 22-count Ds12 sweep, every one
    // carrying a verdict.
    assert_eq!(checked, 46, "expected 46 recorded tx_val__wots verdicts; walked {checked}");
    println!("  verify_wots: {checked} recorded verdicts reproduced ({accepted} accepted, {} refused by named comparison)", checked - accepted);
}

/// A real signature from the anchor account at position 0 over `plan`.
fn sign_plan(name: &str, plan_of: impl Fn(&SpendAddresses) -> SpendPlan) -> (ScratchDir, Keystore, Anchor, SpendAddresses, SpendPlan, SpendSignature) {
    let (dir, mut ks, a, at0) = anchored_store(name);
    let plan = plan_of(&at0);
    let r = ks.persist_advance(&a.tag, &plan.digest(), plan.figures()).unwrap_or_else(|e| panic!("{e}"));
    let sig = ks
        .sign_spend(&plan.digest(), r, KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("sign_spend: {e}"));
    (dir, ks, a, at0, plan, sig)
}

fn simple_plan(at: &SpendAddresses, fee: u64) -> SpendPlan {
    let entry = LedgerEntry {
        address: at.source,
        balance: 10_000,
    };
    SpendPlan::new(at, &entry, vec![dst(0x6b, 1_000)], fee, 0).unwrap_or_else(|e| panic!("{e}"))
}

/// **A plan records the balance it was built against, and the three totals
/// sum to it**. `SpendPlan::balance()` is the
/// observation stored at construction -- the number `tx_val` will demand
/// `send + change + fee` equal exactly -- and the sum over the three public
/// totals is the independently written second value, so a
/// `balance()` that summed the totals could not fail this and a stored value
/// that drifted from them could. `figures()` composes it with the
/// block-to-live, which is what the keystore records for the reservation.
#[test]
fn a_plan_records_the_balance_it_was_built_against_and_the_sum_agrees() {
    let (_dir, _ks, _a, at0) = anchored_store("spend-plan-balance");
    let entry = LedgerEntry {
        address: at0.source,
        balance: 7_777,
    };
    let plan = SpendPlan::new(&at0, &entry, vec![dst(0x6b, 1_000)], MFEE, 77).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.balance(), 7_777, "the plan does not carry the balance it was built against");
    assert_eq!(
        plan.balance(),
        plan.send_total() + plan.change_total() + plan.fee_total(),
        "send + change + fee does not sum to the balance the plan records -- tx_val demands the \
         equality (tx.c:776-792), so one of the four is wrong"
    );
    assert_eq!(plan.change_total(), 7_777 - 1_000 - MFEE, "the change is not the remainder");
    assert_eq!(
        plan.figures(),
        Figures {
            reserved_balance: 7_777,
            blk_to_live: 77,
        },
        "the figures the record will carry are not the plan's balance and block-to-live"
    );
    println!("  plan figures: balance 7777 stored and equal to send + change + fee; block-to-live 77");
}

/// `attach` refuses every component that can disagree with the plan or the
/// key: the position, the public key claimed, the signature bytes, the
/// public seed, and a source address the key does not own. Prints the count
/// the census row for the Reader permission requires.
#[test]
fn attach_refuses_every_mismatched_component() {
    let (_dir, _ks, a, at0, plan, sig) = sign_plan("attach-refusals", |at| simple_plan(at, MFEE));
    let mut refusals = 0usize;

    // The control: the genuine pair attaches.
    let ok = SignedTransaction::attach(&plan, &sig).unwrap_or_else(|e| panic!("the genuine pair was refused: {e}"));
    assert_eq!(ok.lengths(), (116 + 44, 2408));

    // 1. position
    let at1 = SpendAddresses::unverified(a.tag, WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")), at0.source, at0.change);
    let plan1 = simple_plan(&at1, MFEE);
    assert_eq!(
        SignedTransaction::attach(&plan1, &sig).err(),
        Some(Error::PositionMismatch { planned: 1, signed: 0 })
    );
    refusals += 1;
    // 2. the public key claimed
    let claimed = SpendSignature {
        spent_index: sig.spent_index,
        signature: sig.signature.clone(),
        pub_seed: sig.pub_seed,
        adrs: sig.adrs,
        public_key: Box::new([0x11; PK_LEN]),
    };
    assert_eq!(
        SignedTransaction::attach(&plan, &claimed).err(),
        Some(Error::SignatureDoesNotRecover { what: "public key" })
    );
    refusals += 1;
    // 3. one signature byte
    let mut flipped = sig.signature.clone();
    flipped[100] ^= 0x01;
    let bad_sig = SpendSignature {
        spent_index: sig.spent_index,
        signature: flipped,
        pub_seed: sig.pub_seed,
        adrs: sig.adrs,
        public_key: sig.public_key.clone(),
    };
    assert_eq!(
        SignedTransaction::attach(&plan, &bad_sig).err(),
        Some(Error::SignatureDoesNotRecover { what: "public key" })
    );
    refusals += 1;
    // 4. the public seed
    let mut seed = sig.pub_seed;
    seed[0] ^= 0x01;
    let bad_seed = SpendSignature {
        spent_index: sig.spent_index,
        signature: sig.signature.clone(),
        pub_seed: seed,
        adrs: sig.adrs,
        public_key: sig.public_key.clone(),
    };
    assert_eq!(
        SignedTransaction::attach(&plan, &bad_seed).err(),
        Some(Error::SignatureDoesNotRecover { what: "public key" })
    );
    refusals += 1;
    // 5. a source address the key does not own: the recovered key is the
    //    one claimed, and it does not hash to the source's hash half.
    let mut foreign = at0.source;
    foreign[ADDR_TAG_LEN] ^= 0x01;
    let (_dir2, _ks2, _a2, _at2, plan5, sig5) = sign_plan("attach-foreign-source", move |_| {
        let at = SpendAddresses::unverified(a.tag, WotsIndex::ZERO, foreign, at0.change);
        let entry = LedgerEntry {
            address: foreign,
            balance: 10_000,
        };
        SpendPlan::new(&at, &entry, vec![dst(0x6b, 1_000)], MFEE, 0).unwrap_or_else(|e| panic!("{e}"))
    });
    assert_eq!(
        SignedTransaction::attach(&plan5, &sig5).err(),
        Some(Error::SignatureDoesNotRecover {
            what: "source address hash"
        })
    );
    refusals += 1;

    println!("  attach refusals: {refusals} mismatched components refused by name, 1 genuine pair attached");
}

// ---------------------------------------------------------------------------
// The flow, over a recording transport
// ---------------------------------------------------------------------------

/// A transport that answers `/call` with a fixed ledger entry and
/// `/construction/submit` the way the middleware does -- by re-deriving the
/// id from the bytes it received -- while recording every request.
struct Recording {
    entry: LedgerEntry,
    log: RefCell<Vec<(String, Vec<u8>)>>,
    /// Answer submit with this id instead of the one the bytes have.
    lie: Option<[u8; HASHLEN]>,
}

impl Transport for Recording {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.log.borrow_mut().push((path.to_owned(), body.to_vec()));
        match path {
            "/call" => Ok(format!(
                r#"{{"result":{{"address":"0x{}","amount":{}}},"idempotent":true}}"#,
                hex::encode(&self.entry.address),
                self.entry.balance
            )
            .into_bytes()),
            "/construction/submit" => {
                let req: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::MeshResponse { what: "test: request" })?;
                let bytes = hex::decode(req["signed_transaction"].as_str().unwrap_or(""), "test")?;
                let tx = Transaction::from_wire(&bytes)?;
                let id = self.lie.unwrap_or_else(|| tx.id_digest());
                Ok(format!(r#"{{"transaction_identifier":{{"hash":"{}"}},"metadata":{{}}}}"#, hex::encode(&id)).into_bytes())
            }
            _ => Err(Error::MeshResponse {
                what: "test: an endpoint the flow must not call",
            }),
        }
    }
}

/// The whole sequence the module doc gives, executed: addresses, resolve,
/// plan, reserve, check, sign, attach, submit -- with the submitted bytes
/// equal to `wire()`, the reserved digest equal to the signed digest, and
/// the receipt's position equal to the plan's. Then the three refusals the
/// flow's ordering exists for.
#[test]
fn spend_flow_end_to_end_over_a_recording_transport() {
    let (_dir, mut ks, a, at0) = anchored_store("spend-flow");
    let client = MeshClient::new(Recording {
        entry: LedgerEntry {
            address: at0.source,
            balance: 5_000_000,
        },
        log: RefCell::new(Vec::new()),
        lie: None,
    });

    let entry = client.resolve_tag(&a.tag).unwrap_or_else(|e| panic!("resolve_tag: {e}"));
    assert_eq!(entry.address, at0.source);
    let plan = SpendPlan::new(&at0, &entry, vec![dst(0x6b, 1_000_000)], MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let receipt = ks.persist_advance(&a.tag, &plan.digest(), plan.figures()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        receipt.index(),
        plan.position().advanced().unwrap_or_else(|e| panic!("{e}")),
        "the receipt attests the position after the plan's"
    );
    ks.check_spend(&plan.digest(), &receipt, &KeyAccess::Master(&a.master)).unwrap_or_else(|e| panic!("check_spend: {e}"));
    let sig = ks
        .sign_spend(&plan.digest(), receipt, KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("sign_spend: {e}"));
    assert_eq!(sig.spent_index, plan.position());
    let signed = SignedTransaction::attach(&plan, &sig).unwrap_or_else(|e| panic!("attach: {e}"));
    let id = client.submit(&signed).unwrap_or_else(|e| panic!("submit: {e}"));
    assert_eq!(id, signed.id());

    // What went over the transport.
    let log = client.transport().log.borrow();
    assert_eq!(log.len(), 2, "two requests: resolve and submit");
    assert_eq!(log[0].0, "/call");
    assert_eq!(log[0].1, codec::request_tag_resolve(&a.tag));
    assert_eq!(log[1].0, "/construction/submit");
    assert_eq!(log[1].1, codec::request_submit(&signed).unwrap_or_else(|e| panic!("{e}")));
    let req: serde_json::Value = serde_json::from_slice(&log[1].1).unwrap_or_else(|e| panic!("{e}"));
    let sent = hex::decode(req["signed_transaction"].as_str().unwrap_or(""), "sent").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(sent, signed.wire(), "the bytes submitted are wire()");
    let tx = Transaction::from_wire(&sent).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(tx.src_addr, at0.source);
    assert_eq!(tx.chg_addr, at0.change);
    assert_eq!(tx.send_total, 1_000_000);
    assert_eq!(tx.fee_total, MFEE);
    assert_eq!(tx.change_total, 5_000_000 - 1_000_000 - MFEE);
    assert_eq!(tx.trailer.as_ref().map(|t| t.nonce), Some(0));
    verify_wots(&tx).unwrap_or_else(|e| panic!("{e}"));
    drop(log);

    // The account cannot spend again until the chain settles it.
    assert_eq!(
        ks.spend_addresses(&a.tag, &KeyAccess::Master(&a.master)).err(),
        Some(Error::PendingUnresolved { spent_index: 0 })
    );

    // A plan rebuilt after the reservation signs nothing (I3: the record
    // names what was signed).
    let (_dir2, mut ks2, a2, at2) = anchored_store("spend-flow-rebuilt");
    let first = simple_plan(&at2, MFEE);
    let rebuilt = simple_plan(&at2, MFEE + 100);
    let r = ks2.persist_advance(&a2.tag, &first.digest(), first.figures()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks2.sign_spend(&rebuilt.digest(), r, KeyAccess::Master(&a2.master)).err(),
        Some(Error::DigestMismatch)
    );

    // A middleware that acknowledges some other id is refused.
    let (_dir3, mut ks3, a3, at3) = anchored_store("spend-flow-lie");
    let liar = MeshClient::new(Recording {
        entry: LedgerEntry {
            address: at3.source,
            balance: 5_000_000,
        },
        log: RefCell::new(Vec::new()),
        lie: Some([0xEE; HASHLEN]),
    });
    let plan3 = simple_plan(&at3, MFEE);
    let r3 = ks3.persist_advance(&a3.tag, &plan3.digest(), plan3.figures()).unwrap_or_else(|e| panic!("{e}"));
    let sig3 = ks3
        .sign_spend(&plan3.digest(), r3, KeyAccess::Master(&a3.master))
        .unwrap_or_else(|e| panic!("{e}"));
    let signed3 = SignedTransaction::attach(&plan3, &sig3).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(liar.submit(&signed3).err(), Some(Error::SubmitIdMismatch));

    println!(
        "  spend flow: 2 requests recorded, submitted bytes equal wire(), 3 refusals (pending, rebuilt digest, \
         foreign id); validators: {VALIDATORS}"
    );
}

// ---------------------------------------------------------------------------
// Key access chosen per account
// ---------------------------------------------------------------------------

/// A store holding a master seed AND an imported account: the derived
/// account is `F-derive-account-1` under `DERIVED_MASTER` and the imported
/// one is `F-address-widths` by its root, both at position 0, from two
/// master seeds so no key stream is shared. Nothing on the command line can
/// build this store -- there is no import verb -- which is why the case is a
/// library test driven through `cli::run`.
fn store_holding_both_kinds(name: &str) -> (ScratchDir, Keystore) {
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let _ = ks.adopt_master(&Secret::new(DERIVED_MASTER)).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

/// The chain as both accounts stand at position 0, each funded: the
/// imported account at the address its stored first key gives, the derived
/// one at the address the master derives.
fn chain_holding_both(ks: &Keystore) -> Chain {
    let imported = ks
        .address_at(&IMPORTED_TAG, WotsIndex::ZERO, &KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("the imported account's address at position 0: {e}"));
    let derived = recon::derived_address_at(&Secret::new(DERIVED_MASTER), DERIVED_POSITION, WotsIndex::ZERO);
    Chain::new(&[
        (IMPORTED_TAG, ChainState::At(imported, 5_000_000)),
        (DERIVED_TAG, ChainState::At(derived, 5_000_000)),
    ])
}

fn spend_from(tag: [u8; ADDR_TAG_LEN]) -> Spend {
    Spend {
        tag,
        dsts: vec![SpendTo { to: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: Some(1_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
    }
}

/// The id the accepting chain must echo for `spend_from(tag)`: a dry run
/// through the wallet API on a throwaway store under the access the KIND
/// needs, read from `SignedTransaction::id()` -- the crate's own API, never
/// computed by the fake.
fn id_for_spend_from(name: &str, tag: [u8; ADDR_TAG_LEN], access: KeyAccess<'_>) -> [u8; 32] {
    let (_dir, ks) = store_holding_both_kinds(name);
    let chain = chain_holding_both(&ks);
    let master = Secret::new(DERIVED_MASTER);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&master)).unwrap_or_else(|e| panic!("{e}"));
    let s = spend_from(tag);
    let plan = w
        .plan(
            &tag,
            &access,
            vec![Destination {
                tag: s.dsts[0].to,
                reference: [0; 16],
                amount: s.dsts[0].amount.unwrap_or(0),
            }],
            s.fee_total,
            s.blk_to_live,
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
    w.reserve_and_sign(&plan, access).unwrap_or_else(|e| panic!("sign: {e}")).id().0
}

/// The position and whether a reservation is open, for one tag, read back
/// from disk.
fn state_of(dir: &ScratchDir, tag: &[u8; ADDR_TAG_LEN]) -> (u32, bool) {
    let ks = reopen("both kinds", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks
        .view(tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the store no longer holds the account"));
    (v.wots_index.get(), v.pending.is_some())
}

/// **An imported account in a store that also holds a master seed is signed
/// for by its stored root**.
///
/// Choosing key access per STORE -- does the store hold a master seed --
/// routes this account down the master path, where `key_at` refuses it with a
/// key-access mismatch. The choice is per account, the one `Wallet::open`,
/// `status` and `reconcile` make. `address` computes the account's address and
/// `send` lays out, reserves, signs and submits from it; neither page
/// carries the mismatch, the chain sees one body, and the store afterwards
/// is what a send leaves -- position 1 with the reservation open -- while
/// the derived account beside it is untouched. Red with the store-wide
/// choice restored (a fault row is the reversion).
#[test]
fn an_imported_account_in_a_master_holding_store_is_signed_for_by_its_stored_root() {
    let (dir, ks) = store_holding_both_kinds("both-kinds-imported");
    let r = cli::run(ks, MeshClient::new(Chain::new(&[])), &Command::Address { tag: Some(IMPORTED_TAG), account: None });
    assert_eq!(r.code, Code::Ok, "`address` for the imported account was refused:\n{}", r.text);
    assert!(
        !r.text.contains("key access does not match"),
        "the key-access mismatch is still on the page:\n{}",
        r.text
    );

    let ks = reopen("both kinds imported", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id_for_spend_from("both-kinds-imported-id", IMPORTED_TAG, KeyAccess::StoredRoot));
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend_from(IMPORTED_TAG)));
    assert_eq!(
        r.code,
        Code::Ok,
        "`send` from the imported account was refused -- the store-wide choice routed it down the \
         master path:\n{}",
        r.text
    );
    assert!(
        r.text.contains("submitted: the node accepted the SOCKET WRITE"),
        "the page does not carry send's submitted block:\n{}",
        r.text
    );
    assert_eq!(log.borrow().len(), 1, "the chain saw {} submit body(ies), not one", log.borrow().len());
    assert_eq!(state_of(&dir, &IMPORTED_TAG), (1, true), "the imported account is not at position 1 with its reservation open");
    assert_eq!(state_of(&dir, &DERIVED_TAG), (0, false), "the derived account beside it moved");
    println!("  both kinds: the imported account signed from its stored root beside a master; one body on the socket");
}

/// **A derived account in the same store still signs from the master**: the
/// per-account choice changed nothing on its route. Green before and after
/// part 1 (a fault row runs it with the store-wide choice restored), so it
/// is the control the imported case is read against.
#[test]
fn a_derived_account_in_a_master_holding_store_still_signs_from_the_master() {
    let (dir, ks) = store_holding_both_kinds("both-kinds-derived");
    let r = cli::run(ks, MeshClient::new(Chain::new(&[])), &Command::Address { tag: Some(DERIVED_TAG), account: None });
    assert_eq!(r.code, Code::Ok, "`address` for the derived account was refused:\n{}", r.text);

    let ks = reopen("both kinds derived", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = chain_holding_both(&ks);
    let master = Secret::new(DERIVED_MASTER);
    chain.accepts_submit(id_for_spend_from("both-kinds-derived-id", DERIVED_TAG, KeyAccess::Master(&master)));
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend_from(DERIVED_TAG)));
    assert_eq!(r.code, Code::Ok, "`send` from the derived account was refused:\n{}", r.text);
    assert!(
        r.text.contains("submitted: the node accepted the SOCKET WRITE"),
        "the page does not carry send's submitted block:\n{}",
        r.text
    );
    assert_eq!(log.borrow().len(), 1, "the chain saw {} submit body(ies), not one", log.borrow().len());
    assert_eq!(state_of(&dir, &DERIVED_TAG), (1, true), "the derived account is not at position 1 with its reservation open");
    assert_eq!(state_of(&dir, &IMPORTED_TAG), (0, false), "the imported account beside it moved");
    println!("  both kinds: the derived account signed from the master beside an imported root; one body on the socket");
}

// ---------------------------------------------------------------------------
// The destination reference rule, transcribed from the node and pinned here
// ---------------------------------------------------------------------------

/// A reference field from ASCII text, NUL-padded to sixteen bytes, the way
/// `--ref` lays it out.
fn reference(text: &str) -> [u8; 16] {
    assert!(text.len() <= 16, "{text:?} is longer than the field");
    let mut out = [0u8; 16];
    out[..text.len()].copy_from_slice(text.as_bytes());
    out
}

/// `reference_is_valid` against the node's own stated examples -- the four
/// VALID and four INVALID strings the reference states at the pinned commit,
/// and its two byte arrays --
/// and the shapes those leave open: the all-NUL field, sixteen non-NUL
/// bytes ending in a group and in a dash, one group of each kind filling
/// the field, alternation of length fifteen, a lowercase letter, a high-bit
/// byte, a space, two dashes in a row, a dash alone, groups of different
/// kinds with no dash between them, and a letter after a NUL inside the
/// text. No node judged any of these bytes; the two the corpus records go
/// through the same function in the test below.
#[test]
fn the_reference_rule_is_the_references_own() {
    let rows: Vec<(&str, [u8; 16], bool)> = vec![
        // the C's VALID examples, verbatim
        ("AB-00-EF", reference("AB-00-EF"), true),
        ("123-CDE-789", reference("123-CDE-789"), true),
        ("ABC", reference("ABC"), true),
        ("123", reference("123"), true),
        // the C's INVALID examples, verbatim
        ("AB-CD-EF: two letter groups adjacent", reference("AB-CD-EF"), false),
        ("123-456-789: two digit groups adjacent", reference("123-456-789"), false),
        ("ABC-: a trailing dash", reference("ABC-"), false),
        ("-123: a leading dash", reference("-123"), false),
        // the C's two byte arrays
        ("A-1 then NULs", reference("A-1"), true),
        ("A-1 NUL B: a byte after the first NUL", *b"A-1\0B\0\0\0\0\0\0\0\0\0\0\0", false),
        // the field's own shapes
        ("all NUL", [0u8; 16], true),
        ("sixteen non-NUL bytes ending in a group", *b"AB-12-CD-34-EF-5", true),
        ("sixteen non-NUL bytes ending in a dash", *b"AB-12-CD-34-EFG-", false),
        ("sixteen uppercase letters, one group", *b"ABCDEFGHIJKLMNOP", true),
        ("sixteen digits, one group", *b"0123456789012345", true),
        ("alternation of length fifteen", reference("A-1-B-2-C-3-D-4"), true),
        ("a single letter", reference("A"), true),
        ("a single digit", reference("7"), true),
        ("a lowercase letter", reference("AB-00-ef"), false),
        ("lowercase alone", reference("abc"), false),
        ("a high-bit byte", *b"AB-00-\xff\0\0\0\0\0\0\0\0\0", false),
        ("a space", reference("AB 00"), false),
        ("two dashes in a row", reference("AB--00"), false),
        ("a dash alone", reference("-"), false),
        ("letters then digits with no dash", reference("AB00"), false),
        ("digits then letters with no dash", reference("00AB"), false),
        ("a letter after a NUL inside the text", *b"AB\0C\0\0\0\0\0\0\0\0\0\0\0\0", false),
    ];
    let (mut accepted, mut refused) = (0usize, 0usize);
    for (what, field, expected) in &rows {
        let got = reference_is_valid(field);
        assert_eq!(
            got,
            *expected,
            "{what}: the transcription says {got} and the node's rule says {expected} (bytes {})",
            hex::encode(field)
        );
        if got {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert_eq!(rows.len(), 27, "the table moved; restate its size deliberately");
    println!(
        "  reference rule: {} rows through the transcription, {accepted} accepted and {refused} refused, every verdict the node's own",
        rows.len()
    );
}

/// The corpus's two recorded verdicts on the field, through the same
/// function: `D16-badref`'s `ref0_bytes` is the reference the node accepted
/// on destination 0 and `ref1_bytes` the one it refused on destination 1
/// with `EMCM_XTXREF`, read from `fixtures/group_d_tx.json` by id -- the
/// corpus and the transcription held to each other in the test that goes
/// red if either moves. Then the same two fields through `SpendPlan::new`:
/// the accepted one is carried to the wire at bytes 20..36 of its
/// destination, the refused one is refused at its index, and the refusal
/// comes before the fee floor's, in the C's own arm order.
#[test]
fn the_corpus_reference_verdicts_are_the_transcriptions() {
    let v = fixture_vector("group_d_tx.json", "D16-badref");
    assert_eq!(
        v["mdst_val_errno_name"].as_str(),
        Some("EMCM_XTXREF"),
        "D16-badref's recorded refusal is not the reference field's"
    );
    let ref0: [u8; 16] = arr(&hexf(&v, "ref0_bytes"), "ref0_bytes");
    let ref1: [u8; 16] = arr(&hexf(&v, "ref1_bytes"), "ref1_bytes");
    assert!(
        reference_is_valid(&ref0),
        "ref0_bytes {} was accepted by the node and is refused by the transcription",
        hex::encode(&ref0)
    );
    assert!(
        !reference_is_valid(&ref1),
        "ref1_bytes {} was refused by the node (EMCM_XTXREF) and is accepted by the transcription",
        hex::encode(&ref1)
    );

    let (_dir, _ks, _a, at0) = anchored_store("spend-reference");
    let entry = LedgerEntry {
        address: at0.source,
        balance: 1_000_000,
    };
    let mut good = dst(0x6b, 5);
    good.reference = ref0;
    let plan = SpendPlan::new(&at0, &entry, vec![good.clone()], MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.dsts()[0].reference, ref0, "the plan did not carry the accepted reference");
    let image = Transaction::new(plan.dsts().to_vec()).unwrap_or_else(|e| panic!("{e}")).to_wire();
    assert_eq!(&image[116 + 20..116 + 36], &ref0[..], "the reference is not at bytes 20..36 of the destination at 116");
    let mut bad = dst(0x6c, 5);
    bad.reference = ref1;
    assert_eq!(
        SpendPlan::new(&at0, &entry, vec![good, bad], 2 * MFEE, 0).err(),
        Some(Error::InvalidReference { index: 1 }),
        "the refused reference was not refused at its index"
    );
    let mut bad_alone = dst(0x6b, 5);
    bad_alone.reference = ref1;
    assert_eq!(
        SpendPlan::new(&at0, &entry, vec![bad_alone], 0, 0).err(),
        Some(Error::InvalidReference { index: 0 }),
        "with the fee short too, the reference arm must refuse first, as the C's order has it"
    );
    println!(
        "  corpus reference verdicts: D16-badref ref0 {} accepted and ref1 {} refused by the transcription; the plan carries the accepted field at destination bytes 20..36 and refuses the other at its index, before the fee floor",
        hex::encode(&ref0),
        hex::encode(&ref1)
    );
}

// ---------------------------------------------------------------------------
// Several destinations, and the whole balance
// ---------------------------------------------------------------------------

/// The id the accepting chain must echo for an arbitrary spend from the
/// derived account: a dry run through the wallet API on a throwaway store,
/// read from `SignedTransaction::id()` rather than computed by the fake.
fn id_for_multi(name: &str, dsts: &[Destination], fee_total: u64) -> [u8; 32] {
    let (_dir, ks) = store_holding_both_kinds(name);
    let chain = chain_holding_both(&ks);
    let master = Secret::new(DERIVED_MASTER);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&master)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&DERIVED_TAG, &KeyAccess::Master(&master), dsts.to_vec(), fee_total, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    w.reserve_and_sign(&plan, KeyAccess::Master(&master))
        .unwrap_or_else(|e| panic!("sign: {e}"))
        .id()
        .0
}

/// Lower-case hex of some bytes, for building a `0x` tag on a command line.
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The wire image inside a recorded submit body: the request is JSON, and the
/// transaction travels as the hex of `signed_transaction`.
fn submitted_wire(body: &[u8]) -> Vec<u8> {
    let v: serde_json::Value =
        serde_json::from_slice(body).unwrap_or_else(|e| panic!("the submit body is not JSON: {e}"));
    let hex = v
        .get("signed_transaction")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the submit body carries no signed_transaction"));
    let mut out = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let pair = hex.get(i..i + 2).unwrap_or_else(|| panic!("odd-length hex"));
        out.push(u8::from_str_radix(pair, 16).unwrap_or_else(|e| panic!("{pair}: {e}")));
    }
    out
}

/// A destination tag whose bytes are distinct per index, so no two repeat and
/// the wire sort has something to order.
fn payee(n: u8) -> [u8; ADDR_TAG_LEN] {
    [n; ADDR_TAG_LEN]
}

/// `send <tag> <to> <amount> <to> <amount> <to> <amount>`, and what reaches
/// the wire.
///
/// **Three destinations, the floor at `500 x 3`, and the image carrying all
/// three in the node's own order.** The planner has always taken a list; this
/// is the command line handing it one. The body the chain receives is parsed
/// back and its destination array read out, so the assertion is over the
/// bytes that were submitted and not over the page.
#[test]
fn three_destinations_by_pairs_reach_the_wire_in_the_nodes_order() {
    let dsts = vec![
        Destination { tag: payee(0x9c), reference: [0; 16], amount: 3_000 },
        Destination { tag: payee(0x6b), reference: [0; 16], amount: 1_000 },
        Destination { tag: payee(0x7c), reference: [0; 16], amount: 2_000 },
    ];
    let fee = MFEE * 3;
    let (dir, ks) = store_holding_both_kinds("s12-three");
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id_for_multi("s12-three-id", &dsts, fee));
    let log = chain.submit_log();
    let s = Spend {
        tag: DERIVED_TAG,
        dsts: dsts.iter().map(|d| SpendTo { to: d.tag, reference: d.reference, amount: Some(d.amount) }).collect(),
        fee_total: fee,
        blk_to_live: 0,
    };
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(r.code, Code::Ok, "a three-destination send was refused:\n{}", r.text);

    // The page: the count, every destination, the floor, and the change.
    assert!(r.text.contains("sending 6000 nanoMCM to 3 destination(s)"), "{}", r.text);
    assert!(r.text.contains("fee    1500 total (the node's floor is 500 per destination, 1500 here)"), "{}", r.text);
    assert!(r.text.contains("change 4992500 to your own next key under this tag"), "{}", r.text);
    for amount in ["1000 nanoMCM", "2000 nanoMCM", "3000 nanoMCM"] {
        assert!(r.text.contains(amount), "the page does not list {amount}:\n{}", r.text);
    }

    // The bytes: three destinations, non-decreasing by their 44-byte image,
    // which is the order `EMCM_TXMDSTSORT` demands.
    let body = log.borrow().first().cloned().unwrap_or_else(|| panic!("the chain saw no submit body"));
    let tx = Transaction::from_wire(&submitted_wire(&body)).unwrap_or_else(|e| panic!("the submitted body does not parse: {e}"));
    assert_eq!(tx.dsts().len(), 3, "the wire carries {} destination(s), not three", tx.dsts().len());
    let images: Vec<_> = tx.dsts().iter().map(Destination::mdst_image).collect();
    assert!(images.windows(2).all(|w| w[0] <= w[1]), "the destination array is not in the node's order");
    assert_eq!(
        tx.dsts().iter().map(|d| d.amount).collect::<Vec<_>>(),
        vec![1_000, 2_000, 3_000],
        "the amounts did not follow their tags through the sort"
    );
    assert_eq!(tx.fee_total, 1_500, "the fee on the wire is not the floor for three");
    assert_eq!(state_of(&dir, &DERIVED_TAG), (1, true));
    println!("  three destinations: 6000 to 3 payees, fee 1500 = 500 x 3, change 4992500, wire sorted");
}

/// `send <tag> --destinations <path>`, through the real parser and a real
/// file: three payees, a reference on one line, a comment and a blank line.
#[test]
fn a_destinations_file_sends_every_line_and_carries_its_reference() {
    let (dir, ks) = store_holding_both_kinds("s12-file");
    let path = dir.path().join("payees.txt");
    std::fs::write(
        &path,
        format!(
            "# October\n0x{}  1000\n\n0x{}  2000  AB-00-EF\n0x{}  3000\n",
            hexs(&payee(0x6b)),
            hexs(&payee(0x7c)),
            hexs(&payee(0x9c))
        ),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let dsts = vec![
        Destination { tag: payee(0x6b), reference: [0; 16], amount: 1_000 },
        Destination { tag: payee(0x7c), reference: *b"AB-00-EF\0\0\0\0\0\0\0\0", amount: 2_000 },
        Destination { tag: payee(0x9c), reference: [0; 16], amount: 3_000 },
    ];
    let fee = MFEE * 3;
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id_for_multi("s12-file-id", &dsts, fee));
    let log = chain.submit_log();

    let argv: Vec<String> = [
        "--dir",
        "/unused",
        "--node",
        "n",
        "send",
        &format!("0x{}", hexs(&DERIVED_TAG)),
        "--destinations",
        &path.to_string_lossy(),
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let command = match mochimo_crypto::cli::args::parse(&argv) {
        Ok(mochimo_crypto::cli::args::ParsedArgv::Run(inv)) => inv.command,
        other => panic!("the file form did not parse: {other:?}"),
    };
    let r = cli::run(ks, MeshClient::new(chain), &command);
    assert_eq!(r.code, Code::Ok, "the file form was refused:\n{}", r.text);
    assert!(r.text.contains("sending 6000 nanoMCM to 3 destination(s)"), "{}", r.text);
    assert!(r.text.contains("ref AB-00-EF"), "the reference from the file is not on the page:\n{}", r.text);

    let body = log.borrow().first().cloned().unwrap_or_else(|| panic!("no submit body"));
    let tx = Transaction::from_wire(&submitted_wire(&body)).unwrap_or_else(|e| panic!("{e}"));
    let with_ref: Vec<_> = tx.dsts().iter().filter(|d| d.reference != [0u8; 16]).collect();
    assert_eq!(with_ref.len(), 1, "the file put {} reference(s) on the wire, not one", with_ref.len());
    assert_eq!(with_ref[0].reference, *b"AB-00-EF\0\0\0\0\0\0\0\0");
    assert_eq!(with_ref[0].amount, 2_000, "the reference did not stay with its own line's amount");
    assert_eq!(state_of(&dir, &DERIVED_TAG), (1, true));
    println!("  file: three lines, a comment and a blank skipped, one reference on its own line and on the wire");
}

/// What the command line refuses over the whole list, in the operator's own
/// words and before anything is asked of a store or a node.
#[test]
fn the_destination_list_refusals_are_usage_errors_before_any_prompt() {
    let src = format!("0x{}", hexs(&DERIVED_TAG));
    let a = format!("0x{}", hexs(&payee(0x6b)));
    let b = format!("0x{}", hexs(&payee(0x7c)));
    let refuse = |args: &[&str]| -> String {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        match mochimo_crypto::cli::args::parse(&argv) {
            Err(u) => u.0,
            Ok(other) => panic!("{args:?} parsed rather than being refused: {other:?}"),
        }
    };
    let base = ["--dir", "/unused", "--node", "n", "send"];

    let dup = refuse(&[&base[..], &[&src, &a, "1", &a, "2"]].concat());
    assert!(dup.contains("destinations 1 and 2 are the same tag"), "{dup}");

    let mut many: Vec<String> = base.iter().map(|s| (*s).to_string()).collect();
    many.push(src.clone());
    for i in 0..257u32 {
        many.push(format!("0x{:040x}", i + 1));
        many.push("1".to_string());
    }
    let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let over = refuse(&many_refs);
    assert!(over.contains("1 to 256 destinations and 257 were given"), "{over}");

    let two_refs = refuse(&[&base[..], &[&src, &a, "1", &b, "2", "--ref", "ABC"]].concat());
    assert!(two_refs.contains("--ref names one destination's reference and 2 were given"), "{two_refs}");

    let all_two = refuse(&[&base[..], &[&src, &a, "all", &b, "2"]].concat());
    assert!(all_two.contains("only available for a single destination"), "{all_two}");

    println!("  refusals: a repeated tag, a 257th destination, --ref with two, and `all` with two -- each a usage error");
}

/// **`resign` reproduces a three-destination spend byte for byte, and a
/// reorder reproduces it too.**
///
/// The reorder is the interesting half. `SpendPlan::new` sorts the
/// destinations by their 44-byte image before it lays anything out, because
/// that is the order `EMCM_TXMDSTSORT` demands, so a list retyped in another
/// order sorts to the same list and hashes to the same digest. Reproducing it
/// is correct: the bytes are identical, so it is the same transaction, and an
/// operator who retyped their payees in a different order is not stranded.
/// What IS refused is a list that differs in a value -- one amount changed,
/// and one payee swapped -- because those are different bytes.
#[test]
fn resign_reproduces_several_destinations_in_any_order_and_refuses_a_different_list() {
    let dsts = vec![
        Destination { tag: payee(0x6b), reference: [0; 16], amount: 1_000 },
        Destination { tag: payee(0x7c), reference: [0; 16], amount: 2_000 },
        Destination { tag: payee(0x9c), reference: [0; 16], amount: 3_000 },
    ];
    let fee = MFEE * 3;
    let as_spend = |order: &[usize], amounts: Option<&[u64]>| Spend {
        tag: DERIVED_TAG,
        dsts: order
            .iter()
            .enumerate()
            .map(|(k, &i)| SpendTo {
                to: dsts[i].tag,
                reference: dsts[i].reference,
                amount: Some(amounts.and_then(|a| a.get(k).copied()).unwrap_or(dsts[i].amount)),
            })
            .collect(),
        fee_total: fee,
        blk_to_live: 0,
    };

    let (dir, ks) = store_holding_both_kinds("s12-resign");
    let chain = chain_holding_both(&ks);
    let id = id_for_multi("s12-resign-id", &dsts, fee);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(as_spend(&[0, 1, 2], None)));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let sent = submitted_wire(&log.borrow().first().cloned().unwrap_or_else(|| panic!("no body")));

    // The same three, retyped back to front.
    let ks = reopen("s12 resign reorder", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(as_spend(&[2, 1, 0], None)));
    assert_eq!(r.code, Code::Ok, "a reordered retype was refused:\n{}", r.text);
    let again = submitted_wire(&log.borrow().first().cloned().unwrap_or_else(|| panic!("no body")));
    assert_eq!(again, sent, "the reordered retype did not reproduce the artifact byte for byte");
    assert!(r.text.contains("reproduced 3 destination(s)"), "{}", r.text);

    // One amount changed, and one payee swapped: different bytes, refused.
    for (what, s) in [
        ("an amount", as_spend(&[0, 1, 2], Some(&[1_001, 2_000, 3_000]))),
        ("a payee", {
            let mut s = as_spend(&[0, 1, 2], None);
            s.dsts[1].to = payee(0xab);
            s
        }),
    ] {
        let ks = reopen("s12 resign differ", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let chain = chain_holding_both(&ks);
        let log = chain.submit_log();
        let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
        assert_eq!(r.code, Code::Refused, "{what} changed and resign still shipped:\n{}", r.text);
        assert!(r.text.contains("this is not the spend that was reserved"), "{}", r.text);
        assert!(log.borrow().is_empty(), "{what} changed and a body reached the socket");
    }
    println!("  resign: three destinations reproduce in any order (the planner sorts); a changed amount or payee is refused, nothing shipped");
}

/// **`send <tag> <to> all`**: the amount is `balance − fee`, the change is
/// zero, and the page says what an emptied account costs.
#[test]
fn all_lays_out_the_balance_less_the_fee_and_says_the_account_is_emptied() {
    let (dir, ks) = store_holding_both_kinds("s12-all");
    let chain = chain_holding_both(&ks);
    // The chain funds the account at 5,000,000 and the fee is the floor, so
    // `all` is 4,999,500 and nothing returns to the next key.
    let dsts = vec![Destination { tag: payee(0x6b), reference: [0; 16], amount: 4_999_500 }];
    chain.accepts_submit(id_for_multi("s12-all-id", &dsts, MFEE));
    let log = chain.submit_log();
    let s = Spend {
        tag: DERIVED_TAG,
        dsts: vec![SpendTo { to: payee(0x6b), reference: [0; 16], amount: None }],
        fee_total: MFEE,
        blk_to_live: 0,
    };
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(r.code, Code::Ok, "`all` was refused:\n{}", r.text);
    assert!(r.text.contains("sending 4999500 nanoMCM to 1 destination(s)"), "{}", r.text);
    assert!(r.text.contains("change 0 to your own next key under this tag"), "{}", r.text);
    assert!(r.text.contains("THIS EMPTIES THE ACCOUNT"), "the page does not say the account is emptied:\n{}", r.text);
    assert!(r.text.contains("\"account not found\""), "the page does not name the Mesh's answer:\n{}", r.text);
    assert!(r.text.contains("`submit` writes it to the socket"), "the page does not name the route out:\n{}", r.text);
    // The scope of what an emptied account costs, which is the account and not
    // the store: other accounts keep working and paying this one from one of
    // them is the way back.
    assert!(
        r.text.contains("ON THIS ACCOUNT"),
        "the page does not scope the refusal to this account:\n{}",
        r.text
    );
    assert!(
        r.text.contains("Other \naccounts in this store keep working") || r.text.contains("Other accounts in this store keep working"),
        "the page does not say the rest of the store keeps working:\n{}",
        r.text
    );

    let body = log.borrow().first().cloned().unwrap_or_else(|| panic!("no body"));
    let tx = Transaction::from_wire(&submitted_wire(&body)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.dsts().len(), 1);
    assert_eq!(tx.dsts().first().map(|d| d.amount), Some(4_999_500), "`all` did not send balance - fee");
    assert_eq!(tx.change_total, 0, "`all` left a change");
    assert_eq!(tx.send_total + tx.change_total + tx.fee_total, 5_000_000, "the totals do not equal the balance");
    assert_eq!(state_of(&dir, &DERIVED_TAG), (1, true));
    println!("  all: 5,000,000 balance, fee 500 -> sends 4,999,500 with change 0; the page names the emptied-account window and `submit`");
}

/// **A spend laid out and not signed is shown in `send`'s own lines, with the
/// emptying paragraph when its change is zero, and with nothing only signing
/// makes.**
///
/// The spend is `all` from the derived account, and `send`'s page for it is
/// the reference. The planned page carries the same lines from the
/// destinations to the request to check them, byte for byte, and the same
/// emptying paragraph, and says nothing has been signed; it carries no
/// artifact, no submission and no id. Building and rendering it reserved
/// nothing -- the account's record and the store's generation are as they
/// were, nothing reached the socket, and the plan still signs afterwards.
/// The control is a spend with change, whose planned page has no emptying
/// paragraph; and a plan from the imported account names that account as
/// its source, since the source is read from the plan.
#[test]
fn a_planned_spend_shows_sends_lines_and_nothing_that_only_signing_makes() {
    use mochimo_crypto::cli::outcome::{Decided, Outcome};
    let master = Secret::new(DERIVED_MASTER);
    let all = vec![Destination { tag: payee(0x6b), reference: [0; 16], amount: 4_999_500 }];

    let (_sent_dir, ks) = store_holding_both_kinds("s12-planned-sent");
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id_for_multi("s12-planned-id", &all, MFEE));
    let sent = cli::run(
        ks,
        MeshClient::new(chain),
        &Command::Send(Spend {
            tag: DERIVED_TAG,
            dsts: vec![SpendTo { to: payee(0x6b), reference: [0; 16], amount: None }],
            fee_total: MFEE,
            blk_to_live: 0,
        }),
    );
    assert_eq!(sent.code, Code::Ok, "{}", sent.text);

    let (_dir, ks) = store_holding_both_kinds("s12-planned");
    let chain = chain_holding_both(&ks);
    let log = chain.submit_log();
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&master)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&DERIVED_TAG, &KeyAccess::Master(&master), all, MFEE, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let record = w.store().view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let page = cli::render::render(&Decided { standing: Vec::new(), outcome: Outcome::planned(&plan) });
    assert_eq!(page.code, Code::Ok, "{}", page.text);
    assert!(
        page.text.starts_with("NOT SIGNED: a spend of 4999500 nanoMCM to 1 destination(s)"),
        "{}",
        page.text
    );
    assert!(page.text.contains("Nothing has been signed yet."), "{}", page.text);

    // From the line after the first to the end of the request to check.
    let checked = |text: &str| -> String {
        let end_mark = "need not be the order you typed.\n";
        let start = text.find('\n').map_or(0, |i| i + 1);
        let end = text.find(end_mark).map_or(text.len(), |i| i + end_mark.len());
        text.get(start..end).unwrap_or("").to_string()
    };
    assert!(checked(&sent.text).contains("  from   "), "the reference lines were not found:\n{}", sent.text);
    assert_eq!(checked(&page.text), checked(&sent.text), "the planned page lists the spend differently from send's");
    let paragraph = |text: &str| -> String {
        let start = text.find("\nTHIS EMPTIES THE ACCOUNT").unwrap_or(text.len());
        let end_mark = "has to come from somewhere else.\n";
        let end = text.find(end_mark).map_or(text.len(), |i| i + end_mark.len());
        text.get(start..end).unwrap_or("").to_string()
    };
    assert!(!paragraph(&sent.text).is_empty(), "send's page carries no emptying paragraph:\n{}", sent.text);
    assert_eq!(paragraph(&page.text), paragraph(&sent.text), "the planned page warns in other words than send's");
    assert!(page.text.contains("Once it is signed, keep the artifact"), "{}", page.text);
    for only_after_signing in ["RETRY ARTIFACT", "submitted:", "submission FAILED", "Keep the artifact below", " id "] {
        assert!(
            !page.text.contains(only_after_signing),
            "the planned page carries `{only_after_signing}`, which only signing makes:\n{}",
            page.text
        );
    }

    assert_eq!(w.store().view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}")), record, "planning moved the record");
    assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
    assert!(log.borrow().is_empty(), "planning reached the socket");
    assert!(w.reserve_and_sign(&plan, KeyAccess::Master(&master)).is_ok(), "the plan no longer signs");

    let (_change_dir, ks) = store_holding_both_kinds("s12-planned-change");
    let chain = chain_holding_both(&ks);
    let w = Wallet::open(ks, MeshClient::new(chain), Some(&master)).unwrap_or_else(|e| panic!("{e}"));
    let some = vec![Destination { tag: payee(0x6b), reference: [0; 16], amount: 1_000 }];
    let plan = w
        .plan(&DERIVED_TAG, &KeyAccess::Master(&master), some, MFEE, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let page = cli::render::render(&Decided { standing: Vec::new(), outcome: Outcome::planned(&plan) });
    assert!(!page.text.contains("THIS EMPTIES"), "a spend with change is called emptying:\n{}", page.text);
    assert!(page.text.contains("Nothing has been signed yet."), "{}", page.text);

    // The source is the plan's own account. A plan from the imported account
    // names the imported account in its `from` line, in the same store and
    // through the same constructor, so there is no tag to pass beside it
    // that could name another.
    let some = vec![Destination { tag: payee(0x6b), reference: [0; 16], amount: 1_000 }];
    let imported = w
        .plan(&IMPORTED_TAG, &KeyAccess::StoredRoot, some, MFEE, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let outcome = Outcome::planned(&imported);
    assert!(matches!(outcome, Outcome::Planned { source, .. } if source == IMPORTED_TAG), "{outcome:?}");
    let page = cli::render::render(&Decided { standing: Vec::new(), outcome });
    for (tag, named) in [(IMPORTED_TAG, true), (DERIVED_TAG, false)] {
        let from = format!("  from   {}\n", addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}")));
        assert_eq!(page.text.contains(&from), named, "the imported plan's page names the wrong source:\n{}", page.text);
    }
}

/// `resign ... all` reproduces while the balance stands, because the amount
/// is a function of a balance that has not moved.
#[test]
fn resign_all_reproduces_while_the_balance_stands() {
    let (dir, ks) = store_holding_both_kinds("s12-all-resign");
    let chain = chain_holding_both(&ks);
    let dsts = vec![Destination { tag: payee(0x6b), reference: [0; 16], amount: 4_999_500 }];
    let id = id_for_multi("s12-all-resign-id", &dsts, MFEE);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let s = || Spend {
        tag: DERIVED_TAG,
        dsts: vec![SpendTo { to: payee(0x6b), reference: [0; 16], amount: None }],
        fee_total: MFEE,
        blk_to_live: 0,
    };
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s()));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let sent = submitted_wire(&log.borrow().first().cloned().unwrap_or_else(|| panic!("no body")));

    let ks = reopen("s12 all resign", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = chain_holding_both(&ks);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s()));
    assert_eq!(r.code, Code::Ok, "`resign ... all` was refused while the balance stood:\n{}", r.text);
    let again = submitted_wire(&log.borrow().first().cloned().unwrap_or_else(|| panic!("no body")));
    assert_eq!(again, sent, "`resign ... all` did not reproduce the artifact byte for byte");
    println!("  resign all: reproduced byte for byte while the balance stands");
}
