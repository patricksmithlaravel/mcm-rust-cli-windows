//! The scriptable chain: a [`Transport`] whose answers are set per tag.
//!
//! Moved here from `tests/recon.rs`, unchanged in behaviour, because
//! the CLI's cases are the same cases — *chain states*, not mocks of the
//! wallet — and two copies of a fake are two fakes that can disagree about
//! what the chain does. `tests/recon.rs` and `tests/cli.rs` both include this
//! file, so a case that passes in one is a case the other can reproduce.
//!
//! # Why the fake is a `Transport` and not a chain abstraction
//!
//! `MeshClient` is generic over [`Transport`] and the loopback tests in
//! `tests/mesh_http.rs` exercise the real one. Faking at the transport keeps
//! the real `codec` and the real `MeshClient` in every case, so a test that
//! passes is one where the JSON was parsed by the shipping parser. Only the
//! bytes on the wire are ours.
//!
//! # Where the numbers come from
//!
//! `F-address-widths` (group F): its master seed, account index 0, its
//! recorded `account_tag`, and its recorded `wots_address` — the address of
//! the key at position 1. So the chain states scripted here are
//! TypeScript-emitted values wherever one exists.
//!
//! Deliberately **not** here: `store()`. It needs `keystore_harness`'s
//! `ScratchDir`, and a support module that reaches into another support
//! module through `crate::` is a coupling no other file in this directory
//! has. Each consumer keeps its own two-line store helper.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use mochimo_crypto::account::WotsIndex;
use mochimo_crypto::addr::{Address, Tag};
use mochimo_crypto::consts::{ADDR_TAG_LEN, SEED_LEN};
use mochimo_crypto::keystore::KeyAccess;
use mochimo_crypto::mesh::Transport;
use mochimo_crypto::{derive, recon, Error, Secret};

/// `F-address-widths`' master seed (`group_f_derivation.json`), account 0.
pub const MASTER: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Its recorded `account_tag`.
pub const TAG: Tag = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73, 0x05,
    0x4b, 0x58, 0x80, 0x0f,
];

/// Its recorded `wots_address` at `wots_index: 0` -- this crate's position 1.
pub const ADDRESS_AT_1: Address = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73, 0x05,
    0x4b, 0x58, 0x80, 0x0f, 0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83,
    0x86, 0xae, 0xc3, 0xa0, 0xc2, 0xa7, 0xea, 0x8c,
];

pub fn master() -> Secret<SEED_LEN> {
    Secret::new(MASTER)
}

/// A **second** account: `F-address-widths`' master at index 1.
///
/// Not `keystore_harness::imported_account()`. Since format v2 that account IS
/// `F-address-widths` -- the same master, the same account index 0 -- so its
/// `IMPORTED_TAG` and `TAG` above are the same twenty bytes, and a store
/// cannot hold both: `add` refuses on the tag, and would refuse again on the
/// key stream. That refusal working is format v2's result; a second account needs
/// a second seed, and this is it.
pub fn tag1() -> Tag {
    derive::derive_account_tag(&master(), 1)
}

pub fn access(m: &Secret<SEED_LEN>) -> KeyAccess<'_> {
    KeyAccess::Master(m)
}

/// The address of the derived account's key at `i`, by the restore path's
/// derivation (no store involved).
pub fn addr_at(i: u32) -> Address {
    recon::derived_address_at(&master(), 0, pos(i))
}

pub fn pos(i: u32) -> WotsIndex {
    let mut p = WotsIndex::ZERO;
    for _ in 0..i {
        p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    p
}

pub fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What the chain says about one tag.
#[derive(Clone, Copy)]
pub enum ChainState {
    /// The ledger holds the tag at this address with this balance.
    At(Address, u64),
    /// The ledger has no entry: middleware code 4, "account not found"
    /// the middleware's own error shape.
    Absent,
    /// The node could not be reached.
    Unreachable,
}

/// A `Transport` scripted per tag. Records every request so a test can assert
/// how many round trips a reconciliation cost.
pub struct Chain {
    states: RefCell<BTreeMap<Tag, ChainState>>,
    /// Behind an `Rc` for the reason `submits` is: a call that consumes the
    /// client and hands nothing back leaves no chain to ask afterwards.
    calls: Rc<Cell<usize>>,
    /// What `/construction/submit` echoes back, if anything.
    ///
    /// **The id is supplied by the caller, never computed here.** A test gets
    /// it from `SignedTransaction::id()` -- the crate's own API -- on a dry
    /// run, and hands it in. Computing it in the fake would be a test oracle
    /// restating protocol logic, which is the one thing a fake in this tree
    /// may not do. `MeshClient::submit` compares the echo against the id it
    /// computed, so a mismatch fails loudly rather than passing quietly, and
    /// that comparison is itself the check that WOTS+ signing is
    /// deterministic across two identical plans.
    submit_id: RefCell<Option<[u8; 32]>>,
    /// When set, `/construction/submit` fails at the socket instead.
    submit_fails: RefCell<bool>,
    /// Every body posted to `/construction/submit`, accepted or refused,
    /// behind a handle the test keeps.
    ///
    /// `cli::run` consumes the `MeshClient` and the `Chain` inside it, so a
    /// field read after the run would be reading a dropped value -- the shape
    /// found on `calls()` and answered with the `Counting` wrapper's `Rc`
    /// handle. The log is recorded on the refused path too, because the
    /// question the recovery markers ask is *what did the binary put on the
    /// socket*, and a refused write is still a write.
    submits: Rc<RefCell<Vec<Vec<u8>>>>,
    /// The tip `/network/status` answers with, when a test scripts one.
    ///
    /// Unset, the endpoint keeps answering the "must only resolve tags" error
    /// below, so every call-count assertion written before the tip existed sees the
    /// chain it always saw. Set, it answers in the shape the live endpoint
    /// returned (`fixtures/group_n_mesh_live.json`, `N-network-status`):
    /// `current_block_identifier.{index,hash}`, the hash `0x`-prefixed. The
    /// hash is fixed and meaningless -- nothing in the crate reads it beyond
    /// the codec's shape check -- and is not an oracle.
    tip: RefCell<Option<u64>>,
}

impl Chain {
    pub fn new(states: &[(Tag, ChainState)]) -> Chain {
        Chain {
            states: RefCell::new(states.iter().copied().collect()),
            calls: Rc::new(Cell::new(0)),
            submit_id: RefCell::new(None),
            submit_fails: RefCell::new(false),
            submits: Rc::new(RefCell::new(Vec::new())),
            tip: RefCell::new(None),
        }
    }

    /// A handle to the submit log that outlives the chain. Clone it
    /// before handing the chain to `MeshClient::new`.
    pub fn submit_log(&self) -> Rc<RefCell<Vec<Vec<u8>>>> {
        Rc::clone(&self.submits)
    }

    /// A handle to the request count that outlives the chain. Clone it
    /// before handing the chain to `MeshClient::new`, as the submit log is.
    pub fn call_count(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.calls)
    }

    /// Script the tip `/network/status` reports.
    pub fn set_tip(&self, index: u64) {
        *self.tip.borrow_mut() = Some(index);
    }

    /// Echo `id` from `/construction/submit`.
    pub fn accepts_submit(&self, id: [u8; 32]) {
        *self.submit_id.borrow_mut() = Some(id);
        *self.submit_fails.borrow_mut() = false;
    }

    /// Fail the submit at the socket.
    pub fn refuses_submit(&self) {
        *self.submit_fails.borrow_mut() = true;
    }

    pub fn set(&self, tag: Tag, state: ChainState) {
        self.states.borrow_mut().insert(tag, state);
    }

    /// **Fund whatever the operator was told to fund**.
    ///
    /// # Why this door takes a string, and why it is strict
    ///
    /// [`Chain::new`] and [`Chain::set`] take a `Tag` — twenty bytes a test
    /// already holds — which is right for scripting *ledger states*, the
    /// question those two exist to answer. It is exactly wrong for the one
    /// question nothing here asks: **is the thing this program prints
    /// something anybody else would take?**
    ///
    /// A flow test that funds the wallet from `c.tag`, a Rust value, never
    /// looks at what `address` rendered, so it walks create → address → fund
    /// → balance → send → settle over a bare 40-hex tag and passes — because
    /// the other end of that "end to end" is our own fake, and the fake
    /// accepts anything. *A test whose far end is our own double cannot catch
    /// a mismatch with the world.*
    ///
    /// So this door models the far end instead: it takes the destination **as
    /// the operator copies it**, and accepts only Base58 over a tag and its
    /// CRC16. A 40-hex tag is refused (wrong length), an 80-hex address is
    /// refused (wrong length), a string with one character altered is refused
    /// (checksum), and anything outside the alphabet is refused by the codec.
    ///
    /// # It is not an oracle, and must not be read as one
    ///
    /// It validates with `addr::tag_from_base58` — this crate's own decoder —
    /// so it cannot detect an error the encoder and the decoder make together.
    /// What anchors the composition is the KAT in `tests/cli.rs` against group
    /// C's recorded strings, `C9`'s among them being crosschecked against
    /// executed TypeScript. Two mechanisms, and they fail on different faults:
    /// this door catches a *composition* error, the KAT catches a *primitive*
    /// one. `the_fake_refuses_every_form_but_the_reference_one` is this door's
    /// own control — a strict door that accepted everything would be worth
    /// exactly what the old flow test was.
    pub fn credit_destination(
        &self,
        destination: &str,
        address: Address,
        balance: u64,
    ) -> Result<Tag, String> {
        let tag = mochimo_crypto::addr::tag_from_base58(destination).map_err(|e| {
            format!(
                "this chain was handed `{destination}` as a destination and refuses it: {e}.\n                   It accepts only Base58 over a tag and its CRC16 -- the form `tx.c:269-271`                  composes and every Mochimo wallet takes. If the CLI printed this string, the                  CLI cannot be funded from its own output."
            )
        })?;
        self.set(tag, ChainState::At(address, balance));
        Ok(tag)
    }

    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl Transport for Chain {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        if path == "/construction/submit" {
            self.submits.borrow_mut().push(body.to_vec());
            if *self.submit_fails.borrow() {
                return Err(Error::Transport {
                    op: "write",
                    kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::BrokenPipe),
                });
            }
            return match *self.submit_id.borrow() {
                // Bare hex, no `0x`: that is the shape the live endpoint
                // actually returned, recorded in
                // `fixtures/group_n_mesh_live.json`'s submit responses.
                // Prefixing it here makes `parse_submit` refuse at byte 1:
                // the capture is the authority, not the tag encoding two arms
                // up (which IS prefixed).
                Some(id) => Ok(
                    format!(r#"{{"transaction_identifier":{{"hash":"{}"}}}}"#, hexs(&id))
                        .into_bytes(),
                ),
                None => Err(Error::MeshResponse {
                    what: "test: this chain was not told to accept a submission",
                }),
            };
        }
        if path == "/network/status" {
            if let Some(index) = *self.tip.borrow() {
                return Ok(format!(
                    r#"{{"current_block_identifier":{{"index":{index},"hash":"0x{}"}},"sync_status":{{"stage":"synchronized","synced":true}}}}"#,
                    "ab".repeat(32)
                )
                .into_bytes());
            }
        }
        if path != "/call" {
            return Err(Error::MeshResponse {
                what: "test: reconciliation must only resolve tags",
            });
        }
        // The tag is in the request the real codec built; read it back so the
        // fake answers about the tag actually asked for.
        let req: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::MeshResponse {
            what: "test: request",
        })?;
        let asked = req["parameters"]["tag"].as_str().ok_or(Error::MeshResponse {
            what: "test: parameters.tag",
        })?;
        // `request_tag_resolve` sends the 0x-prefixed form (`prefixed(tag)`),
        // so the fake reads it back the way the shipping codec wrote it.
        let raw: [u8; ADDR_TAG_LEN] = mochimo_crypto::mesh::hex::decode_prefixed(asked, "test tag")?;
        let tag: Tag = raw;
        match self.states.borrow().get(&tag).copied() {
            Some(ChainState::At(address, balance)) => Ok(format!(
                r#"{{"result":{{"address":"0x{}","amount":{}}},"idempotent":true}}"#,
                hexs(&address),
                balance
            )
            .into_bytes()),
            Some(ChainState::Absent) | None => {
                Ok(br#"{"code":4,"message":"Account not found","retriable":false}"#.to_vec())
            }
            Some(ChainState::Unreachable) => Err(Error::Transport {
                op: "connect",
                kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
            }),
        }
    }
}
