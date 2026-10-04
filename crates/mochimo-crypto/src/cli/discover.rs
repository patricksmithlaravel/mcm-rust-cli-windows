//! `discover` — which account indices this seed's tags resolve to on the
//! chain, and the extent that was searched.
//!
//! # What it is for
//!
//! `create` derives account 0 and nothing else, and `restore --account N`
//! adds an account only once the chain resolves its tag, so an operator
//! restoring a phrase onto a new machine has a store holding one account and
//! no way to find out whether the seed has others. `address --account N`
//! answers *where would account N receive* and asks nothing; this answers
//! *what does the node say about accounts 0 through N*, which is the other
//! half and the one that needs a node. Once an index resolves, `restore
//! --account N` is what puts it in the store; this verb puts nothing
//! anywhere.
//!
//! # The rule that matters more than any number here
//!
//! **It never asserts that an account does not exist.** It cannot: the
//! Mesh's code 4 conflates three states it does not distinguish (`recon`'s
//! module doc, fact 3, and the specification's *emptied-account window*) —
//! no ledger entry for the tag, a zero balance the middleware's quorum
//! discards, and a lookup that failed — and *no ledger entry* is itself what
//! a never-funded account, a node serving another chain and a seed that is
//! not the one that made the account all produce alike. So a sighting
//! carries what the node **said**, and the page says `searched account
//! indices 0..=64; the node resolved 3 of them` where a count of accounts
//! would be a claim nothing here can support.
//!
//! That is the same error `recon` made once and corrected one level in: a
//! bounded walk's failure was named for the one cause a bound produces by
//! construction. A bounded sweep's silence has exactly that shape, and this
//! module declines it for the same reason.
//!
//! # What it writes: nothing
//!
//! The store is borrowed immutably, so a write here is a compile error, and
//! `tests/cli.rs` holds the snapshot bytes identical across the call. No
//! wallet is constructed, nothing is reserved and nothing is signed:
//! `Wallet::open`'s refusal on a never-funded account is untouched, and this
//! sits beside `address` and `restore` rather than behind the gate, for the
//! reason `cli::address`'s module doc gives.

use crate::account::{AccountKind, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::derive;
use crate::keystore::{Keystore, Medium};
use crate::mesh::{LedgerEntry, MeshClient, Transport};
use crate::recon::{Cancel, Progress, Unfinished};
use crate::{Error, Secret};

/// What the node said about one account index, and what this store holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub account: u32,
    pub tag: Tag,
    /// `Some` when the node resolved the tag: the ledger address it holds
    /// and the balance. `None` when the node answered code 4 — which is
    /// **what was observed** and not a statement that the account does not
    /// exist (module doc).
    pub entry: Option<LedgerEntry>,
    /// What this store records for the tag, when it holds it. Shown and
    /// marked, never hidden: a report that silently omits the accounts you
    /// already have is one you cannot check against your own store.
    pub held: Option<(AccountKind, WotsIndex)>,
}

/// One sweep's whole result. `to` is the extent that was actually searched,
/// so a caller cannot print a range the sweep did not reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sweep {
    /// Indices `0..=to` were searched.
    pub to: u32,
    pub sightings: Vec<Sighting>,
}

impl Sweep {
    /// How many indices the node resolved.
    #[must_use]
    pub fn resolved(&self) -> usize {
        self.sightings.iter().filter(|s| s.entry.is_some()).count()
    }
}

/// Why a sweep stopped before its extent.
///
/// Only one shape, and it is deliberately not "the index was not found": a
/// node that cannot be reached has told us nothing about that index, and a
/// sweep that reported a partial extent as a whole one would be asserting
/// absence by omission — the one thing this module refuses to do. Mesh code
/// 4 is *not* here: it is an answer, and it becomes a `Sighting` with no
/// entry.
#[derive(Debug)]
pub enum SweepFailure {
    ChainUnreachable {
        /// The index the node failed on.
        account: u32,
        /// How many indices were searched before it, `0..account`.
        searched: u32,
        cause: Error,
    },
}

/// Derive the tags of accounts `0..=to` from `master` and ask the node about
/// each, in order.
///
/// One `/call` per index and nothing else: no `/network/status`, no second
/// round for balances (`tag_resolve` returns one already). The store is read
/// for the held markers and never written.
pub fn sweep<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
) -> core::result::Result<Sweep, SweepFailure> {
    // `NEVER` is never asked, so `cancelled` is never called; `Ok` is the
    // answer that ends nothing.
    sweep_asking(store, client, master, to, &Cancel::NEVER, None, || Ok(()))
}

/// [`sweep`], stoppable from outside: `cancel` is asked before each index's
/// node call.
///
/// A cancel is [`Unfinished::Cancelled`], never a [`SweepFailure`] and never
/// a [`Sweep`] of the indices asked so far: a short extent carried as a whole
/// one is the absence by omission this module refuses (module doc).
pub fn sweep_with<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
) -> core::result::Result<Sweep, Unfinished<SweepFailure>> {
    sweep_asking(store, client, master, to, cancel, None, || Err(Unfinished::Cancelled))
}

/// [`sweep_with`], telling `progress` which index it is about to ask the
/// node about ([`Progress`]: index `account` of the `to + 1` searched, with
/// no walk, so `position` and `ceiling` are zero).
pub fn sweep_with_progress<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Sweep, Unfinished<SweepFailure>> {
    sweep_asking(store, client, master, to, cancel, Some(progress), || Err(Unfinished::Cancelled))
}

/// The one sweep the three forms run. `cancelled` is what a cancel ends the
/// call with, and it is called only once `cancel` has said stop.
fn sweep_asking<M: Medium, T: Transport, E: From<SweepFailure>>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
    mut progress: Option<&mut dyn FnMut(Progress)>,
    cancelled: impl Fn() -> core::result::Result<(), E>,
) -> core::result::Result<Sweep, E> {
    let mut sightings = Vec::new();
    for account in 0..=to {
        if cancel.stop() {
            cancelled()?;
        }
        if let Some(report) = progress.as_deref_mut() {
            report(Progress {
                account,
                accounts: to.saturating_add(1),
                position: 0,
                ceiling: 0,
            });
        }
        let tag = derive::derive_account_tag(master, account);
        let entry = match client.resolve_tag(&tag) {
            Ok(e) => Some(e),
            // Code 4 is an answer, and the one answer this verb may not
            // read as absence (module doc).
            Err(Error::Mesh { code: 4, .. }) => None,
            Err(cause) => {
                return Err(SweepFailure::ChainUnreachable {
                    account,
                    searched: account,
                    cause,
                }
                .into())
            }
        };
        sightings.push(Sighting {
            account,
            tag,
            entry,
            held: held_in(store, &tag),
        });
    }
    Ok(Sweep { to, sightings })
}

/// What the store records for `tag`, if anything. A store error is not a
/// finding about the chain, so it is reported as *not held* rather than
/// allowed to abort a sweep that has already paid for its node calls; the
/// caller's own store errors surface on every other verb.
fn held_in<M: Medium>(store: &Keystore<M>, tag: &Tag) -> Option<(AccountKind, WotsIndex)> {
    match store.view(tag) {
        Ok(Some(v)) => Some((v.kind, v.wots_index)),
        Ok(None) | Err(_) => None,
    }
}
