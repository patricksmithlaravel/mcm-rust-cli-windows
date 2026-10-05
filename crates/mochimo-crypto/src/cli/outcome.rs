//! What a command decided, before anything says it in words.
//!
//! # The split, and why the prose was the problem
//!
//! A `cmd_*` that ends by building a `Report` -- a `String` and an exit code
//! -- makes a command's decision and the sentence announcing it one
//! statement. That has two costs and only one of them is the obvious one.
//!
//! The obvious one is that **a dependent cannot read a decision back**. The
//! only thing this layer returned was English, and a caller that needed to
//! know *which* refusal it was had to match on the words. Prose is not an
//! interface: it is written to be read once by a person who is already
//! holding the terminal.
//!
//! The one that costs this repository more is that **a decision nothing can
//! name is a decision nothing can test**. `tests/cli.rs` is seven thousand
//! lines and the great majority of it asserts on rendered text, which is what
//! a fused layer leaves a suite to assert on. A test that means to check
//! *this account was refused because the chain disagreed* can then only check
//! that a particular sentence came out, and it passes just as well when the
//! sentence is right for the wrong reason.
//!
//! [`ChainPosition::Unlocated`](crate::recon::ChainPosition::Unlocated) is
//! the same property one layer down, and it is worth reading as the miniature
//! of this one: it records what stopped a walk rather than leaving the report
//! to supply a cause, because a report that supplies one is right only for as
//! long as there is a single cause to supply. **A renderer can be no more
//! honest than the value it is handed.**
//!
//! # What this module is, then
//!
//! The value. Each variant carries what the command established, in the types
//! the layers below already use -- [`Settlement`], [`RestoreFailure`],
//! [`AccountStatus`], [`Divergence`], [`Error`] -- and `render` in the
//! sibling module turns one into a [`Report`](super::Report).
//!
//! **Almost no new types appear here on purpose.** A command's result has a
//! type in the layer that produced it; this module's job is to carry that
//! type outward rather than to invent a parallel vocabulary. Where a
//! variant does carry a plain field it is because the renderer needed exactly
//! that and the store would otherwise have to be held open across the render
//! -- `upgraded_from` is the whole of that category.
//!
//! # One thing that followed from the split rather than being aimed at
//!
//! **This module does not know what an exit code is.** Nothing here names
//! `Code`, so the decision layer has no opinion on whether a command exits 0
//! or 3 -- a question about how a program reports rather than about what it
//! found. `render` answers it, at one site per outcome, and a dependent that
//! is not a command line ignores the answer.
//!
//! # What has not changed
//!
//! [`super::run`] returns a [`Report`](super::Report) and renders the same
//! bytes it always has. That is not a transitional shim, it is the proof: the
//! seven thousand lines of `tests/cli.rs` are held to this layer without
//! knowing it exists, so every one of them asserts that the words have not
//! moved.

use crate::account::WotsIndex;
use crate::mesh::spend::SpendPlan;
use crate::mesh::{codec, ChainTip, TxId};
use crate::tx::wire::Destination;
use crate::addr::{Address, Tag};
use crate::recon::{AccountStatus, Divergence, RestoreFailure, RestoredAccount};
use crate::wallet::{Settlement, StartupRefusal};
use crate::Error;

use super::address::Held;
use super::discover::Sweep;
use super::args::Command;
use super::reconcile::Reviewed;

/// One account's line in a listing, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLine {
    pub tag: Tag,
    pub status: AccountStatus,
}

/// What the store said about its own format version: `Some(from)` when this
/// invocation rewrote an older version in place.
///
/// **The one-way crossing, carried to the page of the command that made it.**
/// A version-3 store is read as it is and re-sealed as version 4 by its first
/// commit, after which an older build meets `got > supported` on a real file
/// for the first time and prints the fresh-directory advice -- which, for an
/// open reservation, is the second-signature route. `None` for every store
/// that did not cross under this handle, which is every store this build
/// created and every version-3 store a read-only command opened: `open` never
/// rewrites the snapshot, and `status`, `balance` and `address` never ask.
/// The detector for an `upgraded_from` that reports the crossing before it has
/// happened is the pin test's fourth arm, not a page.
///
/// Carried rather than looked up at render time because the renderer does not
/// hold the store -- which is the point of the split and not a limitation of
/// it. It is read where the store is open, which is also the only place the
/// answer is true.
pub type Upgraded = Option<u16>;

/// A spend that was signed and written to the socket, and what the socket
/// said.
///
/// **`submitted` is not a verdict either way**, and the field is a `Result`
/// only because the write either happened or did not. `/construction/submit`
/// writes to one node and returns before any reply, so an `Ok` is a socket
/// write and an id the middleware computed locally -- which is the first of
/// the three residues this layer is required to keep saying out loud.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shipped {
    pub source: Tag,
    /// In the order that goes on the wire, which the layout sorts and which
    /// need not be the order the operator typed.
    pub destinations: Vec<Destination>,
    pub blk_to_live: u64,
    /// The signed image, as it left the builder. The retry artifact is this.
    pub wire: Vec<u8>,
    pub submitted: core::result::Result<TxId, Error>,
}

/// A command, decided: what it established, and the accounts reconciliation
/// could not explain while it ran.
///
/// The standing divergences are carried as [`Divergence`]s rather than as the
/// notice they become, for the reason the whole module exists: the notice is
/// one rendering of them and a caller may want another, or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decided {
    /// Accounts `Wallet::open` could not reconcile. Empty for every command
    /// that runs before the gate, which have no wallet to ask.
    pub standing: Vec<Divergence>,
    pub outcome: Outcome,
}

/// One transaction of the node's queue, as `mempool` lists it: its id, and
/// what `/mempool/transaction` answered for it, or `None` when the queue no
/// longer held it by the time it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolRow {
    pub id: [u8; crate::consts::HASHLEN],
    pub transaction: Option<Box<codec::MeshTransaction>>,
}

/// What a command established. The sibling `render` module is the only thing
/// in this crate that turns one into words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    // ---- the store, read ------------------------------------------------
    /// Every account and what reconciliation made of it.
    Balance { accounts: Vec<AccountLine> },
    /// Every account the store holds, from records alone.
    Accounts { held: Vec<Held> },
    /// One stored account's destination and current ledger address.
    Address {
        tag: Tag,
        address: Address,
        index: WotsIndex,
    },
    /// An account derived from the master and deliberately not stored.
    UnstoredAddress {
        account: u32,
        tag: Tag,
        address: Address,
    },

    // ---- the store, written ---------------------------------------------
    /// `restore` found the index on the chain.
    Restored {
        account: u32,
        found: RestoredAccount,
        /// `Some(stored)` when the store already held the tag at `stored` and
        /// nothing was written.
        held_at: Option<WotsIndex>,
        upgraded: Upgraded,
    },
    /// `settle` asked the chain what became of a reservation.
    Settled {
        settlement: Settlement,
        upgraded: Upgraded,
    },
    /// A spend laid out and **not signed**: the page a person reads before
    /// deciding whether it is. No verb of this command line decides it --
    /// `send` signs what it plans -- so it is built with [`Outcome::planned`]
    /// by a caller that asks first, and rendered like every other outcome.
    Planned {
        source: Tag,
        /// In the order that goes on the wire, as [`SpendPlan::dsts`] holds
        /// them.
        destinations: Vec<Destination>,
        send_total: u64,
        fee_total: u64,
        change_total: u64,
        blk_to_live: u64,
    },
    /// `send` planned, reserved, signed and wrote.
    Sent {
        shipped: Shipped,
        send_total: u64,
        fee_total: u64,
        change_total: u64,
        upgraded: Upgraded,
    },
    /// `resign` reproduced the reserved artifact and wrote it.
    Resigned { shipped: Shipped },
    /// `submit` wrote an artifact it was handed, having opened no store.
    Submitted {
        source: Tag,
        /// The image as it was given, after the layout check.
        bytes: Vec<u8>,
        submitted: core::result::Result<TxId, Error>,
    },

    // ---- one account, and the whole store, reconciled now ---------------
    /// `status` compared one account against the chain and got an answer.
    Status { tag: Tag, status: AccountStatus },
    /// `status` found a divergence, which is an answer about the account and
    /// **not** a refusal of the command: exit 0, and the same report a
    /// refusal prints.
    StatusDiverged { tag: Tag, divergence: Box<Divergence> },
    /// `status` could not ask the question at all.
    StatusRefused { divergence: Box<Divergence> },
    /// `reconcile` reported the store and acted, or declined to.
    Reconciled {
        tag: Tag,
        advance_to: u32,
        reviewed: Reviewed,
        upgraded: Upgraded,
    },
    /// `discover` asked the node about a range of derived indices.
    Discovered { sweep: Sweep },
    /// `discover` on a store with no master to derive from.
    DiscoverNeedsMaster,
    /// `discover` stopped part-way, so it reports **no** extent for what it
    /// never asked about: a partial sweep printed as a whole one asserts
    /// absence by omission.
    SweepStopped {
        account: u32,
        searched: u32,
        to: u32,
        cause: Error,
    },

    // ---- the artifact refusals, before any socket -----------------------
    ArtifactNotHex { cause: Error },
    ArtifactNotATransaction { cause: Error },
    /// The bytes given are not one whole transaction image, so what reached
    /// the socket would not be what the operator holds.
    ArtifactNotWhole { given: usize, described: usize },

    // ---- the node, read -------------------------------------------------
    /// One transaction from the indexer.
    LookedUpTransaction { page: Box<codec::SearchPage> },
    /// The indexer holds no transaction with that hash -- which is not the
    /// same as there being none.
    TransactionNotFound { hash: [u8; crate::consts::HASHLEN] },
    /// The indexer's rows for one tag, the `from` newest skipped.
    RecentTransactions {
        tag: Tag,
        from: u64,
        page: Box<codec::SearchPage>,
    },
    /// One block.
    Block { block: Box<codec::MeshBlock> },
    /// A block that was not served. `by_hash` because a hash lookup reaches
    /// the deployment's archive rather than the chain, and the page says so.
    BlockNotServed { by_hash: bool, cause: Error },
    /// The newest blocks, walked down from the tip.
    Blocks {
        count: u64,
        tip: ChainTip,
        rows: Vec<codec::MeshBlock>,
    },
    /// The walk stopped: the tip was read and one block below it was not.
    BlocksStopped { index: u64, cause: Error },
    /// The node's queue: how many transactions it holds, and the first
    /// `count` of them read whole.
    Mempool {
        count: u64,
        total: usize,
        rows: Vec<MempoolRow>,
    },
    /// The queue's ids were read and one transaction in it was not, for a
    /// reason other than its having left the queue.
    MempoolStopped { id: [u8; crate::consts::HASHLEN], cause: Error },
    /// The node could not be asked at all.
    ExplorerFailed { cause: Error },
    /// The node's index could not be searched: `/search/transactions`
    /// refused, or the node could not be asked. Apart from
    /// [`Outcome::ExplorerFailed`] because what the middleware answers there
    /// says whether the node runs an indexer at all.
    SearchFailed { cause: Error },
    /// `resign` reproduced the artifact and stopped before the socket,
    /// because the source tag would not render.
    ///
    /// The reproduction is carried anyway and rendered anyway: this page may
    /// be the only rendering of the only bytes that can move those funds, so
    /// the refusal is appended to it rather than printed in place of it.
    ReproducedButUnrenderable {
        source: Tag,
        destinations: Vec<Destination>,
        blk_to_live: u64,
        wire: Vec<u8>,
        cause: Error,
    },
    /// `resign` rebuilt the plan and it is not the one the store reserved.
    NotTheReservedSpend,
    /// `resign` on a reservation the chain has already moved past: there is
    /// nothing left to reproduce, and `settle` is the verb.
    ReservationAlreadyLanded {
        source: Tag,
        spent_index: u32,
        settled_index: u32,
    },

    // ---- refusals that carry a shape ------------------------------------
    /// `restore` was asked for without a master seed to derive from.
    RestoreNeedsMaster,
    /// The scan ran and reported. Kept whole because its own `Display` is the
    /// refusal, and `restore` appends this program's spelling of the remedy.
    RestoreRefused { account: u32, failure: RestoreFailure },
    /// A tag this store does not hold, named by a command that needs one.
    NoSuchAccount { tag: Tag },
    /// The same state reached through `address`, which says more because the
    /// operator is asking where to be paid: it names the two verbs that would
    /// put the account in the store. Two variants and not one shared sentence,
    /// because the two sentences were already different and this split is not
    /// licensed to change what either says.
    NoAccountToAddress { tag: Tag },
    /// A derivation was asked of a store whose accounts are all imported.
    NoMasterSeed,
    /// `address --account N` for an account the store already holds: the
    /// answer is the stored one, and position 0 is not it.
    AccountAlreadyStored {
        account: u32,
        tag: Tag,
        index: WotsIndex,
    },
    /// Reconciliation refused this account (I4).
    Diverged(Box<Divergence>),
    /// A tag whose destination could not be rendered at all.
    CannotRender { tag: Tag, cause: Error },
    /// Everything else the layers below refused, in their own words.
    ///
    /// **Not a catch-all for prose.** Every variant here is an `Error` the
    /// crate already defines and a caller can already match on; what this
    /// says is that this command added no reading of its own to it.
    Failed(Error),

    // ---- the wallet never opened ----------------------------------------
    /// The store would not give up its master seed, so nothing could run.
    StoreUnreadable(Error),
    /// `Wallet::open` refused: nothing in the store reconciled (I4).
    StartupRefused(Box<StartupRefusal>),
    /// A command that `decide` routes before the gate reached the post-gate
    /// match anyway. Not reachable from `decide`, which returns first; it
    /// exists because the match is exhaustive over `Command` and a silent arm
    /// would be the thing the panic census refuses.
    HandledBeforeTheWallet,
    /// `run_explorer` was handed a command that is not one of its four.
    NotAReadOnlyVerb { command: Box<Command> },
}

impl Outcome {
    /// The [`Outcome::Planned`] `plan` is shown by before it is signed: the
    /// account it spends from, its destinations in wire order, its totals and
    /// its block-to-live, and nothing else.
    ///
    /// The source is the plan's own [`SpendPlan::tag`], the account
    /// `Wallet::reserve_and_sign` reserves and signs from, and not a tag
    /// passed beside it: a page naming one account for a plan that spends
    /// from another is then unrepresentable rather than checked.
    ///
    /// It reads the plan and nothing more -- no store, no node -- so building
    /// it reserves no key and moves no index, and the plan can still be
    /// signed or dropped afterwards.
    #[must_use]
    pub fn planned(plan: &SpendPlan) -> Outcome {
        Outcome::Planned {
            source: plan.tag(),
            destinations: plan.dsts().to_vec(),
            send_total: plan.send_total(),
            fee_total: plan.fee_total(),
            change_total: plan.change_total(),
            blk_to_live: plan.blk_to_live(),
        }
    }
}
