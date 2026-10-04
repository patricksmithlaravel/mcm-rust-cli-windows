//! Reconciliation: what the chain says about an account, what this store
//! says, and what the wallet does when they disagree (I4, I5).
//!
//! # The two invariants, and that both were decided before this module
//!
//! **I4 fails closed**. Divergence between a local key index and
//! chain state has three causes — a crash between signing and persisting, a
//! restored seed with incomplete history, two wallet instances on one seed —
//! and the divergence alone does not say which. Advancing to match the chain
//! is right for the first and **catastrophic** for the third, where the other
//! instance is still running and will reuse every key skipped past. So the
//! wallet refuses to start and requires explicit operator action.
//!
//! **I5's scan is target-directed**. The chain cannot be asked for
//! a tag's usage history, but it *can* be asked for the tag's current address
//! in one query, so restore derives the index by deriving addresses and
//! stopping on the one that matches — never by scanning for absence, and never
//! by assuming zero.
//!
//! Neither decision is reopened here. What this module adds is the mechanism
//! and the four policies the network client named and left open.
//!
//! # Two facts about the ledger this design rests on
//!
//! Both read from the authoritative tier at `bbbacea`:
//!
//! 1. **A tag absent from the ledger has never been funded — it was not
//!    emptied.** `le_update`'s write of a merged entry
//!    carries **no zero-balance
//!    filter** — its only guard is the merge position — and the only
//!    balance mutation is the `'-'` DEBIT case zeroing it. So a tag
//!    whose balance reaches zero keeps its entry and keeps being rehashed.
//!    Absence means *never paid* — absence **from the ledger**, which is not
//!    what this wallet observes; fact 3.
//! 2. **Per-index usage is unobservable.** The ledger holds **one entry per
//!    tag**: the merge is keyed on `addr_tag_compare`, every
//!    equal-tag transaction is applied to that one entry, and a new
//!    tag's entry is created exactly once. `le_find` then
//!    binary-searches it comparing an address *prefix*, so a
//!    full-address query answers *"is this the tag's current address?"* and
//!    never *"was this address ever used"*. Every index except the current one
//!    reads as unused — including every index already spent from — so a gap
//!    scan has no stopping signal on this chain at all.
//!
//!    **Not the sort check.** `:704` is `addr_compare(le_prev.addr, le.addr)`,
//!    and `addr_compare` is `memcmp(a, b, ADDR_LEN)` — the *whole*
//!    40-byte address. It proves no duplicate **addresses**, which is a
//!    weaker statement than one-entry-per-tag and does not imply it. It was
//!    cited for the stronger claim and the audit caught it; the merge, not
//!    the sort check, is the evidence.
//! 3. **The Mesh's "account not found" is not the ledger's absence**.
//!    Fact 1 is about the ledger; this wallet reads the ledger through the
//!    Mesh, and the Mesh answers code 4 in three situations it does not
//!    distinguish. `callHandler` maps *any* error from `QueryTagResolve` to
//!    `ErrAccountNotFound` (`retriable` is a constant `true` on that error,
//!    so the flag carries nothing), and `QueryTagResolve` asks several nodes,
//!    **discards every answer whose amount is zero**, and errors when no
//!    address reaches quorum. So the answer
//!    arrives for a tag the ledger has no entry for, for a tag the ledger
//!    holds at ZERO balance, and for a lookup that failed — too few nodes
//!    answered, a node between blocks, a timeout — and the first live
//!    recovery saw the third for every tag on the chain for two minutes,
//!    funded ones included. [`Divergence::TagUnresolved`] and
//!    [`RestoreFailure::TagUnresolved`] therefore name what was observed and
//!    prefer no reading. A name asserting *never funded* reasons soundly
//!    from fact 1 about a premise fact 3 denies -- that the answer is the
//!    ledger's. Same shape as the scan-bound diagnosis below, one layer out:
//!    there a name would assert a cause, here that a response is truthful.
//!
//! # The two scans, and the two bounds
//!
//! There are two callers of the scan and they differ in what they know.
//! **Restore** has a seed and no store, so it must walk from zero: its bound,
//! [`RECOVERY_CEILING`], is the *recovery ceiling* — how far along an account
//! may be before the phrase alone cannot recover it without the operator
//! raising it. **The divergence diagnostic** has the local index, so it walks
//! a window of [`DIVERGENCE_WINDOW`] either side of it and then the recovery
//! range: its bound is the *divergence window* — how large a disagreement
//! between local and chain can be diagnosed wherever the account sits.
//!
//! **They do not coincide, and that is the point.** The ceiling is 10,000
//! and the window is 20, so that they are two quantities rather than one is
//! a fact about the code and not a claim about it — a store at position
//! 9,000 is restorable and a disagreement of 30 positions is still outside
//! the window. The two numbers are argued at their own constants. One
//! constant serving both, with the diagnostic walking `0..20` *absolute*,
//! reports a store at position 22 whose chain sits at 24 — a gap of two, I4's
//! two-instance case exactly — as *this seed does not own this tag*.
//!
//! **Either bound bounds only the failing search**: the ordinary case stops on
//! the match. When the walk finds nothing, three things can be true and the
//! failure cannot tell them apart: the account has spent more times than the
//! positions walked; this seed does not own this tag; or the wallet is pointed
//! at another chain. The report says all three and prefers none. It once
//! named the first — the one cause a bound produces by
//! construction — and denied it.
//!
//! # What a match establishes, exactly
//!
//! That the address at a derived position **is the address the ledger holds
//! for this tag now** — nothing more. That the key at that position has not
//! signed is this wallet's own change convention (`spend_addresses` names the
//! next position as `chg_addr`), which the reference does not enforce: `tx_val`
//! constrains `chg_addr` only against the source's hash and tag
//! (`EMCM_TXCHG`, `EMCM_XTXTAGMISMATCH`), and the ledger copies whatever hash
//! the transaction named. Every acknowledged advance in this module rests on
//! that convention, whether the position was found in the window or under a
//! ceiling the operator raised.

use core::fmt;

use crate::account::{AccountKind, AdvanceReceipt, StreamId, WotsIndex};
use crate::addr::{Address, Tag};
use crate::consts::SEED_LEN;
use crate::derive;
use crate::error::{Error, Result};
use crate::keystore::{Figures, KeyAccess, Keystore, Medium, Pending};
use crate::mesh::{LedgerEntry, MeshClient, Transport};
use crate::secret::Secret;

/// **The recovery ceiling**: how many positions restore's failing search walks
/// before giving up, `0..10_000`, unless the caller sets it for one
/// invocation ([`ScanScope::with_ceiling`]).
///
/// # 10,000 is not another borrowing, and that is the whole reason
///
/// BIP-44's 20 is a gap limit over **unused addresses**: how many empty
/// addresses to look past before concluding a branch has ended. This number
/// bounds something else entirely — **how many spends an account has already
/// made** before a phrase alone cannot recover it. BIP-44 does not have that
/// quantity, so the two shared a value and nothing else, and an account
/// spent from 25 times restored as
/// [`RestoreFailure::NoIndexReproducesTheAddress`], which names three causes
/// and prefers none. That is correct — the walk genuinely cannot tell them
/// apart — and it meant the operator was never told the ceiling was the
/// likely one.
///
/// 10,000 is taken from the only other implementation of **this** protocol,
/// whose users' funds are what a phrase restored here has to reach: the
/// shipped browser extension bounds the same quantity at 10,000, in
/// `MasterSeed.deriveWotsIndexFromWotsAddrHash(accountSeed, wotsAddrHash,
/// firstWotsAddress, startIndex = 0, endIndex = 10000)`
/// in the extension at the commit AGENT.md pins,
/// which iterates `deriveSeed(accountSeed, i)` — position
/// by position, the same walk this constant bounds. That program creates five
/// accounts on a phrase restore from a hard-coded `i < 5` and sweeps no
/// account indices at all (`ImportWallet.tsx:53-58`), so the 10,000 is its
/// key-position bound and nothing else; it is the figure this constant
/// matches.
///
/// # What it costs, and when
///
/// It is a limit on **failure**: [`scan_for_address`] returns as soon as a
/// derived address matches, so a wallet inside the bound is found exactly and
/// the constant never enters the ordinary case. Only an exhausted search pays
/// for it — about 15.8 s of derivation in a release build on this machine,
/// once, on a recovery a human is already waiting for. In a debug
/// build the same walk is about 7 m 24 s, which is why no test in this tree
/// walks the default and why the tests that pin it say so at the site.
///
/// It is *not* the divergence window — that is [`DIVERGENCE_WINDOW`], still
/// 20, and the two are separate quantities (module doc). It **is** the
/// divergence diagnostic's ceiling, which follows this constant deliberately:
/// [`ScanScope::DIAGNOSTIC`] says why. Named `SCAN_BOUND` until it stopped
/// being the only scan's only bound.
pub const RECOVERY_CEILING: u32 = 10_000;

/// **The divergence window**: how far either side of the local index the
/// divergence diagnostic looks for the chain's address, in positions.
///
/// BIP-44's 20, and **this one is the borrowing that fits**: a window is a
/// number of positions to look past before giving up on a neighbourhood,
/// which is the shape of BIP-44's gap limit even though the thing counted is
/// a key position rather than an unused address. It bounds the size of a
/// *disagreement* the report can diagnose, where [`RECOVERY_CEILING`] bounds
/// how far along an account may be before the phrase alone cannot recover it.
/// A window is what makes the diagnostic independent of where the account
/// sits — a gap of two is found at position 22 as it is at position 2, and at
/// position 9,000,000, which no ceiling reaches.
///
/// It is deliberately not [`RECOVERY_CEILING`]: a disagreement of more than
/// 20 positions between a store and the chain is not a near miss, and
/// widening the window would
/// only make the diagnostic's *cheap* half expensive for every account at
/// every startup, which is exactly what a window exists to avoid. The
/// diagnostic's reach past the window is the ceiling's, not this constant's.
pub const DIVERGENCE_WINDOW: u32 = 20;

/// The positions a scan walks, as its caller sets them.
///
/// Two parts: a `window` either side of the local index the reconciler reads
/// from the store (restore has no local index and passes none, so its window
/// is ignored), walked **first** so a small gap on a far-along account costs
/// a few derivations; then the first `ceiling` positions (`0..ceiling`),
/// ascending, skipping any the window already covered. Distinct positions
/// have distinct addresses, so order is not correctness; it is cost and
/// determinism. The last position, `u32::MAX`, is never walked: an account
/// there could not be advanced from and could never reserve a spend.
///
/// There is no operator-named position here on purpose. An index the operator
/// names on `reconcile --advance-to N` *raises the ceiling* to `N + 1`, so the
/// walk covers `0..=N` and may find the chain at some other index below `N`
/// and refuse naming that one — a number the operator types only widens the
/// search, and never becomes the answer by being typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanScope {
    /// Walk `0..ceiling`. Restore's whole scope; the diagnostic's floor.
    pub ceiling: u32,
    /// Walk `local - window ..= local + window` (clamped), when a local index
    /// exists.
    pub window: Option<u32>,
}

impl ScanScope {
    /// What restore walks: the first [`RECOVERY_CEILING`] positions.
    pub const RESTORE: ScanScope = ScanScope {
        ceiling: RECOVERY_CEILING,
        window: None,
    };

    /// What the divergence diagnostic walks: [`DIVERGENCE_WINDOW`] either side
    /// of the local index, then the recovery range.
    ///
    /// # The ceiling FOLLOWS [`RECOVERY_CEILING`], and that was decided
    ///
    /// Raising the recovery ceiling from 20 to 10,000 moved this scope's
    /// absolute reach with it, because the two share the field. That is a
    /// behaviour change on the startup path and it was taken deliberately
    /// rather than inherited: the diagnostic's ceiling answers the same
    /// question the recovery ceiling does — *how far along may an account be
    /// and still be described* — and pinning it back at 20 would leave
    /// `Wallet::open` reporting `Unlocated`, whose text names a foreign seed
    /// and a foreign chain among its three causes, for an account this
    /// wallet's own `restore` had just placed at position 5,000. The two
    /// quantities would then disagree in the one direction that is no help
    /// to anybody.
    ///
    /// **What it costs, stated rather than discovered.** The window is
    /// untouched, so nothing changes for an account that reconciles (the
    /// comparison succeeds and no walk runs at all) or for one whose
    /// disagreement is inside ±[`DIVERGENCE_WINDOW`] (found in at most 41
    /// derivations, wherever the account sits). Only a divergence *larger
    /// than the window* now pays: up to a full exhaustion, about 15.8 s in a
    /// release build, at `Wallet::open`, on a startup that is already going
    /// to refuse. The failing path got slower; the succeeding path did not
    /// move.
    pub const DIAGNOSTIC: ScanScope = ScanScope {
        ceiling: RECOVERY_CEILING,
        window: Some(DIVERGENCE_WINDOW),
    };

    /// Raise (or lower) the ceiling for this scope: walk `0..ceiling`.
    #[must_use]
    pub const fn with_ceiling(self, ceiling: u32) -> ScanScope {
        ScanScope { ceiling, ..self }
    }

    /// The window's edges around `local`, inclusive, when there is a window
    /// and a local index. The high edge stops one short of `u32::MAX`.
    fn window_edges(&self, local: Option<WotsIndex>) -> Option<(u32, u32)> {
        match (self.window, local) {
            (Some(w), Some(local)) => {
                let lo = local.get().saturating_sub(w);
                let hi = local.get().saturating_add(w).min(u32::MAX - 1);
                Some((lo, hi))
            }
            _ => None,
        }
    }

    /// The positions, window first, then the recovery range ascending with
    /// the window's members skipped. Lazy: a raised ceiling is walked, never
    /// materialised.
    fn positions(&self, local: Option<WotsIndex>) -> impl Iterator<Item = WotsIndex> {
        let edges = self.window_edges(local);
        let window = edges.map(|(lo, hi)| lo..=hi);
        let ceiling = self.ceiling;
        window
            .into_iter()
            .flatten()
            .chain((0..ceiling).filter(move |i| !edges.is_some_and(|(lo, hi)| (lo..=hi).contains(i))))
            .map(WotsIndex::from_raw)
    }

    /// How many positions a walk of this scope around `local` reaches if it
    /// finds nothing: the [`Progress::ceiling`] it reports against.
    ///
    /// Counted from the scope's edges, not by walking [`ScanScope::positions`]:
    /// the window, plus the recovery range, less the members of the range the
    /// window already holds. A raised ceiling can name four billion
    /// positions, and enumerating them before the first report -- with no
    /// cancel asked meanwhile, and for an account in sync that walks none --
    /// would be the wait this figure exists to describe.
    pub(crate) fn reach(&self, local: Option<WotsIndex>) -> u32 {
        let ceiling = u64::from(self.ceiling);
        let total = match self.window_edges(local) {
            None => ceiling,
            Some((lo, hi)) => {
                let (lo, hi) = (u64::from(lo), u64::from(hi));
                let window = (hi + 1).saturating_sub(lo);
                let shared = match ceiling.checked_sub(1) {
                    None => 0,
                    Some(last) => (hi.min(last) + 1).saturating_sub(lo),
                };
                window + ceiling - shared
            }
        };
        u32::try_from(total).unwrap_or(u32::MAX)
    }
}

/// What a reconciled account is: local and chain agree, and what about. No
/// longer `Copy`: the outstanding arm carries a [`Reservation`], which
/// may hold the error a tip read returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    /// Chain and local agree and nothing is reserved.
    InSync {
        index: WotsIndex,
        address: Address,
        balance: u64,
    },
    /// A reservation is open and the chain still holds the tag at the key
    /// that signed: the spend has not landed. It may never — a 200 from
    /// `/construction/submit` is a socket write and not a verdict — so this
    /// state is resolved by the operator, through
    /// `Wallet::settle_if_landed` when it lands or
    /// `Wallet::resign_pending` when the artifact is gone — which rebuilds
    /// the same bytes with the same key rather than burning it.
    SpendOutstanding {
        spent_index: WotsIndex,
        balance: u64,
        /// Whether the signed artifact can still be accepted, from the
        /// record's figures against the entry and the tip (the diagnosis once
        /// filed as debt). A dead reservation is
        /// still this `Ok` state -- `Wallet::open` succeeds on it -- because
        /// a refusal would take the diagnosis from the operator whose funds
        /// are stuck; the pages render the verdict.
        reservation: Reservation,
    },
    /// A reservation is open and the chain holds the tag at the **change**
    /// key: the spend landed. One observation is the settle rule;
    /// `Wallet::settle_if_landed`'s doc argues why depth buys nothing.
    SpendLanded {
        spent_index: WotsIndex,
        settled_index: WotsIndex,
        balance: u64,
    },
}

/// What reconciliation can say about an open reservation's artifact from the
/// store and the chain alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The figures were not recorded: the reservation was written under
    /// format version 3, which carried neither the balance nor the
    /// block-to-live. Neither live nor dead can be told from this store, and
    /// this arm says so rather than treating an absent balance as an unmoved
    /// one. No tip is read for it.
    Unrecorded,
    /// The figures were recorded and both comparisons were made.
    Recorded(Diagnosis),
}

/// The two comparisons a recorded reservation admits, each with what was
/// observed. Both are rendered; a reservation dead by both causes says both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnosis {
    pub figures: Figures,
    /// `entry.balance != figures.reserved_balance`. In the outstanding arm the
    /// tag is at the spent address, so a spend from this key has not landed
    /// and the balance can only have RISEN -- a deposit credits by tag, in
    /// place (module doc, fact 1) -- and `tx_val` demands
    /// `send + change + fee` equal the balance exactly, so
    /// the signed bytes are dead.
    pub balance_moved: bool,
    /// The balance the entry carries now.
    pub balance_now: u64,
    pub expiry: Expiry,
}

/// The block-to-live against the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// `blk_to_live == 0`: never expires, and the reference
    /// checks only non-zero values (`tx.c`), so no tip is read for it.
    NoExpiry,
    /// The tip is below the block-to-live: still landable.
    Below { tip: u64 },
    /// The tip has REACHED the block-to-live. Block N is the last block that
    /// can carry btl N, and
    /// `txclean` drops it against `Cblocknum + 1`, so the
    /// artifact can never be included: dead at `tip >= blk_to_live`, the
    /// boundary the rule draws. (At `tip == blk_to_live` a node still
    /// accepts the submit and drops it at the next `txclean`; the reservation
    /// is dead because it can never be included, which is what the page
    /// means.)
    Reached { tip: u64 },
    /// `blk_to_live != 0` and `/network/status` could not be read. Neither a
    /// refusal nor a default to live: the outstanding state is
    /// rendered with the expiry unchecked and the failed read named.
    Unreadable { cause: Error },
}

impl Diagnosis {
    /// Dead when the balance moved or the block-to-live was reached; an
    /// unreadable tip is neither dead nor asserted live.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.balance_moved || matches!(self.expiry, Expiry::Reached { .. })
    }
}

impl AccountStatus {
    /// The index this account will sign with next, whatever its state.
    #[must_use]
    pub fn index(&self) -> WotsIndex {
        match self {
            AccountStatus::InSync { index, .. } => *index,
            AccountStatus::SpendOutstanding { spent_index, .. } => *spent_index,
            AccountStatus::SpendLanded { settled_index, .. } => *settled_index,
        }
    }

    /// nanoMochimo the chain holds for the tag.
    #[must_use]
    pub fn balance(&self) -> u64 {
        match self {
            AccountStatus::InSync { balance, .. }
            | AccountStatus::SpendOutstanding { balance, .. }
            | AccountStatus::SpendLanded { balance, .. } => *balance,
        }
    }
}

/// Where the chain's address for a tag sits relative to this seed's keys, as
/// [`scan_for_address`] found it. The diagnostic half of a divergence report:
/// a refusal that says only *mismatch* satisfies I4's letter and manufactures
/// the workaround the invariant exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainPosition {
    /// The chain's address is this seed's key at a position **ahead** of the
    /// local index: a spend from this seed landed that local state does not
    /// record — this wallet's, from an older copy of its state, or a second
    /// wallet's on the same seed.
    Ahead { index: WotsIndex, gap: u32 },
    /// The chain's address is this seed's key at a position **behind** the
    /// local index: a spend has not landed, local state was advanced past the
    /// chain, or the node answers for a chain on which this account has spent
    /// fewer times.
    Behind { index: WotsIndex, gap: u32 },
    /// No position the walk reached reproduces the chain's address. `scope`
    /// is what was walked around `local`, and `stopped` is `Some` when the
    /// walk ended before the scope did, so the report can say exactly that
    /// and nothing more: the account may have spent more times than the walk
    /// reaches, this seed may not own this tag, or the wallet may be on
    /// another chain, and this arm cannot tell which.
    ///
    /// A name like `NotThisSeed` asserts at type level the one explanation a
    /// bounded walk cannot support, and every `match` arm on it then reads
    /// *not this seed* for a wallet merely further along than the walk.
    Unlocated {
        local: WotsIndex,
        scope: ScanScope,
        stopped: Option<Stopped>,
    },
}

impl fmt::Display for ChainPosition {
    /// The neutral rendering, for reports whose action does not depend on the
    /// direction (the reservation arm). The index-mismatch arm renders each
    /// variant with its own action instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainPosition::Ahead { index, gap } => write!(
                f,
                "the chain's address IS this seed's key at index {} -- {gap} ahead of local",
                index.get()
            ),
            ChainPosition::Behind { index, gap } => write!(
                f,
                "the chain's address IS this seed's key at index {} -- {gap} BEHIND local",
                index.get()
            ),
            ChainPosition::Unlocated {
                local,
                scope,
                stopped,
            } => {
                write!(f, "no key index this scan walked reproduces the chain's address (walked: ")?;
                walked(f, *local, scope)?;
                f.write_str(")")?;
                match stopped {
                    Some(Stopped { at, by: StoppedBy::Derivation }) => write!(
                        f,
                        "; the walk stopped at index {at} on a derivation error and did not finish"
                    )?,
                    Some(Stopped { at, by: StoppedBy::Cancelled }) => write!(
                        f,
                        "; the walk was stopped at index {at} before it finished, so this says \
                         less than a completed one would"
                    )?,
                    None => {}
                }
                Ok(())
            }
        }
    }
}

/// The positions a scope walked around `local`, in words, for the report:
/// the window's edges when there is one, then the recovery range as `0
/// through ceiling-1` — never *within ceiling*, which reads as one more than
/// was tried.
fn walked(f: &mut fmt::Formatter<'_>, local: WotsIndex, scope: &ScanScope) -> fmt::Result {
    let mut wrote = false;
    if let Some((lo, hi)) = scope.window_edges(Some(local)) {
        write!(
            f,
            "indices {lo} through {hi}, {} either side of index {}",
            scope.window.unwrap_or(0),
            local.get()
        )?;
        wrote = true;
    }
    if scope.ceiling > 0 {
        if wrote {
            f.write_str(", and ")?;
        }
        write!(f, "indices 0 through {}", scope.ceiling - 1)?;
        wrote = true;
    }
    if !wrote {
        f.write_str("no positions at all")?;
    }
    Ok(())
}

/// A caller's answer to *should this walk stop now?*, asked once per key
/// position.
///
/// [`ScanScope`] says how far a walk may go; this says whether it may keep
/// going. The two are separate because they answer to different people: the
/// scope is a property of the recovery question being asked, and this is the
/// operator changing their mind about waiting.
///
/// # Why a walk needs to be stoppable at all, which is not about patience
///
/// A restore walks up to [`RECOVERY_CEILING`] positions with the master seed
/// borrowed across every one of them, and the seed is a [`Secret`]: it is
/// overwritten when it drops, and that is the whole of this crate's answer
/// for it in memory.
///
/// **The overwrite only happens if the process unwinds or returns.** Nothing
/// in this tree installs a signal handler, so a `SIGINT` at the terminal --
/// the ordinary way a person ends a wait they did not expect to be this long
/// -- terminates the process with no destructor run and the seed intact in
/// pages the kernel is about to hand back. That is the same argument the
/// workspace manifest makes for `panic = "unwind"` over `panic = "abort"`,
/// reaching a signal the manifest does not mention.
///
/// This type is the mechanism that makes the other answer available: a caller
/// that can notice the interruption can stop the walk, get an ordinary
/// `Err(Error::Cancelled)` back, and let every `Drop` between there and the
/// top run. **It is not itself that answer.** Nothing in this crate and
/// nothing in the shipped binary installs a signal handler, so at the command
/// line the gap stays open and `README.md` says so. What is closed is the part
/// a library can close: the walk is stoppable from outside it.
///
/// # Why the binary does not install one, which is a decision and not an omission
///
/// Three things are true together and the trade comes out against it.
///
/// **It cannot be done with what is here.** `std` has no signal interface, so
/// a handler needs `libc` or a wrapper over it -- the first dependency this
/// crate would carry for something that is neither a cryptographic primitive,
/// a codec, nor a check. Every other entry in the manifest is argued against
/// its alternatives; this one would be argued against a `README` paragraph.
///
/// **It costs the `unsafe` count, which is currently nought.** A signal
/// handler is `unsafe` in Rust and is bound by what is async-signal-safe: no
/// allocation, no locks, a relaxed store to a flag and nothing else. The
/// handler that would be written here is a safe one to write -- and it would
/// still be the only `unsafe` block under `src/`, introduced to shorten a
/// wait.
///
/// **What it buys is narrower than it looks.** The scrub it would save is on
/// a path an operator reaches by not wanting to wait, and the wait it
/// shortens is bounded by the scope they themselves named. The caller this
/// type is really for is the one with an event loop and a button, which
/// watches a flag without needing a handler at all -- so the mechanism serves
/// that caller today, while the handler would serve only the terminal, at the
/// price of both lines above.
///
/// The gap is therefore recorded rather than closed: `README.md` carries it
/// in the limits section, beside the paragraph about memory not being locked,
/// which is the same subject and the same kind of answer.
///
/// # The predicate's obligations
///
/// It is called once per position, on the walking thread, and it must be
/// cheap -- a relaxed load of a flag is the shape intended. It must not lock
/// anything the caller also holds elsewhere, and it must not panic: a panic
/// here unwinds through the walk, which does run the destructors, but it
/// leaves the caller with a panic where a refusal was available.
pub struct Cancel<'a>(Option<&'a dyn Fn() -> bool>);

impl Cancel<'static> {
    /// The walk runs to its scope's end. What every caller that cannot be
    /// interrupted passes, including every one in this crate today.
    pub const NEVER: Cancel<'static> = Cancel(None);
}

impl<'a> Cancel<'a> {
    /// Stop as soon as `asked` answers `true`.
    #[must_use]
    pub fn when(asked: &'a dyn Fn() -> bool) -> Cancel<'a> {
        Cancel(Some(asked))
    }

    /// Ask. `NEVER` never asks, so a caller that passes it pays no call at
    /// all rather than a call that returns `false`.
    ///
    /// Crate-visible because the operations that return [`Unfinished`] ask
    /// it between their steps as well as once per position.
    pub(crate) fn stop(&self) -> bool {
        matches!(self.0, Some(asked) if asked())
    }
}

/// What a cancellable operation returns in place of its result: stopped by
/// its [`Cancel`], or refused for a reason of its own.
///
/// # Why a cancel is a variant here and not inside the refusal
///
/// A refusal is a finding -- about an account, the chain or the store -- and
/// a caller shows it to the person it is about. A cancel is the caller's own
/// decision coming back, and it found nothing. Carried inside the refusal it
/// would be one more report for that caller to read and recognise; carried
/// here it is told apart by a `match`, and a walk that ended
/// [`StoppedBy::Cancelled`] never reaches a page that names an account.
///
/// **A call that returns `Cancelled` wrote nothing.** Each of these
/// operations that writes asks its `Cancel` again before its one write, so a
/// call that changed the store returns its result, however late the cancel
/// arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfinished<E> {
    /// The [`Cancel`] said to stop. Nothing was decided and nothing was
    /// written.
    Cancelled,
    /// The operation's own refusal, as the form of it that takes no `Cancel`
    /// returns it.
    Refused(E),
}

impl<E> From<E> for Unfinished<E> {
    fn from(refusal: E) -> Unfinished<E> {
        Unfinished::Refused(refusal)
    }
}

/// Run `walk` under a [`Cancel`] that asks `cancel` and remembers whether it
/// ever said stop, and return that beside the walk's result.
///
/// For a caller that meets a cancel only as a refusal it cannot tell from
/// another, because the walk's own record of it stays inside the call.
/// [`Cancel::when`] asks only that a stop be answered once, so asking the
/// predicate again afterwards may hear `false` from one that already ended
/// the walk -- a flag cleared as it is read, or a predicate that says stop
/// exactly once -- and read the cancel's refusal as a finding. `NEVER` runs
/// as it is, unasked, and says no.
pub(crate) fn remembered<R>(cancel: &Cancel<'_>, walk: impl FnOnce(&Cancel<'_>) -> R) -> (R, bool) {
    if cancel.0.is_none() {
        return (walk(cancel), false);
    }
    let said_stop = core::cell::Cell::new(false);
    let asked = || {
        let stop = cancel.stop();
        if stop {
            said_stop.set(true);
        }
        stop
    };
    let result = walk(&Cancel::when(&asked));
    (result, said_stop.get())
}

/// How far a long operation has got, for a caller that shows it.
///
/// **Counted, never estimated.** `account` of `accounts` is the account the
/// operation is on, counted from zero. `position` of `ceiling` is how many
/// key positions that account's walk has reached of the most it can reach;
/// a walk that finds what it is looking for stops short of `ceiling`, and an
/// operation that walks nothing -- a sweep -- reports a `ceiling` of zero.
///
/// It is reported before each account, with `position` zero, and every
/// [`PROGRESS_EVERY`] positions of a walk. An account in sync needs no walk,
/// so its one report is the first; `ceiling` there is what a walk would
/// reach, since whether one runs is known only after the node has answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub account: u32,
    pub accounts: u32,
    pub position: u32,
    pub ceiling: u32,
}

/// How many positions a walk reaches between two reports of its
/// [`Progress`].
pub const PROGRESS_EVERY: u32 = 256;

/// Run `walk` under a [`Cancel`] that asks `cancel` and, every
/// [`PROGRESS_EVERY`] positions, hands `progress` how far it has got. With no
/// `progress`, `walk` runs under `cancel` itself and nothing is counted.
///
/// The count rests on the predicate's obligation above: a walk asks once per
/// position, so the askings are the positions reached, and no walk grows a
/// parameter for it.
pub(crate) fn watched<'p, R>(
    cancel: &Cancel<'_>,
    progress: Option<&mut (dyn FnMut(Progress) + 'p)>,
    at: Progress,
    walk: impl FnOnce(&Cancel<'_>) -> R,
) -> R {
    let Some(progress) = progress else {
        return walk(cancel);
    };
    let reached = core::cell::Cell::new(0u32);
    let progress = core::cell::RefCell::new(progress);
    let asked = || {
        let n = reached.get().saturating_add(1);
        reached.set(n);
        if n.is_multiple_of(PROGRESS_EVERY) {
            (*progress.borrow_mut())(Progress { position: n, ..at });
        }
        cancel.stop()
    };
    walk(&Cancel::when(&asked))
}

/// A walk that ended before its scope did: where it stopped, and what stopped
/// it.
///
/// # Why the cause is recorded and not inferred
///
/// This was `failed_at: Option<u32>` -- a position and nothing else -- and
/// both renderings of it supplied the missing half themselves, one saying the
/// walk stopped *on a derivation error* and the other that *deriving index
/// n failed*. That was true of every walk that could stop early at the time
/// it was written, and it stopped being true the moment a walk could be
/// cancelled: the same field then carried an operator's decision and the
/// report called it a fault.
///
/// A renderer cannot be careful about this, because the distinction is not in
/// what it was handed. So the record carries the cause and the report reads
/// it, which is the only arrangement in which the sentence cannot drift from
/// the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stopped {
    /// The position the walk had reached.
    pub at: u32,
    /// What ended it.
    pub by: StoppedBy,
}

/// What ended a walk early. Two things can, and they are not the same news.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoppedBy {
    /// Deriving that position's address failed. The walk says less than it
    /// would have, and the reason is a fault worth reporting.
    Derivation,
    /// A [`Cancel`] said to stop. Nothing failed, and the report should not
    /// suggest anything is to be fixed.
    Cancelled,
}

/// Why the wallet will not start. Every variant renders a report naming what
/// diverged, by how much, and one action (I4's clause that message
/// quality is part of the requirement, not a nicety).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Divergence {
    /// The chain holds this tag at an address that is not the key this store
    /// would sign with next, and no reservation explains it.
    IndexMismatch {
        tag: Tag,
        local: WotsIndex,
        local_address: Address,
        chain_address: Address,
        /// The balance the chain holds for the tag: what is at stake in the
        /// decision the report asks for. Without it an operator deciding
        /// whether to advance learns the amount only after advancing.
        balance: u64,
        stream: StreamId,
        found: ChainPosition,
        /// The retained settled block whose `spent_index` is the index the
        /// chain sits at, when `found` is a `Behind` by exactly that block:
        /// this store recorded a settle at that index
        /// and this node's answer does not show it. `None` for an `Ahead`,
        /// an `Unlocated`, a `Behind` at any other index, or no retained
        /// block. The report adds the causes that fit it and prefers none.
        reverted_settle: Option<Pending>,
    },
    /// A reservation is open and the chain holds the tag at neither the key
    /// that signed nor the change key. Something moved this tag that this
    /// store did not.
    ReservationUnexplained {
        tag: Tag,
        spent_index: WotsIndex,
        chain_address: Address,
        /// The balance the chain holds for the tag (see `IndexMismatch`).
        balance: u64,
        stream: StreamId,
        found: ChainPosition,
    },
    /// The node answered *account not found* for this tag. **That is what was
    /// observed, and it is all that was observed** (module doc, fact 3): the
    /// Mesh gives that answer for a tag the ledger has no entry for, for a tag
    /// the ledger holds at zero balance, and for a lookup that failed, and it
    /// does not say which. A name like `TagUnknownToTheChain` asserts at type
    /// level that the answer is the ledger's absence — which by fact 1 means
    /// *never funded*, said to an operator whose account has been paid.
    TagUnresolved { tag: Tag, local: WotsIndex },
    /// The chain could not be reached. Not a divergence in itself; a
    /// reconciliation that could not be performed, which fails the same way
    /// because an unreconciled wallet must not sign.
    ChainUnreachable { tag: Tag, cause: Error },
    /// A derived account with no master seed supplied: its addresses cannot
    /// be computed, so it cannot be reconciled.
    NoMasterForDerivedAccount { tag: Tag },
    /// Reconciliation itself failed — a store error, a response that did not
    /// parse, a key that would not derive.
    CannotReconcile { tag: Tag, cause: Error },
}

impl Divergence {
    /// The tag this is about.
    #[must_use]
    pub fn tag(&self) -> Tag {
        match self {
            Divergence::IndexMismatch { tag, .. }
            | Divergence::ReservationUnexplained { tag, .. }
            | Divergence::TagUnresolved { tag, .. }
            | Divergence::ChainUnreachable { tag, .. }
            | Divergence::NoMasterForDerivedAccount { tag }
            | Divergence::CannotReconcile { tag, .. } => *tag,
        }
    }

    /// The index an operator would have to acknowledge to advance past this,
    /// when the report found one. `None` when advancing is not a remedy.
    ///
    /// **It is the found index itself, not one past it.** The chain's current
    /// address for a tag is the address of the key that will sign *next* —
    /// `SpendPlan::new` refuses unless `entry.address` equals the source
    /// address at the stored index — so a chain sitting at index *i* means
    /// local state belongs at *i*. Written as `index.advanced()` first, and
    /// the test that advances and then reconciles again caught it: after an
    /// off-by-one advance the wallet reconciled as *behind by one* forever.
    ///
    /// Only an [`Divergence::IndexMismatch`] has one. A reservation the chain
    /// explains at neither of its keys is not advanced past; its report says
    /// to find what moved the tag first.
    #[must_use]
    pub fn advance_target(&self) -> Option<WotsIndex> {
        match self {
            Divergence::IndexMismatch {
                found: ChainPosition::Ahead { index, .. },
                ..
            } => Some(*index),
            _ => None,
        }
    }

    /// Whether this report's diagnostic walk was ended by a [`Cancel`].
    ///
    /// Such a report is true -- the comparison had already failed when the
    /// walk began -- and incomplete, so an operation that returns
    /// [`Unfinished`] answers it as `Cancelled` rather than handing it on as
    /// a finding.
    pub(crate) fn stopped_by_cancel(&self) -> bool {
        match self {
            Divergence::IndexMismatch { found, .. } | Divergence::ReservationUnexplained { found, .. } => matches!(
                found,
                ChainPosition::Unlocated {
                    stopped: Some(Stopped {
                        by: StoppedBy::Cancelled,
                        ..
                    }),
                    ..
                }
            ),
            _ => false,
        }
    }
}

fn hex20(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl fmt::Display for Divergence {
    /// The operator's report. **Four things, every arm**: what diverged, the
    /// two indices (or why there is no second one), the size of the gap, and
    /// the action. Asserted as rendered text by
    /// `tests/invariants.rs::startup_refuses_to_start_on_index_divergence`,
    /// because failure-path text is invisible to a passing suite.
    ///
    /// The three arms of the index-mismatch report each name every cause
    /// that fits what was observed and prefer none: a bounded
    /// walk cannot tell a far-along account from a foreign seed, and an
    /// `Ahead` cannot tell this wallet's own older state from a second
    /// wallet's spending.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Divergence::IndexMismatch {
                tag,
                local,
                local_address,
                chain_address,
                balance,
                stream,
                found,
                reverted_settle,
            } => {
                write!(
                    f,
                    "account {}: the chain holds this tag at an address this keystore does not \
                     expect.\n  local index {} expects {}\n  the chain holds        {}\n  \
                     with a balance of      {} nanoMCM\n  key stream {}\n",
                    hex20(tag),
                    local.get(),
                    hex20(local_address),
                    hex20(chain_address),
                    balance,
                    hex20(stream.as_bytes()),
                )?;
                match found {
                    ChainPosition::Ahead { index, gap } => write!(
                        f,
                        "  the chain's address IS this seed's key at index {} -- {gap} ahead of \
                         local. A spend from this seed landed that this local state does not \
                         record: either this wallet's own, and local state is an older copy \
                         (a backup, a restore), or a SECOND WALLET on this seed spent. A crash \
                         between signing and saving cannot leave this state at any gap: the \
                         index and its reservation are written durably before a signature \
                         exists, so a spend interrupted after signing shows up as a reservation, \
                         never as this mismatch.\n  ACTION: confirm no second wallet holds this seed (compare \
                         the key stream above with any other wallet's report), then advance to \
                         {} through the acknowledged path, naming that index. Do NOT edit local \
                         state by hand.",
                        index.get(),
                        index.get(),
                    ),
                    ChainPosition::Behind { index, gap } => {
                        write!(
                            f,
                            "  the chain's address IS this seed's key at index {} -- {gap} BEHIND \
                             local. Either a spend has not landed yet, or local state was advanced \
                             past the chain, or this node answers for a chain on which this account \
                             has spent fewer times (check the node URL if the gap is large).\n  \
                             ACTION: wait for the spend to land and reconcile again. If it never \
                             lands, the key at index {} was skipped and the difference is permanent; \
                             advancing local state backwards is never a remedy.",
                            index.get(),
                            index.get(),
                        )?;
                        // The retained settled block, when the chain sits at
                        // exactly the index it settled.
                        // Added to the causes above rather than replacing
                        // them, every cause that fits named and none
                        // preferred, and both halves of what is
                        // true of the bytes printed.
                        if let Some(s) = reverted_settle {
                            let figures = match s.figures {
                                Some(Figures {
                                    reserved_balance,
                                    blk_to_live,
                                }) => format!(
                                    "reserved balance {reserved_balance} nanoMCM, block-to-live {blk_to_live}"
                                ),
                                None => "figures not recorded: this reservation was written before format version 4 recorded them".to_string(),
                            };
                            write!(
                                f,
                                "\n  This store recorded a SETTLE at index {} (digest {}; {figures}) and this \
                                 node's answer does not show it. Two things produce that and this report \
                                 cannot tell them apart: a reorg reverted the block that settled it, or the \
                                 settle was taken on the single observation the settle rule permits against a \
                                 node that does not share this chain or had not seen it -- in which case \
                                 the spend may be unlanded still and may yet land. The signature at that \
                                 digest is the only one key {} may ever give, and it is still acceptable \
                                 while the balance at the source has not moved and a non-zero block-to-live \
                                 has not passed, so a copy of the artifact held outside the \
                                 store can be re-submitted. THIS BUILD HAS NO COMMAND THAT TURNS THE \
                                 RETAINED BLOCK BACK INTO THOSE BYTES: the store keeps the digest, the index \
                                 and the figures, but `resign` runs only after the wallet opens and the \
                                 wallet refuses on this very divergence, and both re-signers read the open \
                                 reservation, which this state leaves clear. Keep any copy of the artifact \
                                 you have. Whether the wallet may re-open the block is not decided.",
                                s.spent_index.get(),
                                hex20(&s.digest),
                                s.spent_index.get(),
                            )?;
                        }
                        Ok(())
                    }
                    ChainPosition::Unlocated {
                        local,
                        scope,
                        stopped,
                    } => {
                        f.write_str("  NO key index this scan walked reproduces the chain's address (walked: ")?;
                        walked(f, *local, scope)?;
                        f.write_str(").")?;
                        match stopped {
                            Some(Stopped { at, by: StoppedBy::Derivation }) => write!(
                                f,
                                " The walk did not finish: deriving index {at} failed, so this says \
                                 less than it would."
                            )?,
                            Some(Stopped { at, by: StoppedBy::Cancelled }) => write!(
                                f,
                                " The walk did not finish: it was stopped at index {at}, so this \
                                 says less than it would. Nothing failed and nothing is owed but \
                                 the search."
                            )?,
                            None => {}
                        }
                        f.write_str(
                            " Three things produce that and this report cannot tell them apart: \
                             this account has spent more times than the walk reaches -- local \
                             state is an older copy, or a second wallet on this seed has been \
                             spending; this seed does not own this tag; or this wallet is pointed \
                             at another chain.\n  ACTION: if this account may have spent more \
                             times than the walk reaches, search further along by raising the \
                             scan ceiling -- the scan finds the exact index or fails again, and \
                             searching writes nothing. Then advance through the acknowledged path, \
                             naming the index it found: the index you name is derived and compared \
                             to the chain's address, and refused if it does not match. If no \
                             ceiling you can name finds it, check the seed and the node URL. \
                             Before advancing at all, confirm no second wallet holds this seed \
                             (compare the key stream above): nothing is advanced until you name an \
                             index the chain confirms, and the confirmation cannot see a second \
                             wallet.",
                        )
                    }
                }
            }
            Divergence::ReservationUnexplained {
                tag,
                spent_index,
                chain_address,
                balance,
                stream,
                found,
            } => write!(
                f,
                "account {}: a spend is reserved at index {} but the chain holds this tag at \
                 neither the key that signed nor the change key.\n  the chain holds {}\n  with a \
                 balance of {} nanoMCM\n  key stream {}\n  {found}\n  ACTION: something moved this \
                 tag that this wallet did not. Compare the key stream against every other wallet \
                 on this seed before doing anything else. Neither settling nor re-signing is \
                 correct until that is answered.",
                hex20(tag),
                spent_index.get(),
                hex20(chain_address),
                balance,
                hex20(stream.as_bytes()),
            ),
            // Three readings, none preferred (module doc, fact 3). A page
            // that picks one sends an operator whose account has just been
            // paid to fund it, remove it, or check the seed.
            Divergence::TagUnresolved { tag, local } => write!(
                f,
                "account {}: the node did not resolve this tag -- it answered \"account not \
                 found\" -- and local state is at index {}.\n  That answer does not mean what it \
                 says. The Mesh gives it in three situations it does not distinguish: the ledger \
                 has no entry for this tag, which means it has never been funded on this chain; \
                 the ledger holds this tag at ZERO balance, which the Mesh's quorum discards; or \
                 the lookup itself failed -- too few nodes answered, a node between blocks, a \
                 timeout -- which a live node was seen doing for every tag on the chain at once, \
                 funded ones included.\n  ACTION: ask again in a minute. Only if the same answer \
                 comes back from a node that reports itself synchronized is the account absent or \
                 empty: if it is new and unfunded, fund it or remove it from the store before \
                 starting; if it has spent to zero, it cannot be reconciled through this endpoint \
                 until it is paid again; if it should have funds, the wallet is pointed at the \
                 wrong chain or the seed is not the one that made it -- check both. Nothing is \
                 decided by one answer: do not create, restore or advance anything on it.",
                hex20(tag),
                local.get(),
            ),
            Divergence::ChainUnreachable { tag, cause } => write!(
                f,
                "account {}: the chain could not be reached, so this account could not be \
                 reconciled ({cause}).\n  ACTION: an unreconciled wallet must not sign -- a \
                 restored seed and a live second instance both look exactly like a healthy \
                 wallet from local state alone. Restore the connection and start again. There is \
                 no offline mode that signs.",
                hex20(tag),
            ),
            Divergence::NoMasterForDerivedAccount { tag } => write!(
                f,
                "account {}: derived, and no master seed was supplied, so its addresses cannot \
                 be computed and it cannot be reconciled.\n  ACTION: supply the master seed, or \
                 remove the account from this store.",
                hex20(tag),
            ),
            Divergence::CannotReconcile { tag, cause } => write!(
                f,
                "account {}: reconciliation failed before it could compare anything ({cause}).\n  \
                 ACTION: this is not a divergence -- it is a wallet that could not ask the \
                 question. Fix the cause and start again; do not advance local state.",
                hex20(tag),
            ),
        }
    }
}

/// An operator's acknowledgement of one specific divergence, naming the tag
/// and the index they were shown.
///
/// This is what makes *advance silently* unrepresentable. It cannot be built
/// from nothing: [`OperatorAcknowledgement::of`] takes the [`Divergence`] the
/// report produced, so the only route to one is having a divergence in hand,
/// and [`advance_after_operator_review`] refuses an acknowledgement whose tag
/// and target do not match the divergence the store is *currently* in. An
/// operator cannot acknowledge a divergence they did not read, and cannot
/// acknowledge one and apply it to another.
///
/// Re-exported from `wallet`, and defined here because the CLI's `reconcile`
/// runs before a `Wallet` exists: the gate is the acknowledgement, not the
/// wallet type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorAcknowledgement {
    tag: Tag,
    target: WotsIndex,
}

impl OperatorAcknowledgement {
    /// Acknowledge a divergence the report produced. `None` when advancing is
    /// not a remedy for it — a chain that could not be reached, a tag the
    /// ledger does not hold, an address no walked index reproduces, a
    /// reservation the chain explains at neither key. Those are not gaps to
    /// close, and there is deliberately no way to say otherwise: the way to
    /// turn an unlocated address into an `Ahead` is to raise the ceiling and
    /// have the scan find it ([`ScanScope::with_ceiling`]).
    #[must_use]
    pub fn of(divergence: &Divergence) -> Option<OperatorAcknowledgement> {
        divergence.advance_target().map(|target| OperatorAcknowledgement {
            tag: divergence.tag(),
            target,
        })
    }

    #[must_use]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    #[must_use]
    pub fn target(&self) -> WotsIndex {
        self.target
    }
}

/// How one walk ended.
enum Walk {
    Found(WotsIndex),
    NotFound,
    Failed { at: u32, cause: Error },
}

/// Walk the positions `scope` names around `local`, deriving each address,
/// and stop on the one that equals `target`.
fn walk<F>(target: &Address, scope: &ScanScope, local: Option<WotsIndex>, mut address_at: F) -> Walk
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    for p in scope.positions(local) {
        match address_at(p) {
            Ok(a) if a == *target => return Walk::Found(p),
            Ok(_) => {}
            Err(cause) => return Walk::Failed { at: p.get(), cause },
        }
    }
    Walk::NotFound
}

/// Walk the positions `scope` names around `local`, deriving each address,
/// and stop on the one that equals `target`.
///
/// **This is the target-directed shape and it stops on the match**. It is
/// not a gap scan and could not be one: per-index usage is
/// unobservable on this chain (module doc, fact 2), so a run of "unused"
/// indices is not a signal any query produces. The scope is reported on
/// failure and never guessed past.
///
/// `address_at` is the caller's derivation, so the same routine serves an
/// account already in a store (`Keystore::address_at`) and a seed being
/// restored into one (`derived_address_at`). `local` is the index a window
/// is centred on; restore has none.
pub fn scan_for_address<F>(
    target: &Address,
    scope: &ScanScope,
    local: Option<WotsIndex>,
    address_at: F,
) -> Result<Option<WotsIndex>>
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    match walk(target, scope, local, address_at) {
        Walk::Found(p) => Ok(Some(p)),
        Walk::NotFound => Ok(None),
        Walk::Failed { cause, .. } => Err(cause),
    }
}

/// The address of a derived account's key at `position`, from the master seed
/// — the restore path's derivation, where no store exists yet.
///
/// Must agree with [`Keystore::address_at`] for the same account; they reach
/// it by different routes and `tests/recon.rs` asserts they agree, which is
/// the second degree of freedom.
#[must_use]
pub fn derived_address_at(master: &Secret<SEED_LEN>, account_index: u32, position: WotsIndex) -> Address {
    let account = derive::derive_account(master, account_index);
    match position.rotation() {
        None => account.first_key().address(&account.tag()),
        Some(rotation) => derive::derive_wots_key(account.seed(), rotation).address(&account.tag()),
    }
}

/// Which access an account's kind needs: the master for a derived account,
/// the stored root for an imported one. A derived account with no master
/// supplied cannot have its addresses computed at all, so it is a divergence
/// (unreconcilable) rather than a silently skipped account.
///
/// Was `Wallet::access_for`, private, once; the pre-gate commands need
/// the same per-account choice and a store-wide one is wrong for a store
/// holding both kinds (`key_at` refuses the other kind's access).
#[allow(clippy::result_large_err)]
pub fn access_for<'a, M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    master: Option<&'a Secret<SEED_LEN>>,
) -> core::result::Result<KeyAccess<'a>, Divergence> {
    let view = match store.view(tag) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Err(Divergence::CannotReconcile {
                tag: *tag,
                cause: Error::NoSuchAccount,
            })
        }
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };
    match view.kind {
        AccountKind::Imported => Ok(KeyAccess::StoredRoot),
        AccountKind::Derived => master
            .map(KeyAccess::Master)
            .ok_or(Divergence::NoMasterForDerivedAccount { tag: *tag }),
    }
}

/// What a restore found: the tag, the index the chain puts it at, and the
/// balance there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredAccount {
    pub tag: Tag,
    pub index: WotsIndex,
    pub address: Address,
    pub balance: u64,
}

/// Why a restore did not produce an index. **Every variant is a failure and
/// none is a fallback**: I5's clause that restore never defaults to zero is
/// unconditional, and a restore that guesses re-signs with every key the
/// original wallet already used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreFailure {
    /// The chain could not be reached. Fail, never assume.
    ChainUnreachable { tag: Tag, cause: Error },
    /// The node answered *account not found* for the tag, so there is no
    /// address to derive an index from. Three readings and this variant
    /// cannot tell them apart (module doc, fact 3): never funded, emptied, or
    /// a lookup that failed. A text saying *never funded* would tell the
    /// operator to create the account rather than restore it -- for an
    /// account that, under two of the three readings, has spent.
    TagUnresolved { tag: Tag },
    /// The tag resolves, but none of the first `scanned` positions reproduces
    /// its address. Three causes, and this variant cannot tell them apart: the
    /// account has spent at least `scanned` times (a wallet merely far along
    /// — the one cause a ceiling produces by construction), this seed does
    /// not own this tag, or the wallet is on another chain. The remedy for the
    /// first is a higher ceiling for one invocation
    /// ([`ScanScope::with_ceiling`]), which finds the exact index or fails
    /// again; nothing is ever assumed. The ceiling bounds the failing search
    /// only; the message this replaced named the first cause and denied it.
    NoIndexReproducesTheAddress {
        tag: Tag,
        address: Address,
        scanned: u32,
    },
    /// The scan itself failed.
    CannotScan { tag: Tag, cause: Error },
    /// The scan found the index and the store refused to take the account.
    /// Nothing reached disk: the account is written in one commit, at the
    /// found index. Adding at zero and advancing in a second commit would
    /// report a failure between the two as *the scan could not run*.
    CannotStore { tag: Tag, cause: Error },
}

impl fmt::Display for RestoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreFailure::ChainUnreachable { tag, cause } => write!(
                f,
                "restore of account {}: the chain could not be reached ({cause}), so the key \
                 index could not be derived. ACTION: restore the connection and try again. This \
                 does NOT fall back to index zero -- a restored wallet that starts at zero \
                 re-signs with every key the original already used, which is this design's \
                 likeliest path to unrecoverable key reuse (I5).",
                hex20(tag),
            ),
            RestoreFailure::TagUnresolved { tag } => write!(
                f,
                "restore of account {}: the node did not resolve this tag -- it answered \
                 \"account not found\" -- so there is no address to derive an index from. That \
                 answer does not mean what it says. The Mesh gives it in three situations it does \
                 not distinguish: the ledger has no entry for this tag (never funded); the ledger \
                 holds it at ZERO balance, which the Mesh's quorum discards; or the lookup itself \
                 failed -- too few nodes answered, a node between blocks, a timeout -- which a \
                 live node was seen doing for every tag on the chain at once, funded ones \
                 included.\n  ACTION: ask again in a minute. Only if the same answer comes back \
                 from a node that reports itself synchronized: an account never funded has no \
                 index to restore -- fund it, then restore it; an account that has spent to zero \
                 cannot be located through this endpoint until it is paid again; if it should \
                 have funds, check the node URL and the seed. Do NOT put this account in a store \
                 at index 0 on the strength of this answer: an account that has spent is not at 0, \
                 and a restored wallet placed at a used index re-signs with keys the original \
                 already used (I5).",
                hex20(tag),
            ),
            RestoreFailure::NoIndexReproducesTheAddress { tag, address, scanned } => write!(
                f,
                "restore of account {}: the chain holds it at {}, and none of key indices 0 \
                 through {} reproduces that address. Three things produce that and this program \
                 cannot tell them apart from here: this account has spent {scanned} or more \
                 times, so its key is further along than the scan reached; this seed does not \
                 own this tag; or the wallet is on another chain.\n  ACTION: if the account may \
                 have spent that many times, run the restore again with a higher scan ceiling -- \
                 it finds the exact index or fails again, and no index is assumed either way. \
                 Otherwise check the seed and the node URL. Nothing here guesses: a restored \
                 wallet placed at a guessed index re-signs with keys the original already used.",
                hex20(tag),
                hex20(address),
                scanned.saturating_sub(1),
            ),
            // A cancel is not a fault and must not be rendered as one. The
            // arm below tells the reader to fix the cause, which for
            // `Cancelled` is the reader, and says the scan could not run,
            // which is false -- it ran and was stopped. I4's clause is that
            // message quality is part of the requirement.
            RestoreFailure::CannotScan { tag, cause: Error::Cancelled } => {
                write!(
                    f,
                    "restore of account {}: the scan was stopped before it found an index. \
                     ACTION: run it again to search from the start; nothing was written, no \
                     index is assumed, and stopping cost nothing but the search.",
                    hex20(tag),
                )
            }
            RestoreFailure::CannotScan { tag, cause } => write!(
                f,
                "restore of account {}: the scan could not run ({cause}). ACTION: fix the cause; \
                 no index is assumed.",
                hex20(tag),
            ),
            RestoreFailure::CannotStore { tag, cause } => write!(
                f,
                "restore of account {}: the chain named its index but the store refused the \
                 account ({cause}). Nothing was written. ACTION: fix the cause and run the \
                 restore again.",
                hex20(tag),
            ),
        }
    }
}

/// I5's restore: derive a derived account's current key index from the chain,
/// walking the default scope ([`ScanScope::RESTORE`]).
///
/// 1. Compute the tag from the master seed and the account index.
/// 2. Resolve the tag to its current address — one query.
/// 3. Scan positions `0..RECOVERY_CEILING`, **stopping on the match**.
///
/// Fails on an unreachable chain, on a tag the node does not resolve, on an
/// address no position reproduces, on a scan that could not run, and on a
/// store that refused the account (the five `RestoreFailure` arms). **It
/// cannot return zero as a fallback**:
/// zero is returned only when position 0's address is the one the chain holds,
/// which is a match like any other.
pub fn restore_account_index<T: Transport>(
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
) -> core::result::Result<RestoredAccount, RestoreFailure> {
    restore_account_index_with(client, master, account_index, &ScanScope::RESTORE, &Cancel::NEVER)
}

/// [`restore_account_index`] over a caller-set scope — the way an operator
/// raises the recovery ceiling for one invocation when the account may have
/// spent more times than [`RECOVERY_CEILING`]. The scope's
/// window is ignored: there is no local index to centre it on.
pub fn restore_account_index_with<T: Transport>(
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> core::result::Result<RestoredAccount, RestoreFailure> {
    let tag = derive::derive_account_tag(master, account_index);
    let entry = match client.resolve_tag(&tag) {
        Ok(e) => e,
        // Code 4 is the Mesh's answer, not the ledger's absence (module doc,
        // fact 3): the variant names the answer and its text names every
        // reading.
        Err(Error::Mesh { code: 4, .. }) => return Err(RestoreFailure::TagUnresolved { tag }),
        Err(cause) => return Err(RestoreFailure::ChainUnreachable { tag, cause }),
    };
    let found = scan_for_address(&entry.address, scope, None, |p| {
        // Asked before the derivation and not after, so a cancel costs at
        // most the position it arrives during rather than one more.
        // `scan_for_address` already takes the caller's derivation closure,
        // and routing the check through it is why neither `walk` nor
        // `scan_for_address` grows a parameter for this.
        if cancel.stop() {
            return Err(Error::Cancelled);
        }
        Ok(derived_address_at(master, account_index, p))
    })
    .map_err(|cause| RestoreFailure::CannotScan { tag, cause })?;
    match found {
        Some(index) => Ok(RestoredAccount {
            tag,
            index,
            address: entry.address,
            balance: entry.balance,
        }),
        None => Err(RestoreFailure::NoIndexReproducesTheAddress {
            tag,
            address: entry.address,
            scanned: scope.ceiling,
        }),
    }
}

/// Reconcile one account in a store against the chain, with the default
/// diagnostic scope ([`ScanScope::DIAGNOSTIC`]).
///
/// Returns the account's [`AccountStatus`] when local and chain agree, and a
/// [`Divergence`] when they do not. **Never advances anything** — I4's whole
/// posture is that the reconciler reports and the operator acts.
///
/// `clippy::result_large_err` is allowed rather than boxed, and the reason is
/// what the error *is*: [`Divergence`] is not a failure code, it is the
/// operator's report — two addresses, two indices and a key stream, because
/// I4 makes naming them part of the requirement. Boxing it would move
/// the report behind a pointer to satisfy a lint about a return path that
/// runs once per account at startup and never in a loop. The size is the
/// content.
#[allow(clippy::result_large_err)]
pub fn reconcile_account<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
) -> core::result::Result<AccountStatus, Divergence> {
    reconcile_account_with(store, client, tag, access, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
}

/// [`reconcile_account`] with a caller-set diagnostic scope — a raised
/// ceiling, to search further along than the window and the recovery range
/// reach. The comparison that decides *in sync* is the same whatever the
/// scope; the scope only shapes the diagnostic that runs once the comparison
/// has already failed.
#[allow(clippy::result_large_err)]
pub fn reconcile_account_with<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> core::result::Result<AccountStatus, Divergence> {
    let view = match store.view(tag) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Err(Divergence::CannotReconcile {
                tag: *tag,
                cause: Error::NoSuchAccount,
            })
        }
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };
    let entry: LedgerEntry = match client.resolve_tag(tag) {
        Ok(e) => e,
        // Code 4 is the Mesh's answer, not the ledger's absence (module doc,
        // fact 3): the variant names the answer and its text names every
        // reading.
        Err(Error::Mesh { code: 4, .. }) => {
            return Err(Divergence::TagUnresolved {
                tag: *tag,
                local: view.wots_index,
            })
        }
        Err(cause) => return Err(Divergence::ChainUnreachable { tag: *tag, cause }),
    };

    let at = |p: WotsIndex| store.address_at(tag, p, access);
    let stream = match store.stream_id(tag) {
        Ok(s) => s,
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };

    match view.pending {
        // -- no reservation: the chain must hold the key we would sign with --
        None => {
            let local_address = match at(view.wots_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == local_address {
                return Ok(AccountStatus::InSync {
                    index: view.wots_index,
                    address: entry.address,
                    balance: entry.balance,
                });
            }
            let found = locate(&entry.address, view.wots_index, scope, cancel, at);
            // The retained settled block is the report's when -- and only
            // when -- the chain sits at exactly the index it settled. A
            // `Behind` at another index, an `Ahead`, an
            // `Unlocated`, or a store with no retained block carries `None`.
            let reverted_settle = match (found, view.settled) {
                (ChainPosition::Behind { index, .. }, Some(s)) if s.spent_index == index => Some(s),
                _ => None,
            };
            Err(Divergence::IndexMismatch {
                tag: *tag,
                local: view.wots_index,
                local_address,
                chain_address: entry.address,
                balance: entry.balance,
                stream,
                found,
                reverted_settle,
            })
        }
        // -- a reservation is open: the chain holds the old address (not
        // landed) or the change key's (landed). Anything else is divergence.
        Some(Pending {
            spent_index, figures, ..
        }) => {
            let spent_address = match at(spent_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == spent_address {
                // The dead-reservation diagnosis. The
                // balance comparison costs nothing: the entry is in hand.
                // The tip is read only where the comparison is -- a
                // recorded, non-zero block-to-live -- so no account without
                // one gains a second chain call, and a failed read is
                // rendered as unchecked rather than refused or read as live.
                let reservation = match figures {
                    None => Reservation::Unrecorded,
                    Some(fig) => {
                        let expiry = if fig.blk_to_live == 0 {
                            Expiry::NoExpiry
                        } else {
                            match client.network_status() {
                                Ok(tip) if tip.index >= fig.blk_to_live => Expiry::Reached { tip: tip.index },
                                Ok(tip) => Expiry::Below { tip: tip.index },
                                Err(cause) => Expiry::Unreadable { cause },
                            }
                        };
                        Reservation::Recorded(Diagnosis {
                            figures: fig,
                            balance_moved: entry.balance != fig.reserved_balance,
                            balance_now: entry.balance,
                            expiry,
                        })
                    }
                };
                return Ok(AccountStatus::SpendOutstanding {
                    spent_index,
                    balance: entry.balance,
                    reservation,
                });
            }
            let change_address = match at(view.wots_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == change_address {
                return Ok(AccountStatus::SpendLanded {
                    spent_index,
                    settled_index: view.wots_index,
                    balance: entry.balance,
                });
            }
            // The window is centred on the change index (`view.wots_index`,
            // one past the reserved key), which covers both keys the
            // reservation names; the report says which index it was centred
            // on.
            Err(Divergence::ReservationUnexplained {
                tag: *tag,
                spent_index,
                chain_address: entry.address,
                balance: entry.balance,
                stream,
                found: locate(&entry.address, view.wots_index, scope, cancel, at),
            })
        }
    }
}

/// Advance past a divergence the operator read and acknowledged — the route
/// from a report to `Keystore::persist_advance_to`.
///
/// The acknowledgement names a tag and a target, and both must equal what the
/// store is diverged by *now*, under the same `scope` the report was made
/// with — so an acknowledgement of a stale report, of a different account's
/// divergence, or of an index the walk did not find is refused. Advancing
/// without having read a report is unrepresentable in the type:
/// [`OperatorAcknowledgement::of`] takes a [`Divergence`]. What no type can
/// see is whether a human read it; the CLI prints the whole store's report
/// again at the moment of the write for that reason.
///
/// The target is the live divergence's [`Divergence::advance_target`], which
/// is `Some` only for an `Ahead` — a position the walk derived and matched to
/// the chain's address. A raised ceiling only widens the walk: the chain may
/// be found at some index below what the operator named, and then the
/// acknowledgement they hold names the wrong index and is refused. The store
/// then refuses any target not strictly ahead of the stored index on its own
/// account (`persist_advance_to`), so backwards is unrepresentable whatever
/// the caller.
///
/// A free function rather than only a `Wallet` method because a one-shot CLI
/// meets a divergence *before* a `Wallet` can exist — `Wallet::open` refuses
/// on one. `Wallet::advance_after_operator_review` delegates
/// here for the long-running case where a divergence appears after open.
pub fn advance_after_operator_review<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    ack: OperatorAcknowledgement,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> Result<AdvanceReceipt> {
    // Nothing is asked between the re-check and the write: this route, and
    // `Wallet::advance_after_operator_review_with` above it, write as soon
    // as the re-check matches.
    guarded::advance_after_operator_review(store, client, tag, access, ack, scope, cancel, || Ok(()))
}

/// The acknowledged advance with one more question, asked after its
/// re-check has matched and before it writes -- the form an operation that
/// can be cancelled runs.
///
/// The re-check's walk asks its `Cancel` before each position and not after
/// the last, so a cancel raised while that position is derived reaches no
/// asking before the write unless one is put there. `before_write` is that
/// asking: an `Err` from it is returned with nothing written. The public
/// function is this with a question that always answers `Ok`, so its
/// behaviour is what it was.
///
/// A module of its own so the call keeps the name the CLI containment scan
/// permits in `cli/reconcile.rs` alone: the store-writing route is one route
/// however it is reached.
pub(crate) mod guarded {
    use super::{reconcile_account_with, Cancel, OperatorAcknowledgement, ScanScope};
    use crate::account::AdvanceReceipt;
    use crate::addr::Tag;
    use crate::error::{Error, Result};
    use crate::keystore::{KeyAccess, Keystore, Medium};
    use crate::mesh::{MeshClient, Transport};

    /// Eight arguments: the advance's own seven, and the question asked
    /// before its write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_after_operator_review<M: Medium, T: Transport>(
        store: &mut Keystore<M>,
        client: &MeshClient<T>,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<AdvanceReceipt> {
        if ack.tag != *tag {
            return Err(Error::AcknowledgementDoesNotMatch);
        }
        match reconcile_account_with(store, client, tag, access, scope, cancel) {
            Ok(_) => Err(Error::NothingToReconcile),
            Err(d) => {
                if d.advance_target() != Some(ack.target) {
                    return Err(Error::AcknowledgementDoesNotMatch);
                }
                before_write()?;
                store.persist_advance_to(tag, ack.target)
            }
        }
    }
}

/// Where the chain's address sits relative to `local`, for the report. A walk
/// that fails to finish is reported as [`ChainPosition::Unlocated`] with the
/// position it stopped at, rather than propagated: this runs on a path that
/// is already refusing, and a diagnostic that fails to compute must not
/// replace the refusal it was decorating.
/// The diagnostic walk, and the one place the wrapper that makes it
/// cancellable lives -- both call sites would otherwise carry a copy of it.
fn locate<F>(
    chain: &Address,
    local: WotsIndex,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
    mut address_at: F,
) -> ChainPosition
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    let walked = walk(chain, scope, Some(local), |p| {
        if cancel.stop() {
            return Err(Error::Cancelled);
        }
        address_at(p)
    });
    match walked {
        Walk::Found(i) if i.get() > local.get() => ChainPosition::Ahead {
            index: i,
            gap: i.get() - local.get(),
        },
        Walk::Found(i) => ChainPosition::Behind {
            index: i,
            gap: local.get() - i.get(),
        },
        Walk::NotFound => ChainPosition::Unlocated {
            local,
            scope: *scope,
            stopped: None,
        },
        // The cause is mapped here and not carried whole: `ChainPosition` is
        // `Copy` and `Error` is not, and the report needs the distinction
        // rather than the variant.
        Walk::Failed { at, cause } => ChainPosition::Unlocated {
            local,
            scope: *scope,
            stopped: Some(Stopped {
                at,
                by: match cause {
                    Error::Cancelled => StoppedBy::Cancelled,
                    _ => StoppedBy::Derivation,
                },
            }),
        },
    }
}
