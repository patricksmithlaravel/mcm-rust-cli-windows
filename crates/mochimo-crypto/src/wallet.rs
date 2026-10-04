//! The wallet: a keystore and a chain client that were reconciled against
//! each other before either could be used to spend (I4).
//!
//! # What this type is for, in one sentence
//!
//! [`Wallet::open`] is the only constructor and it reconciles every account,
//! so **a `Wallet` that exists holds a partition**: the accounts the chain
//! confirmed, and the accounts it could not explain. Every spend path is a
//! method on it, and every one of them refuses an account from the second set
//! by name. A store in which nothing reconciled is not a wallet at all and is
//! refused outright.
//!
//! The property is per account, because the hazard is: a key signs twice or it
//! does not, and that is a fact about one key stream. An account the node
//! answered for with exactly the address this store derived at its stored
//! position agrees with that node's observation. The response is not a
//! proof of the ledger: a node can repeat a public address and invent a
//! balance. The durable local index prevents reuse within this store; it
//! cannot authenticate chain state or account for another copy of the seed.
//! Nothing that keeps a key from signing twice consults another account.
//!
//! # THE BOUND, and it is exactly [`crate::keystore::Keystore::sign_spend`]'s
//!
//! *Gated at the wallet layer, not absent.* The raw [`Keystore`] is still
//! reachable in-crate and from the test tree, and in-crate code can still
//! call `persist_advance` and `sign_spend` directly — the keystore's own
//! proofs must, because they have no chain to reconcile against. What is
//! enforced is that **this type's users cannot spend unreconciled**, in the
//! same sense and with the same honesty as I1's
//! `key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent`.
//! A caller who wants the unreconciled path must go and get a `Keystore`,
//! which is conspicuous, rather than forgetting to reconcile, which is not.
//!
//! The witness is the type itself rather than a token, deliberately: a token
//! nothing consumes is a claim with nothing behind it, and its presence on a
//! type surface reads as enforcement to whoever audits it — the well-named
//! empty check's shape one layer out. `AdvanceReceipt` is the precedent for the shape that works:
//! unforgeable, bound, minted at one site from a proof token, and consumed.
//!
//! # Why reconciliation is at construction and not at first spend
//!
//! I4's enforcement clause: *reconciliation runs before any signing operation
//! is permitted, not lazily on first spend.* A wallet that reconciles when the
//! user tries to spend has already let the divergent state be the basis for
//! something — a displayed balance, an address handed out, a decision to send.
//!
//! # What the constructor refuses, each with its own message
//!
//! An unreachable chain; **any** divergent account; a tag the ledger does not
//! hold; and a derived account with no master seed to derive it from.
//! [`StartupRefusal`] renders **every** failing account rather than the first,
//! because an operator who fixes one and restarts into the next has been told
//! the truth twice and helped once.
//!
//! ## One accepted cost, recorded as accepted
//!
//! Refusing on a tag the ledger does not hold means **a freshly added,
//! never-funded account blocks startup** until it is funded or removed. The
//! alternative — treating *absent, index 0, nothing pending* as never-funded
//! rather than divergent — is defensible: a tag enters the ledger when it is
//! first paid and is never removed (`recon`'s module doc, fact 1), so the
//! ledger's absence really does mean never funded. But what this wallet
//! observes is the Mesh's answer, and the Mesh answers *account not found*
//! for an emptied tag and for a failed lookup as well (`recon`'s fact 3).
//! It is refused anyway because that answer alone cannot separate
//! *never funded* from *emptied*, *lookup failed*, *wrong chain* and *wrong
//! seed*, and I4's posture is fail-closed. The cost is recorded here the way
//! I4's decision records its own, and the refusal's message names every reading
//! and prefers none.
//!
//! **What would reopen it:** the CLI session finding that a never-funded
//! account blocks startup often enough to matter in the ordinary create-then-
//! fund flow. That is the condition, stated so the evidence is recognisable
//! when it arrives.

use core::fmt;

use crate::account::{AdvanceReceipt, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::keystore::{KeyAccess, Keystore, Medium, SpendAddresses};
use crate::mesh::spend::{SignedTransaction, SpendPlan};
use crate::mesh::{MeshClient, Transport, TxId};
use crate::recon::{self, AccountStatus, Cancel, Divergence, Progress, Reservation, ScanScope, Unfinished};

/// The acknowledgement type lives in `recon` -- the CLI's `reconcile` runs
/// before a `Wallet` exists and the gate is the acknowledgement, not this
/// type -- and is re-exported here where it first lived.
pub use crate::recon::OperatorAcknowledgement;
use crate::secret::Secret;
use crate::tx::wire::Destination;

/// Why the wallet would not start: every account that failed, in tag order.
///
/// `Display` renders each one's full report. Not an [`Error`] variant: an
/// `Error` is one line and this is a page, and flattening it would lose the
/// per-account detail that I4 makes part of the requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupRefusal {
    /// Every account that could not be reconciled. Non-empty by construction:
    /// [`Wallet::open`] returns `Ok` when this would be empty.
    pub diverged: Vec<Divergence>,
    /// How many accounts the store held.
    pub accounts: usize,
}

impl fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "WALLET WILL NOT START: {} of {} account(s) could not be reconciled against the \
             chain.\n\nThis is invariant I4 failing closed, and it is deliberate. Divergence \
             between a local key index and the chain has three causes -- a crash between signing \
             and persisting, a restored seed with incomplete history, or a second wallet live on \
             this seed -- and the divergence alone does not say which. Advancing to match the \
             chain is correct for the first and destroys keys for the third. So nothing is \
             advanced automatically.\n",
            self.diverged.len(),
            self.accounts
        )?;
        for d in &self.diverged {
            writeln!(f, "{d}\n")?;
        }
        write!(
            f,
            "Do not delete local state, reinstall, or restore this seed elsewhere to get past \
             this. Each of those is a path back to the key reuse this refusal exists to prevent."
        )
    }
}

/// What [`Wallet::open_or_return`] gives back when it refuses: the refusal,
/// and the store and the client it was handed, as they were.
///
/// # Why the parts come back
///
/// `open` consumes both and drops them with its refusal, which closes the
/// store and releases its lock. A caller that holds the password only for as
/// long as the request that brought it cannot then open the store again
/// without asking for the password again, though some refusals are gone at
/// the node's next answer: a lookup that failed, a node between blocks.
/// Handed back, the same store can be opened again as it is.
///
/// **This reaches around nothing.** The store is the one the caller handed
/// in, unreconciled then and unreconciled now; no `Wallet` was built from it,
/// so no account was confirmed and nothing that rests on the partition
/// exists. Opening it again goes through the same constructor and the same
/// reconciliation.
pub struct Refused<M: Medium, T: Transport> {
    /// Why the wallet would not start, exactly as [`Wallet::open`] reports it.
    pub refusal: StartupRefusal,
    /// The store, still open and still locked.
    pub store: Keystore<M>,
    pub client: MeshClient<T>,
}

impl<M: Medium, T: Transport> fmt::Debug for Refused<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

/// What [`Wallet::open_or_return_with`] gives back when it does not open: why
/// -- refused, or cancelled -- and the store and the client it was handed, as
/// they were.
///
/// [`Refused`] is the uncancellable open's answer and carries a refusal
/// alone; this carries [`Unfinished`], so a cancel is told apart from a
/// refusal by its variant here as everywhere else, and both hand the parts
/// back on the same terms: the store unreconciled, still open and still
/// locked, with no `Wallet` built from it.
pub struct Unopened<M: Medium, T: Transport> {
    /// `Cancelled`, or the refusal [`Wallet::open`] would report.
    pub why: Unfinished<StartupRefusal>,
    /// The store, still open and still locked.
    pub store: Keystore<M>,
    pub client: MeshClient<T>,
}

impl<M: Medium, T: Transport> fmt::Debug for Unopened<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unopened")
            .field("why", &self.why)
            .finish_non_exhaustive()
    }
}

/// Why an open did not produce a wallet, with the store and the client it
/// was handed: what the one reconciliation every open runs returns short of
/// a wallet, before each open keeps the parts or drops them.
type HandedBack<E, M, T> = (E, Keystore<M>, MeshClient<T>);

/// What settling found. Not `Copy`: `StillOutstanding` carries the
/// reservation's diagnosis, which may hold the error a tip read returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The chain holds the change key's address; the reservation moved to the
    /// retained settled block and the account can spend
    /// again.
    Settled { spent_index: WotsIndex, index: WotsIndex },
    /// The chain still holds the key that signed; the reservation stands.
    /// `reservation` is what reconciliation made of it from the store and
    /// the chain alone -- live, dead, or not
    /// classifiable -- carried here rather than discarded, so `settle`'s
    /// page can say which.
    StillOutstanding {
        spent_index: WotsIndex,
        reservation: Reservation,
    },
    /// Nothing was reserved.
    NothingPending { index: WotsIndex },
}

/// A keystore and a chain client, with every account reconciled or recorded as
/// diverged (module doc).
///
/// **Both sets, and the partition is the point.** An account that reconciled
/// is one the node answered for with exactly the address this store derived at
/// the stored position; an account that diverged is one whose state this
/// wallet cannot explain. The first can act. The second cannot, and every
/// method that would act on it refuses by name.
#[must_use]
pub struct Wallet<M: Medium, T: Transport> {
    store: Keystore<M>,
    client: MeshClient<T>,
    accounts: Vec<(Tag, AccountStatus)>,
    /// Every account reconciliation could not explain, in tag order. Empty
    /// for a whole store; never the only thing here, because [`Wallet::open`]
    /// refuses a store in which nothing reconciled.
    diverged: Vec<Divergence>,
}

impl<M: Medium, T: Transport> Wallet<M, T> {
    /// Open a wallet over a store and a client, reconciling every account
    /// first. **The only constructor.**
    ///
    /// `clippy::result_large_err` allowed for [`StartupRefusal`] on the same
    /// ground as `recon::reconcile_account`: the error is the report.
    ///
    /// `master` is borrowed for this call and not retained: derived accounts
    /// reconcile through [`KeyAccess::Master`] and imported ones through
    /// [`KeyAccess::StoredRoot`], which is the domain's own shape (a wallet
    /// has one master seed plus imported roots) and keeps the signing path's
    /// rule that the caller lends the master per call. A derived account with no
    /// master is a refusal, not a skip.
    #[allow(clippy::result_large_err)]
    pub fn open(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
    ) -> core::result::Result<Wallet<M, T>, StartupRefusal> {
        // `NEVER` is never asked, so `cancelled` is never called; `Ok` is the
        // answer that ends nothing.
        Self::open_asking(store, client, master, &Cancel::NEVER, None, || Ok(())).map_err(|(refusal, _, _)| refusal)
    }

    /// [`Wallet::open`], handing the store and the client back when it
    /// refuses ([`Refused`]).
    ///
    /// The same reconciliation and the same refusal: `open` is this with the
    /// parts dropped. A wallet that opens is the wallet `open` returns.
    #[allow(clippy::result_large_err)]
    pub fn open_or_return(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
    ) -> core::result::Result<Wallet<M, T>, Refused<M, T>> {
        Self::open_asking(store, client, master, &Cancel::NEVER, None, || Ok(()))
            .map_err(|(refusal, store, client)| Refused { refusal, store, client })
    }

    /// [`Wallet::open`], stoppable from outside: `cancel` is asked before
    /// each account and once per position of each diagnostic walk.
    ///
    /// A cancel is [`Unfinished::Cancelled`] and never a refusal. A walk it
    /// ends leaves a report that is true and incomplete -- the account
    /// diverged, and where to is unknown -- and a refusal built from it would
    /// name an account for what was the caller's decision, so the whole call
    /// answers `Cancelled` instead. Nothing is written either way: opening
    /// reads the store and asks the node. The store and the client are
    /// dropped with the call, as they are when `open` refuses;
    /// [`Wallet::open_or_return_with`] hands them back.
    #[allow(clippy::result_large_err)]
    pub fn open_with(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<Wallet<M, T>, Unfinished<StartupRefusal>> {
        Self::open_asking(store, client, master, cancel, None, || Err(Unfinished::Cancelled)).map_err(|(why, _, _)| why)
    }

    /// [`Wallet::open_with`], handing the store and the client back when it
    /// is refused or cancelled ([`Unopened`]).
    ///
    /// The open a caller runs when it holds the password only for as long as
    /// the request that brought it, and must be able to stop: a cancel, like
    /// a refusal, leaves the store open and locked in the caller's hands, so
    /// it can be opened again, or dropped, without asking for the password
    /// again.
    #[allow(clippy::result_large_err)]
    pub fn open_or_return_with(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<Wallet<M, T>, Unopened<M, T>> {
        Self::open_asking(store, client, master, cancel, None, || Err(Unfinished::Cancelled))
            .map_err(|(why, store, client)| Unopened { why, store, client })
    }

    /// [`Wallet::open_with`], telling `progress` how far it has got: before
    /// each account, and every [`recon::PROGRESS_EVERY`] positions of each
    /// diagnostic walk ([`Progress`]).
    ///
    /// `progress` is called on this thread, between steps, and the call
    /// waits for it. What it is handed is counted from the walk, not
    /// predicted, so a report of it is no claim about how long is left.
    #[allow(clippy::result_large_err)]
    pub fn open_with_progress(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        progress: &mut dyn FnMut(Progress),
    ) -> core::result::Result<Wallet<M, T>, Unfinished<StartupRefusal>> {
        Self::open_asking(store, client, master, cancel, Some(progress), || Err(Unfinished::Cancelled))
            .map_err(|(why, _, _)| why)
    }

    /// [`Wallet::open_or_return_with`], telling `progress` how far it has
    /// got, as [`Wallet::open_with_progress`] does.
    #[allow(clippy::result_large_err)]
    pub fn open_or_return_with_progress(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        progress: &mut dyn FnMut(Progress),
    ) -> core::result::Result<Wallet<M, T>, Unopened<M, T>> {
        Self::open_asking(store, client, master, cancel, Some(progress), || Err(Unfinished::Cancelled))
            .map_err(|(why, store, client)| Unopened { why, store, client })
    }

    /// The one reconciliation every open runs. `cancelled` is what a cancel
    /// ends the call with, and it is called only once `cancel` has said stop
    /// or a walk records that it did. Whatever ends the call short of a
    /// wallet comes back with the store and the client it was handed, for the
    /// opens that return them; the others drop them there.
    #[allow(clippy::result_large_err)]
    fn open_asking<E: From<StartupRefusal>>(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        mut progress: Option<&mut dyn FnMut(Progress)>,
        cancelled: impl Fn() -> core::result::Result<(), E>,
    ) -> core::result::Result<Wallet<M, T>, HandedBack<E, M, T>> {
        let tags = match store.tags() {
            Ok(t) => t,
            Err(cause) => {
                let refusal = StartupRefusal {
                    diverged: vec![Divergence::CannotReconcile {
                        tag: [0u8; 20],
                        cause,
                    }],
                    accounts: 0,
                };
                return Err((refusal.into(), store, client));
            }
        };
        let accounts = tags.len();
        let mut ok: Vec<(Tag, AccountStatus)> = Vec::new();
        let mut diverged: Vec<Divergence> = Vec::new();
        for (n, tag) in tags.into_iter().enumerate() {
            if cancel.stop() {
                if let Err(why) = cancelled() {
                    return Err((why, store, client));
                }
            }
            let at = Progress {
                account: u32::try_from(n).unwrap_or(u32::MAX),
                accounts: u32::try_from(accounts).unwrap_or(u32::MAX),
                position: 0,
                // Read only for a caller that watches: it is the one figure
                // here that needs the store's view.
                ceiling: match progress {
                    Some(_) => ScanScope::DIAGNOSTIC.reach(store.view(&tag).ok().flatten().map(|v| v.wots_index)),
                    None => 0,
                },
            };
            if let Some(report) = progress.as_deref_mut() {
                report(at);
            }
            match Self::access_for(&store, &tag, master) {
                Err(d) => diverged.push(d),
                Ok(access) => {
                    let reconciled = recon::watched(cancel, progress.as_deref_mut(), at, |cancel| {
                        recon::reconcile_account_with(&store, &client, &tag, &access, &ScanScope::DIAGNOSTIC, cancel)
                    });
                    match reconciled {
                        Ok(status) => ok.push((tag, status)),
                        Err(d) => {
                            if d.stopped_by_cancel() {
                                if let Err(why) = cancelled() {
                                    return Err((why, store, client));
                                }
                            }
                            diverged.push(d);
                        }
                    }
                }
            }
        }
        // **Refused only when nothing is operable.** A wallet whose every
        // account diverged offers no action at all, and `StartupRefusal` is
        // that state. A wallet with one reconciled account offers exactly that
        // account: its address agrees with the node's observation, and
        // nothing that keeps a key from signing twice consults a sibling.
        // This comparison does not authenticate the node's answer. A store
        // with no accounts in it diverges nowhere and opens, as it always has.
        if ok.is_empty() && !diverged.is_empty() {
            return Err((StartupRefusal { diverged, accounts }.into(), store, client));
        }
        Ok(Wallet {
            store,
            client,
            accounts: ok,
            diverged,
        })
    }

    /// Every account reconciliation could not explain, in tag order.
    ///
    /// A caller that opens a wallet renders these whatever it went on to do:
    /// a diverged account is a standing condition, not a footnote found by
    /// whoever happens to address it.
    #[must_use]
    pub fn diverged(&self) -> &[Divergence] {
        &self.diverged
    }

    /// This account's divergence, if it has one.
    #[must_use]
    pub fn divergence_for(&self, tag: &Tag) -> Option<&Divergence> {
        self.diverged.iter().find(|d| d.tag() == *tag)
    }

    /// Refuse when `tag` is an account this wallet could not explain.
    ///
    /// The guard every operation that acts on one account passes through. It
    /// reads the partition `open` made rather than asking the chain again:
    /// the caller is one process invocation, and an account that diverged when
    /// the wallet opened is diverged for the whole of it.
    fn require_reconciled(&self, tag: &Tag) -> Result<()> {
        match self.divergence_for(tag) {
            None => Ok(()),
            Some(d) => Err(Error::ReconciliationRefused {
                what: divergence_kind(d),
            }),
        }
    }

    /// Which access an account's kind needs. A derived account with no master
    /// supplied cannot have its addresses computed at all, so it is a
    /// divergence (unreconcilable) rather than a silently skipped account.
    /// The choice is `recon::access_for`'s, because the pre-gate
    /// commands need the same per-account answer.
    #[allow(clippy::result_large_err)]
    fn access_for<'a>(
        store: &Keystore<M>,
        tag: &Tag,
        master: Option<&'a Secret<SEED_LEN>>,
    ) -> core::result::Result<KeyAccess<'a>, Divergence> {
        recon::access_for(store, tag, master)
    }

    /// Every account as reconciliation found it at open.
    #[must_use]
    pub fn accounts(&self) -> &[(Tag, AccountStatus)] {
        &self.accounts
    }

    /// Read-only view of the store. There is no `&mut` counterpart: a caller
    /// holding one could `persist_advance` without the plan this type builds,
    /// which is the gate.
    pub fn store(&self) -> &Keystore<M> {
        &self.store
    }

    #[must_use]
    pub fn client(&self) -> &MeshClient<T> {
        &self.client
    }

    /// Reconcile one account again, now — the same comparison `open` made,
    /// with the default diagnostic scope. Reports without refusing.
    ///
    /// The CLI's `status` no longer reaches this: a one-shot process meets a
    /// divergence before a `Wallet` can exist, so it runs `recon` directly
    /// before the gate. This is the long-running caller's
    /// `status`, for a divergence that appears after open.
    #[allow(clippy::result_large_err)]
    pub fn status(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
    ) -> core::result::Result<AccountStatus, Divergence> {
        self.status_with(tag, access, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
    }

    /// [`Wallet::status`] with a caller-set diagnostic scope — a raised
    /// ceiling to search further along than the window reaches.
    #[allow(clippy::result_large_err)]
    pub fn status_with(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<AccountStatus, Divergence> {
        recon::reconcile_account_with(&self.store, &self.client, tag, access, scope, cancel)
    }

    /// The addresses a spend from `tag` is built for.
    ///
    /// Refuses an account this wallet could not reconcile: the addresses are
    /// derived from a stored position, and a position the chain did not
    /// confirm is the one thing that must not be signed from.
    pub fn spend_addresses(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendAddresses> {
        self.require_reconciled(tag)?;
        self.store.spend_addresses(tag, access)
    }

    /// Lay out a spend: resolve the tag, then build and check the plan.
    /// `SpendPlan::new`'s own `ChainAddressMismatch` is the spend-time guard
    /// beside `open`'s startup reconciliation, and it is not redundant — the
    /// chain can move between the two.
    pub fn plan(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        dsts: Vec<Destination>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        self.require_reconciled(tag)?;
        let addresses = self.store.spend_addresses(tag, access)?;
        let entry = self.client.resolve_tag(tag)?;
        SpendPlan::new(&addresses, &entry, dsts, fee_total, blk_to_live)
    }

    /// Reserve the key the plan names, sign, and assemble the wire image.
    ///
    /// Before any write, recheck its position and addresses against the
    /// store, a non-zero expiry against the current tip, and its source and
    /// balance against a fresh ledger read. A refusal leaves the key unused.
    /// These observations trust the configured node and cannot prevent a
    /// balance change or expiry after signing; either can permanently lock
    /// funds because the reserved key must never sign a different digest.
    ///
    /// **The returned bytes are the retry artifact and this wallet does not
    /// keep them**: the caller owns them from here until the
    /// reservation resolves. They are not persisted because the format's
    /// crash-consistency argument is one snapshot, one write, every member
    /// together, and a second on-disk artifact is a second thing that can be
    /// torn. If they are lost while the reservation is open, the recovery is
    /// [`Wallet::resign_pending`], which reproduces them byte for byte from
    /// the store's own reservation — and is the ONLY recovery, because the
    /// index cannot roll back to the reserved key.
    pub fn reserve_and_sign(
        &mut self,
        plan: &SpendPlan,
        access: KeyAccess<'_>,
    ) -> Result<SignedTransaction> {
        let tag = plan.tag();
        // The last place the partition is checked before a key is spent. A
        // plan for a diverged account cannot be built through `plan` above,
        // and this covers a plan built any other way.
        self.require_reconciled(&tag)?;
        // A caller can keep a plan across a settle, or build it from
        // another store's addresses. Check key access and the complete
        // address pair before persisting anything irreversible.
        let addresses = self.store.spend_addresses(&tag, &access)?;
        if addresses.position != plan.position() {
            return Err(Error::StaleSpendPlan {
                planned: plan.position().get(),
                stored: addresses.position.get(),
            });
        }
        if addresses.source != *plan.source() || addresses.change != *plan.change() {
            return Err(Error::SpendPlanAddressMismatch);
        }
        if plan.blk_to_live() != 0 {
            let tip = self.client.network_status()?.index;
            // The next block must still be able to include the spend. The
            // arrival window is 256 blocks (tx_val at the fixture pin;
            // docs/specification.md, Transactions).
            if !matches!(plan.blk_to_live().checked_sub(tip), Some(1..=256)) {
                return Err(Error::InvalidExpiry { expiry: plan.blk_to_live(), tip });
            }
        }
        // Read the ledger last, immediately before reservation. This closes
        // changes since planning, but neither authenticates this node's
        // answer nor prevents an incoming credit after this observation.
        let entry = self.client.resolve_tag(&tag)?;
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch { position: addresses.position.get() });
        }
        if entry.balance != plan.balance() {
            return Err(Error::BalanceChanged { planned: plan.balance(), current: entry.balance });
        }
        // The reservation carries the plan's two figures: the balance it
        // was built against and its block-to-live, so a
        // later `open` can compare them to the entry and the tip.
        let receipt = self.store.persist_advance(&tag, &plan.digest(), plan.figures())?;
        let signature = self.store.sign_spend(&plan.digest(), receipt, access)?;
        SignedTransaction::attach(plan, &signature)
    }

    /// Submit the signed bytes. `Ok` means the middleware wrote them to a
    /// node's socket and echoed their id — **a socket write, not a verdict**.
    /// Whether it landed is `settle_if_landed`'s question.
    pub fn submit(&self, signed: &SignedTransaction) -> Result<TxId> {
        self.client.submit(signed)
    }

    /// Settle a reservation **when the chain holds the tag at the change
    /// key's address**. One observation, no depth.
    ///
    /// # The argument for one confirmation
    ///
    /// Being wrong in the two directions is not symmetric:
    ///
    /// * **Settling too early** — a reorg later reverts the spend — leaves the
    ///   store one position past a key that never signed on chain. That
    ///   **skips a key**. A skipped key costs one position out of 2^32 and
    ///   exposes nothing: the key that signed signed once, and clearing the
    ///   reservation only permits the *next* key to sign. No reuse is created.
    /// * **Settling too late** freezes the account. `persist_advance` refuses
    ///   while a reservation is unresolved, so a depth rule that never clears
    ///   is an account that can never spend again.
    ///
    /// And the early-settle risk lands in the mechanism built for it: a reorg
    /// that reverts a settled spend leaves the chain at the old address with
    /// no reservation, which the next `open` refuses as an index mismatch. A
    /// depth rule buys nothing that check does not already catch, and costs
    /// the unbounded direction.
    pub fn settle_if_landed(&mut self, tag: &Tag, access: &KeyAccess<'_>) -> Result<Settlement> {
        // **Not gated on the partition, because it makes a fresher one.** This
        // reconciles the account again here and refuses on whatever it finds,
        // so the check `require_reconciled` would add is the same comparison
        // against an older observation. It matters in one direction: an
        // account that was invisible at open and has since been paid settles
        // on this call rather than needing the wallet reopened, which is the
        // recovery an emptied account has.
        match recon::reconcile_account(&self.store, &self.client, tag, access) {
            Ok(AccountStatus::SpendLanded {
                spent_index,
                settled_index,
                ..
            }) => {
                self.store.persist_settled(tag)?;
                Ok(Settlement::Settled {
                    spent_index,
                    index: settled_index,
                })
            }
            Ok(AccountStatus::SpendOutstanding {
                spent_index,
                reservation,
                ..
            }) => Ok(Settlement::StillOutstanding {
                spent_index,
                reservation,
            }),
            Ok(AccountStatus::InSync { index, .. }) => Ok(Settlement::NothingPending { index }),
            Err(d) => Err(Error::ReconciliationRefused {
                what: divergence_kind(&d),
            }),
        }
    }

    /// Re-produce the signed bytes an outstanding reservation already
    /// released, when the caller has lost them. **The one recovery**
    /// (as corrected by the audit that retired `abandon_reservation`).
    ///
    /// The caller supplies the spend's *parameters* — the destinations, the
    /// fee, the block-to-live — which is what a human remembers ("I was
    /// sending 1 MCM to X"), not the 2,408 bytes they lost. Everything else
    /// is rebuilt from the store and the chain, and then **the rebuilt plan's
    /// digest must equal the reserved one** or nothing signs. So the
    /// signature is over the reserved digest by construction, and the output
    /// is byte-identical to the artifact that was lost (WOTS+ signing is
    /// deterministic).
    ///
    /// # The three refusals, and the one a live chain found
    ///
    /// `NothingPending` when no reservation is open, `DigestMismatch` when
    /// the rebuilt plan is not the reserved one, and
    /// [`Error::ReservationLanded`] when the chain has already moved to the
    /// reservation's change key -- the state `settle` resolves, which this
    /// verb reported as I4's divergence until a run against mainnet walked
    /// into it. The classification is `reconcile_account_with`'s, the same
    /// one [`Wallet::settle_if_landed`] acts on, so the two cannot drift.
    ///
    /// # Why this exists, and why `abandon_reservation` does not
    ///
    /// Rolling the index back to `spent_index` is correctly forbidden — that
    /// is the road to a second, *different* digest under one key. So a
    /// signature from the reserved key is the **only** way the funds at its
    /// address can ever move, and this is the only way to that signature.
    ///
    /// The first design shipped an `abandon_reservation` instead, on the argument that
    /// giving up cost "one key out of 2^32". The audit measured what it
    /// actually cost: the store advances to `spent_index + 1` while the chain
    /// still holds `spent_index`'s address, so the balance there becomes
    /// unspendable, reconciliation reports a `Behind` divergence for which no
    /// acknowledgement exists, `Wallet::open` refuses forever, and later
    /// deposits credit the same unreachable address (`'A'` does not rehash,
    /// the ledger's own arm). **It bricked the
    /// account.** It was removed rather than documented: a function with no
    /// safe use is worse than an absent one, and through this type every
    /// reservation has a non-zero balance behind it — `plan` refuses
    /// `InsufficientBalance` otherwise — so there is no state in which
    /// abandoning was right and settling was not.
    pub fn resign_pending(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        dsts: Vec<Destination>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SignedTransaction> {
        self.require_reconciled(tag)?;
        let view = self.store.view(tag)?.ok_or(Error::NoSuchAccount)?;
        let pending = view.pending.ok_or(Error::NothingPending)?;
        // The addresses the reserved spend was built for. `address_at` does
        // not refuse an outstanding reservation, which is exactly why it
        // exists (see its doc): this is the moment the question is asked.
        let source = self.store.address_at(tag, pending.spent_index, access)?;
        let change = self.store.address_at(tag, view.wots_index, access)?;
        let addresses = SpendAddresses::of_derived_addresses(*tag, pending.spent_index, source, change);
        let entry = self.client.resolve_tag(tag)?;
        let plan = match SpendPlan::new(&addresses, &entry, dsts, fee_total, blk_to_live) {
            Ok(plan) => plan,
            // **The planner's opening guard is right, and on this path it is
            // right about the wrong thing.** `SpendPlan::new` refuses when
            // the chain does not hold the tag at the source it is laying out
            // against; for `send` that source is the key the store signs with
            // next, so the refusal is I4's divergence and its page names I4's
            // three causes. Here the source is the RESERVED key, and a
            // reservation that landed moves the chain to the change key, so
            // the guard must fire -- on the commonest mistaken route to this
            // verb, running it after a `send` that worked. A run against
            // mainnet got the three-cause page for a spend that had settled,
            // none of the three applying, and `settle` resolved the same
            // state one command later.
            //
            // The guard stays in the planner unchanged: the planner's rules
            // are the node's, and a refusal about this wallet's reservation
            // state is not one of them. What the state IS is asked of the
            // classifier that owns the question, rather than re-derived by
            // comparing `entry.address` against `change` here, so there is
            // one definition of a landed spend in the crate and not two that
            // can drift.
            Err(Error::ChainAddressMismatch { position }) => {
                // The scope walks nothing, deliberately. The comparison that
                // decides *landed* -- the chain's address against the address
                // at the stored position -- is scope-free; the scope shapes
                // only the walk behind a divergence's report, and this path
                // discards the divergence and keeps the guard's own page for
                // it. Under the diagnostic scope a chain standing at neither
                // key would pay a full exhaustion to build a report nothing
                // here renders.
                let comparison_only = ScanScope {
                    ceiling: 0,
                    window: None,
                };
                let status = recon::reconcile_account_with(
                    &self.store,
                    &self.client,
                    tag,
                    access,
                    &comparison_only,
                    // Nothing to stop: `comparison_only` has ceiling 0, so
                    // this reconciles by comparison and walks no positions.
                    &Cancel::NEVER,
                );
                return Err(match status {
                    Ok(AccountStatus::SpendLanded {
                        spent_index,
                        settled_index,
                        ..
                    }) => Error::ReservationLanded {
                        spent_index: spent_index.get(),
                        settled_index: settled_index.get(),
                    },
                    // Every other answer is the guard's own. A chain at
                    // neither of the reservation's two keys is the divergence
                    // the three-cause page describes, and it keeps that page.
                    _ => Error::ChainAddressMismatch { position },
                });
            }
            Err(e) => return Err(e),
        };
        // THE check: the rebuilt plan must be the reserved one. Without this
        // the caller could re-sign the reserved key over a spend it never
        // reserved, which is the second-signature-under-one-key catastrophe.
        if plan.digest() != pending.digest {
            return Err(Error::DigestMismatch);
        }
        let signature = self.store.resign_reserved(tag, access)?;
        SignedTransaction::attach(&plan, &signature)
    }

    /// Advance past a divergence the operator read and acknowledged.
    ///
    /// The **only** route from this type to `persist_advance_to`, and it is
    /// `recon::advance_after_operator_review` over this wallet's store with
    /// the default diagnostic scope: the acknowledgement names a tag and a
    /// target, and both must equal what the store is diverged by *now* — so
    /// an acknowledgement of a stale report, or of a different account's
    /// divergence, is refused. Advancing without having read a report is
    /// unrepresentable: [`OperatorAcknowledgement::of`] takes a
    /// [`Divergence`].
    ///
    /// A one-shot CLI cannot reach this method for the divergence it was
    /// started to reconcile — `open` refuses on it first — which is why the
    /// function it delegates to exists. This is the
    /// long-running caller's route.
    pub fn advance_after_operator_review(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
    ) -> Result<AdvanceReceipt> {
        self.advance_after_operator_review_with(tag, access, ack, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
    }

    /// [`Wallet::advance_after_operator_review`] under a caller-set scope,
    /// which must be the scope the acknowledged report was made with — a
    /// raised ceiling, for a divergence the default window did not reach.
    pub fn advance_after_operator_review_with(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
    ) -> Result<AdvanceReceipt> {
        // **Not gated on the partition, and it is the one method that must not
        // be.** Acting on a diverged account is what this is for: the
        // acknowledgement names the tag and the index the report printed, and
        // `recon` re-derives and re-compares before it writes.
        //
        // It does not update the partition either. A wallet's partition is the
        // one `open` made, so an account advanced through here stays in the
        // diverged set for the life of this wallet and its spend operations go
        // on refusing. Reopening is what re-reconciles, which is what the
        // command line does on every invocation.
        recon::advance_after_operator_review(
            &mut self.store,
            &self.client,
            tag,
            access,
            ack,
            scope,
            cancel,
        )
    }

    /// Take the halves back. The wallet's claim ends here: whoever holds the
    /// keystore afterwards holds an unreconciled one.
    pub fn into_parts(self) -> (Keystore<M>, MeshClient<T>) {
        (self.store, self.client)
    }
}

/// A one-word kind for a divergence, so [`Error`] can carry which one without
/// carrying a page of text or a server-authored string.
fn divergence_kind(d: &Divergence) -> &'static str {
    match d {
        Divergence::IndexMismatch { .. } => "index mismatch",
        Divergence::ReservationUnexplained { .. } => "reservation unexplained",
        Divergence::TagUnresolved { .. } => "tag unresolved by the node",
        Divergence::ChainUnreachable { .. } => "chain unreachable",
        Divergence::NoMasterForDerivedAccount { .. } => "no master for a derived account",
        Divergence::CannotReconcile { .. } => "reconciliation could not run",
    }
}

impl<M: Medium, T: Transport> fmt::Debug for Wallet<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("accounts", &self.accounts.len())
            .finish_non_exhaustive()
    }
}
