//! `status <tag> [--scan-to <M>]` and `reconcile <tag> --advance-to <N>` —
//! the two commands that act on a divergence, and therefore run before the
//! gate.
//!
//! # Why these are not `Wallet` methods in the CLI
//!
//! `Wallet::open` refuses every operation on a diverged account, and refuses
//! outright a store in which no account reconciled (I4). A one-shot process
//! that opens a wallet in order to act on a divergence therefore cannot act on
//! the account it is about: behind that gate, `reconcile <tag> --advance-to N`
//! would be refused by the very divergence it names, and a store with one
//! account -- which is every store until a second is funded -- would not open
//! at all. So the path every I4 report tells the operator to take would be the
//! one path the binary could not offer.
//! Measured by a probe before any edit; the one CLI test of `reconcile`
//! asserted that refusal under a comment describing the mismatch check.
//!
//! So both run on the `Keystore` directly, through `recon`, the way `restore`
//! does (move commands to where a third already was rather than carve
//! exceptions into `open`). The gate they honour is the acknowledgement,
//! not the wallet type: [`recon::advance_after_operator_review`] takes an
//! `OperatorAcknowledgement` that can only be built from a `Divergence`,
//! re-runs the comparison under the same scope, and refuses a target the live
//! divergence does not name. `Wallet::advance_after_operator_review` remains
//! for a long-running process in which a divergence appears after open, and
//! delegates to the same function.
//!
//! # What the gated path supplied, and this module keeps
//!
//! `Wallet::open` reconciled **every** account and rendered every failing one,
//! because the evidence that one account's advance is wrong most often lives
//! in another — a second account showing a spend this wallet did not make is
//! the live-second-wallet signal I4's third cause is about. So
//! [`advance_acknowledged`] reconciles the whole store first, hands every
//! report back for the caller to print **before** anything is written (on the
//! success path too), and refuses the advance outright while any other account
//! reports a reservation the chain explains at neither of its keys.
//!
//! # What that means for the containment rule
//!
//! The CLI's rule is: **no command holds a `Wallet` and a mutable `Keystore`
//! at once; the commands that hold a mutable store are the pre-gate ones
//! (`create`, `restore`, `reconcile`), and none of them reaches a signer.**
//! This module names no wallet type and no signer, and its only store write
//! is through a function that takes an `OperatorAcknowledgement`;
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` holds that
//! mechanically: it is a pre-gate module there, and
//! `advance_after_operator_review(` is permitted in this file alone.

use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::keystore::{Keystore, Medium};
use crate::mesh::{MeshClient, Transport};
use crate::recon::{self, AccountStatus, Cancel, Divergence, OperatorAcknowledgement, Progress, ScanScope, Unfinished};
use crate::{Error, Secret};

/// The diagnostic scope an invocation asks for: the default window and
/// ceiling, or the ceiling raised to walk `0..=to` when the operator named an
/// index.
///
/// `to` is inclusive as the operator reads it — "scan to 500" walks index 500
/// — so the ceiling is one more. The parser refuses `u32::MAX`, so the add
/// cannot overflow; `saturating_add` keeps this file free of a panicking
/// construct regardless.
pub fn scope_to(to: Option<u32>) -> ScanScope {
    match to {
        Some(m) => ScanScope::DIAGNOSTIC.with_ceiling(m.saturating_add(1)),
        None => ScanScope::DIAGNOSTIC,
    }
}

/// `status`: the same comparison `Wallet::open` makes, for one account,
/// reported without refusing — and reported *at all* when the
/// account is diverged, which behind the gate it never was.
#[allow(clippy::result_large_err)]
pub fn account_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> core::result::Result<AccountStatus, Divergence> {
    let access = recon::access_for(store, tag, master)?;
    recon::reconcile_account_with(store, client, tag, &access, &scope_to(scan_to), &recon::Cancel::NEVER)
}

/// What `reconcile` decided, after reading the whole store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The store advanced the named account to the acknowledged index.
    Advanced { index: u32 },
    /// The named account reconciles cleanly; there was nothing to advance past.
    NothingToReconcile(AccountStatus),
    /// The named account is diverged and no advance was made. `target` is the
    /// index the live report names when it names one; `None` when advancing
    /// is not the remedy for this divergence (behind, unlocated, unreachable,
    /// a reservation the chain explains at neither key).
    NoAdvance { target: Option<u32> },
    /// Another account in this store reports a spend this wallet did not make
    /// — a second wallet is live on this seed — so nothing was advanced.
    SecondInstanceSignal { other: Tag },
    /// The store does not hold the tag.
    NotHeld,
}

/// What `reconcile` read and did: every diverged account's report as it
/// stood before the decision, in tag order, and the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reviewed {
    pub reports: Vec<Divergence>,
    pub accounts: usize,
    pub outcome: Outcome,
}

/// `reconcile`: reconcile every account, then advance the named one only if
/// the live report names exactly the index the operator typed.
///
/// The operator's number is a hypothesis, not an instruction. It raises the
/// walk's ceiling to `advance_to + 1`, so the diagnostic covers `0..=advance_to`
/// as well as the window; if `address(advance_to)` is the address the chain
/// holds, the report is `Ahead { index: advance_to }` exactly as it would be
/// had the window found it, and the acknowledgement is built from that
/// report. If the chain is at some other index the walk reaches, the report
/// names *that* index and the acknowledgement the operator holds is refused
/// as not matching it; if the walk finds nothing, there is no acknowledgement
/// at all. Either way nothing is written.
pub fn advance_acknowledged<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
) -> core::result::Result<Reviewed, Error> {
    // `NEVER` is never asked, so `cancelled` is never called; `Ok` is the
    // answer that ends nothing.
    review_asking(store, client, tag, master, advance_to, &Cancel::NEVER, None, || Ok(()))
}

/// [`advance_acknowledged`], stoppable from outside: `cancel` is asked
/// before each account, once per position of each diagnostic walk, before
/// the write's own re-check, and again between that re-check's match and
/// the write itself.
///
/// A cancel is [`Unfinished::Cancelled`], never an [`Error`] and never a
/// [`Reviewed`]. A walk it ends leaves a report that is true and incomplete,
/// and an outcome decided from it would be a decision about an account made
/// out of the caller's own stop, so the whole call answers `Cancelled`. A
/// call that returns it wrote nothing; a cancel that arrives after the write
/// is too late to stop it, and the call returns what it advanced.
pub fn advance_acknowledged_with<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
    cancel: &Cancel<'_>,
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, advance_to, cancel, None, || Err(Unfinished::Cancelled))
}

/// [`advance_acknowledged_with`], telling `progress` how far it has got:
/// before each account, every [`recon::PROGRESS_EVERY`] positions of each
/// diagnostic walk, and again for the named account before the write's own
/// re-check walks it a second time ([`Progress`]).
pub fn advance_acknowledged_with_progress<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, advance_to, cancel, Some(progress), || Err(Unfinished::Cancelled))
}

/// The one review the three forms run. `cancelled` is what a cancel ends the
/// call with, and it is called only once `cancel` has said stop or a walk
/// records that it did.
///
/// Eight arguments: the review's own five, and the three that say whether
/// it may be stopped, who watches it, and what a stop returns.
/// `clippy::result_large_err` is allowed for the walk it watches, on
/// `recon::reconcile_account`'s ground: the error is the report.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn review_asking<M: Medium, T: Transport, E: From<Error>>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
    cancel: &Cancel<'_>,
    mut progress: Option<&mut dyn FnMut(Progress)>,
    cancelled: impl Fn() -> core::result::Result<(), E>,
) -> core::result::Result<Reviewed, E> {
    let tags = store.tags()?;
    let accounts = tags.len();
    let mut reviewed = Reviewed {
        reports: Vec::new(),
        accounts,
        outcome: Outcome::NotHeld,
    };
    if !tags.contains(tag) {
        return Ok(reviewed);
    }
    let scope = scope_to(Some(advance_to));

    // The whole store first, the named account under the raised ceiling and
    // every other under the default scope.
    let mut named: Option<core::result::Result<AccountStatus, Divergence>> = None;
    let of = u32::try_from(accounts).unwrap_or(u32::MAX);
    // The ceiling is read only for a caller that watches: it is the one
    // figure here that needs the store's view.
    let watching = progress.is_some();
    let at = |n: usize, t: &Tag, walked: &ScanScope| Progress {
        account: u32::try_from(n).unwrap_or(u32::MAX),
        accounts: of,
        position: 0,
        ceiling: match watching {
            true => walked.reach(store.view(t).ok().flatten().map(|v| v.wots_index)),
            false => 0,
        },
    };
    for (n, t) in tags.iter().enumerate() {
        if cancel.stop() {
            cancelled()?;
        }
        let this = t == tag;
        let walked = if this { &scope } else { &ScanScope::DIAGNOSTIC };
        let here = at(n, t, walked);
        if let Some(report) = progress.as_deref_mut() {
            report(here);
        }
        let result = match recon::access_for(store, t, master) {
            Err(d) => Err(d),
            Ok(access) => recon::watched(cancel, progress.as_deref_mut(), here, |cancel| {
                recon::reconcile_account_with(store, client, t, &access, walked, cancel)
            }),
        };
        if let Err(d) = &result {
            if d.stopped_by_cancel() {
                cancelled()?;
            }
            reviewed.reports.push(d.clone());
        }
        if this {
            named = Some(result);
        }
    }
    let divergence = match named {
        Some(Ok(status)) => {
            reviewed.outcome = Outcome::NothingToReconcile(status);
            return Ok(reviewed);
        }
        Some(Err(d)) => d,
        // `tags.contains(tag)` above, so the loop visited it.
        None => return Ok(reviewed),
    };

    // The second-wallet signal: a spend this wallet did not make, on any
    // other account of the same store.
    if let Some(other) = reviewed
        .reports
        .iter()
        .find(|d| d.tag() != *tag && matches!(d, Divergence::ReservationUnexplained { .. }))
        .map(Divergence::tag)
    {
        reviewed.outcome = Outcome::SecondInstanceSignal { other };
        return Ok(reviewed);
    }

    let Some(ack) = OperatorAcknowledgement::of(&divergence) else {
        reviewed.outcome = Outcome::NoAdvance { target: None };
        return Ok(reviewed);
    };
    if ack.target().get() != advance_to {
        reviewed.outcome = Outcome::NoAdvance {
            target: Some(ack.target().get()),
        };
        return Ok(reviewed);
    }
    let access = match recon::access_for(store, tag, master) {
        Ok(a) => a,
        // Unreachable in practice -- the same call succeeded a moment ago
        // for this tag -- and answered as the refusal it would be.
        Err(d) => {
            reviewed.reports.push(d);
            reviewed.outcome = Outcome::NoAdvance { target: None };
            return Ok(reviewed);
        }
    };
    if cancel.stop() {
        cancelled()?;
    }
    let here = at(tags.iter().position(|t| t == tag).unwrap_or(0), tag, &scope);
    if let Some(report) = progress.as_deref_mut() {
        report(here);
    }
    // The re-check is asked once more after its walk has matched and before
    // the write, since the walk asks before each position and not after the
    // last: a cancel raised while that position is derived is heard there.
    // That question asks the caller's own cancel, so it is no position of
    // the walk and adds none to the count `watched` reports.
    let (advanced, stopped) = recon::watched(cancel, progress, here, |counted| {
        recon::remembered(counted, |walking| {
            recon::guarded::advance_after_operator_review(store, client, tag, &access, ack, &scope, walking, || {
                match cancel.stop() {
                    true => Err(Error::Cancelled),
                    false => Ok(()),
                }
            })
        })
    });
    let receipt = match advanced {
        Ok(receipt) => receipt,
        // It reconciles once more under `scope` before it writes, and a
        // cancel that ends that walk leaves the account unlocated, which no
        // acknowledgement names: the refusal is the cancel's, not a finding,
        // and nothing was written. Whether the cancel said stop is what the
        // walk heard, remembered, and not asked again.
        Err(Error::AcknowledgementDoesNotMatch) if stopped => {
            cancelled()?;
            return Err(Error::AcknowledgementDoesNotMatch.into());
        }
        // The question between the walk's match and the write said stop.
        Err(Error::Cancelled) => {
            cancelled()?;
            return Err(Error::Cancelled.into());
        }
        Err(e) => return Err(e.into()),
    };
    reviewed.outcome = Outcome::Advanced {
        index: receipt.index().get(),
    };
    Ok(reviewed)
}
