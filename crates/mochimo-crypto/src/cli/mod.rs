//! `tawara` — the command layer.
//!
//! The binary is `src/bin/tawara.rs`; everything it does is here, generic
//! over [`Medium`] and [`Transport`] so the tests drive every command against
//! the scriptable chain rather than against a mock of the wallet.
//!
//! # What this layer is not allowed to hold
//!
//! **A `Wallet` and a mutable `Keystore` at once.** The commands that hold a
//! mutable store are the pre-gate ones — [`create`], [`restore`] and
//! [`reconcile`] — and none of them names a signer or a `Wallet`; every
//! other command takes a `Wallet`, returns rendered text, and never names a
//! signer. `Wallet::store` is `&`-only and there is no `store_mut`, but the
//! crate cannot see whether a caller reached around the gate some other way,
//! so the CLI's own structure is the enforcement and
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` scans these files
//! for the names that would defeat it.
//!
//! **Why `status` and `reconcile` run before the gate**: a
//! one-shot process meets a divergence *before* a `Wallet` can exist, because
//! `Wallet::open` refuses on one. See [`reconcile`]'s module doc.
//!
//! Returning `Report` rather than a signature-bearing type is load-bearing
//! twice: it keeps these functions out of the route scan's flagged set by
//! construction rather than by allow-listing, and it is what lets every
//! refusal be *rendered and read back* in a test.
//!
//! # The three residues
//!
//! A CLI is where a human meets this project's three unfalsified claims, and
//! rendering them softly is worse than not rendering them:
//!
//! * **submit is a socket write, not a verdict.** `/construction/submit`
//!   writes `OP_TX` to one node and returns before any reply, echoing an id it
//!   computed locally. The output says so.
//! * **`tx_val` has never run offline.** Every check this program can make can
//!   pass on a transaction a node then rejects for a ledger, balance-tally or
//!   block-to-live reason.
//! * **the retry artifact is losable.** `send` prints the signed bytes and
//!   says what they are for, because the operator has to know the hex matters
//!   *before* they discard it.
//!
//! I4's message-quality clause governs all of this, not only
//! `Wallet::open`'s refusal: a message that satisfies the letter and produces
//! a workaround is the failure the invariant exists to prevent.

pub mod address;
pub mod args;
pub mod create;
pub mod discover;
pub mod outcome;
pub mod reconcile;
pub mod render;
pub mod restore;

use crate::addr::Tag;
use crate::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SEED_LEN};
use crate::keystore::{KeyAccess, Keystore, Medium};
use crate::mesh::spend::SpendPlan;
use crate::mesh::codec;
use crate::mesh::{MeshClient, Transport, TxId};
use crate::account::WotsIndex;
use crate::recon::{AccountStatus, ChainPosition, Divergence, Expiry, Reservation};
use crate::tx::wire::Destination;
use crate::wallet::Wallet;
use crate::{Error, Result, Secret};

use args::{Command, Spend};
use outcome::{AccountLine, Decided, MempoolRow, Outcome};

/// What the process exits with. A refusal is never `0`.
///
/// The split is by **what the operator does next**, which is why a transport
/// failure is not its own code: unreachable-during-open is a wallet that did
/// not open (2), unreachable-during-a-command is a command that did not happen
/// (3), and the remedy differs by *when* rather than by kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The command did what it says.
    Ok = 0,
    /// argv did not parse.
    Usage = 1,
    /// The wallet refused to open: reconciliation found a divergence (I4).
    StartupRefused = 2,
    /// The wallet opened and the command was refused.
    Refused = 3,
}

/// Rendered output and the code to exit with.
pub struct Report {
    pub text: String,
    pub code: Code,
}

impl Report {
    fn ok(text: String) -> Report {
        Report {
            text,
            code: Code::Ok,
        }
    }
    fn refused(text: String) -> Report {
        Report {
            text,
            code: Code::Refused,
        }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// **The one place this program turns a tag into something an operator
/// copies**.
///
/// Every command that shows a tag calls this, so what `create` prints, what
/// `address` prints, what `balance` prints and what a refusal names are the
/// same string for the same twenty bytes. Four separate call sites of
/// [`hex_bytes`] would be four chances to print a form no other wallet takes.
///
/// # The rule this establishes, and it is narrower than "print Base58"
///
/// **A destination is printed only where it is the ANSWER to the question
/// asked.** Where the program is naming back something the operator supplied
/// -- `address <tag>`'s no-such-account refusal, say -- it renders hex
/// instead. That is not inconsistency: a Base58 string on screen has been
/// taught by `create`, `address` and `balance` to mean *where money goes*, so
/// echoing an unrecognised argument in that form puts a payable-looking string
/// in front of an operator at the exact moment the program is telling them it
/// knows nothing about it. Hex there is unmistakably *the thing you named*.
///
/// # Why the error is propagated rather than answered with hex
///
/// A fallback would be a second identifier printed at exactly the moment the
/// first one could not be produced, and the operator has no way to tell which
/// kind of string they are looking at. Refusing says the one true thing: this
/// program cannot presently tell you where to send money. The branch is not
/// reachable for a tag — [`crate::base58::encode`] refuses only a NULL or
/// empty input and this payload is twenty-two bytes — which
/// is stated here rather than asserted, because no input reaches it and a
/// marker nobody can discharge is worse than knowledge.
fn destination(tag: &Tag) -> crate::Result<String> {
    crate::addr::tag_to_base58(tag)
}

/// A refusal that names the tag it is about, for the paths that cannot
/// propagate. Used only where a `Report` is already being built for another
/// reason.
fn cannot_render(tag: &Tag, e: &Error) -> Report {
    Report::refused(format!(
        "cannot render the destination for the tag whose hex is {}: {e}",
        hex_bytes(tag)
    ))
}

/// **`needs_master` is gone, and its subject went with it**.
///
/// It answered *does this invocation need the operator to type twenty-four
/// words?* -- a question with a per-command answer, because the seed was
/// reconstructed from a prompt and some commands could avoid it. The seed now
/// lives inside the encrypted store, so the question collapsed: **nothing can
/// be read out of the file without the password**, including the account list
/// `address` prints. Every command needs it and there is no arm to get wrong.
///
/// What did NOT collapse is the other half of that function's finding, and it
/// is asserted by `tests/cli.rs::the_listing_needs_no_node_and_no_seed`: the
/// listing still derives nothing and asks no node. It needs the password
/// because the bytes are encrypted, not because it needs a key. (One more
/// command runs without the password: `submit`, which opens no
/// store at all, and the binary dispatches it before the prompt as it does
/// `create`.)
/// The access an account's kind demands, chosen **per account**.
///
/// Built fresh at each call site rather than threaded: `KeyAccess` is neither
/// `Copy` nor `Clone` -- it borrows a `Secret` and the crate declines to make
/// key access duplicable by derive -- and `reserve_and_sign` takes it by
/// value. Constructing one is a store view and a reference copy.
///
/// The choice is
/// `recon::access_for`'s, the same one `Wallet::open`, `status` and
/// `reconcile` already made: the master for a derived account, the stored root
/// for an imported one. Its two refusals become the errors the call sites
/// already render -- a tag the store does not hold is `NoSuchAccount`, and a
/// derived account in a store holding no master is the same key-access
/// mismatch the store-wide choice produced, since `key_at` refuses
/// `StoredRoot` for a derived record. `access_for` returns no other
/// divergence; the last arm names the class so a widening of it is a
/// refusal here rather than a silent route.
pub fn key_access<'a, M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    master: Option<&'a Secret<SEED_LEN>>,
) -> crate::Result<KeyAccess<'a>> {
    match crate::recon::access_for(store, tag, master) {
        Ok(access) => Ok(access),
        Err(Divergence::NoMasterForDerivedAccount { .. }) => Err(Error::KeyAccessMismatch {
            kind: crate::account::AccountKind::Derived,
        }),
        Err(Divergence::CannotReconcile { cause, .. }) => Err(cause),
        Err(_) => Err(Error::ReconciliationRefused {
            what: "the store's view of this account could not choose its key access",
        }),
    }
}

/// Run one command. The store is consumed: every command but `restore` turns
/// it into a `Wallet` and nothing hands it back.
pub fn run<M: Medium, T: Transport>(
    store: Keystore<M>,
    client: MeshClient<T>,
    command: &Command,
) -> Report {
    render::render(&decide(store, client, command))
}

/// A command that answered before a `Wallet` existed, so there are no
/// standing divergences to report beside it: nothing reconciled anything.
fn before_the_gate(outcome: Outcome) -> Decided {
    Decided {
        standing: Vec::new(),
        outcome,
    }
}

/// Run `command` and return **what it decided**, in types, with nothing yet
/// said in words.
///
/// This is [`run`] without the last step. The two exist separately because a
/// decision and the sentence announcing it are different things and only one
/// of them can be tested for being right; `render` is the other, and
/// `outcome`'s module doc carries the argument.
pub fn decide<M: Medium, T: Transport>(
    store: Keystore<M>,
    client: MeshClient<T>,
    command: &Command,
) -> Decided {
    // **The seed comes out of the store, not off the terminal**: the password
    // that opened the file is what produced it.
    // Cloned because the store is consumed into a `Wallet` below and the seed
    // has to outlive that move; `Secret` zeroizes, and both copies go when this
    // function returns.
    let master = match store.master() {
        Ok(m) => m.map(Secret::duplicate),
        Err(e) => {
            return before_the_gate(Outcome::StoreUnreadable(e))
        }
    };
    let master = master.as_ref();
    // The pre-gate commands. `restore`, and `address` -- which is
    // the command the deadlock was about, because a `Wallet` refuses a tag the
    // ledger has never held and that is exactly when you need an address to
    // fund -- and `status` and `reconcile`, which act on a divergence
    // and so cannot sit behind a constructor that refuses on one. `create`
    // never reaches here: there is no store to hand in.
    match command {
        Command::Restore { account, scan_to } => {
            return before_the_gate(cmd_restore(store, &client, master, *account, *scan_to))
        }
        Command::Address { tag, account } => {
            return before_the_gate(cmd_address(&store, tag.as_ref(), *account, master))
        }
        // `discover` sits beside `address` for the same reason and one
        // more: it asks the node about tags the store does NOT hold, and an
        // account the node does not resolve is one `Wallet::open` refuses --
        // which is the state a sweep exists to report on, and a store whose
        // accounts are all in it does not open at all.
        Command::Discover { to } => {
            return before_the_gate(cmd_discover(&store, &client, master, *to))
        }
        // No store at all: the artifact is the input. The binary reaches
        // `run_submit` before it opens one; a caller that hands a store in
        // gets it dropped, unread.
        Command::Submit { artifact } => return before_the_gate(cmd_submit(&client, artifact)),
        // The explorer verbs, for the same reason: the node is the whole
        // input. The binary reaches `run_explorer` before it prompts.
        Command::LookupTransaction { hash } => {
            return before_the_gate(cmd_transaction(&client, hash))
        }
        Command::RecentTransactions { tag, count, from } => {
            return before_the_gate(cmd_recent_transactions_from(&client, tag, *count, *from))
        }
        Command::Block { at } => return before_the_gate(cmd_block(&client, at)),
        Command::Blocks { count } => return before_the_gate(cmd_blocks(&client, *count)),
        Command::Mempool { count } => return before_the_gate(cmd_mempool(&client, *count)),
        Command::Status { tag, scan_to } => {
            return before_the_gate(cmd_status(&store, &client, tag, master, *scan_to))
        }
        Command::Reconcile { tag, advance_to } => {
            return before_the_gate(cmd_reconcile(store, &client, tag, master, *advance_to))
        }
        _ => {}
    }

    let mut w = match Wallet::open(store, client, master) {
        Ok(w) => w,
        Err(refusal) => {
            return before_the_gate(Outcome::StartupRefused(Box::new(refusal)))
        }
    };

    // An imported-only store has no master and reconciles through the stored
    // root; a derived account with no master never reaches here, because
    // `open` already refused it.
    // The account this command acts on, for the three verbs that name one.
    // `balance` names none: it reports the store, and the diverged half of it
    // is rendered by the notice below rather than refusing the command.
    let addressed = match command {
        Command::Settle { tag } | Command::Resign(Spend { tag, .. }) | Command::Send(Spend { tag, .. }) => Some(*tag),
        _ => None,
    };
    // A named account that diverged is refused here, with its own report, and
    // **with no standing divergences carried beside it**, so the notice does
    // not repeat immediately above what the refusal already says. That was an
    // early return before the notice was applied; it is an empty `standing`
    // now, which is the same thing said in the value instead of in the
    // control flow.
    if let Some(tag) = addressed {
        if let Some(d) = w.divergence_for(&tag) {
            return before_the_gate(Outcome::Diverged(Box::new(d.clone())));
        }
    }

    // Owned, so the borrow ends before the commands that need `&mut w`.
    let standing = w.diverged().to_vec();
    let outcome = match command {
        Command::Restore { .. }
        | Command::Address { .. }
        | Command::Discover { .. }
        | Command::Create { .. }
        | Command::Status { .. }
        | Command::Reconcile { .. }
        | Command::Submit { .. }
        | Command::LookupTransaction { .. }
        | Command::RecentTransactions { .. }
        | Command::Block { .. }
        | Command::Blocks { .. }
        | Command::Mempool { .. } => Outcome::HandledBeforeTheWallet,
        Command::Balance => cmd_balance(&w),
        Command::Settle { tag } => cmd_settle(&mut w, tag, master),
        Command::Send(s) => cmd_send(&mut w, s, master),
        Command::Resign(s) => cmd_resign(&mut w, s, master),
    };
    Decided { standing, outcome }
}

/// The in-program spelling of the action a report names, per account, after
/// the report -- and only for the arms an action exists for: an `Ahead` names
/// the `reconcile` line with its index filled in, an `Unlocated` names the
/// `status --scan-to` search and the `reconcile` line to follow it with. The
/// other arms' ACTION lines already say what to do and no command here does
/// it (a refutation pass found a blanket footer false on five of six arms).
///
/// The tag is printed already in its `0x` form so nothing is assembled by
/// hand; a mistyped hex tag reaches `status`/`reconcile`'s no-such-account
/// arm, which pays nobody.
/// The diverged accounts, rendered on **every** page a started wallet produces.
///
/// A store that is not whole says so on every invocation, whatever the command
/// was. The alternative is a condition an operator meets only when they happen
/// to address the account it is about, which for an account they cannot use is
/// exactly when they are not looking.
///
/// Empty for a whole store, so a wallet with nothing diverged renders nothing
/// and every page it produces is the page it produced before.
fn standing_divergence_notice(diverged: &[Divergence]) -> String {
    if diverged.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "THIS STORE IS NOT WHOLE: {} account(s) could not be reconciled against the chain. The \
         accounts below are refused; every other account in this store is not.\n\n",
        diverged.len()
    );
    for d in diverged {
        out.push_str(&format!("{d}\n\n"));
    }
    out.push_str(&next_steps(diverged));
    out.push_str("\n\n---\n\n");
    out
}

/// The page an operation on a diverged account is refused with.
///
/// The whole report, unchanged, and nothing about a sibling: a healthy sibling
/// is evidence of nothing here. A second wallet on this seed touches one
/// account and leaves the others pristine, so the state of another account is
/// exactly what a second signer also produces.
fn refuse_diverged_account(d: &Divergence) -> Report {
    Report::refused(format!(
        "REFUSED: this account is not reconciled with the chain, so no operation on it is \
         permitted. Other accounts in this store are unaffected and are not refused.\n\n{d}{}",
        next_steps(core::slice::from_ref(d))
    ))
}

fn next_steps(diverged: &[Divergence]) -> String {
    let mut out = String::new();
    for d in diverged {
        let Divergence::IndexMismatch { tag, found, .. } = d else { continue };
        let t = format!("0x{}", hex_bytes(tag));
        match found {
            ChainPosition::Ahead { index, .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: after reading the report above, \
                 `reconcile {t} --advance-to {}` takes the acknowledged path. It derives \
                 index {} again, compares it to the chain, and advances only on a match.",
                index.get(),
                index.get()
            )),
            ChainPosition::Unlocated { .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: `status {t} --scan-to <M>` walks \
                 indices 0 through M and reports the index it finds, writing nothing; then \
                 `reconcile {t} --advance-to <N>` with the index it named takes the \
                 acknowledged path, deriving N again and advancing only on a match."
            )),
            ChainPosition::Behind { .. } => {}
        }
    }
    out
}

fn cmd_restore<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    account: u32,
    scan_to: Option<u32>,
) -> Outcome {
    let Some(m) = master else {
        return Outcome::RestoreNeedsMaster;
    };
    match restore::restore_account(&mut store, client, m, account, scan_to) {
        Ok(r) => Outcome::Restored {
            account,
            found: r.found,
            held_at: r.held_at,
            upgraded: store.upgraded_from(),
        },
        Err(failure) => Outcome::RestoreRefused { account, failure },
    }
}

/// One account's state, in the words `balance` and `status` both use.
///
/// Shared so the two commands cannot drift into describing the same three
/// states differently.
fn state_of(status: &AccountStatus) -> String {
    match status {
        AccountStatus::InSync { .. } => "in sync".to_string(),
        // The live line is byte for byte what it was before the diagnosis, and a dead
        // reservation REPLACES it rather than extending it: the old words are
        // literally true and useless beside a dead reservation, and the live line
        // is asserted by equality as a control. The figures go
        // on their own lines beside it, through [`reservation_lines`].
        AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } => match reservation {
            Reservation::Recorded(d) if d.is_dead() => format!(
                "RESERVED SPEND at index {} is DEAD -- the signed artifact can no longer be accepted",
                spent_index.get()
            ),
            _ => format!(
                "SPEND OUTSTANDING at index {} -- not yet seen on the chain",
                spent_index.get()
            ),
        },
        AccountStatus::SpendLanded { spent_index, .. } => format!(
            "spend from index {} has landed -- run `settle`",
            spent_index.get()
        ),
    }
}

/// The reserved spend's two figures and what each says, one line per figure,
/// in the same words on `status` (two-space indent), `balance` (four) and
/// `settle` (two). The words come from one place so
/// the three pages cannot drift, which is `state_of`'s argument again.
///
/// Additive by design: a recorded reservation always gets BOTH lines, each
/// carrying its own verdict, so a reservation dead by both causes says both.
/// A migrated reservation (figures not recorded, format version 3) gets one
/// line saying so and no verdict -- neither live nor dead can be told from
/// the store. A dead reservation gets a closing line that names what
/// is NOT decided (the route out) and states the price of the
/// only other route as a fact, in the unit the audit measured it in; it instructs nothing --
/// no refusal is on these pages, and the route out is escalated.
///
/// What each phrase rests on, read on disk: a deposit credits by tag in place
/// and `tx_val` demands
/// `send + change + fee` equal the balance exactly, so a
/// moved balance is dead for good; block N is the last block that can carry
/// btl N, and `txclean` drops it against the
/// next block, so the artifact is dead once the tip
/// reaches the value; zero never expires.
/// The block-to-live marker in `tests/cli.rs` harvests every decimal token of `status`
/// and `balance` against a ceiling of 64; these lines add the block-to-live
/// and the tip to a page that carried four.
fn reservation_lines(spent_index: WotsIndex, reservation: &Reservation, indent: &str) -> String {
    let mut out = String::new();
    match reservation {
        Reservation::Unrecorded => out.push_str(&format!(
            "{indent}reserved figures  not recorded: this reservation was written under format \
             version 3, which carried neither the balance nor the block-to-live. Whether the \
             artifact can still be accepted cannot be told from this store; the next write \
             re-seals the store as version 4 with the figures declared absent.\n"
        )),
        Reservation::Recorded(d) => {
            let b = d.figures.reserved_balance;
            if d.balance_moved {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built; the ledger holds {} \
                     now. A deposit landed on this tag, and the node demands the signed totals \
                     equal the balance EXACTLY, so the artifact can no longer \
                     be accepted.\n",
                    d.balance_now
                ));
            } else {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built (the ledger holds the \
                     same now)\n"
                ));
            }
            let btl = d.figures.blk_to_live;
            let expiry = match &d.expiry {
                Expiry::NoExpiry => format!("{btl} (never expires)"),
                Expiry::Below { tip } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives; the tip is {tip})"
                ),
                Expiry::Reached { tip } => format!(
                    "{btl} -- the tip is {tip}: the block-to-live has passed and the artifact can no \
                     longer be accepted"
                ),
                Expiry::Unreadable { cause } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives); the tip could not be read \
                     ({cause}), so whether it has passed is UNCHECKED here -- not assumed live"
                ),
            };
            out.push_str(&format!("{indent}block-to-live     {expiry}\n"));
            if d.is_dead() {
                // This build offers no route out, on purpose. The first two sentences
                // are the specification's, word for word (*The block-to-live
                // sits inside the signed digest*).
                out.push_str(&format!(
                    "{indent}A dead reservation has no route out: the whole balance at the reserved \
                     key is reachable only by a signature from that key, and the only signature \
                     this wallet will ever produce from that key is the one already produced. No \
                     command offers a second one, on purpose: a second, different signature under \
                     the key at index {} is the key reuse this wallet's refusals exist to prevent, \
                     and its price would be the whole balance at that key.\n",
                    spent_index.get()
                ));
            }
        }
    }
    out
}

fn cmd_balance<M: Medium, T: Transport>(w: &Wallet<M, T>) -> Outcome {
    Outcome::Balance {
        accounts: w
            .accounts()
            .iter()
            .map(|(tag, status)| AccountLine {
                tag: *tag,
                status: status.clone(),
            })
            .collect(),
    }
}

/// Where to receive. **No wallet, no chain** — see `cli::address`.
///
/// # The first line is the destination, bare, and that is a decision
///
/// Machine-readable answer first, prose after: an operator copies line one, a
/// script reads line one, and neither has to know how this program formats a
/// paragraph. The rendered form is Base58 rather than hex because **it is the
/// only one of the two that catches a typo** — the Base58 payload carries a
/// CRC16 and [`crate::addr::tag_from_base58`] checks it, where a mistyped hex
/// tag is a perfectly well-formed tag for an address nobody holds and the
/// funds are gone with nothing refused.
///
/// # The hex that remains is a different object, not a second spelling
///
/// The 40-byte ledger address is printed too, indented and labelled. It is
/// not a destination and cannot be confused for one: it is eighty characters
/// where a destination is twenty-two to thirty-one, every other wallet
/// refuses it on sight, and this program's own `send <to>` refuses it as
/// longer than a tag. So there is never a *pair* of strings on screen both of
/// which are "where to send" — which is the transcription hazard printing two
/// forms of one identifier would create.
fn cmd_address<M: Medium>(
    store: &Keystore<M>,
    tag: Option<&Tag>,
    account: Option<u32>,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    if let Some(n) = account {
        return cmd_address_of_unstored_account(store, n, master);
    }
    let Some(tag) = tag else {
        return cmd_accounts(store);
    };
    match key_access(store, tag, master).and_then(|access| address::address_of(store, tag, &access)) {
        Ok(w) => Outcome::Address {
            tag: *tag,
            address: w.address,
            index: w.index,
        },
        Err(Error::NoSuchAccount) => Outcome::NoAccountToAddress { tag: *tag },
        Err(e) => Outcome::Failed(e),
    }
}

/// `address --account N`: the destination of an account this store does
/// **not** hold, derived from the master it does hold and stored nowhere.
///
/// # The decision this carries out
///
/// `create` derives account 0 and nothing else, and `restore --account N`
/// adds an account only after the chain resolves its tag -- so nobody could
/// be *given* a second account's destination, because the store could not
/// hold an account the chain had never seen. The operator decided on
/// 2026-09-14 to open that loop here, read-only: derive account N, print
/// the destination and the position-0 ledger address exactly as
/// `address <tag>` does, store nothing. Once the destination has been paid,
/// `restore --account N` asks the chain where the account sits and adds it
/// at that position -- 0 for a first credit -- with the same tag as this
/// page. No invariant moves: `Wallet::open`'s refusal on a never-funded
/// account stays, and this is the route around it, not through it.
///
/// # What it writes, reserves and asks: nothing
///
/// The store is borrowed immutably, so a write here is a compile error, and
/// `tests/cli.rs` holds the snapshot bytes identical across the call. No
/// node is asked: the address is a function of the seed.
///
/// # Two refusals
///
/// A store holding no master (imported accounts only) can derive nothing.
/// An account the store already holds is refused rather than answered:
/// its position may be past 0, and position 0's address is one the chain
/// may no longer hold, so `address <destination>` is the page for it.
fn cmd_address_of_unstored_account<M: Medium>(
    store: &Keystore<M>,
    account: u32,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let Some(master) = master else {
        return Outcome::NoMasterSeed;
    };
    let tag = crate::derive::derive_account_tag(master, account);
    match store.view(&tag) {
        Ok(Some(view)) => {
            return Outcome::AccountAlreadyStored {
                account,
                tag,
                index: view.wots_index,
            }
        }
        Ok(None) => {}
        Err(e) => return Outcome::Failed(e),
    }
    Outcome::UnstoredAddress {
        account,
        tag,
        address: crate::recon::derived_address_at(master, account, WotsIndex::ZERO),
    }
}

/// `discover [--to N]`: what the node says about accounts `0..=N` derived
/// from the master this store holds.
///
/// # The page's one rule
///
/// **Nothing here says an account does not exist.** The header states the
/// extent searched and how many indices the node resolved; the table lists
/// every index that resolved and every index this store holds; the indices
/// the node did not resolve are named, as indices the node did not resolve,
/// beside the three states that answer conflates. `cli::discover`'s module
/// doc argues it, and it is the reason the default of 64 is defensible:
/// not because 64 is the right number of accounts to look for, but because
/// the number searched is printed on the page and `--to` changes it.
///
/// # What it writes: nothing
///
/// The store is borrowed immutably. No wallet is constructed, no
/// reservation is taken, nothing is signed, and `tests/cli.rs` holds the
/// snapshot bytes identical across the call.
fn cmd_discover<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    to: u32,
) -> Outcome {
    let Some(master) = master else {
        return Outcome::DiscoverNeedsMaster;
    };
    match discover::sweep(store, client, master, to) {
        Ok(sweep) => Outcome::Discovered { sweep },
        Err(discover::SweepFailure::ChainUnreachable {
            account,
            searched,
            cause,
        }) => Outcome::SweepStopped {
            account,
            searched,
            to,
            cause,
        },
    }
}

/// A list of indices, sixteen to a line, each line indented under the count
/// that introduces it. A thousand unresolved indices is a legitimate answer
/// and one very long line is not a way to print it.
fn wrapped_indices(indices: &[u32]) -> String {
    let mut out = String::new();
    for (i, n) in indices.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("\n   ");
        }
        out.push_str(&format!(" {n}"));
    }
    out
}

/// `address` with no tag: what this store holds, from the records alone.
///
/// **No seed and no node**, which is the point — this is the route back to a
/// destination for an operator who has one and cannot name it, including the
/// one `create` just refused the confirmation for.
fn cmd_accounts<M: Medium>(store: &Keystore<M>) -> Outcome {
    match address::accounts_in(store) {
        Ok(held) => Outcome::Accounts { held },
        Err(e) => Outcome::Failed(e),
    }
}

/// `status`: one account, reconciled now, **before the gate**.
///
/// Exit 0 whenever the comparison ran and produced an answer -- in sync, a
/// spend state, or a divergence, which is an answer about the account and not
/// a refusal of the command; the report goes to stdout with it. Exit 3 when
/// the question could not be asked: the chain unreachable, no master for a
/// derived account, a tag the store does not hold. `Code::StartupRefused` is
/// not borrowed for a divergence here: no wallet was opened, and that code's
/// one meaning is that one refused to.
fn cmd_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> Outcome {
    status_outcome(tag, reconcile::account_status(store, client, tag, master, scan_to))
}

/// What `status` decides from one account's comparison: the
/// [`reconcile::account_status`] result for `tag`, as the outcome
/// [`cmd_status`] returns, so a caller that runs the comparison itself
/// renders from the same decision.
///
/// In sync or in a spend state is [`Outcome::Status`]; a divergence that is
/// an answer about the account -- an index mismatch, a reservation the chain
/// explains at neither key, a tag the node did not resolve -- is
/// [`Outcome::StatusDiverged`]; a tag the store does not hold is
/// [`Outcome::NoSuchAccount`]; and a comparison that could not run is
/// [`Outcome::StatusRefused`].
pub fn status_outcome(tag: &Tag, compared: core::result::Result<AccountStatus, Divergence>) -> Outcome {
    match compared {
        Ok(status) => Outcome::Status { tag: *tag, status },
        Err(Divergence::CannotReconcile {
            cause: Error::NoSuchAccount,
            ..
        }) => Outcome::NoSuchAccount { tag: *tag },
        // The same report a refusal prints -- one rendering, so what the
        // operator reads when a command reports is what they read when an
        // operation on this account is refused. Exit 0: it is an answer about
        // the account and not a refusal of the command.
        Err(d @ (Divergence::IndexMismatch { .. }
        | Divergence::ReservationUnexplained { .. }
        | Divergence::TagUnresolved { .. })) => Outcome::StatusDiverged {
            tag: *tag,
            divergence: Box::new(d),
        },
        Err(d) => Outcome::StatusRefused {
            divergence: Box::new(d),
        },
    }
}

/// The refusal for a tag this store does not hold, shared by `status` and
/// `reconcile`: hex, not the destination form, for the reason `address`'s
/// arm gives -- it is the string the operator typed, echoed where the
/// program is saying it knows nothing about it.
fn no_such_account(tag: &Tag) -> String {
    format!(
        "no account for the tag {} in this store -- that is the tag you named, in hex so it \
         cannot be mistaken for somewhere to send funds. `address` with no argument lists what \
         is here.",
        hex_bytes(tag)
    )
}

/// `settle`: the page carries the reservation's diagnosis when it stands
/// -- a dead one drops the `resign` prescription, since
/// re-signing dead bytes reproduces bytes the ledger will refuse -- and the
/// crossing line when the settle was the first write over a version-3 store.
fn cmd_settle<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let settlement = match key_access(w.store(), tag, master) {
        Ok(access) => w.settle_if_landed(tag, &access),
        Err(e) => Err(e),
    };
    // Read where the store is open, because the renderer does not hold it.
    let upgraded = w.store().upgraded_from();
    match settlement {
        Ok(settlement) => Outcome::Settled {
            settlement,
            upgraded,
        },
        Err(e) => Outcome::Failed(e),
    }
}

/// The destinations as the wire wants them, with `all` already resolved.
///
/// `amount` is `None` only for the keyword `all`, and only ever at a single
/// destination (the parser enforces both), so `resolved` is the whole balance
/// less the fee and is used exactly once. The planner sorts this list by its
/// 44-byte image afterwards; the order here is the operator's.
fn spend_destinations(s: &Spend, resolved: u64) -> Vec<Destination> {
    s.dsts
        .iter()
        .map(|d| Destination {
            tag: d.to,
            reference: d.reference,
            amount: d.amount.unwrap_or(resolved),
        })
        .collect()
}

/// What a zero change means, said on the page that creates it.
///
/// A change of zero empties the account, and the Mesh's tag resolution
/// answers *account not found* for a tag it holds at zero balance -- the
/// middleware's quorum discards the entry. Reconciliation fails closed on that
/// answer, so every operation on **this account** refuses until the tag is
/// paid again. Other accounts in the store are unaffected, and paying this one
/// from a sibling is the recovery. A store in which this is the only account
/// has no operable account at all and needs a payment from elsewhere. The
/// route to the socket meanwhile is `submit`, which opens no store.
///
/// Printed whenever the change is zero, not only for the `all` keyword: an
/// operator who typed `balance − fee` by hand reaches exactly the same state
/// and is owed the same warning.
fn emptying_text(settle_arg: &str) -> String {
    format!(
        "{}  Keep the artifact below. `submit` writes it to the socket without opening the \
         store, and is the route to a node while the account reads as not found.\n",
        emptying_paragraph(settle_arg)
    )
}

/// The part of [`emptying_text`] that is true before anything is signed:
/// what a zero change does to this account and to the rest of the store.
/// The planned page carries it with its own last sentence, since the
/// artifact it would point at does not exist yet.
fn emptying_paragraph(settle_arg: &str) -> String {
    format!(
        "\nTHIS EMPTIES THE ACCOUNT. The change is zero, so nothing returns to your next key \
         under {settle_arg}.\n  The Mesh reports a tag it holds at zero balance as \"account not \
         found\", which it does not distinguish from never funded or from a failed lookup, so \
         once this lands every operation ON THIS ACCOUNT refuses until it is paid again. Other \
         accounts in this store keep working, and paying this one from another account in the \
         store is the way back. If this is the only account here, the payment has to come from \
         somewhere else.\n"
    )
}

/// Lay the spend out, resolving `all` against the same ledger observation the
/// plan is built on.
///
/// **Why this unrolls `Wallet::plan` instead of calling it.** `plan` is
/// `spend_addresses` + `resolve_tag` + `SpendPlan::new`, and for `all` the
/// amount is a function of the balance that middle call returns. Reading the
/// balance first and then calling `plan` would be two observations of a
/// moving number: if a credit landed between them the change would not be
/// zero and `all` would quietly fail to empty the account. Unrolled, there is
/// one `resolve_tag` -- the same one `plan` makes, no more -- and the amount
/// and the plan are computed from the same `entry`.
///
/// Without `all` this is `plan` exactly, and takes the same route.
pub fn plan_spend<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<SpendPlan> {
    if !s.spends_everything() {
        return w.plan(&s.tag, access, spend_destinations(s, 0), s.fee_total, s.blk_to_live);
    }
    let addresses = w.spend_addresses(&s.tag, access)?;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    SpendPlan::new(
        &addresses,
        &entry,
        spend_destinations(s, amount),
        s.fee_total,
        s.blk_to_live,
    )
}

/// `balance − fee`, or the refusal that says why there is nothing to send.
///
/// A balance at or below the fee leaves nothing for a destination, and a
/// destination amount of zero is refused by the node's own rule, so this is
/// reported as the insufficient balance it is rather than as a zero amount
/// the operator never typed.
pub fn spend_all_amount(balance: u64, fee_total: u64) -> Result<u64> {
    match balance.checked_sub(fee_total) {
        Some(0) | None => Err(Error::InsufficientBalance {
            balance,
            needed: fee_total.saturating_add(1),
        }),
        Some(amount) => Ok(amount),
    }
}

/// The destinations `resign` rebuilds the reserved plan from.
///
/// `all` is reproducible: it resolves against the balance now, and if the
/// balance is what it was when the reservation was made the amount is the
/// same and the digest matches. If it moved, the amount differs, the digest
/// differs, and `resign` refuses as a different transaction -- which is
/// correct, because the bytes that were signed encode the old amount and
/// those are the only bytes the reserved key will ever produce.
fn resign_destinations<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<Vec<Destination>> {
    if !s.spends_everything() {
        return Ok(spend_destinations(s, 0));
    }
    let _ = access;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    Ok(spend_destinations(s, amount))
}

/// The lines of the page that list what is being sent, one per destination.
///
/// Every destination is shown in the checksummed form whichever form was
/// typed, with its amount and its reference when it has one, so the whole
/// spend can be compared against the payees before anything is signed. The
/// order is the operator's, not the wire's: it is what they typed and what
/// `resign` will demand back.
fn destination_lines(dsts: &[Destination]) -> core::result::Result<String, (Tag, Error)> {
    let mut out = String::new();
    for (i, d) in dsts.iter().enumerate() {
        let shown = destination(&d.tag).map_err(|e| (d.tag, e))?;
        out.push_str(&format!("  {:>3}. {} nanoMCM\n       to  {shown}\n", i + 1, d.amount));
        let r = reference_line("       ref ", &d.reference);
        if !r.is_empty() {
            out.push_str(&r);
        }
    }
    Ok(out)
}

/// The `ref` line of `send`'s page and the `reference` line of `resign`'s,
/// present only when a reference was given: the field's ASCII up to its
/// first NUL, which `--ref` guarantees, so the operator sees the text they
/// typed beside the other figures `resign` will demand. Empty for the zero
/// field, so a page without the flag is what it was before the flag existed.
fn reference_line(label: &str, field: &[u8; ADDR_REF_LEN]) -> String {
    if *field == [0u8; ADDR_REF_LEN] {
        return String::new();
    }
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    format!("{label}{}\n", String::from_utf8_lossy(&field[..end]))
}

/// The block-to-live, rendered so the operator can record it beside the
/// artifact.
///
/// The value is inside the signed digest (`blk_to_live` is the last field of
/// `TXHDR`) and `resign` refuses without it, and once no
/// command printed it in any labelled or decimal form. What each phrase
/// rests on, read on disk: zero can never expire; a non-zero
/// value expires for every block number greater than it,
/// which a block enforces against its own number and the queue against the
/// NEXT block, so the transaction is dead once the tip reaches the value; and
/// on arrival a node refuses a value more than 256 blocks past its tip.
///
/// The first mitigation, and no longer the only copy: the record carries the
/// value (format version 4) and `status`/`balance` render it
/// from the store on its own line through `reservation_lines`, which is what
/// `tests/cli.rs::the_block_to_live_is_recovered_from_the_store_without_knowing_the_value`
/// performs -- an operator who lost this page recovers the reservation from
/// the pages alone. This line stays because the value belongs
/// beside the bytes it is signed into.
fn block_to_live_line(blk_to_live: u64) -> String {
    if blk_to_live == 0 {
        "0 (never expires: a node that holds the transaction keeps it until it lands)"
            .to_string()
    } else {
        // The whole of the node's rule, both sides: a value below the tip
        // at arrival is refused as surely as one more than 256 blocks past
        // it, and this page is where an operator who typed `--btl` below the
        // tip learns why the node dropped it.
        // The plan builder still takes no block number; nothing here asks
        // the chain.
        format!(
            "{blk_to_live} (the node accepts it only while the tip is at or below {blk_to_live}, \
             and refuses it on arrival if {blk_to_live} is below the tip or more than 256 blocks \
             past it)"
        )
    }
}

/// The residue block `send` prints beside the artifact.
fn artifact_notices(wire_hex: &str) -> String {
    format!(
        "RETRY ARTIFACT -- save this before going further:\n\n{wire_hex}\n\nThese are the signed \
         bytes. If submission fails and you lose them, `resign` is the only recovery, and it \
         needs the SAME destination, amount, fee, block-to-live and reference (`--ref`, if one \
         was given) -- anything else is refused as a different transaction. The block-to-live is printed above; record it with the \
         bytes, because nothing else keeps it.\n\nThis transaction passed every check that can \
         be run offline. The node applies the ledger, the balance tally and the block-to-live \
         range after we are gone, and a rejection there is silent to this program.\n"
    )
}

/// What `send` says under a refused socket write: the artifact on the page
/// is the only copy there is.
const SEND_REFUSAL: &str =
    "The reservation is open and the artifact above is the only copy. Save it.";

/// What `resign` says under a refused socket write.
///
/// The artifact is NOT the only copy -- `resign` reproduces it -- so the
/// page says what to do rather than what to save. It claims only the
/// store: a submission can fail after the body is on the socket, so whether
/// the bytes reached a node is not knowable here, and `settle` is what
/// answers it once the chain has moved.
fn resign_refusal(settle_arg: &str) -> String {
    format!(
        "The store was not changed and the reservation is still open. Whether these bytes \
         reached the node is not known here -- a submission can fail after the body is on the \
         socket. `settle {settle_arg}` once the chain has moved says whether they landed; \
         `resign` with the same values reproduces them and tries the socket again."
    )
}

/// What a successful write says, on every page that makes one: `send`'s,
/// `resign`'s and `submit`'s. One function, so the sentence that a 200 is a
/// socket write and not acceptance cannot drift between the three.
fn submitted_block(id: &TxId, settle_arg: &str) -> String {
    format!(
        "\nsubmitted: the node accepted the SOCKET WRITE. THIS IS NOT ACCEPTANCE OF THE \
         TRANSACTION.\n  id {}  (computed locally, echoed back -- not the node's \
         verdict)\n\nThe node validates after we are gone. Run `settle {}` once the \
         chain has moved to learn what actually happened.",
        hex_bytes(&id.0),
        settle_arg
    )
}

/// `submit <artifact-hex>`: the artifact `send` printed, written to the
/// socket as it is.
///
/// # Why it opens no store
///
/// After a spend empties an account the Mesh reports its tag as not found, so
/// reconciliation refuses that account and `resign` cannot run on it -- a
/// resign needs the node to resolve the tag first. An operator holding a
/// valid signed artifact needs a route to the socket that asks the node
/// nothing about the account. This command is it: no store, no password, the
/// artifact as the whole input and the socket as the only output. It reserves
/// nothing, signs nothing and writes nothing to disk; the binary reaches it
/// before the password prompt, as it does `create`. It is equally the route
/// when the emptied account is the store's only one and the wallet will not
/// start at all.
///
/// # What it refuses, and what it does not judge
///
/// The hex must decode; the bytes must parse as a transaction through
/// `tx::wire::Transaction`; and the parsed transaction must re-serialize to
/// exactly the bytes given -- a partial trailer, which `from_wire`
/// zero-extends, is refused rather than repaired, because the bytes on the
/// socket would not be the bytes the operator holds. That is layout only.
/// This crate has no transaction validator and this command does not
/// pretend to one: a signature that does not recover, a passed
/// block-to-live, a balance the ledger no longer holds are the node's to
/// refuse, silently, exactly as `send`'s page says. Every refusal here is
/// made before any socket is opened, and the page says so.
///
/// # The page
///
/// The `submitted:` block is `send`'s, from [`submitted_block`], so the
/// sentence that a 200 is a socket write and not acceptance is the same
/// sentence; `settle` is named with the source tag read out of the
/// artifact's own header.
fn cmd_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Outcome {
    let bytes = match crate::mesh::hex::decode(artifact_hex.trim(), "artifact") {
        Ok(b) => b,
        Err(cause) => return Outcome::ArtifactNotHex { cause },
    };
    let tx = match crate::tx::wire::Transaction::from_wire(&bytes) {
        Ok(tx) => tx,
        Err(cause) => return Outcome::ArtifactNotATransaction { cause },
    };
    // Byte-identical or refused: layout is the whole of what is judged here.
    if tx.to_wire() != bytes {
        return Outcome::ArtifactNotWhole {
            given: bytes.len(),
            described: tx.wire_len(),
        };
    }
    let mut source = [0u8; crate::consts::ADDR_TAG_LEN];
    source.copy_from_slice(&tx.src_addr[..crate::consts::ADDR_TAG_LEN]);
    // Attempted here because it decides whether the socket is written to.
    if let Err(cause) = destination(&source) {
        return Outcome::CannotRender { tag: source, cause };
    }
    let submitted = client.submit_wire(&bytes, TxId(tx.id_digest()));
    Outcome::Submitted {
        source,
        bytes,
        submitted,
    }
}

/// [`cmd_submit`] for the binary, which reaches it before any store is
/// opened -- the one command besides `create` that `run` never sees from
/// there.
pub fn run_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Report {
    render::render(&before_the_gate(cmd_submit(client, artifact_hex)))
}

/// The five read-only verbs for the binary, which reaches them **before the
/// password prompt and before any store is opened**, exactly as it reaches
/// `submit`.
///
/// `--dir` is still required of them by the parser, as of every verb, and is
/// not read, created or locked: an operator can ask a node about a block
/// with no wallet on the machine at all. A command this is called with that
/// is not one of the five is a caller error, and is reported as one rather
/// than silently doing nothing.
pub fn run_explorer<T: Transport>(client: &MeshClient<T>, command: &Command) -> Report {
    let outcome = match command {
        Command::LookupTransaction { hash } => cmd_transaction(client, hash),
        Command::RecentTransactions { tag, count, from } => {
            cmd_recent_transactions_from(client, tag, *count, *from)
        }
        Command::Block { at } => cmd_block(client, at),
        Command::Blocks { count } => cmd_blocks(client, *count),
        Command::Mempool { count } => cmd_mempool(client, *count),
        other => Outcome::NotAReadOnlyVerb {
            command: Box::new(other.clone()),
        },
    };
    render::render(&before_the_gate(outcome))
}

fn cmd_send<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let plan = match key_access(w.store(), &s.tag, master).and_then(|access| plan_spend(w, s, &access)) {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(e),
    };
    // Check every destination can render before entering the reservation
    // path, so the account is not emptied by a run that then fails to
    // render its own page. Both renderings are
    // ATTEMPTED here and their results thrown away, because whether they
    // succeed is a decision -- it decides whether a key is spent -- while what
    // they produce is the renderer's.
    if let Err(e) = destination(&s.tag) {
        return Outcome::CannotRender { tag: s.tag, cause: e };
    }
    if let Err((tag, cause)) = destination_lines(plan.dsts()) {
        return Outcome::CannotRender { tag, cause };
    }
    let signed = match key_access(w.store(), &s.tag, master) {
        Ok(access) => match w.reserve_and_sign(&plan, access) {
            Ok(t) => t,
            Err(e) => return Outcome::Failed(e),
        },
        Err(e) => return Outcome::Failed(e),
    };
    let submitted = w.submit(&signed);
    Outcome::Sent {
        shipped: outcome::Shipped {
            source: s.tag,
            destinations: plan.dsts().to_vec(),
            blk_to_live: plan.blk_to_live(),
            wire: signed.wire().to_vec(),
            submitted,
        },
        send_total: plan.send_total(),
        fee_total: plan.fee_total(),
        change_total: plan.change_total(),
        upgraded: w.store().upgraded_from(),
    }
}

/// `resign`: reproduce the reserved artifact and **submit it**.
///
/// What it rests on is the type and the gate below it, not a check here:
/// the bytes `resign_pending` returns are, by its digest comparison, the
/// store's own reservation signed by the reserved key, so nothing this
/// command ships is bytes this wallet did not sign, and there is no state
/// in which it ships with no reservation behind it. What that does NOT
/// cover is whether the matched reservation is still live: a passed
/// block-to-live is in no plan input, so an expired reservation reproduces
/// and is written under `submitted:` exactly as `send` writes one -- the
/// expired-reservation scenario. `status`, `balance` and `settle` say the
/// reservation is dead before an operator reaches this verb; whether this
/// verb should refuse or warn instead of shipping is the route-out question,
/// which is open. (A moved balance never reaches the write: the
/// balance is a plan input, so the rebuilt digest differs and
/// `DigestMismatch` refuses first.)
///
/// What the write does and does not establish is [`ship`]'s text, `send`'s
/// own; the exit-0 page is on stdout and the exit-3 page on stderr, the
/// artifact on whichever the socket decides. The page is built BEFORE the
/// destination is rendered, so a render failure returns the reproduction
/// with the refusal appended rather than in place of it: this page may be
/// the only rendering of the only bytes that can move those funds.
///
/// There are two refusal arms and they refuse for different reasons. A plan
/// that is not the reserved one signs nothing and ships nothing, which the
/// wrong-spend test in `tests/cli.rs` holds at the socket (a fault-injection
/// row is the injection). A reservation the chain has already moved past has
/// nothing to reproduce at all, and its page names `settle` and says what the
/// chain does and does not establish -- the arm a run against mainnet asked
/// for, where the chain-address guard's three-cause divergence page had been
/// standing in and naming the wrong verb.
fn cmd_resign<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let access = match key_access(w.store(), &s.tag, master) {
        Ok(access) => access,
        Err(e) => return Outcome::Failed(e),
    };
    let dsts = match resign_destinations(w, s, &access) {
        Ok(d) => d,
        Err(e) => return Outcome::Failed(e),
    };
    // The page lists them in the order the planner will put them on the wire,
    // which is the same sort `SpendPlan::new` applies, so `send`'s page and
    // this one list the same spend the same way.
    let mut listed_dsts = dsts.clone();
    listed_dsts.sort_by_key(Destination::mdst_image);
    let resigned = w.resign_pending(&s.tag, &access, dsts, s.fee_total, s.blk_to_live);
    resign_outcome(w, &s.tag, listed_dsts, s.blk_to_live, resigned)
}

/// What `resign` decides from [`Wallet::resign_pending`]'s answer, as the
/// outcome [`cmd_resign`] returns, so a caller that re-signs through the
/// wallet itself renders from the same decision.
///
/// `listed_dsts` are the destinations in the order the planner puts them on
/// the wire, and `blk_to_live` is the one the re-sign was asked for. A
/// reproduction is written to the socket through `w` -- unless the source
/// tag will not render, when it is returned unwritten as
/// [`Outcome::ReproducedButUnrenderable`]; a digest that is not the
/// reservation's is [`Outcome::NotTheReservedSpend`]; a reservation the chain
/// has moved past is [`Outcome::ReservationAlreadyLanded`]; and anything else
/// is [`Outcome::Failed`].
pub fn resign_outcome<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    source: &Tag,
    listed_dsts: Vec<Destination>,
    blk_to_live: u64,
    resigned: Result<crate::mesh::spend::SignedTransaction>,
) -> Outcome {
    match resigned {
        Ok(signed) => {
            let wire = signed.wire().to_vec();
            // **Asked here and not in the renderer**, because whether the
            // source tag renders decides whether the socket is written to,
            // and that is not a rendering question. The reproduction goes out
            // either way: this page may be the only rendering of the only
            // bytes that can move those funds.
            if let Err(cause) = destination(source) {
                return Outcome::ReproducedButUnrenderable {
                    source: *source,
                    destinations: listed_dsts,
                    blk_to_live,
                    wire,
                    cause,
                };
            }
            let submitted = w.submit(&signed);
            Outcome::Resigned {
                shipped: outcome::Shipped {
                    source: *source,
                    destinations: listed_dsts,
                    blk_to_live,
                    wire,
                    submitted,
                },
            }
        }
        Err(Error::DigestMismatch) => Outcome::NotTheReservedSpend,
        Err(Error::ReservationLanded {
            spent_index,
            settled_index,
        }) => Outcome::ReservationAlreadyLanded {
            source: *source,
            spent_index,
            settled_index,
        },
        Err(e) => Outcome::Failed(e),
    }
}

/// `reconcile`: the acknowledged path, **before the gate**.
///
/// The whole store's report is printed first, on every path including the
/// success path, because the evidence that this advance is wrong most often
/// lives in another account's report and the write is the most dangerous one
/// this program makes. Exit 0 on the advance, 3 on every refusal.
fn cmd_reconcile<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
) -> Outcome {
    match reconcile::advance_acknowledged(&mut store, client, tag, master, advance_to) {
        Ok(reviewed) => Outcome::Reconciled {
            tag: *tag,
            advance_to,
            reviewed,
            upgraded: store.upgraded_from(),
        },
        Err(e) => Outcome::Failed(e),
    }
}

// ---------------------------------------------------------------------------
// The explorer verbs: a node, and nothing else
// ---------------------------------------------------------------------------

/// nanoMCM rendered beside its MCM, which is the figure a person reads.
///
/// One MCM is 1,000,000,000 nanoMCM. The sign is
/// carried, because a source operation is a debit.
fn nano_and_mcm(v: i128) -> String {
    // The leading `-` is `minus` and not `sign`: the I1 scan's taint set is a
    // fixpoint over function NAMES, `wots.rs::sign` is in it, and a local of
    // that name in any body reads as a function that reaches the signer. The
    // scan is name-based on purpose; this keeps it exact.
    let a = v.unsigned_abs();
    let whole = a / 1_000_000_000;
    let frac = a % 1_000_000_000;
    let minus = if v < 0 { "-" } else { "" };
    format!("{minus}{a} nanoMCM ({minus}{whole}.{frac:09} MCM)")
}

/// A Mesh timestamp: milliseconds since the epoch, as the middleware sends
/// it. Rendered as the integer seconds and the raw value, because this crate
/// carries no calendar and will not invent one.
fn stamp(ms: i64) -> String {
    format!("{ms} ms since the epoch ({} s)", ms / 1_000)
}

/// External text stays on its own display line and cannot control the terminal.
/// Program-owned newlines and indentation are added by each caller.
///
/// Four kinds of character are written as escapes: controls; the
/// bidirectional formatting characters, which reorder what follows them; the
/// characters that render with no width, which make two different strings
/// look the same; and the backslash itself, so that every escape on the page
/// is one this function wrote, and a node cannot send text that only looks
/// like one.
fn terminal_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let bidi = matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        let zero_width = matches!(ch, '\u{00ad}' | '\u{180e}' | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{feff}');
        if ch.is_control() || bidi || zero_width || ch == '\\' {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

/// An operation's address, rendered for a person where it can be.
///
/// The Mesh sends a 20-byte tag for the accounts it indexes and a 40-byte
/// ledger address elsewhere; the first is what a person holds and is shown
/// in the checksummed Base58 form beside its hex, and the second is shown as
/// hex with a word saying what it is, because a ledger address is not a
/// destination and must never be pasted as one.
fn explorer_address(text: &str) -> String {
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.len() == ADDR_TAG_LEN * 2 {
        let mut tag = [0u8; ADDR_TAG_LEN];
        for (i, b) in tag.iter_mut().enumerate() {
            match body.get(i * 2..i * 2 + 2).and_then(|p| u8::from_str_radix(p, 16).ok()) {
                Some(v) => *b = v,
                None => return terminal_text(text),
            }
        }
        return match destination(&tag) {
            Ok(d) => format!("{d}  ({})", terminal_text(text)),
            Err(_) => terminal_text(text),
        };
    }
    if body.len() == ADDR_LEN * 2 {
        return format!("{}  (a 40-byte ledger address: tag then the key's hash -- not a destination)", terminal_text(text));
    }
    terminal_text(text)
}

/// The sentence every page that reads `/search/transactions` carries.
const SEARCH_CONVENTION: &str = "read from /search/transactions, the Mesh's indexer. That endpoint \
     replays rows written when the block was first seen: the source is debited its GROSS amount \
     and the change comes back as its own destination. /block re-parses the wire and shows the \
     NET debit with no change operation. Both are correct and this page does not reconcile them.";

/// The sentence every page that reads `/block` carries.
const BLOCK_CONVENTION: &str = "read from /block, which re-parses the wire: a source is debited \
     its NET amount and the change does not appear as an operation. The indexer's \
     /search/transactions shows the same transaction gross, with the change as a destination.";

fn operation_lines(ops: &[codec::Operation], indent: &str) -> String {
    let mut out = String::new();
    for op in ops {
        out.push_str(&format!("{indent}{:>2}. {:<21} {}\n", op.index, terminal_text(&op.kind), nano_and_mcm(op.amount)));
        out.push_str(&format!("{indent}    {}\n", explorer_address(&op.address)));
        if !op.memo.is_empty() {
            out.push_str(&format!("{indent}    memo {}\n", terminal_text(&op.memo)));
        }
    }
    out
}

fn metadata_lines(meta: &[(String, String)], indent: &str) -> String {
    let mut out = String::new();
    for (k, v) in meta {
        out.push_str(&format!("{indent}{} = {}\n", terminal_text(k), terminal_text(v)));
    }
    out
}

/// `transaction <hash>`: one transaction from the indexer.
pub fn cmd_transaction<T: Transport>(client: &MeshClient<T>, hash: &[u8; HASHLEN]) -> Outcome {
    match client.search_by_hash(hash) {
        Err(cause) => Outcome::SearchFailed { cause },
        Ok(page) if page.transactions.is_empty() => Outcome::TransactionNotFound { hash: *hash },
        Ok(page) => Outcome::LookedUpTransaction {
            page: Box::new(page),
        },
    }
}

/// `recent-transactions <tag> [--count N]`: what touched a tag, newest first.
pub fn cmd_recent_transactions<T: Transport>(
    client: &MeshClient<T>,
    tag: &Tag,
    count: u64,
) -> Outcome {
    match client.search_by_account(tag, count) {
        Ok(page) => Outcome::RecentTransactions {
            tag: *tag,
            from: 0,
            page: Box::new(page),
        },
        Err(cause) => Outcome::SearchFailed { cause },
    }
}

/// `recent-transactions <tag> [--count N] [--from M]`: what touched a tag,
/// newest first, the `from` newest skipped. With `from` 0 it sends the
/// request [`cmd_recent_transactions`] sends, byte for byte, so the first
/// page is asked for as it always was.
pub fn cmd_recent_transactions_from<T: Transport>(
    client: &MeshClient<T>,
    tag: &Tag,
    count: u64,
    from: u64,
) -> Outcome {
    if from == 0 {
        return cmd_recent_transactions(client, tag, count);
    }
    match client.search_by_account_from(tag, count, from) {
        Ok(page) => Outcome::RecentTransactions {
            tag: *tag,
            from,
            page: Box::new(page),
        },
        Err(cause) => Outcome::SearchFailed { cause },
    }
}

/// `block <number|hash>`: one block, with its reward and what it moved.
pub fn cmd_block<T: Transport>(client: &MeshClient<T>, at: &args::BlockAt) -> Outcome {
    let got = match at {
        args::BlockAt::Index(i) => client.block_by_index(*i),
        args::BlockAt::Hash(h) => client.block_by_hash(h),
    };
    match got {
        Ok(block) => Outcome::Block {
            block: Box::new(block),
        },
        Err(cause) => Outcome::BlockNotServed {
            by_hash: matches!(at, args::BlockAt::Hash(_)),
            cause,
        },
    }
}

/// `blocks [--count N]`: the tip and the N newest, one row each.
pub fn cmd_blocks<T: Transport>(client: &MeshClient<T>, count: u64) -> Outcome {
    let tip = match client.network_status() {
        Ok(t) => t,
        Err(cause) => return Outcome::ExplorerFailed { cause },
    };
    let mut rows = Vec::new();
    for i in 0..count {
        let Some(index) = tip.index.checked_sub(i) else { break };
        // Index 0 is the tip to this endpoint, never genesis, so the walk
        // stops above it rather than ask for a page about another block.
        if index == 0 {
            break;
        }
        match client.block_by_index(index) {
            Ok(b) => rows.push(b),
            // The partial walk is discarded on purpose: a page listing some
            // of the newest blocks reads as a complete answer.
            Err(cause) => return Outcome::BlocksStopped { index, cause },
        }
    }
    Outcome::Blocks { count, tip, rows }
}

/// `mempool [--count N]`: the node's queue, its ids and the first `count`
/// of them read whole.
///
/// A transaction the queue no longer holds when it is asked for -- code 3,
/// *Transaction not found* -- has been mined since the list was read, or
/// dropped, and its row says so: that is the queue moving, not a failure.
/// Any other failure discards the rows read so far, as `blocks` does: a page
/// listing some of the queue reads as the whole of it.
pub fn cmd_mempool<T: Transport>(client: &MeshClient<T>, count: u64) -> Outcome {
    let ids = match client.mempool() {
        Ok(ids) => ids,
        Err(cause) => return Outcome::ExplorerFailed { cause },
    };
    let mut rows = Vec::new();
    for id in ids.iter().take(usize::try_from(count).unwrap_or(usize::MAX)) {
        let transaction = match client.mempool_transaction(id) {
            Ok(t) => Some(Box::new(t)),
            Err(Error::Mesh { code: 3, .. }) => None,
            Err(cause) => return Outcome::MempoolStopped { id: *id, cause },
        };
        rows.push(MempoolRow { id: *id, transaction });
    }
    Outcome::Mempool { count, total: ids.len(), rows }
}

/// A failed explorer read, said in the operator's terms.
///
/// The Mesh answers its own failures as HTTP 200 carrying a code, which the
/// codec has already turned into `Error::Mesh`; any other status is
/// `Error::HttpStatus`.
fn explorer_refusal(e: &Error) -> String {
    refusal_with(e, None)
}

/// A failed search of the node's index, said in the operator's terms, with
/// what the middleware's answer says about its indexer: the difference
/// between a useful page and a number.
///
/// `mochimo-mesh` registers `/search/transactions` only when its indexer is
/// enabled as it starts (`main.go`), and it is not unless the deployment
/// was configured to, so a node that runs none answers that route with a
/// 404. One that runs an indexer answers its internal error, code 2, while
/// the indexer's database is not connected and when a search fails
/// (`search_handler.go`). Code 1 is *Invalid request*, a body it could not
/// decode, and says nothing about the indexer.
fn search_refusal(e: &Error) -> String {
    let note = match e {
        Error::HttpStatus { status: 404 } => Some(
            "The Mesh serves /search/transactions only when its indexer was enabled as it \
             started, and a deployment runs no indexer unless it was configured to: this node \
             does not index. Another may.",
        ),
        Error::Mesh { code: 2, .. } => Some(
            "The Mesh answers its internal error on /search/transactions while its indexer's \
             database is not connected and when a search fails: this node runs an indexer, and \
             it did not answer. It may answer if asked again, and another node may.",
        ),
        _ => None,
    };
    refusal_with(e, note)
}

fn refusal_with(e: &Error, note: Option<&str>) -> String {
    let mut text = format!("{e}");
    if let Some(note) = note {
        text.push_str("\n  ");
        text.push_str(note);
    }
    text.push_str("\n  Nothing was read but the node: no store was opened and no password asked.");
    text
}
