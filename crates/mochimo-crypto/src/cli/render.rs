//! Words, and nothing else.
//!
//! Every sentence this program prints for a decided command is here, and
//! [`render`] is a function of an [`Outcome`] alone -- no store, no client, no
//! seed. That is the property the split was for: what a command decided can
//! be read without reading English, and what it says can be changed without
//! touching what it decided.
//!
//! **Nothing here may reach a fact the outcome does not carry.** The
//! temptation is a renderer that opens the store for one more field; the
//! answer is that the field belongs in the variant, because a renderer that
//! can ask questions is a second place decisions get made. `Upgraded` is the
//! shape that rule produces: the store's format-version answer is read where
//! the store is open and carried, rather than looked up here.
//!
//! The text is moved verbatim from the `cmd_*` functions it came from.
//! `tests/cli.rs` was not touched by the move, so it is the assertion that
//! nothing shifted by a byte.

use super::outcome::{AccountLine, Decided, Outcome, Shipped, Upgraded};
use super::{
    cannot_render, destination, hex_bytes, no_such_account, reservation_lines, state_of, Code,
    Report,
};
use crate::recon::AccountStatus;

/// The store's format-version note, from the answer the command carried out.
fn upgrade(upgraded: Upgraded) -> String {
    match upgraded {
        Some(from) => format!(
            "\n\nThis store was written in format version {} by this command (it was version {from} \
             until now). An older build of this wallet will no longer open \
             it; this build and later ones do. Nothing was retyped and nothing needs to be.",
            crate::keystore::format::VERSION
        ),
        None => String::new(),
    }
}

fn balance(accounts: &[AccountLine]) -> Report {
    if accounts.is_empty() {
        return Report::ok("no accounts in this store.".into());
    }
    let mut out = String::new();
    for AccountLine { tag, status } in accounts {
        let state = state_of(status);
        let dest = match destination(tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(tag, &e),
        };
        out.push_str(&format!(
            "{dest:<width$}  {:>20} nanoMCM  index {}  {}\n",
            status.balance(),
            status.index().get(),
            state,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
        if let AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } = status
        {
            out.push_str(&reservation_lines(*spent_index, reservation, "    "));
        }
    }
    Report::ok(out)
}

fn accounts(held: &[super::address::Held]) -> Report {
    if held.is_empty() {
        return Report::ok(
            "no accounts in this store. `create` makes one; `restore --account N` adds one the \
             chain already knows."
                .into(),
        );
    }
    let mut out = format!("{} account(s) in this store:\n", held.len());
    for h in held {
        let dest = match destination(&h.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&h.tag, &e),
        };
        out.push_str(&format!(
            "  {dest:<width$}  index {}  {}\n",
            h.index.get(),
            match h.kind {
                crate::account::AccountKind::Derived => "derived",
                crate::account::AccountKind::Imported => "imported",
            },
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }
    out.push_str(
        "\nEach line begins with a DESTINATION -- give one to whoever is paying you. Read from \
         the store's own records: no node was asked and no seed was needed, so this works \
         before the account has any funds and without the phrase. `address <destination>` adds \
         the 40-byte ledger address, and that one does need the seed.",
    );
    Report::ok(out)
}

/// Turn a decided command into the page it prints and the code it exits with.
///
/// The standing-divergence notice goes in front of whatever the command said,
/// which is where it was before the split and is why [`Decided`] carries the
/// divergences rather than the command's own outcome carrying a prefix.
pub fn render(decided: &Decided) -> Report {
    let report = outcome(&decided.outcome);
    let notice = super::standing_divergence_notice(&decided.standing);
    Report {
        text: format!("{notice}{}", report.text),
        code: report.code,
    }
}

fn outcome(outcome: &Outcome) -> Report {
    match outcome {
        Outcome::Balance { accounts: a } => balance(a),
        Outcome::Accounts { held } => accounts(held),

        Outcome::Address {
            tag,
            address,
            index,
        } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
                "{dest}\n  address  {}\n  index    {}\n\nThe first line is this account's \
                 DESTINATION -- Base58 over the tag and its CRC16, the form every Mochimo wallet \
                 takes. Give that to whoever is paying you. It is computed from this store alone: \
                 no node was asked, and it is the destination whether or not the chain has ever \
                 heard of this tag.\n\nThe indented `address` is the 40-byte entry the \
                 LEDGER WILL HOLD for this account at this index. Before the first credit the \
                 ledger holds nothing at all, and the entry the first credit creates comes from \
                 the tag alone -- it matches this line only because a derived account at index 0 \
                 has its tag in both halves. It is not a destination: no wallet takes it, and \
                 neither does this one.",
                hex_bytes(address),
                index.get()
            )),
        },

        Outcome::Restored {
            account,
            found,
            held_at,
            upgraded,
        } => {
            let restored_tag = match destination(&found.tag) {
                Ok(d) => d,
                Err(e) => return cannot_render(&found.tag, &e),
            };
            let what = match held_at {
                None => "added to the store at that index, in one write".to_string(),
                Some(stored) if *stored == found.index => format!(
                    "already in the store, at that same index {}; nothing was written",
                    stored.get()
                ),
                Some(stored) => format!(
                    "ALREADY IN THE STORE, at index {} -- and NOT moved. Restore builds an \
                     account the store lacks; moving one it holds is reconciliation, which \
                     shows you the whole store's report first. Run `status 0x{}` to see it and \
                     `reconcile 0x{} --advance-to {}` to act on it.",
                    stored.get(),
                    hex_bytes(&found.tag),
                    hex_bytes(&found.tag),
                    found.index.get()
                ),
            };
            Report::ok(format!(
                "restored account {account}\n  destination  {}\n  index    {} (from the chain, \
                 never assumed)\n  address  {}\n  balance  {} nanoMCM\n  {what}\n\nthe index came from \
                 scanning derived addresses against the one the chain holds for this tag. \
                 Position 0 is a match like any other, never a default.{}",
                restored_tag,
                found.index.get(),
                hex_bytes(&found.address),
                found.balance,
                upgrade(*upgraded)
            ))
        }

        Outcome::RestoreNeedsMaster => Report::refused(
            "restore derives an account from the master seed, and none was supplied.".into(),
        ),

        Outcome::RestoreRefused { account, failure } => match failure {
            crate::recon::RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => {
                Report::refused(format!(
                    "{failure}\n\nIn this program: `restore --account {account} --scan-to <M>` walks \
                     indices 0 through M instead of 0 through {}. Each index costs one key \
                     derivation.",
                    scanned.saturating_sub(1)
                ))
            }
            other => Report {
                text: format!("{other}"),
                code: Code::Refused,
            },
        },

        Outcome::Settled {
            settlement,
            upgraded,
        } => settled(settlement, *upgraded),

        Outcome::NoSuchAccount { tag } => Report::refused(no_such_account(tag)),

        // Hex, not the destination form, and deliberately: this is a
        // re-rendering of what the operator typed for an account this store
        // does not hold. Base58 would put a string in the shape this program
        // teaches means *where money goes* on screen at the moment it is
        // saying it knows nothing about it.
        Outcome::NoAccountToAddress { tag } => Report::refused(format!(
            "no account for the tag {} in this store -- that is the tag you named, in hex so it \
             cannot be mistaken for somewhere to send funds.\n  `create` makes an account; \
             `restore --account N` adds one the chain already knows; `address` with no argument \
             lists what is here.",
            hex_bytes(tag)
        )),

        Outcome::NoMasterSeed => Report::refused(
            "this store holds no master seed (its accounts are imported), so no account can be \
             derived from it; `address <destination>` prints a stored account's address. Nothing \
             was written."
                .into(),
        ),

        Outcome::AccountAlreadyStored {
            account,
            tag,
            index,
        } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::refused(format!(
                "account {account} is already in this store (its destination is {dest}, at index \
                 {}); run `address {dest}` for the address it will next present -- position 0's \
                 address is one the chain may no longer hold. Nothing was written.",
                index.get()
            )),
        },
        Outcome::CannotRender { tag, cause } => cannot_render(tag, cause),
        Outcome::Failed(e) => Report::refused(format!("{e}")),
        Outcome::Diverged(d) => super::refuse_diverged_account(d),

        Outcome::Sent {
            shipped,
            send_total,
            fee_total,
            change_total,
            upgraded,
        } => sent(shipped, *send_total, *fee_total, *change_total, *upgraded),

        Outcome::Planned {
            source,
            destinations,
            send_total,
            fee_total,
            change_total,
            blk_to_live,
        } => planned(source, destinations, *send_total, *fee_total, *change_total, *blk_to_live),

        Outcome::Resigned { shipped } => resigned(shipped),

        Outcome::ReproducedButUnrenderable {
            source,
            destinations,
            blk_to_live,
            wire,
            cause,
        } => Report::refused(format!(
            "{}\ncannot render the destination for the tag whose hex is {}: {cause}",
            reproduction(destinations, *blk_to_live, wire),
            hex_bytes(source)
        )),

        Outcome::NotTheReservedSpend => Report::refused(
            "this is not the spend that was reserved.\n  `resign` rebuilds the reserved plan and \
             compares it to what the store recorded; the destination, amount, fee, \
             block-to-live or reference differs.\n  ACTION: re-run with the exact values the \
             original `send` used, `--ref` included if one was given. Nothing was signed."
                .into(),
        ),

        Outcome::ReservationAlreadyLanded {
            source,
            spent_index,
            settled_index,
        } => {
            let settle_arg =
                destination(source).unwrap_or_else(|_| format!("0x{}", hex_bytes(source)));
            Report::refused(format!(
                "the chain has moved past the key this reservation holds, so there is nothing \
                 left to reproduce.\n  The chain holds this tag at the key at position \
                 {settled_index}, which is the change key of the reservation at position \
                 {spent_index} -- the state reconciliation calls a landed spend, and the one \
                 `settle` resolves.\n  ACTION: `settle {settle_arg}`, which re-reads the chain, \
                 clears the reservation and keeps the settled block, so a reorg that reverts it \
                 is reported with the digest it settled. Nothing was reserved, nothing was \
                 signed, and nothing reached the socket here.\n  What was observed is the chain \
                 standing at the change key, not which transaction put it there: a change \
                 address follows the POSITION and not the transaction, so any spend from the \
                 reserved key leaves the tag exactly here. `transaction <hash>` on the id the \
                 original `send` printed is what names it."
            ))
        }

        Outcome::Submitted {
            source,
            bytes,
            submitted,
        } => submitted_page(source, bytes, submitted),

        Outcome::ArtifactNotHex { cause } => {
            Report::refused(format!("the artifact is not hex: {cause}\n{SUBMIT_NOTHING}"))
        }
        Outcome::ArtifactNotATransaction { cause } => Report::refused(format!(
            "the artifact does not parse as a transaction: {cause}\n{SUBMIT_NOTHING}"
        )),
        Outcome::ArtifactNotWhole { given, described } => Report::refused(format!(
            "the artifact is not a whole transaction image: {given} bytes were given and the \
             transaction they describe is {described} bytes, so the bytes on the socket would not be the \
             bytes you hold. A truncated or padded artifact is refused rather than repaired.\n\
             {SUBMIT_NOTHING}"
        )),

        Outcome::Status { tag, status } => status_page(tag, status),
        Outcome::StatusDiverged { tag, divergence } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
                "{dest}\n  state    DIVERGED -- every operation on this account is refused \
                 (I4). Other accounts in this store are not. Nothing was changed.\n\n{divergence}{}",
                super::next_steps(core::slice::from_ref(&**divergence))
            )),
        },
        Outcome::StatusRefused { divergence } => Report::refused(format!("{divergence}")),

        Outcome::Reconciled {
            tag,
            advance_to,
            reviewed,
            upgraded,
        } => reconciled(tag, *advance_to, reviewed, *upgraded),

        Outcome::Discovered { sweep } => discovered(sweep),
        Outcome::DiscoverNeedsMaster => Report::refused(
            "this store holds no master seed (its accounts are imported), so no account index \
             can be derived from it and there is nothing to sweep; `address` with no argument \
             lists what this store holds. Nothing was written."
                .into(),
        ),
        Outcome::SweepStopped {
            account,
            searched,
            to,
            cause,
        } => Report::refused(format!(
            "the sweep stopped at account index {account}: {cause}\n  {searched} of {} index(es) \
             were searched. The node was not asked about index {account} or anything above it, \
             so this page reports NO extent and says nothing at all about those indices -- a \
             partial sweep printed as a whole one would be asserting absence by omission.\n  \
             Nothing was written. Fix the node and run it again.",
            u64::from(*to) + 1
        )),

        Outcome::LookedUpTransaction { page } => transaction(page),
        Outcome::TransactionNotFound { hash } => Report::refused(format!(
            "no transaction with hash {} is in this node's index.\n  The indexer holds what it saw \
             when each block arrived; a transaction still in the mempool is not there, and a \
             deployment that runs no indexer answers nothing at all.\n  Nothing was read but the \
             node.",
            hex_bytes(hash)
        )),
        Outcome::RecentTransactions { tag, from, page } => recent_transactions(tag, *from, page),
        Outcome::Block { block } => block_page(block),
        Outcome::BlockNotServed { by_hash, cause } => {
            let mut text = super::explorer_refusal(cause);
            if *by_hash {
                text.push_str(
                    "\n  A block is served by hash only from the deployment's own archive folder, \
                     so a not-found here is about that archive rather than about the chain. The \
                     index always works.",
                );
            }
            Report::refused(text)
        }
        Outcome::Blocks { count, tip, rows } => blocks(*count, tip, rows),
        Outcome::BlocksStopped { index, cause } => Report::refused(format!(
            "{}\n  The tip was read; block {index} was not.",
            super::explorer_refusal(cause)
        )),
        Outcome::Mempool { count, total, rows } => mempool(*count, *total, rows),
        Outcome::MempoolStopped { id, cause } => Report::refused(format!(
            "{}\n  The queue's ids were read; transaction {} was not.",
            super::explorer_refusal(cause),
            hex_bytes(id)
        )),
        Outcome::ExplorerFailed { cause } => Report::refused(super::explorer_refusal(cause)),
        Outcome::SearchFailed { cause } => Report::refused(super::search_refusal(cause)),

        Outcome::StoreUnreadable(e) => Report {
            text: format!("{e}"),
            code: Code::StartupRefused,
        },
        Outcome::StartupRefused(refusal) => Report {
            text: format!("{refusal}{}", super::next_steps(&refusal.diverged)),
            code: Code::StartupRefused,
        },
        Outcome::HandledBeforeTheWallet => {
            Report::refused("this command is handled before the wallet opens".into())
        }
        Outcome::NotAReadOnlyVerb { command } => Report::refused(format!(
            "internal: {command:?} is not one of the read-only verbs and cannot be run without a store"
        )),

        Outcome::UnstoredAddress {
            account,
            tag,
            address,
        } => unstored_address(*account, tag, address),
    }
}

fn settled(settlement: &crate::wallet::Settlement, upgraded: Upgraded) -> Report {
    use crate::recon::Reservation;
    use crate::wallet::Settlement;
    let upgrade = upgrade(upgraded);
    match settlement {
        Settlement::Settled {
            spent_index,
            index,
        } => Report::ok(format!(
            "settled: the chain holds this tag at the change key.\n  spent index {}  ->  next \
             index {}\nthe reservation is cleared and the account can spend again. The settled \
             block is kept in the record until the next spend or advance, so a reorg that \
             reverts it is reported with the digest it settled.{upgrade}",
            spent_index.get(),
            index.get()
        )),
        Settlement::StillOutstanding {
            spent_index,
            reservation,
        } => {
            let lines = reservation_lines(*spent_index, reservation, "  ");
            let dead = matches!(reservation, Reservation::Recorded(d) if d.is_dead());
            Report::ok(if dead {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}), \
                     and the reserved artifact can no longer be accepted -- the spend will never \
                     land. The store was not advanced.\n{lines}",
                    spent_index.get()
                )
            } else {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}).\nThe \
                     spend has not landed. It may never -- submission is a socket write, not a verdict. \
                     If the retry artifact is lost, `resign` rebuilds it.\n{lines}",
                    spent_index.get()
                )
            })
        }
        Settlement::NothingPending { index } => Report::ok(format!(
            "nothing is reserved for this tag; it is at index {}.",
            index.get()
        )),
    }
}

fn unstored_address(account: u32, tag: &crate::addr::Tag, address: &crate::addr::Address) -> Report {
    let dest = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    Report::ok(format!(
        "{dest}\n  address  {}\n  index    0\n\nNOT STORED. Account {account} was derived from this \
         store's master seed and written nowhere: nothing was written, nothing reserved, no node \
         asked. The first line is its DESTINATION -- Base58 over the tag and its CRC16, the form \
         every Mochimo wallet takes -- and the indented `address` is the 40-byte entry the ledger \
         will hold at index 0 once it is paid. Give the destination to whoever is paying you; once \
         it has been paid, run `restore --account {account}`, which asks the chain where the \
         account sits and adds it to this store at that position (0 for a first credit), under \
         this same tag. Until then the store does not hold it and `balance` will not show it.",
        hex_bytes(address)
    ))
}

/// The socket's answer, appended to whichever page it followed. This is
/// `ship`'s tail: the write either happened or it did not, and the page says
/// which in the same words it always did.
fn shipped_tail(page: &mut String, s: &Shipped, settle_arg: &str, on_refusal: &str) -> Code {
    match &s.submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, settle_arg));
            Code::Ok
        }
        Err(e) => {
            page.push_str(&format!("\nsubmission FAILED: {e}\n{on_refusal}"));
            Code::Refused
        }
    }
}

fn sent(
    s: &Shipped,
    send_total: u64,
    fee_total: u64,
    change_total: u64,
    upgraded: Upgraded,
) -> Report {
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.source, &e),
    };
    let listed = match super::destination_lines(&s.destinations) {
        Ok(l) => l,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let emptying = if change_total == 0 {
        super::emptying_text(&settle_arg)
    } else {
        String::new()
    };
    let wire_hex = hex_bytes(&s.wire);
    let mut page = format!(
        "sending {send_total} nanoMCM to {} destination(s)\n{}{}\n{}{}",
        s.destinations.len(),
        laid_out(&listed, &settle_arg, s.destinations.len(), fee_total, change_total, s.blk_to_live),
        emptying,
        super::artifact_notices(&wire_hex),
        upgrade(upgraded)
    );
    let code = shipped_tail(&mut page, s, &settle_arg, super::SEND_REFUSAL);
    Report { text: page, code }
}

/// The lines a spend is checked by, from the destinations to the request to
/// check them: what `send`'s page shows after its first line, and what the
/// planned page shows before anything is signed. One function, so the two
/// pages cannot list one spend in two ways.
fn laid_out(listed: &str, settle_arg: &str, count: usize, fee_total: u64, change_total: u64, blk_to_live: u64) -> String {
    format!(
        "{listed}  from   {settle_arg}\n  fee    {fee_total} total (the node's floor is {} per \
         destination, {} here)\n  change {change_total} to your own next key under this tag\n  btl    \
         {}\n\nCheck every destination against its payee before going further. Each is shown in \
         the checksummed form whichever form you typed, so it can be compared character for \
         character with what their wallet shows. They are listed in the order that goes on the \
         wire, which the layout sorts and which need not be the order you typed.\n",
        crate::consts::MFEE,
        crate::consts::MFEE.saturating_mul(u64::try_from(count).unwrap_or(u64::MAX)),
        super::block_to_live_line(blk_to_live),
    )
}

/// A spend laid out and not signed, for the person who decides whether it
/// is: the lines [`laid_out`] gives `send`'s page, the emptying paragraph
/// when the change is zero, and what has not happened yet. Nothing on it
/// exists only after signing -- no artifact, no submission, no id.
fn planned(
    source: &crate::addr::Tag,
    destinations: &[crate::tx::wire::Destination],
    send_total: u64,
    fee_total: u64,
    change_total: u64,
    blk_to_live: u64,
) -> Report {
    let settle_arg = match destination(source) {
        Ok(d) => d,
        Err(e) => return cannot_render(source, &e),
    };
    let listed = match super::destination_lines(destinations) {
        Ok(l) => l,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let emptying = if change_total == 0 {
        format!(
            "{}  Once it is signed, keep the artifact: `submit` writes it to the socket without \
             opening the store, and is the route to a node while the account reads as not found.\n",
            super::emptying_paragraph(&settle_arg)
        )
    } else {
        String::new()
    };
    Report::ok(format!(
        "NOT SIGNED: a spend of {send_total} nanoMCM to {} destination(s), laid out for you to \
         check. Nothing has been signed yet.\n{}{emptying}\nNo key has been reserved or used, \
         nothing has been signed, and nothing has been sent to a node. Signing reserves this \
         spend's key first, and from then on these figures -- each destination, amount and \
         reference, the fee and the block-to-live -- are the only spend that key will sign: \
         signing it again later needs exactly them.",
        destinations.len(),
        laid_out(&listed, &settle_arg, destinations.len(), fee_total, change_total, blk_to_live),
    ))
}

/// The reproduction page, which `resign` builds before it reaches the socket
/// and prints whether or not it gets there.
fn reproduction(destinations: &[crate::tx::wire::Destination], blk_to_live: u64, wire: &[u8]) -> String {
    let listed = match super::destination_lines(destinations) {
        Ok(l) => l,
        // Unreachable from `decide`, which renders the same list before it
        // ships; kept total rather than panicking, per the panic census.
        Err((tag, e)) => format!("  <cannot render {}: {e}>\n", hex_bytes(&tag)),
    };
    format!(
        "reproduced {} destination(s)\n{listed}block-to-live {}\n{}\nThese are the SAME \
         bytes the original signing produced -- the reserved key signed the reserved \
         digest again, which WOTS+ determinism makes byte-identical. No second signature \
         was created.\n",
        destinations.len(),
        super::block_to_live_line(blk_to_live),
        super::artifact_notices(&hex_bytes(wire))
    )
}

fn resigned(s: &Shipped) -> Report {
    let mut page = reproduction(&s.destinations, s.blk_to_live, &s.wire);
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        // `decide` refuses before shipping when this fails, so this arm is
        // not reachable through it; it renders rather than panicking.
        Err(e) => {
            return Report::refused(format!(
                "{page}\ncannot render the destination for the tag whose hex is {}: {e}",
                hex_bytes(&s.source)
            ))
        }
    };
    let on_refusal = super::resign_refusal(&settle_arg);
    let code = shipped_tail(&mut page, s, &settle_arg, &on_refusal);
    Report { text: page, code }
}

const SUBMIT_NOTHING: &str =
    "Nothing was written to the socket, nothing to disk, and no store was opened.";

fn submitted_page(
    source: &crate::addr::Tag,
    bytes: &[u8],
    submitted: &core::result::Result<crate::mesh::TxId, crate::Error>,
) -> Report {
    let settle_arg = match destination(source) {
        Ok(d) => d,
        Err(e) => return cannot_render(source, &e),
    };
    let mut page = format!(
        "submitting {} bytes ({} hex characters) from {settle_arg}\n\nNo store was opened and no \
         password asked: the artifact is the input, and this command's one job is to reach the \
         socket. It reserves nothing, signs nothing and writes nothing to disk. The bytes were \
         checked for layout only -- this program has no transaction validator -- so a signature \
         that does not recover, a passed block-to-live or a balance the ledger no longer holds is \
         refused by the node, silently.\n",
        bytes.len(),
        bytes.len() * 2
    );
    match submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, &settle_arg));
            Report::ok(page)
        }
        Err(e) => {
            page.push_str(&format!(
                "\nsubmission FAILED: {e}\nThe artifact is unchanged and still yours. Whether the \
                 bytes reached a node before the failure is not knowable here; `settle {settle_arg}` \
                 answers it once the chain has moved, and this command can be run again."
            ));
            Report::refused(page)
        }
    }
}

fn status_page(tag: &crate::addr::Tag, s: &AccountStatus) -> Report {
    let dest = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    // After the state line: the ledger address for an in-sync account, or the
    // reserved figures on their own lines for an outstanding one -- never
    // appended to the state line itself.
    let tail = match s {
        AccountStatus::InSync { address, .. } => format!("\n  address  {}", hex_bytes(address)),
        AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } => {
            let lines = reservation_lines(*spent_index, reservation, "  ");
            format!("\n{}", lines.trim_end_matches('\n'))
        }
        AccountStatus::SpendLanded { .. } => String::new(),
    };
    Report::ok(format!(
        "{dest}\n  balance  {} nanoMCM\n  index    {}\n  state    {}{tail}",
        s.balance(),
        s.index().get(),
        state_of(s),
    ))
}

fn reconciled(
    tag: &crate::addr::Tag,
    advance_to: u32,
    reviewed: &super::reconcile::Reviewed,
    upgraded: Upgraded,
) -> Report {
    use super::reconcile::Outcome as Reconcile;
    let report = if reviewed.reports.is_empty() {
        String::new()
    } else {
        let mut r = format!(
            "THE STORE BEFORE THIS DECISION: {} of {} account(s) diverged. Read every report \
             below -- the evidence that one account's advance is wrong is most often in \
             another account's.\n\n",
            reviewed.reports.len(),
            reviewed.accounts
        );
        for d in &reviewed.reports {
            r.push_str(&format!("{d}\n\n"));
        }
        r
    };
    let others = reviewed.reports.iter().filter(|d| d.tag() != *tag).count();
    let still = if others > 0 {
        format!(
            "\n{others} other account(s) in the report above are still diverged; every \
             operation on each of them is refused until it is reconciled, and `balance` \
             reports them on every run."
        )
    } else {
        String::new()
    };
    match &reviewed.outcome {
        Reconcile::NotHeld => Report::refused(no_such_account(tag)),
        Reconcile::NothingToReconcile(_) => Report::refused(format!(
            "{report}account 0x{}: not diverged; there is nothing to reconcile.{still}",
            hex_bytes(tag)
        )),
        Reconcile::SecondInstanceSignal { other } => Report::refused(format!(
            "{report}NOT ADVANCED. Account 0x{} shows a spend this wallet did not make -- a \
             reservation the chain explains at neither of its keys -- which is the signal that \
             a SECOND WALLET is live on this seed. Advancing account 0x{} would hand that wallet \
             the key at index {advance_to} as well. Find the other wallet first (compare the key \
             streams above); nothing was written.",
            hex_bytes(other),
            hex_bytes(tag)
        )),
        Reconcile::NoAdvance { target: None } => Report::refused(format!(
            "{report}This divergence has no advance to acknowledge. Advancing is only correct \
             when the chain is AHEAD of the local index, at an index the walk confirmed; the \
             report above says what the walk found, and for this account it walked indices 0 \
             through {advance_to} as well as the window. Nothing was written.{still}"
        )),
        Reconcile::NoAdvance { target: Some(t) } => Report::refused(format!(
            "{report}--advance-to {advance_to} does not match the index this divergence reports \
             ({t}). Type the number in the report above. Nothing was written.{still}"
        )),
        Reconcile::Advanced { index } => Report::ok(format!(
            "{report}advanced account 0x{} to index {index} after operator review. Index {index} \
             was derived and its address compared to the one the chain holds before anything was \
             written; the report above is what was acknowledged. The key at every skipped \
             position is now unreachable by this wallet, which is the point: they may already \
             have signed.{still}{}",
            hex_bytes(tag),
            upgrade(upgraded)
        )),
    }
}

fn discovered(sweep: &super::discover::Sweep) -> Report {
    let to = sweep.to;
    let mut rows = String::new();
    let mut unresolved: Vec<u32> = Vec::new();
    for s in &sweep.sightings {
        // Every index the node resolved, and every index this store holds
        // whatever the node said, gets its own row. A held account the node
        // does not resolve is exactly the emptied-account window, and
        // hiding it would hide the one row an operator most needs.
        if s.entry.is_none() && s.held.is_none() {
            unresolved.push(s.account);
            continue;
        }
        let dest = match destination(&s.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&s.tag, &e),
        };
        let balance = match &s.entry {
            Some(e) => super::nano_and_mcm(i128::from(e.balance)),
            None => "not resolved by the node".to_string(),
        };
        let held = match s.held {
            None => String::new(),
            Some((kind, index)) => format!(
                "  IN THIS STORE ({}, at key index {})",
                match kind {
                    crate::account::AccountKind::Derived => "derived",
                    crate::account::AccountKind::Imported => "imported",
                },
                index.get()
            ),
        };
        rows.push_str(&format!(
            "  {:>5}  {dest:<width$}  {balance}{held}\n",
            s.account,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }

    let mut out = format!(
        "searched account indices 0..={to} from this store's master seed -- {} index(es), one \
         node call each. The node resolved {} of them.\n\n{rows}",
        u64::from(to) + 1,
        sweep.resolved()
    );
    if !unresolved.is_empty() {
        out.push_str(&format!(
            "  the node did not resolve {} index(es):{}\n",
            unresolved.len(),
            super::wrapped_indices(&unresolved)
        ));
    }
    out.push_str(&format!(
        "\n`did not resolve` is what was OBSERVED, and this page does NOT say those accounts do \
         not exist -- it cannot. The node answers `account not found` for a tag the ledger has no \
         entry for, for a tag it holds at ZERO balance, and for a lookup that failed, and it does \
         not tell the three apart; never funded, a node serving another chain, and a seed that is \
         not the one that made the account all produce the first of them. What is reported per \
         index is the node's answer and nothing beyond it.\n\n\
         The extent is 0..={to} because that is what was asked for: `discover --to N` searches \
         0..=N for any N from 1 to {}, and the number searched is on the first line so it can be \
         raised when it is too small. An index the node resolved is added to this store by \
         `restore --account N`. An index you expected to see and do not is a reason to check the \
         node and the seed, not a verdict.\n\n\
         Nothing was written: no account was added, nothing reserved, nothing signed, and the \
         store is unchanged.",
        super::args::DISCOVER_MAX_TO
    ));
    Report::ok(out)
}

fn transaction(page: &crate::mesh::codec::SearchPage) -> Report {
    let Some(tx) = page.transactions.first() else {
        // `decide` sends an empty page to `TransactionNotFound`, so this is
        // not reachable through it; rendered rather than panicked.
        return Report::refused("no transaction in this page.".into());
    };
    let mut out = format!("transaction {}\n", hex_bytes(&tx.hash));
    if let Some(b) = tx.block {
        out.push_str(&format!("  in block {} ({})\n", b.index, hex_bytes(&b.hash)));
    }
    if let Some(ms) = tx.timestamp_ms {
        out.push_str(&format!("  at       {}\n", super::stamp(ms)));
    }
    out.push_str(&format!("  {} operation(s)\n", tx.operations.len()));
    out.push_str(&super::operation_lines(&tx.operations, "    "));
    if !tx.metadata.is_empty() {
        out.push_str("  metadata, in the endpoint's own spelling:\n");
        out.push_str(&super::metadata_lines(&tx.metadata, "    "));
    }
    out.push_str(&format!("\n{}\n", super::SEARCH_CONVENTION));
    Report::ok(out)
}

fn recent_transactions(
    tag: &crate::addr::Tag,
    from: u64,
    page: &crate::mesh::codec::SearchPage,
) -> Report {
    use crate::mesh::codec;
    let shown = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    let rows = page.transactions.len() as u64;
    let mut out = if from == 0 {
        format!(
            "recent transactions for {shown}\n  {} of {} row(s), newest first\n",
            rows, page.total_count
        )
    } else if rows == 0 {
        format!(
            "recent transactions for {shown}\n  0 of {} row(s) after the {from} newest\n",
            page.total_count
        )
    } else {
        format!(
            "recent transactions for {shown}\n  rows {} to {} of {}, newest first: the {from} newest \
             are skipped\n",
            from.saturating_add(1),
            from.saturating_add(rows),
            page.total_count
        )
    };
    if page.transactions.is_empty() && from == 0 {
        out.push_str(
            "  (none: this node's index holds no transaction for this tag. A tag never paid has \
             none.)\n",
        );
    } else if page.transactions.is_empty() {
        out.push_str(&format!(
            "  (none after the {from} newest: this node's index holds {} for this tag.)\n",
            page.total_count
        ));
    }
    for tx in &page.transactions {
        let touched: i128 = tx
            .operations
            .iter()
            .filter(|o| o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag))
            .map(|o| o.amount)
            .sum();
        let out_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_SOURCE && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let in_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_DESTINATION && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let direction = match (out_ops, in_ops) {
            (true, true) => "both",
            (true, false) => "out",
            (false, true) => "in",
            (false, false) => "--",
        };
        let memo = tx
            .operations
            .iter()
            .find(|o| !o.memo.is_empty())
            .map(|o| super::terminal_text(&o.memo))
            .unwrap_or_default();
        out.push_str(&format!(
            "  block {:>9}  {}  {:<4}  {}\n",
            tx.block.map_or(0, |b| b.index),
            hex_bytes(&tx.hash),
            direction,
            super::nano_and_mcm(touched)
        ));
        if !memo.is_empty() {
            out.push_str(&format!("                    memo {memo}\n"));
        }
    }
    if let Some(n) = page.next_offset {
        out.push_str(&format!(
            "  more rows exist; the endpoint's next offset is {n}, and `--from {n}` reads them\n"
        ));
    }
    out.push_str(&format!("\n{}\n", super::SEARCH_CONVENTION));
    Report::ok(out)
}

fn block_page(block: &crate::mesh::codec::MeshBlock) -> Report {
    use crate::mesh::codec;
    // The reward transaction is the one carrying a REWARD operation.
    let (rewards, spends): (Vec<_>, Vec<_>) = block
        .transactions
        .iter()
        .partition(|t| t.operations.iter().any(|o| o.kind == codec::OP_REWARD));
    let moved: i128 = spends
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_DESTINATION)
        .map(|o| o.amount)
        .sum();
    let fees: i128 = block
        .transactions
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_FEE)
        .map(|o| o.amount)
        .sum();

    let mut out = format!(
        "block {}\n  hash     {}\n  parent   {} ({})\n  at       {}\n",
        block.block.index,
        hex_bytes(&block.block.hash),
        block.parent.index,
        hex_bytes(&block.parent.hash),
        super::stamp(block.timestamp_ms)
    );
    out.push_str(&block_figures(block));
    match rewards.first().and_then(|t| t.operations.iter().find(|o| o.kind == codec::OP_REWARD)) {
        Some(r) => {
            out.push_str(&format!("  reward   {}\n    to     {}\n", super::nano_and_mcm(r.amount), super::explorer_address(&r.address)));
        }
        None => out.push_str("  reward   none in this block\n"),
    }
    out.push_str(&format!(
        "  spends   {}\n  moved    {}  (every destination of every non-reward transaction; the \
         reward is newly minted, not moved, and is not counted)\n  fees     {}\n",
        spends.len(),
        super::nano_and_mcm(moved),
        super::nano_and_mcm(fees)
    ));
    for t in &spends {
        let dests = t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).count();
        let total: i128 = t
            .operations
            .iter()
            .filter(|o| o.kind == codec::OP_DESTINATION)
            .map(|o| o.amount)
            .sum();
        out.push_str(&format!(
            "    {}  {} destination(s)  {}\n",
            hex_bytes(&t.hash),
            dests,
            super::nano_and_mcm(total)
        ));
    }
    out.push_str(&format!("\n{}\n", super::BLOCK_CONVENTION));
    Report::ok(out)
}

/// The sentence every page that reads the node's queue carries.
const MEMPOOL_CONVENTION: &str = "read from /mempool and /mempool/transaction, which render a waiting \
     transaction as /block renders one: the source debited its NET amount and the change not an \
     operation. The queue is the node's own; another node's may differ.";

fn mempool(count: u64, total: usize, rows: &[super::outcome::MempoolRow]) -> Report {
    use crate::mesh::codec;
    let mut out = format!(
        "the mempool: {total} transaction(s) waiting to be mined; the first {} read\n",
        rows.len()
    );
    if total == 0 {
        out.push_str("  (none: this node's queue is empty.)\n");
    }
    for row in rows {
        match &row.transaction {
            Some(t) => {
                let sent: i128 = t
                    .operations
                    .iter()
                    .filter(|o| o.kind == codec::OP_DESTINATION)
                    .map(|o| o.amount)
                    .sum();
                let destinations = t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).count();
                out.push_str(&format!(
                    "  {}  {} destination(s)  {}\n",
                    hex_bytes(&row.id),
                    destinations,
                    super::nano_and_mcm(sent)
                ));
                out.push_str(&super::operation_lines(&t.operations, "    "));
            }
            None => out.push_str(&format!(
                "  {}  left the queue before it was read: mined since the list was read, or dropped\n",
                hex_bytes(&row.id)
            )),
        }
    }
    if total > rows.len() {
        out.push_str(&format!(
            "  {} more waiting, not read: this page reads the first {count}, and --count reads up to \
             {}\n",
            total - rows.len(),
            super::args::MAX_COUNT
        ));
    }
    out.push_str(&format!("\n{MEMPOOL_CONVENTION}\n"));
    Report::ok(out)
}

fn blocks(count: u64, tip: &crate::mesh::ChainTip, rows: &[crate::mesh::codec::MeshBlock]) -> Report {
    let mut out = format!("the {count} newest block(s); the tip is {}\n", tip.index);
    for b in rows {
        out.push_str(&format!(
            "  {:>9}  {}  {}  {} transaction(s)  {}\n",
            b.block.index,
            hex_bytes(&b.block.hash),
            super::stamp(b.timestamp_ms),
            b.transactions.len(),
            kind_word(b.kind())
        ));
    }
    Report::ok(out)
}

/// A block's kind as a page names it, or that the node sent nothing to tell
/// it by.
fn kind_word(kind: Option<crate::mesh::codec::BlockKind>) -> &'static str {
    use crate::mesh::codec::BlockKind;
    match kind {
        Some(BlockKind::Normal) => "normal",
        Some(BlockKind::Pseudo) => "pseudo",
        Some(BlockKind::Neogenesis) => "neogenesis",
        None => "kind not sent",
    }
}

/// The lines `block` prints from the block's own figures: its kind and
/// difficulty, its size, count and minimum fee, its Merkle root and nonce,
/// and for a normal block the haiku, one display line per line the node
/// sent, joined. A node that sent no metadata gets one line saying so, and
/// a neogenesis block is still named from its number.
fn block_figures(block: &crate::mesh::codec::MeshBlock) -> String {
    use crate::mesh::codec::BlockKind;
    let kind = block.kind();
    let Some(m) = &block.metadata else {
        return format!(
            "  type     {}; this node sent no block metadata\n",
            kind_word(kind)
        );
    };
    let what = match kind {
        Some(BlockKind::Pseudo) => "pseudo: no transactions, and no proof of work is checked for it",
        Some(BlockKind::Neogenesis) => "neogenesis: it carries the ledger, at every 256th block",
        _ => "normal",
    };
    let mut out = format!(
        "  type     {what}\n  work     difficulty {}, nonce {}\n  root     {}\n  size     {} bytes, {} transaction(s) besides the reward, minimum fee {}\n",
        m.difficulty,
        hex_bytes(&m.nonce),
        hex_bytes(&m.root),
        m.block_size,
        m.tx_count,
        super::nano_and_mcm(i128::from(m.fee))
    );
    if kind == Some(BlockKind::Normal) {
        let lines: Vec<String> = m
            .haiku
            .split('\n')
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(super::terminal_text)
            .collect();
        if !lines.is_empty() {
            out.push_str(&format!("  haiku    {}\n", lines.join(" / ")));
        }
    }
    out
}
