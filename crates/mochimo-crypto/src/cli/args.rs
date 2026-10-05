//! Argument parsing, hand-rolled.
//!
//! # Why no dependency
//!
//! Ten commands and seven flags. `clap` would add crates to a binary that
//! already carries rustls through `mesh-https`, generate a `--help` we would
//! not otherwise write, and leave the failure modes still needing enumeration
//! — because exit code 1 has to mean *argv did not parse* and the panic census
//! has to see no panicking construct here either way. The project argues every
//! dependency; this one does not pay for itself.
//!
//! **What that costs, stated rather than discovered:** no generated help, no
//! shell completions, no `--flag=value` spelling (only `--flag value`), and the
//! parser is ours to test. That last is why it has its own cases and its own
//! injection rows.
//!
//! # Panic-freedom is structural here
//!
//! Nothing in this file indexes a slice, unwraps, or asserts. Every read is
//! through `Iterator::next` or `str::strip_prefix`, every conversion returns
//! `Result`. A CLI that panics on argv is a CLI that panics on the first typo,
//! and `panicking_constructs_are_declared_at_their_sites` would need a row for
//! each one.

use crate::addr::Tag;
use crate::consts::{ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, MFEE};

/// Where the store is, which node to ask, and what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub dir: String,
    /// `Some` whenever `--node` was given, and [`parse`] refuses an
    /// invocation whose command [`Command::needs_node`] with none -- so a
    /// reconciling command always arrives here with one. `None` reaches the
    /// binary only for `create` and `address`, the two that never dial.
    ///
    /// This was a plain `String` once, required by every verb,
    /// while three operator-facing texts said the two need no node. They
    /// were true of the socket and false of argv, and an operator following
    /// the help could run neither command.
    pub node: Option<String>,
    pub command: Command,
}

/// One command, with its arguments already in the types the wallet takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Make a keystore and put account 0 in it. **Outside the `Wallet`
    /// gate**, where `restore` already is: it signs nothing and constructs no
    /// wallet, which is what lets it run before the account is funded.
    Create {
        /// Read an existing phrase instead of generating one.
        ///
        /// Without this the flow *restore a wallet on a new machine* does not
        /// exist: `restore --account N` needs a store, and a generate-only
        /// `create` would make a different wallet. That is the same shape of
        /// deadlock the pre-gate `create` exists to remove, one step along.
        from_phrase: bool,
    },
    /// Every account, as reconciliation found it.
    Balance,
    /// Where to receive. With a tag, the address that tag will next present;
    /// **without one, every account in the store** — which is the route back
    /// to a destination after `create` refused the confirmation, and the one
    /// route that needs neither a node nor the master seed. With `--account
    /// N` (exclusive with a tag), the position-0 address of account N derived
    /// from the store's master and **not stored**: the route to a second
    /// account's destination before it is funded, after which `restore
    /// --account N` adds it.
    Address { tag: Option<Tag>, account: Option<u32> },
    /// Lay out, reserve, sign, print the artifact, submit.
    Send(Spend),
    /// Settle a reservation if the chain shows the change key.
    Settle { tag: Tag },
    /// Reproduce a lost retry artifact **and submit it** (it once shipped
    /// nothing). Takes the **whole spend**
    /// again — see the type's note.
    Resign(Spend),
    /// Advance past a divergence the operator has read, to an index the
    /// chain confirms: the walk covers `0..=advance_to` and the advance
    /// happens only if the live report names exactly that index.
    Reconcile { tag: Tag, advance_to: u32 },
    /// Derive an account, find its index on the chain, add it to the store.
    /// `scan_to` raises the recovery ceiling for this one invocation: walk
    /// indices `0..=scan_to` instead of the default `0..=9999` -- the
    /// recovery ceiling, which is the bound the shipped browser extension
    /// walks for the same quantity rather than BIP-44's 20
    /// (`recon::RECOVERY_CEILING`).
    Restore { account: u32, scan_to: Option<u32> },
    /// Reconcile one account now and report without refusing -- before the
    /// gate, so a diverged account is reported rather than refused.
    /// `scan_to` widens the search as it does for `restore`.
    Status { tag: Tag, scan_to: Option<u32> },
    /// Write a saved artifact -- the hex `send` printed -- to the socket as
    /// it is. Opens no store, asks no password, reserves and signs nothing:
    /// the route to the socket for an operator whose account the Mesh no
    /// longer resolves (the emptied-account window), where `resign` cannot
    /// run. The hex is carried as typed; decoding it is the command's, so a
    /// bad artifact is a refusal (exit 3) rather than a usage error.
    Submit { artifact: String },
    /// One transaction, read from the Mesh's indexer by its hash
    /// (`/search/transactions`). Read-only: opens no store, asks no
    /// password, writes nothing.
    ///
    /// **Not spelled `Transaction`**, though the verb is `transaction`: the
    /// I1 signature scan resolves bearing types by name across the crate,
    /// and `tx::wire::Transaction` is bearing because it holds a
    /// `[u8; SIG_LEN]`. A variant of that name would put the identifier into
    /// `Command`'s token stream and make `args::parse` read as a function
    /// that returns a signature-bearing type. Renaming keeps the scan exact;
    /// allow-listing `parse` would have hidden a real one.
    LookupTransaction { hash: [u8; HASHLEN] },
    /// The newest transactions that touched a tag, newest first
    /// (`/search/transactions` by account). `count` is the endpoint's
    /// `limit`, and `from` its `offset`: how many of the newest to skip.
    RecentTransactions { tag: Tag, count: u64, from: u64 },
    /// One block, by index or by hash (`/block`).
    Block { at: BlockAt },
    /// The `count` newest blocks: the tip from `/network/status`, then
    /// `/block` for each index below it.
    Blocks { count: u64 },
    /// The transactions the node's queue holds, waiting to be mined: the
    /// ids from `/mempool`, then `/mempool/transaction` for the first
    /// `count` of them.
    Mempool { count: u64 },
    /// What the node says about accounts `0..=to` derived from the master
    /// this store holds: one `/call` per index, nothing written. Opens the
    /// store (the master is in it) but constructs no wallet, so it runs on
    /// a store `Wallet::open` would refuse -- which is the state a sweep
    /// exists to report on.
    ///
    /// **It never reports an account as absent**, only as *not resolved by
    /// the node*; `cli::discover`'s module doc says why that distinction is
    /// the whole verb.
    Discover { to: u32 },
}

/// How `block` was asked for.
///
/// The endpoint takes either, but **not index 0**: `getBlock`
/// routes to the by-number query only when
/// `Index != 0`, so an identifier carrying 0 falls through to the arm that
/// serves the *current* block. Genesis is unreachable by number there, and
/// the parser refuses `block 0` rather than let the tip be printed under
/// that name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAt {
    Index(u64),
    Hash([u8; HASHLEN]),
}

impl Command {
    /// Whether this command asks a node anything.
    ///
    /// **Exhaustive on purpose: no wildcard arm.** This is the one place the
    /// rule lives -- `parse` refuses a missing `--node` exactly when this is
    /// true, and nothing downstream re-tests it -- so an eleventh verb is a
    /// compile error here rather than a default that quietly decides for it.
    /// The two that answer `false` open no wallet and send no request.
    /// `create` by construction -- `orchestrate` takes no client, so there
    /// is nothing it could dial -- and `address` by measurement:
    /// `tests/cli.rs::address_makes_no_request_at_all` counts the transport's
    /// calls through a counting wrapper, for both shapes of the command, with
    /// `balance` as the control that shows the counter counts. "Asks a node"
    /// rather than "reconciles" for the seven, because `restore` scans and is
    /// reconciled by the *next* command's `Wallet::open` (its module doc), and
    /// reconciliation is a load-bearing word here (I4).
    pub fn needs_node(&self) -> bool {
        match self {
            Command::Create { .. } | Command::Address { .. } => false,
            Command::Balance
            | Command::Send(_)
            | Command::Settle { .. }
            | Command::Resign(_)
            | Command::Reconcile { .. }
            | Command::Restore { .. }
            | Command::Status { .. }
            | Command::Submit { .. }
            | Command::LookupTransaction { .. }
            | Command::RecentTransactions { .. }
            | Command::Block { .. }
            | Command::Blocks { .. }
            | Command::Mempool { .. }
            | Command::Discover { .. } => true,
        }
    }

    /// Whether the verb reads a node and **nothing else**: no store is
    /// opened, no password asked, nothing written. `submit` and the five
    /// explorer verbs; the binary routes them before the prompt.
    ///
    /// `--dir` is still required of them by the parser, as it is of every
    /// verb, and is not read, created or locked.
    #[must_use]
    pub fn opens_no_store(&self) -> bool {
        matches!(
            self,
            Command::Submit { .. }
                | Command::LookupTransaction { .. }
                | Command::RecentTransactions { .. }
                | Command::Block { .. }
                | Command::Blocks { .. }
                | Command::Mempool { .. }
        )
    }
}

/// A spend's parameters.
///
/// **`Resign` carries the same fields as `Send`, and that is not a
/// convenience.** `Wallet::resign_pending` rebuilds the reserved plan and
/// compares its digest to the one the store recorded, so the operator has to
/// re-supply the destination, the amount, the fee and the block-to-live
/// exactly; anything else is `DigestMismatch`. Reported as the strongest
/// argument for keeping the signed bytes in the record, where recovery would
/// need no reconstruction at all (rejected on width; `format.rs`'s module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub tag: Tag,
    /// The destinations in the order the operator gave them, one to 256.
    ///
    /// The planner sorts them by their 44-byte wire image before anything
    /// else, so this order is not the wire order; it is the order the page
    /// lists and the order `resign` demands back, which is the order the
    /// operator can read off their own command line.
    pub dsts: Vec<SpendTo>,
    /// A **total**, never per destination. Defaults to `MFEE × N`, which is
    /// exactly the floor the node applies (`500 × N`), so the default is the
    /// cheapest spend that can be accepted.
    pub fee_total: u64,
    pub blk_to_live: u64,
}

/// One destination as the command line gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendTo {
    pub to: Tag,
    /// `MDST::ref`, the destination's 16-byte reference field: `--ref
    /// <text>` for the single-destination form, the third column of a
    /// `--destinations` line, or sixteen zero bytes. Validated at parse time
    /// by the node's own rule (`crate::mesh::spend::reference_is_valid`), so
    /// a reference the node would refuse is a usage error before any prompt.
    /// Inside the signed digest like every other field here, so `resign`
    /// needs the same value.
    pub reference: [u8; ADDR_REF_LEN],
    /// `None` when the amount was the keyword `all`, which means
    /// `balance − fee` read from the same ledger observation the plan is
    /// built against. The parser admits `None` only for a single
    /// destination, so `dsts.len() == 1` wherever it appears.
    pub amount: Option<u64>,
}

impl Spend {
    /// Whether the one destination's amount was the keyword `all`.
    #[must_use]
    pub fn spends_everything(&self) -> bool {
        self.dsts.len() == 1 && self.dsts.iter().any(|d| d.amount.is_none())
    }
}

/// Why argv did not parse. Rendered to the operator; exit code 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage(pub String);

impl core::fmt::Display for Usage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "usage: {}\n\n{}", self.0, HELP)
    }
}

pub const HELP: &str = "\
tawara --dir <DIR> [--node <URL>] [--allow-plaintext-node] <command>
tawara -h | --help | help

  create [--from-phrase]                   make the store and account 0. Generates a
                                           24-word phrase and shows it ONCE, or reads
                                           one you already have. Needs no chain
  address [<tag> | --account <N>]          where to receive. With no argument, every
                                           account in the store -- no node, and no
                                           phrase. With a tag, that account's address
                                           too. With --account N, the address of an
                                           account this store does NOT hold, derived
                                           from its seed and not stored: fund it, then
                                           `restore --account N` adds it. Works before
                                           the account has any funds
  balance                                  every account, as reconciliation found it
  send <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
  send <tag> --destinations <path> [--fee N] [--btl N]
                                           lay out, reserve, sign, print the artifact
                                           and submit it. One to 256 destinations, as
                                           positional pairs or a file of them; <amount>
                                           may be `all` for a single destination
  settle <tag>                             settle a reservation the chain shows landed
  resign <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
  resign <tag> --destinations <path> [--fee N] [--btl N]
                                           rebuild a lost retry artifact and submit it
                                           -- the SAME spend, exactly, or it is refused
  submit <artifact-hex>                    write a saved artifact -- the hex `send`
                                           printed -- to the socket as it is. Opens no
                                           store and asks no password; the layout is
                                           checked and nothing else is judged
  reconcile <tag> --advance-to <N>         advance past a divergence you have read, to
                                           the index its report names; N is derived
                                           and compared to the chain first, never trusted
  discover [--to <N>]                      ask the node about accounts 0..=N derived from
                                           this store's seed and print what it said about
                                           each, N defaulting to 64 and running 1..=1024.
                                           Writes nothing. It reports what the node
                                           ANSWERED and never that an account does not
                                           exist, which it cannot know
  restore --account <N> [--scan-to <M>]    re-derive an account and find its index;
                                           --scan-to walks indices 0..=M (default 0..=9999)
  status <tag> [--scan-to <M>]             reconcile one account now, without refusing
                                           -- reports a divergence rather than stopping
                                           on it; --scan-to searches further along
  transaction <hash>                       one transaction from the node's indexer
  recent-transactions <tag> [--count N] [--from M]
                                           what touched a tag, newest first (N: 5),
                                           skipping the M newest (M: 0)
  block <number | hash>                    one block, its reward and what it moved
  blocks [--count N]                       the newest blocks, one row each (N: 5)
  mempool [--count N]                      the transactions waiting to be mined, the
                                           first N read whole (N: 5)

amounts are in nanoMochimo.

the last five verbs READ ONLY: they open no store and ask no password, so they work
with no wallet on this machine. --dir is still required, and is not touched. --count
runs 1..=100: the Mesh takes a limit only inside that window and otherwise answers
with its own default of ten rows without saying so, so a count it would ignore is
refused here. --from runs 0..=9223372036854775807, the Mesh's own range for an
offset; a page that has more after it names the --from that reads them. `block 0`
is refused too -- the Mesh serves index 0 as the CURRENT block, not as genesis.

`--ref TEXT` sets the destination's 16-byte reference field, checked against the
node's own rule before anything is asked or signed: groups of uppercase letters
A-Z or digits 0-9, each group one kind, neighbouring groups of different kinds,
single dashes between groups and none at either end, at most sixteen characters
-- `AB-00-EF`, `123-CDE-789`, `ABC`, `123`. Without it the field is zero. `resign`
needs the same `--ref` the `send` used. It names ONE destination's reference, so
it is taken only with a single destination; with several, the file's third column
gives a reference per line.

`discover` is the other half of `address --account N`: that one says where account N
would receive and asks nobody, this one asks the node about a range of accounts at one
call each. An index it reports as not resolved is not an account that does not exist --
the node answers `account not found` for a tag with no ledger entry, for a tag at zero
balance, and for a lookup that failed, and tells none of the three apart. An index it
resolves is added to this store by `restore --account N`; `discover` itself writes
nothing and reserves nothing.

`--destinations <path>` reads one destination per line, `<to> <amount> [<ref>]`,
whitespace separated, `#` starting a comment. Blank lines are skipped. Use it when
the payees do not fit on a command line, or when they need references.

`--fee` is a TOTAL, never per destination. It defaults to 500 x the number of
destinations, which is exactly the floor the node applies; a fee below that floor
is refused before anything is signed.

`all` as the <amount> sends the whole balance less the fee, read from the same
ledger observation the plan is built against, so the change is zero and the
account is emptied. Only for a single destination.

a destination is Base58 over a tag and its CRC16 -- 22 to 31 characters, the form
every Mochimo wallet emits and takes, and the only form that catches a typo.
`0x` followed by 40 hex characters is accepted too: that is the machine form the
Mesh endpoints use and the form this project's fixtures record. The `0x` is
REQUIRED, because hex carries no checksum and a form with no checksum has to be
asked for -- bare 40-hex would also accept the second half of the 80-character
ledger address `address` prints, which is a tag nobody holds.
the store is encrypted: every command prompts for its password on the terminal, and
the master seed is read out of the store rather than typed. the recovery phrase is a
backup, not a login -- only `create --from-phrase` asks for it.
`--scan-to` and `--advance-to` walk key indices from 0 up to the number given, and every
index walked costs one key derivation: name a number near where the account is. Without
`--scan-to`, `restore` and `status` walk 0..=9999, which is what the only other wallet
for this chain walks; a search that finds nothing pays for all ten thousand, about
sixteen seconds, and a search that finds the account stops there and pays nothing.
create and address need no `--node`; every other command asks a node before it runs
and requires one. An `http://` node off the loopback interface needs
`--allow-plaintext-node`: the node's answers drive reconciliation and the amounts a
spend is built from, and on a plaintext link anyone on the path can rewrite them.
`https://`, and `http://` to 127.0.0.0/8, ::1 or localhost, need no flag.";

/// A tag the operator supplied, in **either** accepted form.
///
/// # The two forms, and why one of them must say so out loud
///
/// * a **destination** — Base58 over the tag and its CRC16, 22 to 31
///   characters. This is what every human-facing Mochimo tool emits and takes:
///   the reference node parses it for `-m/--maddr`, `tag-utils.ts`
///   produces it, and the shipped extension accepts nothing else.
/// * **`0x` followed by 40 hex characters** — the machine form, which is what
///   every Mesh endpoint in the pinned tree uses -- each requires exactly
///   `0x` plus 40 hex -- and what this project's fixtures record.
///
/// # Bare forty-hex is refused, and that is the destination form correcting itself
///
/// The recorded values are written that way, so accepting it looks free.
/// What it costs: `address` prints the 40-byte ledger address as
/// **eighty** hex characters, and characters 41..80 — the hash half — are
/// forty hex characters that a bare-hex parser accepts as a tag. At `wots_index
/// 0` both halves are the same twenty bytes (`addr_from_implicit`), which
/// teaches an operator that *the tag is half the address*; after one spend they
/// are not, and the second half is a tag derived from a public-key hash that
/// nobody controls. It carries no checksum, `mdst_val` has no
/// ledger-existence check, and `ledger.c` creates the account on credit — so
/// the payment settles and is gone.
///
/// Requiring `0x` closes that without losing anything: the recorded values are
/// still pasteable, two characters ahead of them, and **no substring of
/// anything this program prints carries the prefix.** A form with no checksum
/// has to be asked for.
///
/// # Disjointness, doubly
///
/// The Base58 alphabet excludes `0`,
/// so no
/// destination can begin `0x` and the prefix arm cannot capture one. And a
/// destination is at most [`crate::addr::TAG_BASE58_MAX_CHARS`] = 31
/// characters where a hex tag is 40, so the two do not overlap by length
/// either. `tests/cli.rs::the_two_destination_forms_cannot_collide` walks both.
///
/// # Trimmed, as the shipped clients trim
///
/// `SendModal.tsx` and `address-input.tsx` both trim before validating, and a
/// 30-character destination with a trailing newline is 31 characters — inside
/// the window, and refused by the codec with a backend error about Base58,
/// not about the tag. Trimming here means a pasted
/// destination behaves the way it does in the wallet the operator copied it
/// from.
fn tag_from_text(s: &str, what: &'static str) -> Result<Tag, Usage> {
    let t = s.trim();
    if t.starts_with("0x") {
        return refuse_the_zero_tag(tag_from_hex(t, what)?, t, what);
    }
    if t.chars().count() == ADDR_TAG_LEN * 2 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Usage(format!(
            "{what}: `{t}` is a bare hex tag. Write it as `0x{t}` if that is what you mean.\n  \
             Hex carries no checksum, so it is accepted only when you say it is hex. The reason \
             is specific: `address` prints a 40-byte ledger address as eighty hex characters, \
             and its second half is also forty hex characters -- a tag nobody holds, which a \
             bare-hex parser would take without complaint."
        )));
    }
    let tag = crate::addr::tag_from_base58(t).map_err(|e| {
        Usage(format!(
            "{what}: `{t}` is not a destination -- {e}.\n  A destination is Base58 over a tag \
             and its CRC16, which is what every Mochimo wallet emits; `0x` and {} hex \
             characters is accepted too.",
            ADDR_TAG_LEN * 2
        ))
    })?;
    refuse_the_zero_tag(tag, t, what)
}

/// The one destination the checksum provably cannot refuse.
///
/// `crc16` of twenty zero bytes is **zero** — fixture `C7` records
/// `"crc16": 0` and `"base58_of_tag22": "1111111111111111111111"` — so the
/// all-zero tag's own checksum matches, and `tag_from_base58` returns it on
/// the happy path. Everything downstream accepts it too: `SpendPlan::new` has
/// no zero-tag rule, `mdst_val`
/// refuses a zero *amount* and a destination equal to the source but not a
/// zero tag, and the ledger creates the account on credit. So a payment to it
/// settles, and nothing can ever spend it again.
///
/// It is the value an uninitialised field, a truncated column or a template
/// placeholder produces, which makes it the one twenty-byte value likeliest to
/// arrive by accident — and the only one the encoding's whole safety argument
/// does not cover.
///
/// **Refused here rather than in [`crate::addr::tag_from_base58`]**, and the
/// split is deliberate: that function is a codec and must agree with the
/// reference, which encodes and decodes this value like any other (group C's
/// `C7` round-trips through it, and the KAT walks it). This is a *policy* about
/// what a wallet will pay to, and policy belongs at the boundary where a human
/// typed something.
fn refuse_the_zero_tag(tag: Tag, given: &str, what: &'static str) -> Result<Tag, Usage> {
    if tag.iter().any(|&b| b != 0) {
        return Ok(tag);
    }
    Err(Usage(format!(
        "{what}: `{given}` is the all-zero tag, and this wallet will not use it.\n  Its checksum \
         is zero as well -- crc16 of twenty zero bytes is 0 -- so the CRC16 that refuses every \
         other mistyped destination cannot refuse this one. It is what an uninitialised or \
         truncated buffer produces, the chain will credit it, and nothing can ever spend it \
         again."
    )))
}

fn tag_from_hex(s: &str, what: &'static str) -> Result<Tag, Usage> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; ADDR_TAG_LEN];
    let mut written = 0usize;
    let mut hi: Option<u8> = None;
    for c in body.chars() {
        let d = match c.to_digit(16) {
            Some(d) => d as u8,
            None => return Err(Usage(format!("{what}: `{s}` is not hexadecimal"))),
        };
        match hi {
            None => hi = Some(d),
            Some(h) => {
                match out.get_mut(written) {
                    Some(slot) => *slot = (h << 4) | d,
                    None => {
                        return Err(Usage(format!(
                            "{what}: `{s}` is longer than {ADDR_TAG_LEN} bytes"
                        )))
                    }
                }
                written += 1;
                hi = None;
            }
        }
    }
    if hi.is_some() || written != ADDR_TAG_LEN {
        return Err(Usage(format!(
            "{what}: `{s}` is {} hex characters; a tag is {}",
            body.chars().count(),
            ADDR_TAG_LEN * 2
        )));
    }
    Ok(out)
}

fn u64_arg(s: &str, what: &'static str) -> Result<u64, Usage> {
    s.parse::<u64>()
        .map_err(|_| Usage(format!("{what}: `{s}` is not a whole number")))
}

/// A flag that takes a value, read from the tail of a command's arguments.
fn u64_flag(rest: &[String], name: &str) -> Result<Option<u64>, Usage> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == name {
            return match it.next() {
                Some(v) => u64_arg(v, "flag value").map(Some),
                None => Err(Usage(format!("{name} needs a value"))),
            };
        }
    }
    Ok(None)
}

/// A flag whose value is text, read from the tail as [`u64_flag`] reads a
/// number: the first occurrence, after [`reject_unknown_flags`] has refused
/// a second.
fn text_flag<'a>(rest: &'a [String], name: &str) -> Result<Option<&'a str>, Usage> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == name {
            return match it.next() {
                Some(v) => Ok(Some(v.as_str())),
                None => Err(Usage(format!("{name} needs a value"))),
            };
        }
    }
    Ok(None)
}

/// The node's rule for a destination reference, in the words every `--ref`
/// refusal carries; the rule itself is `mesh::spend::reference_is_valid`,
/// transcribed from the node.
pub const REFERENCE_RULE: &str = "a reference is up to sixteen characters: groups of uppercase \
letters A-Z or digits 0-9, each group all one kind, neighbouring groups of different kinds, \
single dashes between groups and none at either end -- `AB-00-EF`, `123-CDE-789`, `ABC` and \
`123` are accepted; `AB-CD-EF`, `123-456-789`, `ABC-` and `-123` are not";

/// `--ref <text>`: the destination's reference field, validated here by the
/// node's own rule before anything is prompted for, reserved or signed, and
/// NUL-padded to the sixteen bytes the wire carries. Sixteen zero bytes
/// without the flag -- the field `send` wrote before the flag existed, which
/// `tests/cli.rs` still pins byte for byte.
fn reference_flag(rest: &[String]) -> Result<[u8; ADDR_REF_LEN], Usage> {
    match text_flag(rest, "--ref")? {
        None => Ok([0u8; ADDR_REF_LEN]),
        Some(text) => reference_field(text, "--ref"),
    }
}

/// One reference's text, NUL-padded to the sixteen bytes the wire carries and
/// checked against the node's own rule. `whose` names where it came from --
/// the flag, or a file and line -- so a refusal points at the text the
/// operator wrote rather than at a field index the wire will assign later.
fn reference_field(text: &str, whose: &str) -> Result<[u8; ADDR_REF_LEN], Usage> {
    let mut field = [0u8; ADDR_REF_LEN];
    if !text.is_ascii() {
        return Err(Usage(format!("{whose}: `{text}` is not ASCII; {REFERENCE_RULE}")));
    }
    if text.len() > ADDR_REF_LEN {
        return Err(Usage(format!(
            "{whose}: `{text}` is {} characters and the field holds {ADDR_REF_LEN}; {REFERENCE_RULE}",
            text.len()
        )));
    }
    field[..text.len()].copy_from_slice(text.as_bytes());
    if !crate::mesh::spend::reference_is_valid(&field) {
        return Err(Usage(format!(
            "{whose}: `{text}` does not follow the node's rule for a destination reference; {REFERENCE_RULE}"
        )));
    }
    Ok(field)
}

/// Reject anything in the tail that is not one of the flags a command takes,
/// so a typo'd flag is a usage error rather than a silently ignored one --
/// and a flag given twice, so a repeated flag is a usage error naming it
/// rather than a silent first-one-wins (`u64_flag` reads the first
/// occurrence, and this runs before it in every command, so the second is
/// never reached).
///
/// Two lists because `--from-phrase` was the first valueless flag: a `valued`
/// flag consumes the token after it, a `bare` one does not. One list could not
/// tell them apart, and the failure would have been silent in the direction
/// that matters -- `--from-phrase` would have eaten the next argument.
fn reject_unknown_flags(rest: &[String], valued: &[&str], bare: &[&str]) -> Result<(), Usage> {
    let mut it = rest.iter();
    let mut seen: Vec<&str> = Vec::new();
    while let Some(a) = it.next() {
        let is_bare = bare.contains(&a.as_str());
        if !is_bare && !valued.contains(&a.as_str()) {
            return Err(Usage(format!("unexpected argument `{a}`")));
        }
        if seen.contains(&a.as_str()) {
            return Err(Usage(format!("{a} given twice")));
        }
        seen.push(a.as_str());
        if is_bare {
            continue;
        }
        if it.next().is_none() {
            return Err(Usage(format!("{a} needs a value")));
        }
    }
    Ok(())
}

/// A flag that is present or absent.
fn bare_flag(rest: &[String], name: &str) -> bool {
    rest.iter().any(|a| a == name)
}

/// `send` and `resign`, in either of two exclusive forms:
///
/// ```text
/// <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
/// <tag> --destinations <path>            [--fee N] [--btl N]
/// ```
///
/// **Why positional pairs and not a repeated flag.** A repeated flag is a
/// usage error everywhere else in this parser, and making one flag the
/// exception would mean an operator has to know which. Pairs also read in the
/// order the page prints and the order `resign` demands back.
///
/// **Why `--ref` only with one destination.** It names *a* destination's
/// reference, and with several there is no way to say which; the file's third
/// column says it per line instead. Given with pairs or a file it is a usage
/// error rather than a value silently applied to one of them or to all.
///
/// **Why `all` only with one destination.** It means the whole balance less
/// the fee; split across several it would need a division rule the protocol
/// does not have.
fn spend_args(rest: &[String], verb: &'static str) -> Result<Spend, Usage> {
    let Some(tag) = rest.first() else {
        return Err(Usage(format!("{verb} needs <tag> <to> <amount>")));
    };
    let tag = tag_from_text(tag, "source tag")?;
    let after = rest.get(1..).unwrap_or(&[]);

    // The two forms are told apart by the first token after the tag, which is
    // either `--destinations` or the first `<to>`.
    let from_file = after.first().is_some_and(|a| a == "--destinations");
    let (dsts, tail) = if from_file {
        reject_unknown_flags(after, &["--destinations", "--fee", "--btl", "--ref"], &[])?;
        if text_flag(after, "--ref")?.is_some() {
            return Err(Usage(
                "--ref names one destination's reference and --destinations carries a \
                 reference per line; give it in the file's third column instead"
                    .into(),
            ));
        }
        let path = match text_flag(after, "--destinations")? {
            Some(p) => p,
            None => return Err(Usage("--destinations needs a value".into())),
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| Usage(format!("--destinations: cannot read `{path}`: {e}")))?;
        (destinations_from_text(&text, path)?, after)
    } else {
        // Positional pairs run until the first flag.
        let pairs_len = after.iter().take_while(|a| !a.starts_with("--")).count();
        let (pairs, tail) = after.split_at(pairs_len);
        if pairs.is_empty() {
            return Err(Usage(format!("{verb} needs <tag> <to> <amount>")));
        }
        if pairs.len() % 2 != 0 {
            return Err(Usage(format!(
                "{verb} takes <to> <amount> pairs and {} token(s) were given after the tag; \
                 the last destination has no amount",
                pairs.len()
            )));
        }
        reject_unknown_flags(tail, &["--fee", "--btl", "--ref"], &[])?;
        let single = pairs.len() == 2;
        let reference = reference_flag(tail)?;
        if !single && reference != [0u8; ADDR_REF_LEN] {
            return Err(Usage(format!(
                "--ref names one destination's reference and {} were given; use \
                 `--destinations <path>`, whose third column is a reference per line",
                pairs.len() / 2
            )));
        }
        // Walked by `next`, never indexed: this file's panic-freedom is
        // structural, so the odd-count case is a refusal here as well as
        // above rather than an `unwrap` the even check makes unreachable.
        let mut dsts = Vec::new();
        let mut it = pairs.iter();
        while let Some(to) = it.next() {
            let Some(amount) = it.next() else {
                return Err(Usage(format!("{verb}: `{to}` has no amount")));
            };
            dsts.push(SpendTo {
                to: tag_from_text(to, "destination tag")?,
                reference,
                amount: amount_arg(amount, single)?,
            });
        }
        (dsts, tail)
    };

    check_destinations(&dsts)?;
    let n = u64::try_from(dsts.len()).unwrap_or(u64::MAX);
    Ok(Spend {
        tag,
        fee_total: u64_flag(tail, "--fee")?.unwrap_or(MFEE.saturating_mul(n)),
        blk_to_live: u64_flag(tail, "--btl")?.unwrap_or(0),
        dsts,
    })
}

/// `<amount>`: a whole number of nanoMochimo, or the keyword `all`.
///
/// `all` is refused for anything but a single destination, and the message
/// says so rather than reporting `all` as a malformed number.
fn amount_arg(s: &str, single: bool) -> Result<Option<u64>, Usage> {
    if s == "all" {
        return if single {
            Ok(None)
        } else {
            Err(Usage(
                "`all` means the whole balance less the fee and is only available for a \
                 single destination; give each destination its own amount"
                    .into(),
            ))
        };
    }
    u64_arg(s, "amount").map(Some)
}

/// The rules over the whole list, in the order they are checked.
///
/// The count bound is the protocol's (`crate::tx::MAX_DESTINATIONS`). The
/// duplicate refusal is **not** the protocol's: the node accepts two
/// destinations sharing a tag, and orders them by the bytes that follow. It
/// is refused here, as a usage error before any prompt, because two
/// destinations with one tag is almost always a mistyped second payee and
/// the money does not come back. An operator who means it sends twice. The
/// refusal is deliberately not in `SpendPlan`, whose rules are the node's
/// and nothing else.
fn check_destinations(dsts: &[SpendTo]) -> Result<(), Usage> {
    let max = usize::from(crate::tx::MAX_DESTINATIONS);
    if dsts.is_empty() || dsts.len() > max {
        return Err(Usage(format!(
            "a spend carries 1 to {max} destinations and {} were given",
            dsts.len()
        )));
    }
    for (i, d) in dsts.iter().enumerate() {
        if let Some(j) = dsts.iter().take(i).position(|e| e.to == d.to) {
            return Err(Usage(format!(
                "destinations {} and {} are the same tag. The node would accept it, but one \
                 tag twice in one spend is almost always a mistyped payee and the money does \
                 not come back; send twice if you mean it",
                j + 1,
                i + 1
            )));
        }
    }
    Ok(())
}

/// `--count N`, the row count the explorer verbs take.
///
/// Defaults to 5. The ceiling is the **endpoint's**, not a taste:
/// `searchTransactionsHandler` takes the `limit` it is sent only when
/// `0 < limit <= 100` and otherwise silently uses its own default of 10
/// at the Mesh commit the corpus pins. It does
/// not clamp. So a count of 250 would be answered with ten rows and nothing
/// to say it had been ignored, which is worse than a refusal; the refusal is
/// here, before any socket is opened, and it names the window.
///
/// `blocks` and `mempool` are bounded by the same number for a different
/// reason -- one `/block` or `/mempool/transaction` call per row -- and the
/// one ceiling keeps the three verbs' flag meaning one thing.
fn count_flag(rest: &[String]) -> Result<u64, Usage> {
    reject_unknown_flags(rest, &["--count"], &[])?;
    count_value(rest)
}

/// [`count_flag`]'s reading of `--count`, for a verb that takes other flags
/// beside it and has refused any it does not.
fn count_value(rest: &[String]) -> Result<u64, Usage> {
    let n = u64_flag(rest, "--count")?.unwrap_or(DEFAULT_COUNT);
    if n == 0 || n > MAX_COUNT {
        return Err(Usage(format!(
            "--count: {n} is outside 1..={MAX_COUNT}. The Mesh's search endpoint takes a limit \
             only inside that window and otherwise answers with its own default of ten rows \
             without saying so, so a count it would ignore is refused here instead"
        )));
    }
    Ok(n)
}

/// `--from M`, the rows `recent-transactions` skips: the endpoint's
/// `offset`.
///
/// Defaults to 0, the newest. The ceiling is the endpoint's again:
/// `searchTransactionsHandler` decodes `offset` into an `int64`, so a value
/// above [`MAX_FROM`] does not decode and the whole request is answered
/// *Invalid request*. It is refused here, before any socket is opened, with
/// that reason. A value past the tag's last row is not refused: the index
/// answers an empty page with its total, and the page says so.
fn from_flag(rest: &[String]) -> Result<u64, Usage> {
    let m = u64_flag(rest, "--from")?.unwrap_or(0);
    if m > MAX_FROM {
        return Err(Usage(format!(
            "--from: {m} is outside 0..={MAX_FROM}. The Mesh reads an offset as a signed 64-bit \
             number and answers a larger one as an invalid request, so it is refused here \
             instead"
        )));
    }
    Ok(m)
}

/// The largest `--from` `recent-transactions` takes: `i64::MAX`, the
/// Mesh's own range for an offset.
pub const MAX_FROM: u64 = i64::MAX as u64;

/// How many rows an explorer verb prints without `--count`.
pub const DEFAULT_COUNT: u64 = 5;
/// The largest `--count` either explorer verb takes; the Mesh's own ceiling.
pub const MAX_COUNT: u64 = 100;

/// How far `discover` sweeps without `--to`: account indices `0..=64`.
///
/// **Not a claim that an operator has at most 65 accounts.** The number is
/// printed on the page, and the page says how to raise it -- which is the
/// only honest form a default can take here, because the sweep cannot tell
/// *no account at this index* from *the node did not answer for this index*
/// (`cli::discover`'s module doc). 64 is a starting extent an operator can
/// see and change, and the shipped browser extension's own phrase restore
/// creates five accounts, so it is comfortably past what that client
/// produces.
pub const DISCOVER_DEFAULT_TO: u32 = 64;

/// The largest `--to` `discover` takes.
///
/// **Each index is one call to a node**, so an unbounded `--to` is a way to
/// put a thousand-fold request amplification behind a single typo -- a
/// mistyped `--to 1000000` would be a million round trips and hours of
/// derivation before the first line of output. 1,024 is where that stops:
/// well past any account count a wallet for this chain produces, and small
/// enough that the worst invocation an operator can type by accident is a
/// few minutes rather than a day. It is this program's number and not a
/// protocol limit, which is why the refusal says so.
pub const DISCOVER_MAX_TO: u32 = 1_024;

/// `discover`'s `--to`, defaulting to [`DISCOVER_DEFAULT_TO`].
///
/// Zero is refused too, and in its own arm: a sweep bounded at 0 searches the
/// single index `create` derives, which a store holding a master already
/// holds, so it can observe nothing the store does not record while still
/// costing a node call -- and it is what an unexpanded shell variable
/// produces. `address` with no argument lists what is held, and `balance`
/// reports it. The ceiling's arm says nothing about any of that; the two
/// reasons are two arms because they are two reasons.
fn discover_to_flag(rest: &[String]) -> Result<u32, Usage> {
    reject_unknown_flags(rest, &["--to"], &[])?;
    let n = match u64_flag(rest, "--to")? {
        Some(n) => n,
        None => return Ok(DISCOVER_DEFAULT_TO),
    };
    // **Two arms, not one string.** The two ends of this range are refused
    // for different reasons, and one message covering both told an operator
    // who mistyped `--to 2000` about account index 0 -- advice with nothing
    // to do with the number they typed, on a page whose only job is to
    // explain the refusal. Both arms keep the bounds and echo the value; only
    // the reason differs, because only the reason differed.
    match u32::try_from(n) {
        Ok(to) if (1..=DISCOVER_MAX_TO).contains(&to) => Ok(to),
        Ok(0) => Err(Usage(format!(
            "--to: {n} is outside 1..={DISCOVER_MAX_TO}. A sweep bounded at 0 searches only \
             account index 0, which a store with a master already holds, so it can observe \
             nothing the store does not record while still costing a node call -- `address` \
             with no argument lists what is here, and `balance` reports it. Zero is also what \
             an unexpanded shell variable produces"
        ))),
        _ => Err(Usage(format!(
            "--to: {n} is outside 1..={DISCOVER_MAX_TO}. Every index in the sweep is one call \
             to the node, so the ceiling is this program's own: it keeps a mistyped number from \
             turning into thousands of round trips before the first line of output. Name a \
             bound at or below {DISCOVER_MAX_TO}"
        ))),
    }
}

/// A 32-byte transaction hash, `0x` + 64 hex or the bare 64.
///
/// Both spellings are taken here, unlike a destination, where bare hex is
/// refused because it could be half of a printed ledger address. A
/// transaction hash is not a destination, nothing is paid to it, and every
/// explorer that shows one shows it bare as often as prefixed.
fn hash_arg(arg: Option<&String>, verb: &'static str) -> Result<[u8; HASHLEN], Usage> {
    let Some(text) = arg else {
        return Err(Usage(format!("{verb} needs <hash>")));
    };
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.len() != HASHLEN * 2 || !body.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Usage(format!(
            "{verb}: `{text}` is not a transaction hash; it is {} hex characters and a hash is \
             {} (with or without a leading `0x`)",
            body.len(),
            HASHLEN * 2
        )));
    }
    let mut out = [0u8; HASHLEN];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = body.get(i * 2..i * 2 + 2).ok_or_else(|| Usage(format!("{verb}: `{text}` is not a hash")))?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| Usage(format!("{verb}: `{text}` is not a hash")))?;
    }
    Ok(out)
}

/// `block <number>` or `block <hash>`.
///
/// **Index 0 is refused.** The endpoint's `getBlock` routes by number only
/// when `Index != 0`, so a request carrying 0
/// falls through to the arm that serves the *current* block: `block 0` would
/// print the tip and label it block 0. Genesis is not reachable by number
/// through this endpoint at all, and a refusal that says so is better than a
/// page that is quietly about a different block.
fn block_at(arg: Option<&String>) -> Result<BlockAt, Usage> {
    let Some(text) = arg else {
        return Err(Usage("block needs <number> or <hash>".into()));
    };
    if text.as_bytes().iter().all(u8::is_ascii_digit) {
        let n = u64_arg(text, "block number")?;
        if n == 0 {
            return Err(Usage(
                "block 0: the Mesh serves index 0 as the CURRENT block, not as genesis -- its \
                 getBlock routes by number only for a non-zero index -- so a page for `block 0` \
                 would be the tip under the wrong name. Use `blocks` for the tip, or name a \
                 block from 1 up"
                    .into(),
            ));
        }
        return Ok(BlockAt::Index(n));
    }
    Ok(BlockAt::Hash(hash_arg(arg, "block")?))
}

/// `--destinations <path>`, parsed from the file's text.
///
/// One destination per non-empty line, `<to> <amount> [<ref>]`, whitespace
/// separated. `#` starts a comment, to the end of the line. Pure, so the
/// syntax is testable without a file on disk; the parser reads the path and
/// hands the text here. Every refusal names the line number, because a file
/// of two hundred payees is not read by eye.
fn destinations_from_text(text: &str, path: &str) -> Result<Vec<SpendTo>, Usage> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        };
        let mut f = line.split_whitespace();
        let Some(to) = f.next() else { continue };
        let at = format!("{path} line {}", n + 1);
        let Some(amount) = f.next() else {
            return Err(Usage(format!("{at}: `{to}` has no amount")));
        };
        let reference = match f.next() {
            Some(r) => reference_field(r, &at)?,
            None => [0u8; ADDR_REF_LEN],
        };
        if let Some(surplus) = f.next() {
            return Err(Usage(format!(
                "{at}: unexpected `{surplus}`; a line is <to> <amount> [<ref>]"
            )));
        }
        out.push(SpendTo {
            to: tag_from_text(to, "destination tag")?,
            reference,
            // `all` is a command-line keyword only: a file line is one of
            // many destinations by construction, and `all` needs exactly one.
            amount: Some(u64_arg(amount, "amount")?),
        });
    }
    if out.is_empty() {
        return Err(Usage(format!("{path}: no destinations; every line was blank or a comment")));
    }
    Ok(out)
}

/// A key index named on the command line -- `--advance-to`, `--scan-to`.
///
/// Refused at `u32::MAX` as well as above it: the last position cannot be
/// advanced from, so an account placed there could never reserve a spend,
/// and a walk "to" it would be a walk to a position the scan never derives.
fn index_flag(rest: &[String], name: &str) -> Result<Option<u32>, Usage> {
    match u64_flag(rest, name)? {
        None => Ok(None),
        Some(n) => match u32::try_from(n) {
            Ok(i) if i < u32::MAX => Ok(Some(i)),
            _ => Err(Usage(format!(
                "{name}: {n} is out of range; key indices run from 0 to {}",
                u32::MAX - 1
            ))),
        },
    }
}

/// The tag a command takes first, before its flags -- `status`, `reconcile`.
/// A flag in that position is diagnosed as the missing tag rather than as a
/// destination that fails to decode (a refutation pass's finding).
fn leading_tag(rest: &[String], verb: &'static str) -> Result<Tag, Usage> {
    match rest.first() {
        Some(t) if !t.starts_with("--") => tag_from_text(t, "tag"),
        _ => Err(Usage(format!("{verb} needs <tag>"))),
    }
}

/// `submit`'s one argument, the artifact hex as typed. Decoding is the
/// command's (a refusal naming the offset, exit 3), not the parser's: argv
/// parsed. A flag in its place is diagnosed as the missing artifact.
fn artifact_arg(rest: &[String], verb: &'static str) -> Result<String, Usage> {
    match rest.first() {
        Some(a) if rest.len() == 1 && !a.starts_with("--") => Ok(a.clone()),
        Some(a) if a.starts_with("--") => Err(Usage(format!("{verb} needs <artifact-hex>"))),
        Some(_) => Err(Usage(format!("{verb} takes one <artifact-hex>"))),
        None => Err(Usage(format!("{verb} needs <artifact-hex>"))),
    }
}

fn tag_arg(rest: &[String], verb: &'static str) -> Result<Tag, Usage> {
    match rest.first() {
        Some(t) if rest.len() == 1 => tag_from_text(t, "tag"),
        Some(_) => Err(Usage(format!("{verb} takes one tag"))),
        None => Err(Usage(format!("{verb} needs <tag>"))),
    }
}

/// `address`'s argument, which is optional.
///
/// `None` is not "no tag given, so use a default" -- it is a **different
/// command**: list the store. The two are distinguished here rather than in
/// the dispatch so that `address a b` is still a usage error rather than a
/// listing that silently ignored both arguments.
fn optional_tag_arg(rest: &[String], verb: &'static str) -> Result<Option<Tag>, Usage> {
    match rest.first() {
        None => Ok(None),
        Some(t) if rest.len() == 1 => tag_from_text(t, "tag").map(Some),
        Some(_) => Err(Usage(format!("{verb} takes one tag, or none at all"))),
    }
}

/// What argv asked for.
///
/// **Named `ParsedArgv` rather than `Parsed`, and that is not taste.**
/// `keystore::format::Parsed` holds key material, and the Debug-holder scan
/// closes transitively over **bare type names** — so a second `Parsed`
/// anywhere in `crates/*/src` inherits the first one's holder status and is
/// flagged for deriving `Debug`. That is the route scan's bare-name finding in a
/// second scan: the granularity is a property of this project's syn-based
/// scans, not of any one of them. Renamed on this side rather than loosening
/// the scan.
///
/// **Help is an outcome, not an error.** Once the `HELP` text was
/// reachable only as the tail of a `Usage`, so the way to read it was to make
/// a mistake -- and the exit code said the invocation had failed, which for
/// `--help` it had not. A binary a human drives owes a help path that is not
/// spelled *get something wrong*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedArgv {
    /// `-h`, `--help`, or the `help` verb. The caller prints [`HELP`] and
    /// exits **0**.
    Help,
    /// A command to run.
    Run(Invocation),
}

/// The three spellings that ask for help. Recognised where a verb or a
/// global flag is recognised -- `help` as the verb, `-h` or `--help` before
/// it -- and nowhere else: anywhere after the verb they are unexpected
/// tokens and are refused as such, like every other stray token.
fn asks_for_help(a: &str) -> bool {
    a == "-h" || a == "--help" || a == "help"
}

/// Parse `argv` **without** the program name.
/// Whether `url` is plaintext HTTP to something other than the loopback
/// interface, which is the case `--allow-plaintext-node` exists to gate.
///
/// # What counts as loopback here
///
/// Any address in `127.0.0.0/8`, `::1`, and the literal name `localhost`.
///
/// The two address forms are decided by the bytes in the argv and nothing
/// else. `localhost` is not: it is a name, and what it resolves to comes from
/// the host's own configuration, so it is a weaker guarantee than either
/// literal. It is exempt anyway, because it is how a local node is spelled
/// almost every time, and a gate that fires on the common local case teaches
/// an operator to pass the flag out of habit -- at which point it no longer
/// gates the case it exists for. Reaching a non-loopback address through
/// `localhost` needs control of the host's name resolution, which is a larger
/// capability than the network position this refusal is about, and one that
/// can replace the binary instead.
///
/// Anything that is not a scheme this program knows is left alone: the
/// transport refuses it by scheme, and refusing it twice in two vocabularies
/// helps nobody.
pub fn plaintext_off_loopback(url: &str) -> bool {
    // One trailing slash, as the transport strips before it reads the
    // authority, so `http://localhost/` and `http://localhost` are one case.
    let url = url.strip_suffix('/').unwrap_or(url);
    let Some(authority) = url.strip_prefix("http://") else {
        return false;
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8080`: the brackets are what separate an IPv6 literal from
        // its port, so the host ends at the first `]`.
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return true,
        }
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    // A host that is not an IP literal is a name, and a name that is not
    // `localhost` is not loopback whatever it resolves to. `127.0.0.1.example.com`
    // fails to parse and is treated as the remote name it is.
    match host.parse::<core::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => true,
    }
}

/// What an operator is accepting when they pass `--allow-plaintext-node`.
///
/// The refusal names the decisions the link carries rather than the scheme,
/// because "use https" is advice an operator who has only an http node cannot
/// take, and it tells them nothing about what they are weighing.
fn plaintext_node_refusal(url: &str) -> String {
    format!(
        "--node {url} is plaintext http to a host that is not loopback, and everything this \
         wallet decides comes from that link: the balance a spend is laid out against, the \
         ledger address reconciliation compares its own record to, the chain tip a \
         block-to-live is judged against, and the key position that says whether a key has \
         already signed. Anyone on the path can rewrite all of it, and can read every tag you \
         ask about.\n  A rewritten balance does not move funds -- the node checks send + \
         change + fee against the ledger and rejects a transaction built on a lie -- but a \
         rewritten reconciliation report is what `reconcile --advance-to` acts on.\n  ACTION: \
         use an https node, or pass --allow-plaintext-node to accept this. http to \
         127.0.0.0/8, ::1 or localhost needs no flag."
    )
}

pub fn parse(argv: &[String]) -> Result<ParsedArgv, Usage> {
    let mut dir: Option<String> = None;
    let mut node: Option<String> = None;
    let mut allow_plaintext = false;
    let mut it = argv.iter();
    let verb = loop {
        match it.next() {
            None => return Err(Usage("no command".into())),
            Some(a) if asks_for_help(a) => return Ok(ParsedArgv::Help),
            // A repeated global flag is a usage error naming the flag.
            Some(a) if a == "--dir" => {
                if dir.is_some() {
                    return Err(Usage("--dir given twice".into()));
                }
                match it.next() {
                    Some(v) => dir = Some(v.clone()),
                    None => return Err(Usage("--dir needs a value".into())),
                }
            }
            Some(a) if a == "--node" => {
                if node.is_some() {
                    return Err(Usage("--node given twice".into()));
                }
                match it.next() {
                    Some(v) => node = Some(v.clone()),
                    None => return Err(Usage("--node needs a value".into())),
                }
            }
            Some(a) if a == "--allow-plaintext-node" => {
                if allow_plaintext {
                    return Err(Usage("--allow-plaintext-node given twice".into()));
                }
                allow_plaintext = true;
            }
            Some(a) if a.starts_with("--") => {
                return Err(Usage(format!("unknown global flag `{a}`")))
            }
            Some(a) => break a.clone(),
        }
    };
    let rest: Vec<String> = it.cloned().collect();
    if let Some(h) = rest.iter().find(|a| asks_for_help(a)) {
        return Err(Usage(format!(
            "unexpected argument `{h}` after `{verb}`; help is `help` as the command, or -h or \
             --help before it"
        )));
    }

    let command = match verb.as_str() {
        "balance" => {
            reject_unknown_flags(&rest, &[], &[])?;
            Command::Balance
        }
        "create" => {
            reject_unknown_flags(&rest, &[], &["--from-phrase"])?;
            Command::Create {
                from_phrase: bare_flag(&rest, "--from-phrase"),
            }
        }
        "address" => {
            if bare_flag(&rest, "--account") {
                // Exclusive with a tag: anything beside the flag and its
                // value is an unexpected argument.
                reject_unknown_flags(&rest, &["--account"], &[])?;
                let n = u64_flag(&rest, "--account")?
                    .ok_or_else(|| Usage("--account needs a value".into()))?;
                let account = u32::try_from(n)
                    .map_err(|_| Usage(format!("--account: {n} is out of range")))?;
                Command::Address {
                    tag: None,
                    account: Some(account),
                }
            } else {
                Command::Address {
                    tag: optional_tag_arg(&rest, "address")?,
                    account: None,
                }
            }
        }
        "status" => {
            let tag = leading_tag(&rest, "status")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--scan-to"], &[])?;
            Command::Status {
                tag,
                scan_to: index_flag(tail, "--scan-to")?,
            }
        }
        "settle" => Command::Settle {
            tag: tag_arg(&rest, "settle")?,
        },
        "send" => Command::Send(spend_args(&rest, "send")?),
        "resign" => Command::Resign(spend_args(&rest, "resign")?),
        "transaction" => Command::LookupTransaction {
            hash: hash_arg(rest.first(), "transaction")?,
        },
        "recent-transactions" => {
            let tag = leading_tag(&rest, "recent-transactions")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--count", "--from"], &[])?;
            Command::RecentTransactions {
                tag,
                count: count_value(tail)?,
                from: from_flag(tail)?,
            }
        }
        "block" => Command::Block { at: block_at(rest.first())? },
        "blocks" => Command::Blocks {
            count: count_flag(&rest)?,
        },
        "mempool" => Command::Mempool {
            count: count_flag(&rest)?,
        },
        "discover" => Command::Discover {
            to: discover_to_flag(&rest)?,
        },
        "submit" => Command::Submit {
            artifact: artifact_arg(&rest, "submit")?,
        },
        "reconcile" => {
            let tag = leading_tag(&rest, "reconcile")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--advance-to"], &[])?;
            let advance_to = index_flag(tail, "--advance-to")?
                .ok_or_else(|| Usage("reconcile needs --advance-to <N>".into()))?;
            Command::Reconcile { tag, advance_to }
        }
        "restore" => {
            reject_unknown_flags(&rest, &["--account", "--scan-to"], &[])?;
            let n = u64_flag(&rest, "--account")?
                .ok_or_else(|| Usage("restore needs --account <N>".into()))?;
            let account = u32::try_from(n)
                .map_err(|_| Usage(format!("--account: {n} is out of range")))?;
            Command::Restore {
                account,
                scan_to: index_flag(&rest, "--scan-to")?,
            }
        }
        other => return Err(Usage(format!("unknown command `{other}`"))),
    };

    let dir = dir.ok_or_else(|| Usage("--dir is required".into()))?;
    // **Required exactly where it is used**, not unconditionally: a verb
    // that asks no node takes no `--node`. The verb is named because the
    // refusal is about this command and not about the flag -- the same argv
    // with `address` in place of `balance` is accepted.
    if let Some(url) = &node {
        if plaintext_off_loopback(url) && !allow_plaintext {
            return Err(Usage(plaintext_node_refusal(url)));
        }
    }

    let node = match (command.needs_node(), node) {
        (true, None) => {
            return Err(Usage(format!(
                "--node is required for `{verb}`, which asks a node before it runs; only \
                 `create` and `address` work without one"
            )))
        }
        (_, node) => node,
    };
    Ok(ParsedArgv::Run(Invocation { dir, node, command }))
}

#[cfg(test)]
mod tests {
    //! The parser's own cases: what argv is refused, and where help is
    //! recognised. Each case names its outcome; the `cli` target holds the
    //! rendered refusals and the exit codes through the binary.
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn refusal(a: &[&str]) -> String {
        match parse(&argv(a)) {
            Err(u) => u.0,
            Ok(other) => panic!("{a:?} parsed rather than being refused: {other:?}"),
        }
    }

    /// The `Spend` a `send` argv parses to, or a panic naming what came back.
    fn sent(a: &[&str]) -> Spend {
        match parse(&argv(a)) {
            Ok(ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => s,
                other => panic!("{a:?} parsed as {other:?}, not a send"),
            },
            other => panic!("{a:?} did not parse as a run: {other:?}"),
        }
    }

    /// Help is recognised where a verb or a global flag is: `help` as the
    /// verb, `-h`/`--help` before it, alone or after a global flag.
    #[test]
    fn help_is_recognised_before_the_verb_or_as_the_verb() {
        for a in [
            vec!["-h"],
            vec!["--help"],
            vec!["help"],
            vec!["--dir", "/d", "--help"],
            vec!["--dir", "/d", "-h", "balance"],
            vec!["--dir", "/d", "--node", "n", "help"],
        ] {
            assert!(matches!(parse(&argv(&a)), Ok(ParsedArgv::Help)), "{a:?} did not ask for help");
        }
    }

    /// After the verb a help spelling is a stray token, refused by name,
    /// like every other -- in a flag position, a tag position or an amount
    /// position alike.
    #[test]
    fn help_after_the_verb_is_an_unexpected_argument() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        for (a, token) in [
            (vec!["--dir", "/d", "--node", "n", "balance", "--help"], "--help"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, "-h", "5"], "-h"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, tag, "help"], "help"),
            (vec!["--dir", "/d", "address", "-h"], "-h"),
        ] {
            let u = refusal(&a);
            assert!(
                u.contains(&format!("unexpected argument `{token}`")),
                "{a:?}: the refusal does not name the token: {u}"
            );
            assert!(u.contains("help is `help` as the command"), "{a:?}: the refusal does not say where help is: {u}");
        }
    }

    /// Every flag given twice is a usage error naming the flag: the two
    /// global flags, the two spend flags, the two index flags, `restore`'s
    /// account and the one bare flag. Neither the first nor the last wins.
    #[test]
    fn a_repeated_flag_is_a_usage_error_naming_the_flag() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let to = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        for (a, flag) in [
            (vec!["--dir", "/a", "--dir", "/b", "balance"], "--dir"),
            (vec!["--dir", "/d", "--node", "n", "--node", "m", "balance"], "--node"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--fee", "500", "--fee", "600"], "--fee"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--btl", "1", "--btl", "2"], "--btl"),
            (vec!["--dir", "/d", "--node", "n", "resign", tag, to, "1", "--fee", "500", "--fee", "500"], "--fee"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--ref", "AB", "--ref", "CD"], "--ref"),
            (vec!["--dir", "/d", "--node", "n", "resign", tag, to, "1", "--ref", "AB", "--ref", "AB"], "--ref"),
            (vec!["--dir", "/d", "--node", "n", "status", tag, "--scan-to", "1", "--scan-to", "2"], "--scan-to"),
            (vec!["--dir", "/d", "--node", "n", "reconcile", tag, "--advance-to", "1", "--advance-to", "1"], "--advance-to"),
            (vec!["--dir", "/d", "--node", "n", "restore", "--account", "0", "--account", "1"], "--account"),
            (vec!["--dir", "/d", "--node", "n", "restore", "--account", "0", "--scan-to", "3", "--scan-to", "4"], "--scan-to"),
            (vec!["--dir", "/d", "create", "--from-phrase", "--from-phrase"], "--from-phrase"),
        ] {
            let u = refusal(&a);
            assert_eq!(u, format!("{flag} given twice"), "{a:?}: the refusal does not name the repeated flag");
        }
        // `address --account N` parses to the derive-only shape; with a tag
        // beside it, or nothing after it, it is refused.
        assert_eq!(
            parse(&argv(&["--dir", "/d", "address", "--account", "1"])).ok(),
            Some(ParsedArgv::Run(Invocation {
                dir: "/d".into(),
                node: None,
                command: Command::Address { tag: None, account: Some(1) },
            }))
        );
        assert!(refusal(&["--dir", "/d", "address", tag, "--account", "1"]).contains("unexpected argument"));
        assert_eq!(refusal(&["--dir", "/d", "address", "--account"]), "--account needs a value");
        // The control: each flag once still parses.
        assert!(parse(&argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1", "--fee", "600", "--btl", "2"])).is_ok());
    }

    /// `--ref` is validated by the node's rule at parse time: the node's
    /// own accepted examples parse to the NUL-padded field, its refused
    /// ones and a lowercase, spaced or double-dashed value are refusals
    /// naming the flag, the value and the rule's words, a seventeenth
    /// character and a non-ASCII value are refused by their own reasons,
    /// and no flag is sixteen zero bytes.
    #[test]
    fn a_reference_is_validated_at_parse_time() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let to = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let with = |r: &str| argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1", "--ref", r]);
        for (text, field) in [
            ("AB-00-EF", *b"AB-00-EF\0\0\0\0\0\0\0\0"),
            ("123-CDE-789", *b"123-CDE-789\0\0\0\0\0"),
            ("ABC", *b"ABC\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            ("123", *b"123\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            ("AB-12-CD-34-EF-5", *b"AB-12-CD-34-EF-5"),
        ] {
            match parse(&with(text)) {
                Ok(ParsedArgv::Run(inv)) => match inv.command {
                    Command::Send(s) => assert_eq!(s.dsts[0].reference, field, "--ref {text} did not lay out as expected"),
                    other => panic!("--ref {text} parsed to {other:?}"),
                },
                other => panic!("--ref {text} was refused or read as help: {other:?}"),
            }
        }
        for text in ["AB-CD-EF", "123-456-789", "ABC-", "-123", "ab-00-ef", "AB 00", "AB--00"] {
            let u = refusal(&with(text).iter().map(String::as_str).collect::<Vec<_>>());
            assert!(u.starts_with("--ref: ") && u.contains(text), "the refusal of --ref {text} does not name the flag and the value: {u}");
            assert!(u.contains("node's rule") && u.contains(REFERENCE_RULE), "the refusal of --ref {text} does not carry the rule's words: {u}");
        }
        let long = refusal(&with("AB-12-CD-34-EF-56").iter().map(String::as_str).collect::<Vec<_>>());
        assert!(long.contains("17 characters and the field holds 16"), "seventeen characters: {long}");
        let wide = refusal(&with("AB-\u{e9}0").iter().map(String::as_str).collect::<Vec<_>>());
        assert!(wide.contains("is not ASCII"), "a non-ASCII value: {wide}");
        match parse(&argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1"])) {
            Ok(ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => assert_eq!(s.dsts[0].reference, [0u8; ADDR_REF_LEN], "without --ref the field is not zero"),
                other => panic!("parsed to {other:?}"),
            },
            other => panic!("refused or read as help: {other:?}"),
        }
    }

    /// The explorer verbs' `--count`, and the two refusals that exist
    /// because of what the Mesh does with a value it will not take.
    #[test]
    fn the_count_flag_defaults_to_five_and_refuses_what_the_mesh_would_ignore() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        match run(&["blocks"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Blocks { count: DEFAULT_COUNT }),
            other => panic!("blocks did not default: {other:?}"),
        }
        match run(&["recent-transactions", tag]) {
            Ok(ParsedArgv::Run(i)) => match i.command {
                Command::RecentTransactions { count, .. } => assert_eq!(count, DEFAULT_COUNT),
                other => panic!("not a recent-transactions: {other:?}"),
            },
            other => panic!("recent-transactions did not default: {other:?}"),
        }
        match run(&["blocks", "--count", "100"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Blocks { count: MAX_COUNT }),
            other => panic!("the ceiling itself was refused: {other:?}"),
        }
        // Zero and above the ceiling: refused here, because the endpoint
        // would answer a count outside its window with its own default of
        // ten rows and say nothing about having ignored the ask.
        for bad in ["0", "101", "250"] {
            let e = refusal(&[&base[..], &["blocks", "--count", bad]].concat());
            assert!(e.contains(&format!("--count: {bad} is outside 1..=100")), "{e}");
            assert!(e.contains("its own default of ten rows"), "{e}");
        }
        println!("  --count: defaults to {DEFAULT_COUNT}, takes {MAX_COUNT}, refuses 0 and 101 with the endpoint's reason");
    }

    /// `recent-transactions`' `--from`: the default, the ceiling, the
    /// refusal above it, and `--count` beside it in either order.
    #[test]
    fn the_from_flag_defaults_to_the_newest_and_refuses_what_the_mesh_cannot_decode() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        let read = |a: &[&str]| match run(a) {
            Ok(ParsedArgv::Run(i)) => match i.command {
                Command::RecentTransactions { count, from, .. } => (count, from),
                other => panic!("not a recent-transactions: {other:?}"),
            },
            other => panic!("{a:?} was refused or read as help: {other:?}"),
        };
        assert_eq!(read(&["recent-transactions", tag]), (DEFAULT_COUNT, 0));
        assert_eq!(read(&["recent-transactions", tag, "--from", "100"]), (DEFAULT_COUNT, 100));
        assert_eq!(read(&["recent-transactions", tag, "--from", "200", "--count", "100"]), (100, 200));
        assert_eq!(read(&["recent-transactions", tag, "--count", "100", "--from", "200"]), (100, 200));
        let top = MAX_FROM.to_string();
        assert_eq!(read(&["recent-transactions", tag, "--from", &top]), (DEFAULT_COUNT, MAX_FROM));
        assert_eq!(MAX_FROM, 9_223_372_036_854_775_807);
        // Above the Mesh's int64: refused here, because the endpoint would
        // not decode the request at all.
        for bad in ["9223372036854775808", &u64::MAX.to_string()] {
            let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", bad]].concat());
            assert!(e.contains(&format!("--from: {bad} is outside 0..=9223372036854775807")), "{e}");
            assert!(e.contains("invalid request"), "{e}");
        }
        // The count's window still holds beside it, and neither flag twice.
        let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", "1", "--count", "0"]].concat());
        assert!(e.contains("--count: 0 is outside 1..=100"), "{e}");
        let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", "1", "--from", "2"]].concat());
        assert!(e.contains("--from given twice"), "{e}");
        // `blocks` takes no offset.
        let e = refusal(&[&base[..], &["blocks", "--from", "1"]].concat());
        assert!(e.contains("unexpected argument `--from`"), "{e}");
        println!("  --from: defaults to 0, takes {MAX_FROM}, refuses the next with the endpoint's reason");
    }

    /// `discover`'s `--to`: the default, the ceiling, and the two refusals.
    ///
    /// The ceiling is this program's own and the refusal says so, because
    /// unlike `--count` there is no endpoint window behind it: what 1,024
    /// bounds is how many round trips one typed number can turn into.
    #[test]
    fn the_discover_to_flag_defaults_to_sixty_four_and_refuses_outside_its_own_window() {
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        match run(&["discover"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: DISCOVER_DEFAULT_TO }),
            other => panic!("discover did not default: {other:?}"),
        }
        match run(&["discover", "--to", "1024"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: DISCOVER_MAX_TO }),
            other => panic!("the ceiling itself was refused: {other:?}"),
        }
        match run(&["discover", "--to", "1"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: 1 }),
            other => panic!("the floor itself was refused: {other:?}"),
        }
        // Zero, one past the ceiling, and a number a typo produces. Every
        // refusal names the bounds and echoes the value; WHICH reason it
        // gives is the two tests below, one per arm.
        for bad in ["0", "1025", "1000000"] {
            let e = refusal(&[&base[..], &["discover", "--to", bad]].concat());
            assert!(e.contains(&format!("--to: {bad} is outside 1..=1024")), "{e}");
        }
        // And the flag obeys the parser's own rules: given twice, and given
        // without a value.
        assert!(refusal(&[&base[..], &["discover", "--to", "2", "--to", "3"]].concat()).contains("--to given twice"));
        assert!(refusal(&[&base[..], &["discover", "--to"]].concat()).contains("--to needs a value"));
        assert!(refusal(&[&base[..], &["discover", "7"]].concat()).contains("unexpected argument `7`"));
        println!("  --to: defaults to {DISCOVER_DEFAULT_TO}, takes 1 and {DISCOVER_MAX_TO}, refuses 0 and 1025 with this program's own reason");
    }

    /// **`--to 0` is told about zero, and about nothing else.**
    ///
    /// One format string served both ends of the range until a live run
    /// mistyped `--to 2000` and was told "A sweep bounded at 0 searches only
    /// account index 0". The arms are split, and these two tests are what
    /// hold them apart: this one pins zero's reason, and pins that the
    /// ceiling's reason is absent from it.
    #[test]
    fn the_to_refusal_for_zero_is_about_zero_and_not_about_the_ceiling() {
        let base = ["--dir", "/d", "--node", "n"];
        let e = refusal(&[&base[..], &["discover", "--to", "0"]].concat());
        assert!(e.contains("--to: 0 is outside 1..=1024"), "the bounds and the value are not both named: {e}");
        assert!(e.contains("searches only account index 0"), "zero's refusal does not give zero's reason: {e}");
        assert!(e.contains("`address` with no argument"), "zero's refusal does not name the verb that answers it: {e}");
        assert!(
            !e.contains("thousands of round trips"),
            "zero's refusal carries the CEILING's reason, which is the defect the split fixed: {e}"
        );
        println!("  --to 0: refused with zero's own reason, and without the ceiling's");
    }

    /// **`--to` above the ceiling is told about the ceiling, and about
    /// nothing else.**
    ///
    /// The value an operator most plausibly mistypes is a real number one
    /// digit too long, so this walks the ceiling's own successor, a mistyped
    /// `2000` for `200`, and a value past `u32` -- the third going through
    /// the `try_from` failure rather than the range test, which is the same
    /// arm and must give the same reason.
    #[test]
    fn the_to_refusal_above_the_ceiling_is_about_the_ceiling_and_not_about_zero() {
        let base = ["--dir", "/d", "--node", "n"];
        for bad in ["1025", "2000", "4294967296"] {
            let e = refusal(&[&base[..], &["discover", "--to", bad]].concat());
            assert!(e.contains(&format!("--to: {bad} is outside 1..=1024")), "the bounds and the value are not both named: {e}");
            assert!(e.contains("one call to the node"), "the ceiling's refusal does not give the ceiling's reason: {e}");
            assert!(e.contains("Name a bound at or below 1024"), "the ceiling's refusal does not say what to type instead: {e}");
            assert!(
                !e.contains("bounded at 0") && !e.contains("account index 0"),
                "`--to {bad}` is told about account index 0, which is the defect the split fixed: {e}"
            );
        }
        println!("  --to above the ceiling: 1025, 2000 and one past u32 each refused with the ceiling's reason, and without zero's");
    }

    /// **Plaintext `--node` off the loopback interface needs the flag.**
    ///
    /// Three arms, because the rule has three: `https` passes untouched,
    /// `http` to a loopback address passes untouched, and `http` anywhere else
    /// is refused until `--allow-plaintext-node` is given. The refusal has to
    /// name what the link decides, not merely the scheme -- an operator who
    /// reads "use https" and cannot learns nothing about what they are
    /// accepting.
    #[test]
    fn plaintext_node_off_loopback_needs_the_flag() {
        fn with(n: &str) -> Vec<&str> {
            vec!["--dir", "/d", "--node", n, "balance"]
        }
        fn allowed(n: &str) -> Vec<&str> {
            vec!["--dir", "/d", "--node", n, "--allow-plaintext-node", "balance"]
        }

        // https, and http to every spelling of loopback: no flag, no refusal.
        for ok in [
            "https://api.mochimo.org",
            "http://127.0.0.1:8080",
            "http://127.9.9.9",
            "http://[::1]:8080",
            "http://localhost:8080",
            "http://LocalHost",
            "http://localhost/",
        ] {
            assert!(parse(&argv(&with(ok))).is_ok(), "{ok} was refused without the flag");
        }

        // http anywhere else: refused, and the refusal says what is at stake.
        for bad in ["http://api.mochimo.org", "http://10.0.0.5:8080", "http://127.0.0.1.example.com"] {
            let e = refusal(&with(bad));
            assert!(e.contains("--allow-plaintext-node"), "the refusal does not name the flag: {e}");
            assert!(e.contains("reconciliation"), "the refusal does not say what the link decides: {e}");
            assert!(e.contains("balance"), "the refusal does not say a spend is laid out against it: {e}");
            // And the flag is what clears it.
            assert!(parse(&argv(&allowed(bad))).is_ok(), "{bad} stayed refused with the flag given");
        }
        println!("  --node: https and loopback http pass, other http refused until --allow-plaintext-node");
    }

    /// `block 0` is refused, because the endpoint serves index 0 as the tip.
    #[test]
    fn block_zero_is_refused_because_the_mesh_reads_it_as_the_tip() {
        let base = ["--dir", "/d", "--node", "n"];
        let e = refusal(&[&base[..], &["block", "0"]].concat());
        assert!(e.contains("the CURRENT block, not as genesis"), "{e}");
        match parse(&argv(&[&base[..], &["block", "1"]].concat())) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Block { at: BlockAt::Index(1) }),
            other => panic!("block 1 did not parse: {other:?}"),
        }
        // A hash, with and without the prefix, is the other form.
        let h = "18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
        for spelling in [h.to_owned(), format!("0x{h}")] {
            match parse(&argv(&[&base[..], &["block", &spelling]].concat())) {
                Ok(ParsedArgv::Run(i)) => match i.command {
                    Command::Block { at: BlockAt::Hash(got) } => assert_eq!(got[0], 0x18),
                    other => panic!("{spelling} did not parse as a hash: {other:?}"),
                },
                other => panic!("{spelling} did not parse: {other:?}"),
            }
        }
        let e = refusal(&[&base[..], &["block", "deadbeef"]].concat());
        assert!(e.contains("is not a transaction hash"), "{e}");
        println!("  block: 0 refused as the tip's index, a number and a hash in both spellings parse, a short hash is refused");
    }

    /// `transaction <hash>` takes the hash in both spellings and refuses
    /// anything that is not one.
    #[test]
    fn transaction_takes_a_hash_in_either_spelling() {
        let base = ["--dir", "/d", "--node", "n"];
        let h = "18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
        for spelling in [h.to_owned(), format!("0x{h}")] {
            match parse(&argv(&[&base[..], &["transaction", &spelling]].concat())) {
                Ok(ParsedArgv::Run(i)) => match i.command {
                    Command::LookupTransaction { hash } => assert_eq!(hash[0], 0x18),
                    other => panic!("not a transaction: {other:?}"),
                },
                other => panic!("{spelling} did not parse: {other:?}"),
            }
        }
        assert!(refusal(&[&base[..], &["transaction"]].concat()).contains("transaction needs <hash>"));
        assert!(refusal(&[&base[..], &["transaction", "zz"]].concat()).contains("is not a transaction hash"));
        println!("  transaction: a hash bare or prefixed, and two refusals");
    }

    /// **Positional `<to> <amount>` pairs**, and what the parser makes of
    /// them: the order is kept as typed, `--fee` defaults to the floor for
    /// the count rather than for one, and an odd token count is refused as
    /// the missing amount it is rather than as an unexpected argument.
    #[test]
    fn several_destinations_parse_as_pairs() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let b = "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
        let c = "0x8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d";
        let s = sent(&["--dir", "/d", "--node", "n", "send", src, a, "1", b, "2", c, "3"]);
        assert_eq!(s.dsts.len(), 3, "three pairs did not give three destinations");
        assert_eq!(
            s.dsts.iter().map(|d| d.amount).collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)],
            "the amounts did not stay with their destinations, in order"
        );
        assert_eq!(s.dsts[0].to[0], 0x6b);
        assert_eq!(s.dsts[1].to[0], 0x7c);
        assert_eq!(s.dsts[2].to[0], 0x8d);
        assert_eq!(s.fee_total, MFEE * 3, "--fee did not default to the floor for three");
        assert!(s.dsts.iter().all(|d| d.reference == [0u8; ADDR_REF_LEN]));

        // One destination is the unchanged case: the default is still 500.
        let one = sent(&["--dir", "/d", "--node", "n", "send", src, a, "1"]);
        assert_eq!(one.fee_total, MFEE);
        assert_eq!(one.dsts.len(), 1);

        let odd = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", b]);
        assert!(odd.contains("the last destination has no amount"), "{odd}");
        println!(
            "  pairs: three parse in order with fee floor {}, one still defaults to {MFEE}, an odd \
             token count is refused as the missing amount",
            MFEE * 3
        );
    }

    /// The whole-list rules: the count bound, and the duplicate refusal that
    /// is this parser's and not the node's.
    #[test]
    fn the_destination_list_is_bounded_and_refuses_a_repeated_tag() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let dup = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", a, "2"]);
        assert!(dup.contains("destinations 1 and 2 are the same tag"), "{dup}");
        assert!(dup.contains("mistyped payee"), "{dup}");

        // 257 distinct destinations, built from the index so no two repeat.
        let mut argvv: Vec<String> =
            ["--dir", "/d", "--node", "n", "send", src].iter().map(|s| (*s).to_string()).collect();
        for i in 0..257u32 {
            argvv.push(format!("0x{:040x}", i + 1));
            argvv.push("1".to_string());
        }
        let refs: Vec<&str> = argvv.iter().map(String::as_str).collect();
        let over = refusal(&refs);
        assert!(over.contains("1 to 256 destinations and 257 were given"), "{over}");
        println!("  list: a repeated tag and a 257th destination are both usage errors");
    }

    /// `--ref` names ONE destination's reference, so it is refused with
    /// several; `all` means the whole balance, so it is refused with several.
    #[test]
    fn ref_and_all_are_single_destination_only() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let b = "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
        let r = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", b, "2", "--ref", "ABC"]);
        assert!(r.contains("--ref names one destination's reference and 2 were given"), "{r}");
        let all = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "all", b, "2"]);
        assert!(all.contains("only available for a single destination"), "{all}");

        let one = sent(&["--dir", "/d", "--node", "n", "send", src, a, "all"]);
        assert_eq!(one.dsts.len(), 1);
        assert_eq!(one.dsts[0].amount, None, "`all` did not park the amount as unknown");
        assert!(one.spends_everything());
        println!("  all/--ref: both refused with several destinations; `all` alone parses as an unknown amount");
    }

    /// The `--destinations` file, through the pure text parser so no file has
    /// to exist: three columns, the third optional, comments and blank lines
    /// skipped, and every refusal naming its line.
    #[test]
    fn a_destinations_file_parses_three_columns_and_names_its_lines() {
        let text = "\
# payroll, October
0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b  1000  AB-00-EF

0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c  2000   # no reference on this one
0x8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d  3000  INVOICE-99
";
        let d = destinations_from_text(text, "p").unwrap_or_else(|e| panic!("the file parses: {}", e.0));
        assert_eq!(d.len(), 3, "comments and blank lines were not skipped");
        assert_eq!(d[0].reference, *b"AB-00-EF\0\0\0\0\0\0\0\0", "the third column is the reference");
        assert_eq!(d[1].reference, [0u8; ADDR_REF_LEN], "a line without a third column is not zero");
        assert_eq!(d[2].reference, *b"INVOICE-99\0\0\0\0\0\0");
        assert_eq!(d.iter().map(|x| x.amount).collect::<Vec<_>>(), vec![Some(1000), Some(2000), Some(3000)]);

        for (bad, needle) in [
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b\n", "has no amount"),
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b 1 AB-CD-EF\n", "does not follow the node's rule"),
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b 1 ABC junk\n", "unexpected `junk`"),
            ("# only a comment\n", "no destinations"),
        ] {
            let e = destinations_from_text(bad, "p").expect_err(needle);
            assert!(e.0.contains(needle), "wanted {needle:?} in {:?}", e.0);
        }
        println!("  file: three columns with the reference optional, comments and blanks skipped, four refusals by line");
    }
}
