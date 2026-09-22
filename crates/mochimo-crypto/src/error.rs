use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// How a Mesh transport failed, without the message.
///
/// The transport's own error carries hostnames, certificate subjects and
/// system text; none of it is `Clone + PartialEq` and none of it belongs in a
/// value the wallet compares against. What survives is the class, which is
/// what a caller branches on: retry a timeout, report a refused connection,
/// stop on a TLS failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// The host name did not resolve.
    Resolve,
    /// The TCP connection was refused or reset before a response.
    Connect,
    /// A connect or global timeout elapsed.
    Timeout,
    /// TLS could not be established, or `https://` was asked of a transport
    /// built without a TLS provider (`mesh-https` off).
    Tls,
    /// The bytes on the wire were not HTTP the client understood, or the URL
    /// did not parse.
    Protocol,
    /// The server answered with a redirect. Never followed: a redirect would
    /// re-POST a signed image to a host the caller did not name.
    Redirect,
    /// An I/O error of the given kind, mid-request.
    Io(std::io::ErrorKind),
    /// A class the mapping does not name. The transport's error enum is
    /// non-exhaustive upstream, so this arm exists rather than a panic.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A reference function returned a failure code. `errno` is captured where
    /// the reference sets one, because the fixtures record it.
    Reference {
        function: &'static str,
        rc: core::ffi::c_int,
    },
    /// A reference function returned a failure code and set `errno`.
    ReferenceErrno {
        function: &'static str,
        rc: core::ffi::c_int,
        errno: i32,
    },
    /// A slice was not the length the reference requires.
    Length {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// A value fell outside the range the protocol can encode it in.
    ///
    /// Distinct from [`Error::Length`], which is about a buffer being the wrong
    /// size. This is about a number the reference would read back as a
    /// different number — a destination count of 257 does not overflow a
    /// buffer, it silently becomes 1.
    Range {
        what: &'static str,
        min: u64,
        max: u64,
        got: u64,
    },
    /// A Base58 string contained an interior NUL and cannot be handed to a C
    /// `const char *`.
    InteriorNul,
    /// A Base58 string was not ASCII. The reference indexes its alphabet table
    /// with a `char`, so non-ASCII input is out of contract.
    NotAscii,
    /// A keystore I/O step failed. Carries the step's name and the kind, never
    /// the `std::io::Error` (not `Clone`/`PartialEq`) and never file bytes.
    Io {
        op: &'static str,
        kind: std::io::ErrorKind,
    },
    /// The snapshot did not parse. `offset` is where the parser stopped;
    /// offsets, never bytes -- a root byte in an error message is an I6 breach.
    Corrupt {
        what: &'static str,
        offset: usize,
    },
    /// A snapshot written by a format this build does not read. Distinct from
    /// `Corrupt` so a future encrypted file says "upgrade", not "damaged".
    ///
    /// `first_account` is the first record's tag and kind, read from a
    /// version-1 or version-2 image whose length fits that version's closed
    /// formula -- both layouts this crate ever wrote keep them in the clear at
    /// bytes 22..42 and 42 -- so the refusal can say how to tell whether the
    /// refused store holds an account the store in hand holds (the reads are
    /// `format::older_first_account`). `None` for every
    /// other version, for the KDF-id arm (which reuses this variant with
    /// `got` = the id), and for an image whose length fits no older layout:
    /// a version-3 file under a forged version word has its salt at those
    /// bytes, and naming salt as a tag would send an operator to compare
    /// noise. The field is public, so adding it changed this variant's shape.
    UnsupportedVersion {
        got: u16,
        supported: u16,
        first_account: Option<(crate::addr::Tag, crate::account::AccountKind)>,
    },
    /// Another live process holds the keystore lock.
    Locked,
    /// The keystore directory has no snapshot. Not an empty store: treating an
    /// absent file as zero accounts is I5's index-zero assumption reached
    /// through the filesystem.
    Missing,
    /// `create` on a directory that already holds a keystore, or `add` of a tag
    /// already present.
    Exists {
        what: &'static str,
    },
    /// `cli::create::create` was handed a password below the floor
    /// (`cli::create::MIN_PASSWORD_LEN`), counted in characters. The
    /// terminal path refuses earlier and in prose; this is what the
    /// library entry point returns, so no route to a store under an
    /// operator's password is exempt from the floor. `chars` is the count the
    /// password had, `min` the floor -- Unicode scalar values, not bytes.
    PasswordTooShort {
        chars: usize,
        min: usize,
    },
    /// No account under that tag.
    NoSuchAccount,
    /// The keystore directory is group- or other-writable.
    UnsafePermissions {
        mode: u32,
    },
    /// The keystore directory's access list lets someone other than this
    /// user, `SYSTEM` or the Administrators group write to it: the Windows
    /// arm of [`Error::UnsafePermissions`].
    ///
    /// **A separate variant, not that one reporting a mode it did not
    /// measure.** `UnsafePermissions` carries `mode: u32` and renders it as
    /// octal; a Windows directory has no mode, and a number synthesised to
    /// fill the field would be a refusal whose evidence is invented. Adding a
    /// Windows-only variant leaves the Unix variant's shape, and every match
    /// on it, exactly as it is.
    ///
    /// `trustee` is the security identifier the write is granted to, in its
    /// `S-1-...` form -- `S-1-1-0`, Everyone, when the directory has no access
    /// list at all, since that is what a null list grants. `rights` is the
    /// access mask of the entry that grants it, or `WRITE_DAC | READ_CONTROL`
    /// for a directory owned by someone else, which is what an owner holds
    /// whatever the list says. Which trustees are accepted and which rights
    /// count as write is argued at `keystore::perms`'s Windows arm.
    #[cfg(windows)]
    UnsafeAcl {
        trustee: String,
        rights: u32,
    },
    /// Windows refused to move the new snapshot over the old one, with the
    /// system error `code` -- `ERROR_ACCESS_DENIED` or
    /// `ERROR_SHARING_VIOLATION`, the two a held file produces.
    ///
    /// **Named because it is the one commit failure an operator can do
    /// something about.** A replacing move fails on Windows while another
    /// process holds the snapshot or its replacement open without delete
    /// sharing, and the processes that do that are ordinary residents of a
    /// desktop: an antivirus scanner, a search indexer, a backup or sync
    /// agent. Reported as `Io { op: "rename", .. }` it reads as a damaged
    /// disk. The refused move changes nothing -- the previous snapshot is
    /// intact and nothing was committed -- so this is availability and not
    /// correctness, and the handle is poisoned as after any commit failure.
    ///
    /// The two codes are not proof of a holder: `ERROR_ACCESS_DENIED` is
    /// also what a genuine access refusal returns, which is why the message
    /// says *usual cause* and not *cause*. Every other code stays `Io`.
    /// Windows-only, because on the platforms `rename(2)` serves, an open
    /// descriptor never blocks a rename.
    #[cfg(windows)]
    ReplaceRefused {
        code: i32,
    },
    /// A key is reserved for an unsettled spend; no further advance until
    /// `persist_settled`.
    PendingUnresolved {
        spent_index: u32,
    },
    /// `persist_settled` with nothing pending.
    NothingPending,
    /// A commit failed part-way. Memory and disk may disagree, so every later
    /// call is refused: drop the handle and reopen from disk. Never retry the
    /// write -- after an fsync error the kernel may already have discarded the
    /// dirty pages, and a retry can report success for data that never
    /// reached disk.
    Poisoned {
        first: Box<Error>,
    },
    /// The store did not decrypt: the password is wrong, or the file has been
    /// damaged or tampered with.
    ///
    /// **One variant for all three on purpose.** Telling a wrong password from
    /// a damaged file would be a decryption oracle -- an attacker who can tell
    /// which of his guesses failed *differently* learns something about the
    /// password. The AEAD gives one answer and this carries it. It holds
    /// nothing: no offset, no byte, no hint about which half of the file
    /// disagreed.
    WrongPassword,
    /// A BIP39 phrase or entropy was refused. `what` names the rule, never a
    /// word or a byte: a phrase is the master seed spelled out.
    Mnemonic {
        what: &'static str,
    },
    /// A shipped-wallet `wotsIndex` with no position in this crate. The
    /// correspondence is `ours = shipped + 1`: `-1` is the first
    /// key at position 0, and anything below `-1` or above `u32::MAX - 1`
    /// names nothing.
    ShippedIndex {
        got: i64,
    },
    /// `sign_spend`: the receipt attests an index the store has moved past
    /// (or, unreachably, one it has not reached). A receipt names the live
    /// state it was minted for and nothing else; a hoarded one is refused.
    StaleReceipt {
        attested: u32,
        stored: u32,
    },
    /// `sign_spend`: the account has no key reserved. A receipt from
    /// `persist_advance_to` -- the reconciliation path, which moves the index
    /// without reserving a key -- or one whose reservation was settled.
    NoReservation,
    /// `sign_spend`: the digest is not the one the key was reserved for. The
    /// durable pending record must name what was signed (I3), so a
    /// transaction rebuilt between reserve and sign is refused rather than
    /// signed under a record that lies about it.
    DigestMismatch,
    /// `sign_spend`: the key access does not match the account's kind -- a
    /// derived account needs the master seed, an imported account needs
    /// nothing but its stored root, and supplying the wrong shape is refused
    /// rather than guessed at.
    KeyAccessMismatch {
        kind: crate::account::AccountKind,
    },
    /// `sign_spend`: the supplied master seed does not derive this account's
    /// tag at its recorded position. Fires alike for a wrong master, a wrong
    /// `account_index` and a wrong tag; the name says what was tested.
    DerivedTagNotReproduced {
        account_index: u32,
    },
    /// `sign_spend` (derived path): this account's seed is also held as an
    /// imported root in the same store, so the two slots share one key
    /// stream and their independent indices would let one key sign twice.
    /// Refused; see `duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`,
    /// which is green -- this arm is one of the halves that cleared it.
    KeyStreamSharedWithImportedAccount,
    /// `Account::import`: `wots::pkgen(root, pub_seed, adrs)` over the first
    /// address's own tail does not reproduce that address's public key, so
    /// the root and the 2208 bytes are not a pair. Also
    /// `Account::restore_from_record`: the stored components and root do not
    /// produce the stored tag. Never carries a byte of either (I6).
    FirstAddressNotReproduced,
    /// The key-stream identity a record carries is not the one its key
    /// material produces -- `Account::restore_from_record` recomputing an
    /// imported account's from its root, or `sign_spend` recomputing a
    /// derived account's from the master. The identity is what refuses two
    /// accounts over one stream, so a wrong one is refused
    /// rather than acted on.
    StreamIdNotReproduced,
    /// A wallet operation needed a reconciled account and reconciliation
    /// refused. `what` is the divergence's kind in one phrase; the full
    /// report is `recon::Divergence`'s `Display`, which is what an operator
    /// reads.
    ReconciliationRefused {
        what: &'static str,
    },
    /// An `OperatorAcknowledgement` does not name the tag and index the store
    /// is diverged by now. Advancing on a stale or foreign acknowledgement is
    /// advancing on a divergence nobody read.
    AcknowledgementDoesNotMatch,
    /// `advance_after_operator_review` on an account that reconciles cleanly.
    NothingToReconcile,
    /// A caller's [`crate::recon::Cancel`] asked a key-position walk to stop,
    /// and it stopped.
    ///
    /// **Not a failure of anything**, which is why it is its own variant
    /// rather than an `Io` or a `Range`: the walk was working, and the
    /// operator or the interface driving it asked for it to end. It is an
    /// `Error` because the alternative is to report it as `Ok(None)` -- the
    /// same value a walk that reached its ceiling and found nothing returns
    /// -- and those two say opposite things. One means *this seed does not
    /// hold that address anywhere the scan reached*, which is a finding; this
    /// one means *nothing was learned*.
    ///
    /// **It carries no position.** A cancelled walk stopped somewhere, and
    /// the number is deliberately not here: the only caller that can cancel
    /// is the one driving the predicate, which is already counting, and a
    /// figure this type reported would be a second count to keep in step with
    /// the first.
    Cancelled,
    /// The Mesh transport failed before a response body arrived. `op` names
    /// the step (`"connect"`, `"send"`, `"read body"`), `kind` the class;
    /// never the transport's message, which can carry a host or a
    /// certificate subject.
    Transport {
        op: &'static str,
        kind: TransportKind,
    },
    /// The Mesh answered with an HTTP status other than 200. The middleware's
    /// own failures are 200s carrying an error object (`giveError`); a
    /// non-200 is a proxy, a
    /// route miss or the middleware's request-size gate.
    HttpStatus {
        status: u16,
    },
    /// The Mesh returned its error object: `{code, message, retriable}`.
    /// `code` is the middleware's table (1 invalid
    /// request, 4 account not found, 5 wrong network, 8 invalid account
    /// format, ...); the message is dropped, because a server-authored
    /// string is not something to render or compare.
    Mesh {
        code: u64,
        retriable: bool,
    },
    /// A Mesh response body did not have the shape the endpoint documents.
    /// `what` names the field or the expectation (`"result.address"`,
    /// `"balances[0].value: decimal"`), never the bytes: a response is
    /// untrusted input and a byte of it in an error message is a byte of it
    /// in a log.
    MeshResponse {
        what: &'static str,
    },
    /// A request body over the middleware's cap, or a response body over this
    /// crate's, refused before it is sent or buffered.
    PayloadTooLarge {
        what: &'static str,
        max: usize,
        got: usize,
    },
    /// A hex field did not decode. `offset` is the first byte the decoder
    /// refused, in the string; offsets, never characters.
    Hex {
        what: &'static str,
        offset: usize,
    },
    /// The chain's current address for the tag is not the address of the key
    /// this keystore would sign with next. Refused BEFORE anything is
    /// reserved, and deliberately not reconciled: a spend that was broadcast
    /// and never settled, a restored seed with incomplete history, and a
    /// second wallet live on this seed all present this way, and only one
    /// of them is safe to advance past (I4). The reconciliation
    /// session decides; this crate stops.
    ChainAddressMismatch {
        position: u32,
    },
    /// `resign` was asked to reproduce a reservation the chain has already
    /// moved past: the ledger holds the tag at the key one position on, which
    /// is that reservation's own change key. Nothing is left to reproduce and
    /// nothing was signed.
    ///
    /// **Deliberately not [`Error::ChainAddressMismatch`]**, although one
    /// comparison produces both. That one is the spend-time guard, and its
    /// three causes are I4's: a broadcast spend that never settled, a
    /// restored seed, a second wallet. None of them is this. A live run
    /// against mainnet reached this state by the commonest mistaken route to
    /// the verb -- `resign` after a `send` that worked -- and read the
    /// three-cause page, while `settle` resolved the identical state one
    /// command later in a line.
    ///
    /// What the state is gets asked of `recon::reconcile_account`, so the
    /// crate holds one definition of a landed spend rather than two. What it
    /// is NOT is a certainty: a change address follows the position and not
    /// the transaction, so the chain standing here says the balance at the
    /// reserved key has moved on and not which transaction moved it. The
    /// page says so.
    ReservationLanded {
        /// The reserved position -- the key that signed.
        spent_index: u32,
        /// The change key's position, which is where the chain stands.
        settled_index: u32,
    },
    /// `send + fee` exceeds the balance the chain reports.
    InsufficientBalance {
        balance: u64,
        needed: u64,
    },
    /// `fee_total` is under the protocol floor of one `MFEE` per destination
    /// (`mdst_val`).
    FeeBelowMinimum {
        fee: u64,
        min: u64,
    },
    /// A destination amount of zero (`mdst_val`).
    ZeroAmount {
        index: usize,
    },
    /// A destination whose tag is the source's (`mdst_val`).
    DestinationIsSource {
        index: usize,
    },
    /// A destination reference the node's rule refuses (`mdst_val`,
    /// `EMCM_XTXREF`); the rule is
    /// `mesh::spend::reference_is_valid`, transcribed from the reference.
    InvalidReference {
        index: usize,
    },
    /// A 64-bit total overflowed while being tallied.
    Overflow {
        what: &'static str,
    },
    /// The signature the keystore released is for a different position than
    /// the plan was built for.
    PositionMismatch {
        planned: u32,
        signed: u32,
    },
    /// The signature does not recover to the key it claims, or that key does
    /// not own the source address. `what` names which comparison failed:
    /// `"public key"`, `"address scheme"` or `"source address hash"`.
    SignatureDoesNotRecover {
        what: &'static str,
    },
    /// The Mesh acknowledged a submission with a transaction id that is not
    /// the id of the bytes sent. The server parsed something else.
    SubmitIdMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reference { function, rc } => {
                write!(f, "reference {function}() returned {rc}")
            }
            Error::ReferenceErrno { function, rc, errno } => {
                write!(f, "reference {function}() returned {rc}, errno {errno}")
            }
            Error::Length {
                what,
                expected,
                got,
            } => write!(f, "{what}: expected {expected} bytes, got {got}"),
            Error::Range {
                what,
                min,
                max,
                got,
            } => write!(f, "{what}: {got} is outside {min}..={max}"),
            Error::InteriorNul => f.write_str("base58 input contains an interior NUL"),
            Error::NotAscii => f.write_str("base58 input is not ASCII"),
            Error::Io { op, kind } => write!(f, "keystore {op}: {kind:?}"),
            Error::Corrupt { what, offset } => {
                write!(f, "keystore snapshot corrupt: {what} at byte offset {offset}")
            }
            Error::UnsupportedVersion { got, supported, first_account } => {
                // Two producers share this variant (`read_header`'s version
                // arm, `supported == format::VERSION`; its KDF-id arm,
                // `supported == 1`), so the version-specific sentences are
                // rendered for the version producer alone and the KDF-id
                // refusal keeps the text it had before the version-3 read arm
                // existed, byte for byte.
                let version_arm = *supported == crate::keystore::format::VERSION;
                if version_arm && got > supported {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads versions {} \
                         and {supported} and writes version {supported}. A version this build does \
                         not read is not damage: a NEWER build of this wallet wrote this store. Open \
                         it with a build at least that new, and do not rewrite it or re-add its \
                         accounts elsewhere -- a reservation open in it can be re-signed only from \
                         it.",
                        crate::keystore::format::V3_VERSION
                    )?;
                } else if version_arm {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads version \
                         {supported} (and reads a version-3 store, re-sealing it as version \
                         {supported} on its first write). A version this \
                         build does not read is not damage: an older store is migrated by \
                         re-adding its accounts into a FRESH directory (from the master seed, and \
                         from each imported account's root and first address), never by rewriting \
                         it in place."
                    )?;
                } else {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads version \
                         {supported}. A version this build does not read is not damage: an older \
                         store is migrated by re-adding its accounts into a FRESH directory (from \
                         the master seed, and from each imported account's root and first address), \
                         never by rewriting it in place."
                    )?;
                }
                // How to tell whether the refused store is the wallet in hand.
                // Hex and not the destination form, by the
                // CLI's rule: a payable-looking string belongs only where it
                // answers "where do I send"; this names a thing to compare.
                match first_account {
                    Some((tag, kind)) => {
                        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
                        let kind_word = match kind {
                            crate::account::AccountKind::Derived => "derived",
                            crate::account::AccountKind::Imported => "imported",
                        };
                        write!(
                            f,
                            " This file's first account (its records sort by tag) is {kind_word} and \
                             has the tag 0x{hex}, which a version-{got} file stores unencrypted at \
                             bytes 22..42. To learn whether the refused store is on the SEED of the \
                             store in hand, run `address 0x{hex}` against the store in hand: an \
                             answer means the store in hand derives that same account -- one account \
                             seed, one WOTS+ key stream -- so a spend from each store is one key \
                             signing twice; destroy one before either spends. `no \
                             account for the tag` means that account is not held here, which does \
                             not prove a different seed. {}",
                            match kind {
                                crate::account::AccountKind::Derived =>
                                    "The refused store derived it from a master seed at an account \
                                     index, so a match is one master seed.",
                                crate::account::AccountKind::Imported =>
                                    "The refused store holds it as an imported root; the master \
                                     behind that root, if any, is not recorded there.",
                            }
                        )
                    }
                    None => f.write_str(
                        " No account tag was read from this file: one is named only for a \
                         version-1 or version-2 file whose length fits that version's layout, \
                         where the first account's tag stands unencrypted at bytes 22..42.",
                    ),
                }
            }
            Error::Locked => f.write_str(
                "another wallet process holds keystore.lock; the lock releases when that \
                 process exits -- do not delete the file",
            ),
            Error::Missing => f.write_str(
                "keystore directory has no snapshot; an absent file is not an empty store \
                 (use create only for a genuinely new keystore)",
            ),
            // The snapshot's refusal names the next step: a fresh store
            // wants a different directory, and an account joins this one
            // through `restore`.
            Error::Exists { what: "snapshot" } => f.write_str(
                "keystore: a snapshot already exists in this directory. To make a new store, use \
                 a different --dir; to add an account to this one, run `restore --account N` \
                 against it (`address` lists what it holds). Nothing was changed",
            ),
            Error::Exists { what } => write!(f, "keystore: {what} already exists"),
            Error::PasswordTooShort { chars, min } => write!(
                f,
                "password is {chars} character(s); this wallet will not seal a store under fewer \
                 than {min} (cli::create::MIN_PASSWORD_LEN -- a floor under the search space, \
                 counted in characters and not bytes). Nothing was \
                 created"
            ),
            Error::NoSuchAccount => f.write_str("keystore: no account under that tag"),
            Error::UnsafePermissions { mode } => write!(
                f,
                "keystore directory mode {mode:o} is group- or other-writable; refusing to \
                 hold key material there"
            ),
            #[cfg(windows)]
            Error::UnsafeAcl { trustee, rights } => write!(
                f,
                "keystore directory lets {trustee} write to it (access mask {rights:#010x}), and \
                 {trustee} is neither this user, SYSTEM nor the Administrators group; refusing to \
                 hold key material there"
            ),
            #[cfg(windows)]
            Error::ReplaceRefused { code } => write!(
                f,
                "keystore rename: Windows refused to replace accounts.mks (system error {code}). \
                 The usual cause is another program holding the snapshot or its replacement open \
                 without delete sharing -- an antivirus scanner, a search indexer, a backup or \
                 sync agent. The previous snapshot is intact and nothing was committed; run the \
                 command again, and if the refusal persists, exclude the keystore directory from \
                 that program"
            ),
            Error::PendingUnresolved { spent_index } => write!(
                f,
                "key {spent_index} is reserved for an unsettled spend; settle it before \
                 advancing again"
            ),
            Error::NothingPending => f.write_str("keystore: nothing is pending for that tag"),
            Error::Poisoned { first } => write!(
                f,
                "keystore poisoned by an earlier failure ({first}); memory and disk may \
                 disagree -- drop this handle and reopen from disk, and do not retry the \
                 write: after an fsync error the kernel may have discarded the dirty pages, \
                 and a retry can report success for data that never reached disk"
            ),
            Error::WrongPassword => write!(
                f,
                "the keystore did not decrypt. Either the password is wrong, or the file has \
                 been damaged or altered -- this cannot tell you which, by design: an error that \
                 distinguished them would tell an attacker which of his guesses was closer. What \
                 to try, in order: the password again, minding the keyboard layout and caps \
                 lock; a backup copy of the store, if one exists; and then `create --from-phrase` \
                 into a fresh directory and `restore --account N` for each account, from the \
                 recovery phrase -- a damaged file cannot be repaired here, and nothing in it \
                 can be read without the key"
            ),
            Error::Mnemonic { what } => write!(f, "bip39: {what}"),
            Error::ShippedIndex { got } => write!(
                f,
                "shipped wotsIndex {got} has no position in this crate: -1 is the first \
                 key (position 0) and n >= 0 is position n + 1, up to u32::MAX"
            ),
            Error::StaleReceipt { attested, stored } => write!(
                f,
                "the receipt attests index {attested} but the store holds {stored}; a receipt \
                 names the state it was minted for, and this one is stale"
            ),
            Error::NoReservation => f.write_str(
                "no key is reserved for that account: the receipt came from a reconciliation \
                 advance or its reservation was settled, and neither names a key to sign with",
            ),
            Error::DigestMismatch => f.write_str(
                "the digest is not the one this key was reserved for; the pending record \
                 must name what was signed, so a rebuilt transaction needs a fresh reservation",
            ),
            Error::KeyAccessMismatch { kind } => write!(
                f,
                "key access does not match the account: a {kind:?} account needs {}",
                match kind {
                    crate::account::AccountKind::Derived => "KeyAccess::Master, the master seed it derives from",
                    crate::account::AccountKind::Imported => "KeyAccess::StoredRoot, nothing beyond its stored root",
                }
            ),
            Error::DerivedTagNotReproduced { account_index } => write!(
                f,
                "the master seed supplied does not derive this account's tag at position \
                 {account_index}; wrong seed, wrong position or wrong tag, and none of them signs"
            ),
            Error::KeyStreamSharedWithImportedAccount => f.write_str(
                "this derived account's seed is also held as an imported root in this store; \
                 two accounts over one key stream would let one key sign twice, so neither signs \
                 (duplicate_key_streams_are_refused_within_one_keystore_not_across_stores)",
            ),
            Error::FirstAddressNotReproduced => f.write_str(
                "the root does not reproduce this first address: wots_pkgen over the address's \
                 own public seed and hash address gives a different public key, so the pair did \
                 not come from one account and position 0 would sign under an address nobody \
                 funded",
            ),
            Error::StreamIdNotReproduced => f.write_str(
                "the stored key-stream identity is not the one this account's key material \
                 produces; the identity is what stops two accounts sitting over one key stream, \
                 so a record that disagrees with itself is refused",
            ),
            Error::ReconciliationRefused { what } => write!(
                f,
                "this account is not reconciled with the chain ({what}), so no spend operation \
                 on it is permitted. Read the divergence report and act on it; I4 fails closed \
                 because the three causes of divergence have three different correct recoveries"
            ),
            Error::AcknowledgementDoesNotMatch => f.write_str(
                "this acknowledgement does not name the divergence this store is in now. An \
                 acknowledgement carries the tag and the index the report printed, and it is \
                 checked against the live state, so a stale report or another account's cannot \
                 be used to advance this one",
            ),
            Error::NothingToReconcile => f.write_str(
                "this account reconciles cleanly against the chain; there is no divergence to \
                 advance past",
            ),
            Error::Cancelled => f.write_str(
                "the key-position walk was stopped before it reached a conclusion; nothing was \
                 decided and no index is assumed",
            ),
            Error::Transport { op, kind } => write!(f, "mesh transport {op}: {kind:?}"),
            Error::HttpStatus { status } => write!(
                f,
                "mesh answered HTTP {status}; the middleware's own failures are 200s with an \
                 error object, so this is a proxy, a route miss or its request-size gate"
            ),
            Error::Mesh { code, retriable } => write!(
                f,
                "mesh error code {code}{}",
                if *retriable { " (retriable)" } else { "" }
            ),
            Error::MeshResponse { what } => write!(f, "mesh response is not the documented shape: {what}"),
            Error::PayloadTooLarge { what, max, got } => {
                write!(f, "{what}: {got} bytes exceeds the cap of {max}")
            }
            Error::Hex { what, offset } => write!(f, "{what}: not hex at byte offset {offset}"),
            Error::ChainAddressMismatch { position } => write!(
                f,
                "the chain's current address for this tag is not the address of the key at \
                 position {position}, which is the key this keystore would sign with next. \
                 Nothing was reserved. This is I4's divergence and it has three causes with \
                 three different remedies -- a broadcast spend that never settled, a restored \
                 seed with incomplete history, or a second wallet live on this seed -- so do \
                 not advance the index by hand; reconcile"
            ),
            Error::ReservationLanded {
                spent_index,
                settled_index,
            } => write!(
                f,
                "the chain holds this tag at the key at position {settled_index}, which is the \
                 change key of the reservation at position {spent_index}: the reserved spend has \
                 landed and there is nothing left to reproduce. Nothing was signed. `settle` is \
                 the verb that resolves this state"
            ),
            Error::InsufficientBalance { balance, needed } => write!(
                f,
                "the chain reports a balance of {balance} nanoMCM and the spend needs {needed} \
                 (send plus fee)"
            ),
            Error::FeeBelowMinimum { fee, min } => write!(
                f,
                "fee {fee} is under the protocol floor of {min} (one MFEE per destination, \
                 mdst_val)"
            ),
            Error::ZeroAmount { index } => {
                write!(f, "destination {index} has a zero amount, which mdst_val rejects")
            }
            Error::DestinationIsSource { index } => write!(
                f,
                "destination {index} carries the source's own tag, which mdst_val rejects"
            ),
            Error::InvalidReference { index } => write!(
                f,
                "destination {index} carries a reference the node's rule refuses (mdst_val, \
                 EMCM_XTXREF): uppercase letters and digits in groups, each group all one kind, \
                 neighbouring groups of different kinds, single dashes between groups and none \
                 at either end, NUL-terminated with nothing after the first NUL"
            ),
            Error::Overflow { what } => write!(f, "{what} overflows 64 bits"),
            Error::PositionMismatch { planned, signed } => write!(
                f,
                "the plan was built for the key at position {planned} but the signature came \
                 from position {signed}"
            ),
            Error::SignatureDoesNotRecover { what } => write!(
                f,
                "the signature does not validate against the transaction it is attached to: \
                 {what} does not match. Nothing was broadcast"
            ),
            Error::SubmitIdMismatch => f.write_str(
                "the mesh acknowledged a transaction id that is not the id of the bytes sent; \
                 the server parsed something else, and its acknowledgement says nothing about \
                 this transaction",
            ),
        }
    }
}

impl std::error::Error for Error {}

// --- what a reference validator said ------------------------------------

/// A reference validator's outcome: the code it returned and the `errno` it
/// left behind.
///
/// # Why both, and why not a `Result`
///
/// `mdst_val` and `tx_val__wots` report through two channels at once, and the
/// fixtures record both. The generator's `verdict()` writes `_rc` and
/// `_rc_name` unconditionally, and then — only
/// when the code is not `VEOK` — either `_errno`/`_errno_name`/`_errno_text`
/// **or** `_errno_set: false`. That last case is real: `mdst_val__reference`
/// fails without touching `errno`, and its caller supplies `EMCM_XTXREF`
/// afterwards.
///
/// A `Result<(), Error>` would drop the code on success, and the fixtures pin
/// the success code too. Collapsing "failed with `errno` 0" into "failed" would
/// erase exactly the distinction `_errno_set` exists to record. So the pair
/// travels intact and the caller decides what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The `int` the reference returned.
    pub rc: core::ffi::c_int,
    /// `errno` immediately after the call, with `errno` cleared immediately
    /// before it. Zero means the reference set none, not that nothing failed.
    pub errno: i32,
}

impl Verdict {
    /// Whether the code is `VEOK`.
    #[must_use]
    pub fn is_ok(self) -> bool {
        self.rc == crate::consts::VEOK
    }

    /// The reference's own spelling of [`Self::rc`] — `ve2str`.
    #[must_use]
    pub fn rc_name(self) -> String {
        ve2str(self.rc)
    }
}

/// `ve2str`: the reference's name for a `VE*` return code.
///
/// **Panics.** The reference's diagnostic strings are deliberately not
/// ported: a Rust `match rc { 0 => "VEOK", .. }` would compare our naming to
/// our naming -- the fixtures' `mdst_val_rc_name` strings were produced by
/// the reference's own function, which is what would have to be asked, and
/// it is not in this repository. There is therefore no condition that turns
/// a native version green, which makes this knowledge rather than debt (a
/// marker nobody can discharge is worse than knowledge); it is deliberately
/// excluded from
/// `every_unimplemented_site_is_knowledge_not_debt`, whose entries are all
/// dischargeable, and `docs/specification.md` records it under "What this
/// crate does not do". Nothing on the wallet path calls it.
#[must_use]
pub fn ve2str(_rc: core::ffi::c_int) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}

/// The shared reason the three diagnostic-string functions have no native form.
///
/// One constant because it is one argument, made once in [`ve2str`]'s
/// documentation and applying unchanged to all three.
const NO_NATIVE_DIAGNOSTIC_STRINGS: &str = "the reference's diagnostic strings \
     are deliberately not ported: a Rust restatement of upstream's own spelling \
     would compare our naming to our naming, so no version of it could be \
     checked. This is knowledge, not debt: no condition can turn it green, so it \
     is deliberately absent from \
     invariants.rs::every_unimplemented_site_is_knowledge_not_debt, whose entries \
     are all dischargeable.";

/// `mcm_strerrorname`: the symbolic name of an `errno` value,
/// including the reference's own `EMCM_*` extensions.
///
/// **Panics.** See [`ve2str`] for why this is not ported.
#[must_use]
pub fn errno_name(_errnum: i32) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}

/// `mcm_strerror`: the human-readable text for an `errno`
/// value, including the reference's own `EMCM_*` extensions.
///
/// **Panics.** See [`ve2str`] for why this is not ported.
#[must_use]
pub fn errno_text(_errnum: i32) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}
