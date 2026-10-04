//! `create` — make the store and put account 0 in it.
//!
//! # Why this is outside the `Wallet` gate
//!
//! Where `restore` already is, and for the same reason: it signs nothing and
//! constructs no `Wallet`, so it can run before the account is funded. That
//! matters because **every command that goes through `Wallet::open` refuses a
//! tag the ledger has never held** — deliberately, and it was argued on the
//! case where absence genuinely cannot be told from a wrong seed.
//! Once there was no verb outside that gate that could make a store, so
//! the ordinary create-then-fund flow did not exist through the binary at all.
//! `Wallet::open`'s refusal is untouched; two commands moved to where `restore`
//! was.
//!
//! # What the phrase exposes
//!
//! Stated here because this is the first command that puts one on screen
//! deliberately:
//!
//! * **it appears once and is not recoverable from the store.** The store holds
//!   the derived account, not the phrase, and nothing in this crate reverses
//!   that;
//! * **it is the only backup that survives a forgotten password.** The store
//!   is sealed under the
//!   password, which *raises* the phrase's importance rather than lowering it:
//!   the password protects the file, and the phrase is what reconstructs the
//!   accounts when the password is gone;
//!
//! * **it is on a terminal** — in the scrollback, in whatever the terminal
//!   emulator logs, and in any session recording.
//!
//! [`mnemonic::Phrase`] is `Zeroizing<String>` with a redacting `Debug`, so the generated
//! phrase clears on drop by type rather than by anyone remembering to.
//!
//! # Entropy is a parameter, and that is a dependency decision
//!
//! There is no RNG in this crate's graph — no `rand`, no `getrandom` — and the
//! command layer is under `native` alone, so `ring` is not reachable either.
//! Rather than add a crate for one call (`tempfile` was declined on the same
//! ground), **the caller supplies the entropy** and the binary reads 32
//! bytes from `/dev/urandom` through `std::fs`. That is the OS CSPRNG rather
//! than anything hand-rolled, and it makes `create` deterministic under test,
//! which a crate-supplied generator would not.

use std::path::Path;

use zeroize::Zeroizing;

use super::{Code, Report};
use crate::account::Account;
use crate::consts::SEED_LEN;
use crate::keystore::Keystore;
use crate::mnemonic;
use crate::{Error, Result, Secret};

/// 32 bytes of entropy is BIP39's 24-word case, which is what the shipped
/// wallet uses and what `group_f`'s vectors are.
pub const ENTROPY_LEN: usize = 32;

/// Everything `create` needs from a random source, in one value.
///
/// **Three separate draws, not one split three ways.** The phrase entropy
/// becomes the wallet; the salt makes two stores under one password different
/// files; the nonce seed keeps a fork of a store from reusing a nonce. Deriving
/// them from each other would tie the store's key to the seed it protects,
/// which is the relationship the password exists to break.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CreateEntropy {
    pub phrase: [u8; ENTROPY_LEN],
    pub salt: [u8; crate::keystore::SALT_LEN],
    pub nonce_seed: [u8; crate::keystore::NONCE_SEED_LEN],
}

/// What `create` made.
///
/// **No phrase in here**. This once carried `phrase: Option<Phrase>`,
/// present when [`create`] had generated one from entropy and absent when the
/// operator supplied it -- which meant the library's own API wrote the store
/// *first* and handed back the phrase *afterwards*, and every caller inherited
/// that order. The order is now the other way round and the type says so:
/// [`create`] takes a phrase and returns a tag, and generating the phrase is
/// the caller's step, taken -- and confirmed -- before anything is written.
pub struct Created {
    /// Account 0's tag — the thing to fund.
    pub tag: crate::addr::Tag,
}

/// Make the store from a phrase, derive account 0, write it.
///
/// [`Keystore::create`] refuses an existing store (`Error::Exists`), a
/// directory with unsafe permissions, and a held lock, so this calls it
/// rather than reimplementing any of that. **This is the write**, and it is
/// the last thing `create` does rather than the first: the phrase
/// has been generated, shown and read back before this runs, or was typed by
/// the operator. The refusal that keeps a mistyped `--dir` from burning a
/// phrase is [`crate::keystore::occupied`], asked by [`orchestrate`] before
/// the password prompt; the one here is the authoritative one, at write time,
/// and it also covers the lock and the permissions.
///
/// # The password floor is asked here too, and first
///
/// Asking it only at the prompt, through [`read_new_password`], would enforce
/// it exactly where no test looks: every test in the tree comes in through
/// this function with the harness's password. It is asked here, before
/// `Keystore::create` makes the directory, and the prompt keeps its copy as
/// the **early** one: the arrangement `occupied` already has, an early
/// refusal at the prompt so the operator is told before typing twenty-four
/// words or being shown a phrase, and the authoritative one at the write.
/// Every caller of this function is making a store under an operator's
/// password, on the generate path and the `--from-phrase` path alike, and
/// that is the property the floor is about.
///
/// What was rejected, so it is not re-proposed: the floor inside
/// `Keystore::create`, which takes bytes and is deliberately agnostic about
/// guess cost -- `Kdf::CHEAP_FOR_TESTS` exists because the suite makes
/// hundreds of stores, and a keystore that judged passwords would judge
/// those; and the floor at the terminal alone, which leaves every other
/// caller of this function exempt. `password` is `&str` because the
/// floor counts characters and every path that reaches here has text.
pub fn create(
    dir: &Path,
    words: &str,
    password: &str,
    salt: [u8; crate::keystore::SALT_LEN],
    nonce_seed: [u8; crate::keystore::NONCE_SEED_LEN],
) -> Result<Created> {
    if let Some(chars) = short_password_chars(password) {
        return Err(Error::PasswordTooShort {
            chars,
            min: MIN_PASSWORD_LEN,
        });
    }
    // **The phrase is parsed before the directory exists**. Once
    // `Keystore::create` ran first, and it makes the directory,
    // seals an EMPTY image and commits it -- so a phrase the parser refused
    // (`bip39: checksum mismatch`, a typo in twenty-four words) left a
    // 112-byte store and a lock file behind, the refusal did not say so, and
    // the retry into the same directory was refused as an existing store
    // whose only advice was to run another command against it. The
    // write-before-validate order found at the terminal, one prompt along; predicted from source in
    // the first live recovery, measured by
    // `tests/cli.rs::a_refused_phrase_leaves_nothing_on_disk` before this
    // line moved. The same measurement is what makes "Nothing was created"
    // true on the `--from-phrase` refusal.
    let master: Secret<SEED_LEN> = mnemonic::master_seed_from_phrase(words, "")?;

    let mut ks = Keystore::create(
        dir,
        &crate::keystore::Init {
            password: password.as_bytes(),
            salt,
            nonce_seed,
            // The shipped cost. A real wallet pays it once per command; see
            // `keystore::Kdf::RECOMMENDED` for the measurement behind it.
            kdf: crate::keystore::Kdf::RECOMMENDED,
        },
    )?;

    // **The master goes into the store.** Before version 3 it was
    // reconstructed from twenty-four typed words on every
    // command; it is now written once, under the password, and read back by
    // whatever runs next. Adopted BEFORE the account so a store that holds an
    // account always holds the seed that derives it -- the other order leaves
    // a window where a crash produces a store whose account nothing can sign
    // for.
    let _durable = ks.adopt_master(&master)?;
    let account = Account::derive(&master, 0);
    let tag = account.tag();
    ks.add(account)?;
    Ok(Created { tag })
}

/// The shortest password `create` will accept.
///
/// # Refused, not warned about, and not a character-class rule
///
/// Three options were on the table and each has a cost. Accepting anything
/// silently makes the operator's worst choice invisible at the one moment the
/// program could have said something. Warning trains people to read past
/// warnings, and a warning about the only thing protecting the funds is a
/// warning that should have been a refusal. Refusing has a real cost too --
/// it is the program overriding somebody about their own wallet -- and
/// *"the operator chose it"* is the usual answer to that, but it is a poor one
/// here, because what they chose is the only barrier: a stolen store file
/// yields every account in it or none, depending on this password alone.
///
/// So: a **length floor and nothing else**. No required digit, no required
/// symbol, no strength meter. Those rules are heuristics about the shape of a
/// password rather than facts about its search space, and they reliably
/// produce `Password1!` -- they would refuse a five-word passphrase that is
/// enormously stronger. A length floor is not a heuristic; it is a floor under
/// the search space, and it is the only claim of that kind this program can
/// make without pretending to measure entropy it cannot see.
///
/// Twelve, because Argon2id at [`crate::keystore::Kdf::RECOMMENDED`] makes a
/// guess cost about seventy milliseconds of 64 MiB -- which buys a great deal
/// against a moderate passphrase and nothing at all against a short one that
/// is in a wordlist. The KDF raises the price per guess; it cannot reduce the
/// number of guesses, and below about a dozen characters that number is the
/// whole problem.
///
/// **Twelve characters, and the unit is load-bearing**. Comparing the
/// password's UTF-8 byte count against this constant makes the floor twelve
/// BYTES, and a message saying *character(s)* then lies: eleven characters
/// with one accented letter pass, four CJK characters pass, three emoji
/// pass. The argument above is about the symbols an operator chose, not
/// their encoding, so the count is Unicode scalar values -- see
/// [`short_password_chars`].
pub const MIN_PASSWORD_LEN: usize = 12;

/// The character count of a password below [`MIN_PASSWORD_LEN`], or `None`
/// when it is not below it. **The one place the floor is measured**; both
/// [`password_refusal`] (the prompt's prose) and [`create`] (the library's
/// `Error`) read it.
///
/// Unicode scalar values, which is what `chars()` counts and what a
/// keystroke produces in the common case. A decomposed accent counts as two
/// where a reader sees one; that errs toward accepting, and grapheme
/// segmentation would need a dependency for a case nobody has shown. Bytes,
/// which this once counted, err the same way and further:
/// every non-ASCII character counts as two to four.
fn short_password_chars(password: &str) -> Option<usize> {
    let chars = password.chars().count();
    (chars < MIN_PASSWORD_LEN).then_some(chars)
}

/// Refuse a password too short to be the only thing protecting the store.
///
/// The prompt's copy of the floor: prose for the operator, asked by
/// [`read_new_password`] before a second read, a phrase or a store exists.
/// [`create`] asks the same measurement again and is the authoritative one.
pub fn password_refusal(password: &str) -> Option<String> {
    let chars = short_password_chars(password)?;
    Some(format!(
        "that password is {chars} character(s); this wallet will not take fewer than \
         {MIN_PASSWORD_LEN}.\n  It is not a rule about digits or symbols -- there is none, and a \
         passphrase of ordinary words is a fine answer. It is that this password is now the ONLY \
         thing between somebody holding your store file and every account in it. Nothing was \
         created."
    ))
}

/// The words the confirmation asks for, by position, one-based.
///
/// First, middle and last: enough that the operator has to look at the whole
/// phrase rather than the first line of it.
pub const CONFIRM_POSITIONS: [usize; 3] = [1, 12, 24];

/// Does `answer` give the words `phrase` has at [`CONFIRM_POSITIONS`]?
///
/// # What this establishes, and what it does not
///
/// It establishes that the operator was present and could **read** the phrase
/// at that moment. It does **not** establish that the phrase is recorded
/// anywhere, and nothing available in this design could: the phrase is on the
/// same screen the answer is typed into, so re-typing all twenty-four words
/// would be satisfiable the same way and buy nothing but hostility. Said here
/// rather than left implied, because a check whose name suggests more than it
/// checks is a shape this project has measured before.
pub fn confirmation_matches(phrase: &str, answer: &str) -> bool {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let given: Vec<&str> = answer.split_whitespace().collect();
    if given.len() != CONFIRM_POSITIONS.len() {
        return false;
    }
    for (slot, position) in CONFIRM_POSITIONS.iter().enumerate() {
        match (words.get(position - 1), given.get(slot)) {
            (Some(want), Some(got)) if want.eq_ignore_ascii_case(got) => {}
            _ => return false,
        }
    }
    true
}


/// What `create` needs from a terminal, behind a seam a test can fail.
///
/// # Why this is a trait rather than two `fn`s in the binary
///
/// The property this seam has to establish is **negative**: with no controlling
/// terminal, `create` writes nothing and shows no phrase. A negative about an
/// absent device cannot be asserted from the binary — `cargo test` runs
/// without a terminal too, so the test would be asserting the same absence it
/// is running in, from outside the process that has to react to it.
///
/// Putting the acquisition behind `acquire` moves the decision into the
/// library, where a test can supply a source that fails and then check the two
/// things that matter: **the directory does not exist, and nothing was
/// shown**. `show` goes through the terminal for the same reason — a `println!`
/// is invisible to the test, and the phrase reaching a stream nobody chose is
/// the defect itself.
/// What `create --from-phrase` shows before it reads anything.
///
/// # Why a warning and not a refusal
///
/// Several Mochimo wallets derive a seed from a phrase, and they do not agree:
/// they consume and produce different things, so one phrase means a different
/// wallet under each. This program implements the shipped browser extension's
/// scheme, which is the one the corpus pins, and it cannot tell which scheme a
/// phrase was written under -- a phrase carries no such mark. So there is
/// nothing to refuse on, and the common case is a phrase this program wrote.
///
/// # Why it names what the operator will see rather than the error they will not
///
/// A phrase from another scheme is accepted. It derives a real master seed, a
/// real account 0 and a real store, and every command that follows works. The
/// accounts are empty, and an empty account is also what an unfunded wallet
/// has. There is no failure anywhere for the operator to notice, which is why
/// the text describes the silence instead of promising an error.
pub const SCHEME_WARNING: &str = "\
BEFORE YOU TYPE: this wallet implements one derivation scheme.

Mochimo wallets do not agree on how a recovery phrase becomes a seed. This one
follows the shipped browser extension. A phrase written under a different
scheme is accepted here and derives a working store -- there is no error, and
nothing refuses it. What you get is a wallet whose accounts are empty, which is
exactly what a wallet nobody has ever paid looks like.

If the phrase came from this program or from the browser extension, continue.
If it came from somewhere else, confirm what that wallet derives before you
read an empty balance here as the truth about your funds.
";

pub trait Terminal: Sized {
    /// Show text the operator must read -- and say whether it was written.
    ///
    /// **Returns a `Result`.** The confirmation read immediately after the
    /// phrase looks like a stronger check than the write's own result, and it
    /// is not a substitute for it: the confirmation is asked on the same
    /// descriptor by design, so a descriptor that cannot be written fails
    /// both, and the read-back is blind to exactly the failure it would be
    /// standing in for. The two are complementary: this
    /// result catches the descriptor class, the read-back catches the human
    /// class. [`orchestrate`] refuses on `Err` here before any store exists.
    fn show(&mut self, text: &str) -> core::result::Result<(), String>;
    /// Read one line without echoing it.
    fn read_secret_line(&mut self, prompt: &str) -> core::result::Result<Zeroizing<String>, String>;
    /// Read one line **with** echo — and **consume the terminal**.
    ///
    /// # Why this takes `self`, and why that is the whole safety argument
    ///
    /// The create path made *the terminal is present and silent* a precondition the
    /// compiler holds, by acquiring both through `?` on the first line of the
    /// create path. Echoing anything at all appears to reopen that: something
    /// has to turn echo back on, and a later secret read would then run
    /// visibly.
    ///
    /// Taking `self` by value closes it without adding a mechanism. **After
    /// this call there is no terminal**, so no secret read can follow it — not
    /// because the statements are in the right order, but because there is
    /// nothing left to read from and the borrow checker says so. The property
    /// established there survives verbatim: no path reads a secret with echo
    /// on.
    ///
    /// What the implementor must do is therefore the *natural* implementation
    /// rather than a careful one: release the echo guard — which was going to
    /// drop a few lines later anyway — and read. The window between that drop
    /// and the process exiting is the window that already existed, and nothing
    /// secret is read inside it.
    ///
    /// # What echoing costs, which is nothing this program was protecting
    ///
    /// The only caller asks for three words of a phrase that is on the same
    /// screen, three lines above, in the same scrollback, in the same session
    /// recording. The mnemonic prompt's argument is about **exposure**, and there is
    /// none left to prevent here; hiding the answer buys no secrecy and costs
    /// a real `exit 3`. The master-seed prompt keeps echo
    /// off, where 172's argument holds unchanged: that phrase is not on screen.
    ///
    /// The answer is still [`Zeroizing`] — it is three words of a mnemonic and
    /// the buffer clears on drop whatever the terminal did with it.
    fn read_visible_line(self, prompt: &str) -> core::result::Result<Zeroizing<String>, String>;
}

/// `create`, whole: acquire the terminal, then everything else.
///
/// **Named `orchestrate` rather than `run`, and that is not taste.** The route
/// scan taints by bare function name, `cli::run` reaches the signer through the
/// wallet, and a second `run` anywhere in `crates/*/src` inherits that taint --
/// so this function, which touches no wallet and no signer, was flagged as an
/// unlisted route to a signature. Third instance of the bare-name collision finding, and
/// the first where the colliding name is the one a module's entry point would
/// naturally take. Renamed rather than allow-listed: an allow-list entry would
/// assert a permission for a route that does not exist.
///
/// # The acquisition is first, and that is the session's subject
///
/// The *echo* refusal is structural — a guard through `?`, so no path reads
/// with echo on. Probing *terminal availability* at the confirmation instead
/// would put it after the store is written and after the phrase is shown: in
/// a terminal that is invisible, and without one it means a real store exists
/// and a real phrase has been printed to whatever captured stdout, before
/// anything discovers there is nowhere to confirm it.
///
/// `acquire()?` on the first line is the same move one level out: the `?` that
/// already prevented reading with echo on now also prevents **generating a
/// phrase with nowhere to confirm it**.
///
/// # The cost of holding the guard longer, stated
///
/// The terminal — and with it echo-off, since the binary's implementation
/// acquires both together — is held across the password reads and the phrase
/// display. The write follows the confirmation, which consumes the terminal
/// and releases the guard, so the store is written with echo already
/// restored. Three consequences, and what answers each:
///
/// * **A longer window with echo disabled.** A `SIGKILL` inside it leaves the
///   operator's terminal silent. Not defended against: `Drop` cannot run on
///   `SIGKILL`, the remedy is `stty echo`, and the alternative — verify the
///   terminal, restore echo, re-disable it per read — trades a recoverable
///   annoyance for a gap between the check and the use, in the property the
///   guard establishes.
/// * **The `show` path.** None: terminal echo governs what the driver echoes
///   back from *input*. Writing to the terminal is unaffected, so the phrase
///   displays normally with echo off.
/// * **Drop ordering.** Not load-bearing. The binary's guard holds its own
///   duplicated descriptor, so it restores echo whether it drops before or
///   after the handle the reads use.
pub fn orchestrate<T: Terminal>(
    dir: &Path,
    from_phrase: bool,
    entropy: impl FnOnce() -> core::result::Result<Zeroizing<CreateEntropy>, String>,
    acquire: impl FnOnce() -> core::result::Result<T, String>,
) -> Report {
    let refused = |text: String| Report {
        text,
        code: Code::Refused,
    };

    // FIRST. Nothing below this line runs without somewhere to confirm.
    let mut term = match acquire() {
        Ok(t) => t,
        Err(e) => return refused(nothing_was_created(e)),
    };

    // **An occupied directory refuses before anything is asked or shown**.
    // The write is now the last step, so the keystore's own refusal of
    // an existing store would arrive after a password had been chosen and a
    // phrase shown and read back. Asking the keystore's check up front keeps
    // the earlier property -- a mistyped `--dir` cannot burn a phrase -- at the
    // new order. The check at write time is still the authoritative one.
    // **What this probe deliberately does not see**: a lock file with no
    // snapshot beside it. Refusing that state here would also refuse a
    // concurrent `create` inside its own key-derivation window -- lock taken,
    // snapshot not yet renamed in -- before this one prompted. Such a race
    // reaches the write instead, where `take_lock`
    // refuses it with `Locked` after the password, the phrase and the
    // confirmation, with nothing written: the phrase shown is one
    // `--from-phrase` from a store and the window is one
    // Argon2id derivation wide. A probe of the flock itself, opening the file
    // without creating it, would restore the early refusal; not taken, and
    // recorded as the alternative.
    if let Some(what) = crate::keystore::occupied(dir) {
        return refused(nothing_was_created(format!(
            "a keystore already exists at {} (its {what} is present). Nothing was shown and \
             nothing was changed. `create` makes a new store: use a different --dir for one. To \
             add an account to this store, run `restore --account N` against it; `address` \
             lists what it holds.",
            dir.display()
        )));
    }

    if from_phrase {
        // **Before either read**, because both of them cost the operator
        // something to undo. The password argument below is about not throwing
        // away typed work; this is about not asking for the work at all. A
        // phrase from another scheme restores here with no error to see, so
        // the only moment the warning can change what somebody does is before
        // they start typing.
        if let Err(e) = term.show(SCHEME_WARNING) {
            return refused(nothing_was_created(e));
        }
        // **The password first, on this path too.** The generate path reads it
        // first so a refusal cannot leave a phrase on screen with no store
        // behind it; here nothing is displayed, so that argument does not
        // apply -- but a different one does. `read_new_password` can refuse
        // (too short, or the two did not match), and refusing after the
        // operator has typed twenty-four words throws that work away for a
        // reason they could have been given first. Same order on both paths,
        // for two different reasons pointing the same way.
        let password = match read_new_password(&mut term) {
            Ok(p) => p,
            Err(e) => return refused(e),
        };
        // **"12 or 24" and not "24"**. The old prompt said 24 and the
        // path checked nothing: `entropy_from_phrase` accepts 12, 15, 18, 21
        // and 24, which is exactly the set `@scure/bip39`'s `normalize`
        // accepts and therefore exactly what the shipped extension takes. A
        // prompt naming one count while five work reads like a constraint and
        // is decoration -- and it would turn somebody with a 12-word phrase
        // from another wallet away from a wallet that would have restored it.
        // The two common counts are named; the odd ones work and are not worth
        // the line.
        let words = match term.read_secret_line("existing recovery phrase (12 or 24 words): ") {
            Ok(w) => w,
            Err(e) => return refused(nothing_was_created(e)),
        };
        let e = match entropy() {
            Ok(e) => e,
            Err(e) => return refused(nothing_was_created(e)),
        };
        return match create(dir, &words, &password, e.salt, e.nonce_seed) {
            Ok(c) => match super::destination(&c.tag) {
                Ok(dest) => Report {
                    text: created_text(dir, &dest, None),
                    code: Code::Ok,
                },
                Err(e) => refused(format!(
                    "the store at {} was created from the phrase you supplied, but its \
                     destination could not be rendered ({e}). `address` with no argument reads \
                     it back from the store.",
                    dir.display()
                )),
            },
            // True: `create` parses the phrase before it makes the
            // directory, so every refusal from it leaves nothing on disk.
            Err(e) => refused(nothing_was_created(e)),
        };
    }

    // **The password is read BEFORE the phrase is generated**, for the
    // terminal acquisition's reason one step along: a refusal here must not leave a phrase on screen
    // that no store corresponds to. `acquire()?` already guaranteed there is
    // somewhere to type; this guarantees there is something to encrypt with.
    let password = match read_new_password(&mut term) {
        Ok(p) => p,
        Err(e) => return refused(e),
    };
    let entropy = match entropy() {
        Ok(e) => e,
        Err(e) => return refused(nothing_was_created(e)),
    };
    let phrase = match mnemonic::phrase_from_entropy(&entropy.phrase) {
        Ok(p) => p,
        Err(e) => return refused(nothing_was_created(e)),
    };

    // **Shown, and the showing is checked**. Nothing has been written
    // yet, so a display that fails is an ordinary refusal with nothing to
    // clean up -- which is the whole point of the order below.
    if let Err(e) = term.show(&format!(
        "\nWRITE THIS DOWN. It is shown once.\n\n  {}\n\n\
         It is the ONLY backup of this wallet. It cannot be recovered from the store.\n\
         The store is sealed with the password you just chose; forget it and these words \
         are the only way back in.\n\
         These words are now in this terminal's scrollback, and in whatever your terminal \
         emulator keeps.\n",
        phrase.expose()
    )) {
        return refused(nothing_was_created(e));
    }

    // **The confirmation comes BEFORE the write**. Once
    // the store was written first, the phrase shown second and
    // the confirmation asked third, so a wrong answer exited 3 with a real,
    // fundable store on disk -- argued as protecting an operator who had
    // written the phrase down and mistyped three words. When the display
    // broke (the binary wrote its prompts to a read-only descriptor) that
    // order turned a display bug into a fund-loss defect: exit 3, a store,
    // and a phrase nobody had seen. The argument for write-first was also
    // wrong on its own terms: a phrase for "a wallet that does not exist" is
    // one `create --from-phrase` away from that wallet, and the pty harness
    // measures that the phrase shown here reproduces the destination. So
    // every refusal from `create` now leaves nothing on disk, and the exit
    // code and the filesystem say the same thing.
    let p = CONFIRM_POSITIONS;
    let answer = match term.read_visible_line(&format!(
        "type words {}, {} and {}, separated by spaces: ",
        p[0], p[1], p[2]
    )) {
        Ok(a) => a,
        Err(e) => return refused(nothing_was_created(e)),
    };
    if !confirmation_matches(phrase.expose(), &answer) {
        return refused(format!(
            "those are not words {}, {} and {}. Nothing was created.\n\n  The phrase above \
             belongs to no store. Run `create` again for a fresh phrase, or `create \
             --from-phrase` to build the store from this one -- and either way, write the \
             phrase down before anything is sent to the wallet.",
            p[0], p[1], p[2]
        ));
    }

    let created = match create(
        dir,
        phrase.expose(),
        &password,
        entropy.salt,
        entropy.nonce_seed,
    ) {
        Ok(c) => c,
        Err(e) => return refused(nothing_was_created(e)),
    };

    let Ok(dest) = super::destination(&created.tag) else {
        return refused(after_the_store_exists(dir));
    };
    Report {
        text: created_text(dir, &dest, Some(p.len())),
        code: Code::Ok,
    }
}

/// The one refusal that can follow the write.
///
/// # Why one arm, where there were four
///
/// An audit found that `create`'s confirmation refusal carried no route
/// back to the account it had just made, and this helper was written so that
/// every path returning from under [`create`] named the store. A later change moved the
/// confirmation, the terminal reads and the phrase display **in front of** the
/// write, so three of its four callers no longer have a store to name and
/// say "Nothing was created" instead. What remains is the destination failing
/// to render after a successful write -- the store is real and correct, only
/// the Base58 rendering of its tag did not come out -- and that is the arm
/// this text is for.
///
/// # The order is the argument
///
/// The way out is stated before the way on, with its expiry attached: an
/// operator reading this has a store they have not yet funded, and deleting
/// the directory is free exactly until they do.
fn after_the_store_exists(dir: &Path) -> String {
    format!(
        "the confirmation was answered correctly and the store was written, but its \
         destination could not be rendered.\n\nA keystore WAS created at {} and account 0 is in \
         it. The phrase shown above is its only backup and cannot be recovered from the \
         store.\n\n  IF YOU DID NOT WRITE THE PHRASE DOWN: delete {} and run `create` again. \
         That is free right now and stops being possible the moment this account holds \
         funds.\n\nThe destination could not be rendered here. `address` with no argument reads \
         it back from the store, and needs neither a node nor the phrase.",
        dir.display(),
        dir.display()
    )
}

/// **Takes the rendered destination rather than the [`Created`]**.
///
/// Forty hex characters is not a destination the shipped Chrome wallet takes
/// -- *"Tag must be between 22 and 31 characters"* -- so a wallet printing
/// one here cannot be funded from its own output. Passing the string in
/// rather than the bytes means this
/// function cannot render a second form by accident: there is no tag here to
/// render.
/// Read a new password twice and require the two to agree.
///
/// # Echo stays OFF here, and that is not in tension with the confirmation
///
/// The three-word phrase confirmation was made to ECHO, on the ground that the
/// phrase it asks about is already on screen three lines above, so hiding the
/// answer bought no secrecy and cost a mistyped confirmation. **That argument
/// does not transfer.** A password being created is on no screen and in no
/// scrollback; it is exactly the thing the mnemonic prompt's argument is about. So it
/// goes through `read_secret_line`, which the `Terminal` seam still gives with
/// `&mut self`, and the typed-twice comparison is what replaces seeing it.
///
/// This also keeps the confirmation's ordering property intact by construction: the only
/// method that echoes takes `self` by value, so it can be called once and
/// nothing can read after it. Both reads here are echo-off and both come
/// first; the visible confirmation is still the last thing `create` does.
///
/// # Every refusal from here says "Nothing was created."
///
/// The floor and the mismatch spell the sentence themselves. The two
/// terminal reads refuse in the terminal's own words -- end of input, a
/// read failure -- and the sentence is appended to those here, so every
/// refusal this function returns ends the same way.
fn read_new_password<T: Terminal>(term: &mut T) -> core::result::Result<Zeroizing<String>, String> {
    let first = term
        .read_secret_line("choose a password for this wallet (it will be needed for every command): ")
        .map_err(nothing_was_created)?;
    if let Some(why) = password_refusal(&first) {
        return Err(why);
    }
    let again = term
        .read_secret_line("type it again: ")
        .map_err(nothing_was_created)?;
    if first.as_bytes() != again.as_bytes() {
        return Err("those two passwords are not the same. Nothing was created.".into());
    }
    Ok(first)
}

/// The promise every refusal from `create` keeps, appended to a refusal that
/// arrived in its own words -- the terminal's, the entropy source's, the
/// phrase parser's, the keystore's. Every arm of [`orchestrate`] that returns
/// before the write goes through here or spells the sentence itself, which
/// is what lets the specification say "every one" rather than "most". A
/// space if the text already ends a sentence, a period and a space if it
/// does not, so no source has to know another's punctuation: the binary's
/// end-of-input text ends in a period and its write failures do not.
pub fn nothing_was_created(text: impl core::fmt::Display) -> String {
    let text = text.to_string();
    let text = text.trim_end();
    if text.ends_with(['.', '!', '?']) {
        format!("{text} Nothing was created.")
    } else {
        format!("{text}. Nothing was created.")
    }
}

fn created_text(dir: &Path, dest: &str, confirmed: Option<usize>) -> String {
    let mut out = format!("created {}\n  destination  {dest}\n", dir.display());
    if let Some(n) = confirmed {
        out.push_str(&format!("  confirmed    {n} words read back\n"));
    }
    out.push_str(
        "\nThat destination is where funds are sent -- Base58 over the tag and its CRC16, the \
         form every Mochimo wallet takes. Give it to whoever is paying you.\n\nNext: `address` \
         with no argument prints it again, and `address <destination>` adds the 40-byte ledger \
         address; both need no `--node` and work before this account has any funds. Every other \
         command asks a node first, requires `--node`, and refuses until the account has been \
         funded at least once.",
    );
    out
}
