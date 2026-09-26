//! The shipped binary at a Windows console, driven through a pseudoconsole.
//!
//! `tests/cli.rs`'s `pty` module drives the binary at a Unix terminal and is
//! compiled out on Windows; `tests/support/conpty.rs` says what stands in for
//! `script(1)` here. What these tests hold is what the console module in
//! `src/bin/mcm-wallet.rs` claims, and what one person checked by hand at a
//! Windows 11 console, as `FORK.md` records under the binary's item: prompts
//! on the console and never on a stream, echo off for a secret and back on
//! for the confirmation, `Ctrl-Z` beginning a line as the end of input and
//! anywhere else as a character, a line longer than one console read joined
//! across two, and characters beyond ASCII read as the UTF-8 the same keys
//! give on Linux and macOS.
//!
//! On Linux and macOS, and under Miri, which cannot start a process, this
//! target builds and lists nothing.

#![cfg(all(feature = "native", windows, not(miri)))]

#[path = "support/conpty.rs"]
mod conpty;
#[path = "support/keystore_harness.rs"]
mod keystore_harness;

use conpty::{Outcome, Session, CTRL_Z, ENTER};
use keystore_harness::ScratchDir;
use mochimo_crypto::account::Account;
use mochimo_crypto::cli::create::CONFIRM_POSITIONS;
use mochimo_crypto::keystore::{Init, Kdf, Keystore, Unlock, NONCE_SEED_LEN};
use mochimo_crypto::Secret;

/// The suite's usual password, the one the `pty` module types.
const PASSWORD: &str = keystore_harness::TEST_PASSWORD_STR;

/// A node the binary never dials: `balance` needs the flag, and the tests
/// that pass it end before any socket.
const NODE: &str = "http://127.0.0.1:1";

/// The phrase of the hand-run checks: twenty-four words of eight letters,
/// 215 characters, so it is longer than one console read.
const PHRASE: &str = "abstract announce bachelor category congress cupboard decorate dinosaur disorder electric \
                      envelope exercise festival hospital indicate interest marriage midnight multiply ordinary \
                      position priority question sentence";

/// The destination macOS printed for [`PHRASE`], copied from that run.
const PHRASE_DESTINATION: &str = "ymDfL9C6eftjnVuhfHdhqjMp4KBfbu";

/// The prefix of the end-of-input refusal on Windows. The binary's
/// `END_OF_INPUT` names the keys this console takes, where the Unix text
/// names `Ctrl-D`.
const END_OF_INPUT: &str = "end of input at the prompt: the console reported end of input (Ctrl-Z at the start of \
                            the line, or Ctrl-C)";

/// A store holding account 0 of the harness's derived master, made in this
/// process under `password` with the cheap KDF every harness store uses: the
/// same format path as a store the binary writes, without paying the
/// recommended KDF once per test.
fn store_under(test: &str, password: &str) -> ScratchDir {
    let store = ScratchDir::new(test);
    let init = Init {
        password: password.as_bytes(),
        salt: keystore_harness::TEST_SALT,
        nonce_seed: keystore_harness::TEST_NONCE_SEED,
        kdf: Kdf::CHEAP_FOR_TESTS,
    };
    let master = Secret::new(keystore_harness::DERIVED_MASTER);
    let mut ks = Keystore::create(store.path(), &init).unwrap_or_else(|e| panic!("{e}"));
    let _ = ks.adopt_master(&master).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master, 0)).unwrap_or_else(|e| panic!("{e}"));
    store
}

/// Account 0's destination for the harness's derived master.
fn stored_destination() -> String {
    let master = Secret::new(keystore_harness::DERIVED_MASTER);
    let tag = mochimo_crypto::derive::derive_account_tag(&master, 0);
    mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"))
}

/// Account 0's destination for a phrase, derived in this process: a second
/// route to the value the binary prints, so the two can disagree.
fn destination_of(phrase: &str) -> String {
    let m = mochimo_crypto::mnemonic::master_seed_from_phrase(phrase, "").unwrap_or_else(|e| panic!("{e}"));
    let tag = mochimo_crypto::derive::derive_account_tag(&m, 0);
    mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"))
}

/// The twenty-four words `create` shows: the line between the notice and its
/// explanation with exactly that many lowercase words on it.
fn phrase_after_notice(s: &mut Session) -> Vec<String> {
    s.expect("WRITE THIS DOWN");
    let block = s.expect("It is the ONLY backup of this wallet.");
    let words: Vec<String> = block
        .lines()
        .map(|l| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .find(|ws| ws.len() == 24)
        .unwrap_or_else(|| panic!("no 24-word line between the notice and its explanation:\n{block}"));
    for w in &words {
        assert!(!w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()), "a shown word is not a lowercase word: {w:?}");
    }
    words
}

/// The positions the question asks for, read off the console and checked
/// against the constant the binary was built with.
fn positions_asked(s: &mut Session) -> [usize; 3] {
    s.expect("type words ");
    let text = s.expect_prompt(", separated by spaces: ");
    let nums: Vec<usize> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .map(|t| t.parse().unwrap_or_else(|e| panic!("{t:?} in {text:?}: {e}")))
        .collect();
    let got: [usize; 3] = nums
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("the question names {} position(s), not 3: {text:?}", nums.len()));
    assert_eq!(got, CONFIRM_POSITIONS, "the question on the console asks for different positions than the code confirms");
    got
}

/// Everything a failed assertion needs to be read.
fn shown(o: &Outcome) -> String {
    format!("exit {}\n--- screen ---\n{}\n--- stdout ---\n{}\n--- stderr ---\n{}", o.code, o.screen, o.stdout, o.stderr)
}

/// **The harness's property, at a console.** The shipped binary shows a
/// phrase, reads the password with echo off and the confirmation with echo
/// on, and the phrase it shows recovers the store it writes -- which exercises
/// the console's output, both echo states and `BCryptGenRandom` in one run.
#[test]
fn create_at_a_console_shows_a_phrase_that_recovers_the_store() {
    let io = ScratchDir::new("console-create-io");
    let store = ScratchDir::new("console-create");
    let dir = store.path().to_string_lossy().into_owned();

    let mut s = Session::spawn(io.path(), &["--dir", &dir, "create"]);
    s.expect_prompt("choose a password for this wallet");
    s.send(PASSWORD);
    s.expect_prompt("type it again: ");
    s.send(PASSWORD);
    let words = phrase_after_notice(&mut s);
    let p = positions_asked(&mut s);
    let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
    s.send(&answer);
    let o = s.finish();
    let phrase = words.join(" ");

    assert_eq!(o.code, 0, "create did not exit 0.\n{}", shown(&o));
    assert_eq!(o.screen.matches(&phrase).count(), 1, "the phrase is not on the console exactly once.\n{}", shown(&o));
    assert!(!o.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the console.\n{}", shown(&o));
    assert_eq!(
        o.screen.matches(&answer).count(),
        1,
        "the confirmation answer was not echoed exactly once -- either echo was not restored before the \
         question or the echo landed twice.\n{}",
        shown(&o)
    );
    assert!(
        !o.stdout.contains(&phrase) && !o.stderr.contains(&phrase),
        "THE PHRASE LEFT THE CONSOLE through a process-wide stream.\n{}",
        shown(&o)
    );
    assert!(!o.screen.contains("destination"), "the report went to the console rather than to stdout.\n{}", shown(&o));
    assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path.\n{}", shown(&o));
    let expected = destination_of(&phrase);
    assert!(o.stdout.contains("created "), "no `created` line on stdout.\n{}", shown(&o));
    assert!(
        o.stdout.contains(&format!("destination  {expected}")),
        "stdout does not carry the destination this process derived from the shown phrase, {expected}.\n{}",
        shown(&o)
    );
    assert!(o.stdout.contains("confirmed    3 words read back"), "stdout does not say the confirmation happened.\n{}", shown(&o));

    let ks = Keystore::open(store.path(), &Unlock { password: PASSWORD.as_bytes(), nonce_seed: [7u8; NONCE_SEED_LEN] })
        .unwrap_or_else(|e| panic!("the store the binary wrote does not open with the password that was typed: {e}"));
    let tags = ks.tags().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tags.len(), 1, "the store should hold exactly account 0");
    assert_eq!(
        mochimo_crypto::addr::tag_to_base58(&tags[0]).unwrap_or_else(|e| panic!("{e}")),
        expected,
        "the store holds a different account than the phrase on the console derives"
    );
    drop(ks);

    // The phrase recovers the store: `create --from-phrase`, typed at a second
    // console with echo off, into a fresh directory, lands on the same
    // destination.
    let io2 = ScratchDir::new("console-restore-io");
    let store2 = ScratchDir::new("console-restore");
    let dir2 = store2.path().to_string_lossy().into_owned();
    let mut s2 = Session::spawn(io2.path(), &["--dir", &dir2, "create", "--from-phrase"]);
    s2.expect_prompt("choose a password for this wallet");
    s2.send(PASSWORD);
    s2.expect_prompt("type it again: ");
    s2.send(PASSWORD);
    s2.expect_prompt("existing recovery phrase (12 or 24 words): ");
    s2.send(&phrase);
    let o2 = s2.finish();
    assert_eq!(o2.code, 0, "create --from-phrase did not exit 0.\n{}", shown(&o2));
    assert!(!o2.screen.contains(&phrase), "THE TYPED PHRASE WAS ECHOED on the --from-phrase path.\n{}", shown(&o2));
    assert!(
        o2.stdout.contains(&format!("destination  {expected}")),
        "the phrase the first run showed did not reproduce its destination, {expected}.\n{}",
        shown(&o2)
    );

    println!("console create: {} prompt(s) answered at a pseudoconsole by the shipped binary", o.prompts + o2.prompts);
}

/// `address` asks for the password on the console, reads it with echo off,
/// opens the store with it, and refuses one that is wrong. The listing goes
/// to stdout and the prompt to the console, never to the redirected stderr.
#[test]
fn address_at_a_console_reads_the_password_hidden_and_refuses_a_wrong_one() {
    let store = store_under("console-address", PASSWORD);
    let dir = store.path().to_string_lossy().into_owned();
    let expected = stored_destination();

    let io = ScratchDir::new("console-address-io");
    let mut s = Session::spawn(io.path(), &["--dir", &dir, "address"]);
    s.expect_prompt("password: ");
    s.send(PASSWORD);
    let o = s.finish();
    assert_eq!(o.code, 0, "address did not exit 0.\n{}", shown(&o));
    assert_eq!(o.screen.matches("password:").count(), 1, "the password prompt is not on the console exactly once.\n{}", shown(&o));
    assert!(!o.stderr.contains("password"), "THE PASSWORD PROMPT WENT TO STDERR.\n{}", shown(&o));
    assert!(!o.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the console.\n{}", shown(&o));
    assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path.\n{}", shown(&o));
    assert!(o.stdout.contains("1 account(s) in this store:"), "address did not list the store.\n{}", shown(&o));
    assert!(o.stdout.contains(&expected), "the listing lacks account 0's destination, {expected}.\n{}", shown(&o));
    assert!(!o.screen.contains(&expected), "the listing went to the console rather than to stdout.\n{}", shown(&o));

    let io2 = ScratchDir::new("console-address-wrong-io");
    let mut s2 = Session::spawn(io2.path(), &["--dir", &dir, "address"]);
    s2.expect_prompt("password: ");
    s2.send("a-different-harness-password");
    let o2 = s2.finish();
    assert_eq!(o2.code, 2, "a wrong password did not exit 2.\n{}", shown(&o2));
    assert!(o2.stderr.contains("did not decrypt"), "the refusal does not say the store did not decrypt.\n{}", shown(&o2));
    assert!(o2.stdout.is_empty(), "stdout is not empty on the exit-2 path.\n{}", shown(&o2));

    println!("console password: {} prompt(s) answered at a pseudoconsole by the shipped binary", o.prompts + o2.prompts);
}

/// `Ctrl-Z` at the start of a line is the end of input: at the password
/// prompt the binary exits 2 in the prompt's own words and compares nothing,
/// and at `create`'s first prompt it exits 3 having created nothing.
#[test]
fn ctrl_z_beginning_a_line_is_the_end_of_input_at_a_console() {
    let store = store_under("console-eof", PASSWORD);
    let dir = store.path().to_string_lossy().into_owned();
    let before = store.snapshot_bytes();

    let io = ScratchDir::new("console-eof-io");
    let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "balance"]);
    s.expect_prompt("password: ");
    s.type_keys(CTRL_Z);
    s.type_keys(ENTER);
    let o = s.finish();
    assert_eq!(o.code, 2, "Ctrl-Z at the password prompt did not exit 2.\n{}", shown(&o));
    assert!(o.stderr.contains(END_OF_INPUT), "the refusal is not the Windows end-of-input text.\n{}", shown(&o));
    assert!(
        !o.stderr.contains("did not decrypt"),
        "END OF INPUT WAS REPORTED AS A WRONG PASSWORD: the binary read Ctrl-Z as a line and compared it.\n{}",
        shown(&o)
    );
    assert!(o.stdout.is_empty(), "stdout is not empty on the exit-2 path.\n{}", shown(&o));
    assert_eq!(store.snapshot_bytes(), before, "the store was touched by a refused prompt");
    drop(
        Keystore::open(store.path(), &keystore_harness::unlock())
            .unwrap_or_else(|e| panic!("the store does not open after the refusal: {e}")),
    );

    let fresh = ScratchDir::new("console-eof-create");
    let fresh_dir = fresh.path().to_string_lossy().into_owned();
    let io2 = ScratchDir::new("console-eof-create-io");
    let mut s2 = Session::spawn(io2.path(), &["--dir", &fresh_dir, "create"]);
    s2.expect_prompt("choose a password for this wallet");
    s2.type_keys(CTRL_Z);
    s2.type_keys(ENTER);
    let o2 = s2.finish();
    assert_eq!(o2.code, 3, "Ctrl-Z at create's first prompt did not exit 3.\n{}", shown(&o2));
    assert!(o2.stderr.contains(END_OF_INPUT), "create's refusal is not the Windows end-of-input text.\n{}", shown(&o2));
    assert!(o2.stderr.contains("Nothing was created"), "create's refusal does not say nothing was created.\n{}", shown(&o2));
    assert!(!fresh.path().exists(), "Ctrl-Z at create's prompt made the directory {}", fresh.path().display());

    println!("console end of input: {} prompt(s) answered at a pseudoconsole by the shipped binary", o.prompts + o2.prompts);
}

/// `Ctrl-Z` typed after 169 characters is a character of the line.
///
/// The binary asks the console for at most 169 units a read, so the 170th
/// character begins a second read. `Ctrl-Z` ends the input only when it
/// begins a line, so here it and the `x` after it are part of the password,
/// which then does not match. The same 169 characters alone open the store.
#[test]
fn ctrl_z_as_the_170th_character_is_part_of_the_line() {
    let password = "a".repeat(169);
    let store = store_under("console-170", &password);
    let dir = store.path().to_string_lossy().into_owned();

    let io = ScratchDir::new("console-170-io");
    let mut s = Session::spawn(io.path(), &["--dir", &dir, "address"]);
    s.expect_prompt("password: ");
    s.type_keys(password.as_bytes());
    s.type_keys(CTRL_Z);
    s.send("x");
    let o = s.finish();
    assert_eq!(o.code, 2, "169 characters, Ctrl-Z and x did not exit 2.\n{}", shown(&o));
    assert!(
        o.stderr.contains("did not decrypt"),
        "CTRL-Z AFTER 169 CHARACTERS WAS NOT A CHARACTER: the line was cut there or read as the end of input.\n{}",
        shown(&o)
    );
    assert!(!o.stderr.contains(END_OF_INPUT), "the refusal is the end-of-input text.\n{}", shown(&o));

    let io2 = ScratchDir::new("console-170-alone-io");
    let mut s2 = Session::spawn(io2.path(), &["--dir", &dir, "address"]);
    s2.expect_prompt("password: ");
    s2.send(&password);
    let o2 = s2.finish();
    assert_eq!(o2.code, 0, "the 169 characters alone did not open the store.\n{}", shown(&o2));
    assert!(o2.stdout.contains(&stored_destination()), "the listing lacks account 0's destination.\n{}", shown(&o2));

    println!("console long line: {} prompt(s) answered at a pseudoconsole by the shipped binary", o.prompts + o2.prompts);
}

/// A 215-character phrase, typed with echo off, arrives over two console
/// reads and derives the destination macOS derived from it.
#[test]
fn a_phrase_longer_than_one_console_read_derives_the_destination_macos_derives() {
    assert_eq!(PHRASE.len(), 215, "the phrase is no longer the length the two-read property needs");
    assert_eq!(destination_of(PHRASE), PHRASE_DESTINATION, "this process no longer derives macOS's destination");

    let io = ScratchDir::new("console-phrase-io");
    let store = ScratchDir::new("console-phrase");
    let dir = store.path().to_string_lossy().into_owned();
    let mut s = Session::spawn(io.path(), &["--dir", &dir, "create", "--from-phrase"]);
    s.expect_prompt("choose a password for this wallet");
    s.send(PASSWORD);
    s.expect_prompt("type it again: ");
    s.send(PASSWORD);
    s.expect_prompt("existing recovery phrase (12 or 24 words): ");
    s.send(PHRASE);
    let o = s.finish();
    assert_eq!(o.code, 0, "create --from-phrase did not exit 0.\n{}", shown(&o));
    assert!(!o.screen.contains(PHRASE), "THE TYPED PHRASE WAS ECHOED.\n{}", shown(&o));
    assert!(
        o.stdout.contains(&format!("destination  {PHRASE_DESTINATION}")),
        "the phrase did not derive macOS's destination, {PHRASE_DESTINATION}: the two reads were not joined \
         into the line that was typed.\n{}",
        shown(&o)
    );

    println!("console phrase: {} prompt(s) answered at a pseudoconsole by the shipped binary", o.prompts);
}

/// Passwords with characters beyond ASCII, typed at the console, are read as
/// the UTF-8 the same keys give on Linux and macOS: stores made under their
/// UTF-8 bytes open. The second holds characters outside the Basic
/// Multilingual Plane, which the console delivers as surrogate pairs that the
/// binary has to keep together.
#[test]
fn passwords_beyond_ascii_typed_at_a_console_are_their_utf8_bytes() {
    let mut prompts = 0;
    for (test, password) in [("console-latin", "Grüße-aus-Zürich-ñandú"), ("console-emoji", "Schlüssel-🔑-und-Schloss-🔒")] {
        let store = store_under(test, password);
        let dir = store.path().to_string_lossy().into_owned();
        let io = ScratchDir::new(&format!("{test}-io"));
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "address"]);
        s.expect_prompt("password: ");
        s.send(password);
        let o = s.finish();
        assert_eq!(o.code, 0, "the store made under {password:?} did not open with it typed.\n{}", shown(&o));
        assert!(o.stdout.contains(&stored_destination()), "the listing lacks account 0's destination.\n{}", shown(&o));
        prompts += o.prompts;
    }

    println!("console characters: {prompts} prompt(s) answered at a pseudoconsole by the shipped binary");
}
