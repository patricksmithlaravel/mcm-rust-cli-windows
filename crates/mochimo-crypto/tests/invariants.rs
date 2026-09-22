#![cfg(not(miri))]
//! The invariant scans and proofs: every check here reads this crate's own
//! source, its fixture corpus, its documents, or libtest's own run list, and
//! several spawn `cargo` or a sibling test binary. Gated on `not(miri)`
//! because Miri interprets the default configuration and cannot spawn a
//! process or walk the tree at useful speed; the property each check holds is
//! about the source, not about any one execution of it.
//!
//! This file was planted from a repository where most of these checks also
//! compared against a vendored C reference and a bindgen crate. Neither is
//! here, and the checks whose subject they were are gone with them; the
//! specification (`docs/specification.md`, "Invariants") describes in the
//! present tense what the survivors hold. The corpus under `fixtures/` is
//! the executable form of the same specification, and the checks that read
//! it hold its provenance against the commits the documents state.
//!
//! An invariant with no test that fails when it is broken is not enforced.
//! Where a check demands another test, it demands its *execution*, through
//! the `census` module below, which asks libtest rather than searching source
//! for a name.

// `support` is shared by every test binary and each uses a different slice of
// it; this one needs only the fixture loader, for the coverage census. The
// allow is scoped to this binary rather than to the module, so a helper that is
// dead *everywhere* still shows up in the crate's other test targets.
#[allow(dead_code)]
mod support;
#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/drop_witness.rs"]
mod drop_witness;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mochimo_crypto::consts::SEED_LEN;
use mochimo_crypto::Secret;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <repo>/crates/mochimo-crypto")
        .to_path_buf()
}

/// `text` with `//` line comments and `/* */` block comments blanked out.
///
/// Several checks here search source for a symbol name, and the files they
/// search discuss those names deliberately: a comment that states why a symbol
/// is absent contains the symbol. A search that could not tell a comment from
/// code would make explaining a decision indistinguishable from reversing it.
///
/// String literals are opaque to the comment scanner but are **emitted
/// verbatim**. Both halves matter. Opaque, because `t.pass("ui/pass/*.rs")` in
/// `compile_fail.rs` is a glob, not a comment, and treating it as one
/// discarded 13,310 bytes of the concatenated test corpus (see
/// `code_only_understands_every_construct_its_inputs_contain`). Verbatim,
/// because the checks that read this output search for quoted names --
/// `crosscheck_fields_stay_asserted` looks for `"amount"` -- so a stripper that
/// deleted literal *contents* would be a second, quieter bug wearing the first
/// one's fix.
///
/// This is still not a parser. It reads Rust: `"..."` strings, `'x'` char
/// literals and every spelling of a raw string; a bare `'` is a lifetime. It
/// is pointed at every `.rs` under `crates/`, and that its raw-string reading
/// agrees with an independent reader over that corpus is asserted by
/// `code_only_understands_every_construct_its_inputs_contain` rather than
/// judged acceptable here. It once read C and TypeScript too, under two more
/// quoting rules, for reference sources that are not in this repository; the
/// rules went with the inputs.
///
/// The two arms that can silently truncate -- an unterminated block comment and
/// an unterminated string -- **panic**, and the panic names this function. That
/// is deliberate: when a stray token in one file broke two checks once,
/// the reds were about crosscheck independence and group E constants and pointed nowhere near
/// the cause. A parser's mistakes must report the parser.
fn code_only(text: &str) -> String {
    strip_comments(text)
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0usize;
    // Emits a quoted run verbatim: opaque to the comment scanner, but present
    // in the output, because the checks downstream search for quoted names.
    let emit_string = |out: &mut String, open: usize, delim: u8| -> usize {
        let mut j = open + 1;
        let end = loop {
            if j >= b.len() {
                panic!(
                    "code_only: string opened at byte {open} and never closed. \
                     Everything after it would be discarded. This is the \
                     stripper reporting on its input, not a claim about \
                     whatever check called it."
                );
            }
            match b[j] {
                // Skips the escaped byte. If that byte begins a multi-byte
                // char this lands mid-sequence, which is harmless: a UTF-8
                // continuation byte is never 0x5C and never equals a delimiter.
                b'\\' => j += 2,
                c if c == delim => break j,
                _ => j += 1,
            }
        };
        out.push_str(&text[open..=end]);
        end + 1
    };
    while i < b.len() {
        if b[i..].starts_with(b"/*") {
            let Some(rel) = text[i + 2..].find("*/") else {
                panic!(
                    "code_only: block comment opened at byte {i} and never closed. \
                     Everything after it would be discarded. This is the stripper \
                     reporting on its input, not a claim about whatever check \
                     called it."
                );
            };
            i += 2 + rel + 2;
        } else if b[i..].starts_with(b"//") {
            match text[i..].find('\n') {
                Some(rel) => i += rel,
                // A line comment running to EOF discards nothing but itself.
                None => break,
            }
        } else if (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            && matches!(b[i], b'r' | b'b' | b'c')
        {
            // A raw string is emitted verbatim like any other string, but it
            // cannot go through `emit_string`: raw strings have no escapes, so
            // the `\\` rule there would step over `r"a\"`'s own terminator, and
            // the delimiter is a quote plus N hashes rather than a single byte.
            match raw_string_len(b, i) {
                Some(RawString::Terminated(n)) => {
                    out.push_str(&text[i..i + n]);
                    i += n;
                }
                Some(RawString::Unterminated) => panic!(
                    "code_only: raw string opened at byte {i} and never closed. \
                     Everything after it would be discarded. This is the \
                     stripper reporting on its input, not a claim about \
                     whatever check called it."
                ),
                // A `b`, `c` or `r` that opens no raw string is an ordinary
                // identifier byte -- `b"x"`, `c"x"`, `r#ident`, or just a name
                // starting with one of the three.
                None => {
                    out.push(char::from(b[i]));
                    i += 1;
                }
            }
        } else if b[i] == b'"' {
            i = emit_string(&mut out, i, b'"');
        } else if b[i] == b'\'' {
            match char_literal_len(b, i) {
                Some(n) => {
                    out.push_str(&text[i..i + n]);
                    i += n;
                }
                // Not a char literal, so a lifetime (`&'a`). An ordinary
                // character here.
                None => {
                    out.push('\'');
                    i += 1;
                }
            }
        } else {
            out.push(text[i..].chars().next().unwrap_or('\0'));
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

/// The byte length of the Rust char literal starting at `i`, or `None` if what
/// starts there is not one.
///
/// Lookahead rather than delimiter-tracking, because `'` opens a char literal
/// and also introduces a lifetime, and nothing but lookahead separates `'a'`
/// from `&'a str`. A stripper that treated every `'` as a delimiter would pair
/// the lifetimes in this file with each other and swallow the code between.
///
/// The two that make this load-bearing are `.trim_matches('\'')` and
/// `.matches('"')`, both in this file: a `"`-tracking stripper with no
/// char-literal rule reads the second as opening a string and runs to the next
/// quote thousands of lines away.
fn char_literal_len(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i + 1) == Some(&b'\\') {
        // `'\''` closes at i+3, so the search starts there rather than at the
        // escaped byte -- otherwise the escaped quote closes the literal early.
        // The window covers the longest Rust escape, `'\u{10FFFF}'`.
        let hi = b.len().min(i + 14);
        return b
            .get(i + 3..hi)
            .and_then(|w| w.iter().position(|&c| c == b'\''))
            .map(|rel| 3 + rel + 1);
    }
    // One char, possibly multi-byte, then a closing quote.
    let mut j = i + 2;
    while j < b.len() && (b[j] & 0xC0) == 0x80 {
        j += 1;
    }
    (b.get(j) == Some(&b'\'')).then_some(j + 1 - i)
}

/// What [`raw_string_len`] found at a position that could open a raw string.
///
/// Three outcomes, not two, because "this is not a raw string" and "this is a
/// raw string whose terminator is missing" must not collapse. The first is
/// ordinary code and the scanner walks on; the second is the input being
/// malformed, and silently walking on there is precisely the truncation the
/// other two panicking arms exist to prevent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RawString {
    /// Byte length of the whole literal, prefix and closing hashes included.
    Terminated(usize),
    Unterminated,
}

/// The Rust raw string starting at `i`, if one starts there.
///
/// # What it accepts
///
/// Every spelling: an optional `b` or `c` prefix, then `r`, then **any** number
/// of `#` including zero, then `"`. The literal ends at the first `"` followed
/// by exactly that many `#`. There are no escapes inside -- that is what "raw"
/// means, and it is the half that the hash count does not cover.
///
/// The caller checks the left boundary (the byte before must not continue an
/// identifier) so that `our"` and `for#"` cannot open one.
///
/// # Why this is a separate function from `emit_string`
///
/// `emit_string` implements the *escaped* string grammar: `\\` skips the next
/// byte. Applied to a raw string that rule steps straight over the terminator,
/// so `r"a\"` reads as unterminated and runs to the next `"` in the file. That
/// is one of the three defect classes this repair closes and the only one whose
/// cause is the escape rule rather than the hash count.
///
/// # What it runs over
///
/// **Measured on this tree: 39 raw strings across the inputs `code_only` is
/// pointed at**, in the `r"..."` and `r#"..."#` spellings. The agreement arm
/// below compares this reader's extent against `code_only`'s on every one of
/// them, so the corpus is live evidence rather than a population waiting to
/// exist.
///
/// The constructed unit tests below are still the enforcement rather than the
/// corpus scan, and the reason is unchanged by the count: a corpus scan finds
/// only the spellings today's corpus happens to contain, and the escape-rule
/// defect is reached by `r"a\"`, which nothing in the tree writes. A count
/// above zero makes the agreement arm meaningful; it does not make the
/// constructed cases redundant.
fn raw_string_len(b: &[u8], i: usize) -> Option<RawString> {
    let mut j = i;
    if matches!(b.get(j), Some(&b'b') | Some(&b'c')) {
        j += 1;
    }
    if b.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let first_hash = j;
    while b.get(j) == Some(&b'#') {
        j += 1;
    }
    let hashes = j - first_hash;
    if b.get(j) != Some(&b'"') {
        return None;
    }
    let mut k = j + 1;
    while k < b.len() {
        if b[k] == b'"' && b[k + 1..].iter().take(hashes).filter(|&&c| c == b'#').count() == hashes {
            return Some(RawString::Terminated(k + 1 + hashes - i));
        }
        k += 1;
    }
    Some(RawString::Unterminated)
}

/// The extent of a Rust raw string at `i`, in any spelling, or `None`.
///
/// The auditor's half of the raw-string grammar: a second reader of the same
/// rules as [`raw_string_len`], written separately rather than calling it, so a
/// defect has to occur twice to stay invisible. It is deliberately
/// shaped differently -- one function, one return type, unterminated folded into
/// "runs to EOF" rather than reported -- because two readers that differ only in
/// name share every bug.
///
/// That is weaker than true independence and is said plainly rather than
/// implied: what pins the *grammar* is
/// `stripper_reads_every_raw_string_spelling` and its siblings, whose expected
/// values come from the language. What this pins is the two readers to each
/// other, over the real corpus, inside
/// `code_only_understands_every_construct_its_inputs_contain`.
fn raw_extent(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let mut p = i;
    if matches!(b.get(p), Some(&b'b') | Some(&b'c')) {
        p += 1;
    }
    if b.get(p) != Some(&b'r') {
        return None;
    }
    p += 1;
    let first = p;
    while b.get(p) == Some(&b'#') {
        p += 1;
    }
    let hashes = p - first;
    if b.get(p) != Some(&b'"') {
        return None;
    }
    let mut k = p + 1;
    'scan: while k < b.len() {
        if b[k] == b'"' {
            for d in 0..hashes {
                if b.get(k + 1 + d) != Some(&b'#') {
                    k += 1;
                    continue 'scan;
                }
            }
            return Some(k + 1 + hashes);
        }
        k += 1;
    }
    Some(b.len())
}

#[test]
fn raw_extent_agrees_with_the_strippers_own_reader() {
    // The two readers, side by side on the constructed cases. This is the only
    // place they are compared on inputs the tree does not contain -- the corpus
    // scan compares them on inputs it does, and today there are none.
    for src in [
        "r\"a // b\"",
        "r#\"a\" // b\"#",
        "r##\"a\"# /* b\"##",
        "br#\"a\" // b\"#",
        "cr\"a // b\"",
    ] {
        let b = src.as_bytes();
        let mine = raw_extent(b, 0);
        let theirs = raw_string_len(b, 0);
        assert_eq!(
            mine,
            Some(src.len()),
            "raw_extent disagrees with the language on {src:?}"
        );
        assert_eq!(
            theirs,
            Some(RawString::Terminated(src.len())),
            "raw_string_len disagrees with the language on {src:?}"
        );
    }
    // Both must decline the same non-raw-string bytes.
    for src in ["our\"x\"", "b\"x\"", "r#fn", "rest"] {
        let b = src.as_bytes();
        assert_eq!(raw_extent(b, 0), None, "raw_extent took {src:?}");
        assert_eq!(raw_string_len(b, 0), None, "raw_string_len took {src:?}");
    }
}

// -------------------------------------------------------------------------
// The stripper's own tests
//
// A source-scanning check's own lesson turned on itself: when a check's subject is source
// text, the parser between the two is untested infrastructure. Every other
// check in this file leaned on `code_only` for two phases and nothing pointed
// at it directly, so its one real bug was found by a check about something
// else going red for an unrelated-looking reason.
//
// These are constructed inputs, not corpus scans. That is the point: a corpus
// scan can only find what today's corpus happens to contain, and the two arms
// that panic cannot appear in the corpus at all -- an unterminated string does
// not compile in any of the three languages `code_only` is pointed at, so no
// real input can ever exercise them. They are reachable only from here.
// -------------------------------------------------------------------------

#[test]
fn stripper_removes_comments_and_keeps_code() {
    assert_eq!(code_only("a /* b */ c"), "a  c");
    assert_eq!(code_only("a // b\nc"), "a \nc");
    // Nested-looking, but block comments do not nest in Rust or C: the first
    // closer wins, and the trailing text is code.
    assert_eq!(code_only("a /* b /* c */ d"), "a  d");
}

#[test]
fn stripper_does_not_open_a_comment_inside_a_string() {
    // The stripper's bug, in one line. `t.pass("ui/pass/*.rs")` was read as opening
    // a block comment, and the closer it found was in another file.
    let src = "let g = \"ui/pass/*.rs\"; let x = 1;";
    assert_eq!(code_only(src), src);
    // ... and the literal's contents survive, because the checks downstream
    // search for quoted names.
    assert!(code_only(src).contains("\"ui/pass/*.rs\""));
}

#[test]
fn stripper_does_not_close_a_string_on_an_escaped_quote() {
    let src = "let s = \"a \\\" b\"; let x = 1;";
    assert_eq!(code_only(src), src);
}

#[test]
fn stripper_reads_char_literals_and_leaves_lifetimes_alone() {
    // Both of these appear in this file, and both break a naive quote-tracker:
    // the first opens a string that never closes, the second is not a literal
    // at all.
    let quote_char = "let q = '\"'; let s = \"x\"; let y = 1;";
    assert_eq!(code_only(quote_char), quote_char);
    let escaped = "let q = '\\''; let s = \"x\"; let y = 1;";
    assert_eq!(code_only(escaped), escaped);
    let lifetime = "fn f<'a>(s: &'a str) -> &'a str { s }";
    assert_eq!(code_only(lifetime), lifetime);
    // A lifetime must not swallow the code up to the next one.
    let two = "fn f<'a, 'b>(x: &'a u8, y: &'b u8) {}";
    assert_eq!(code_only(two), two);
}

#[test]
fn stripper_distributes_over_concatenation() {
    // The property `code_only_understands_every_construct_its_inputs_contain`
    // asserts over the real corpus, here on a constructed pair so it is
    // checked even if the corpus stops containing a case that would break it.
    let a = "let g = \"a/*b\";\n";
    let b = "let h = \"c*/d\";\n";
    assert_eq!(
        code_only(&format!("{a}{b}")),
        format!("{}{}", code_only(a), code_only(b))
    );
}

#[test]
#[should_panic(expected = "block comment opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_comment() {
    code_only("let x = 1; /* and then nothing");
}

#[test]
#[should_panic(expected = "string opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_string() {
    code_only("let x = \"and then nothing");
}

// -------------------------------------------------------------------------
// Raw strings
//
// Every input below is written as an ORDINARY escaped Rust string whose
// *contents* spell a raw string. Writing them as raw-string literals would put
// real raw strings into `invariants.rs`, which is in the corpus these very
// tests certify -- the rule that a check must not read its own prose, and here it also protects a measurement:
// the repair's headline number is that it moved the corpus by zero bytes,
// which stops being checkable the moment the checking code adds the construct.
//
// These are constructed rather than scanned for a second reason. The tree
// contains no raw string in any spelling, so a corpus scan for this class can
// only ever report absence. `raw_string_len`'s doc comment states the
// consequence in full: the repair is prophylactic and these tests are its only
// enforcement.
// -------------------------------------------------------------------------

#[test]
fn stripper_does_not_open_a_comment_inside_a_raw_string() {
    // Class 1, and the silent one. A stripper that re-pairs the quotes reads
    // `"a"` as a complete string, leaving ` // b"#;` as code, so the line
    // comment runs to the newline and takes the statement's `;` with it.
    let line = "let s = r#\"a\" // b\"#;\nlet keep = 1;";
    assert_eq!(code_only(line), line);

    // Class 2, silent and the worst of the three: the phantom opener finds a
    // real `*/` further down and deletes everything between. The unrelated
    // comment here must still be stripped, so this asserts both halves at once
    // -- the raw string survives whole AND the genuine comment does not.
    let across = "let s = r##\"a\" /* b\"##;\nlet gone = 1; /* x */\nlet keep = 2;";
    assert_eq!(code_only(across), "let s = r##\"a\" /* b\"##;\nlet gone = 1; \nlet keep = 2;");

    // A closer with no opener, which a stripper that scans for one reads past
    // the `"` after `b` and off the end of the input.
    let closer = "let s = r#\"a\" */ b\"#;\nlet keep = 1;";
    assert_eq!(code_only(closer), closer);
}

#[test]
fn stripper_does_not_apply_escapes_inside_a_raw_string() {
    // Class 3, and the only one whose cause is the escape rule rather than the
    // hash count -- so the `r"` spelling, with no hashes at all, is where it
    // shows. `\` is not an escape in a raw string, so the literal ends at the
    // quote that follows it. `emit_string`'s `\\ => j += 2` steps over that
    // quote and runs to the next one in the file.
    let trailing_backslash = "let s = r\"a\\\";\nlet keep = 1;";
    assert_eq!(code_only(trailing_backslash), trailing_backslash);
}

#[test]
fn stripper_reads_every_raw_string_spelling() {
    // Zero hashes, one, two, and the `b`/`c` prefixes. Each carries a comment
    // token so a spelling that is *not* recognised shows up as damage rather
    // than as an equal string.
    for src in [
        "let s = r\"a // b\";\nlet keep = 1;",
        "let s = r#\"a\" // b\"#;\nlet keep = 1;",
        "let s = r##\"a\"# // b\"##;\nlet keep = 1;",
        "let s = br#\"a\" // b\"#;\nlet keep = 1;",
        "let s = cr\"a // b\";\nlet keep = 1;",
    ] {
        assert_eq!(code_only(src), src, "spelling not recognised: {src:?}");
    }

    // The closing delimiter is a quote followed by EXACTLY the opening hash
    // count. A hash after that belongs to the code, not to the literal.
    let extra_hash = "let s = r#\"a\"#;\nlet keep = 1;";
    assert_eq!(code_only(extra_hash), extra_hash);
}

#[test]
fn stripper_does_not_mistake_ordinary_code_for_a_raw_string() {
    // The other polarity, which is the half a widened rule gets wrong. Each of
    // these contains `r"`, `b"` or `c"` and none of them opens a raw string; if
    // one did, the trailing comment would survive instead of being stripped.

    // `r` continuing an identifier. This is the case the left-boundary check
    // exists for: without it, `our"x"` swallows to the next `"`.
    assert_eq!(code_only("let v = our\"x\"; // c\nlet k = 1;"), "let v = our\"x\"; \nlet k = 1;");
    // A byte string is escaped, not raw: the `\"` must not close it.
    assert_eq!(code_only("let v = b\"x\\\"y\"; // c\nlet k = 1;"), "let v = b\"x\\\"y\"; \nlet k = 1;");
    // A raw *identifier* has hashes and no quote.
    assert_eq!(code_only("let r#fn = 1; // c\nlet k = 2;"), "let r#fn = 1; \nlet k = 2;");
    // A bare `r`, `b` or `c` that begins an ordinary name.
    assert_eq!(code_only("let rest = 1; // c\nlet k = 2;"), "let rest = 1; \nlet k = 2;");

    // The left-boundary rule, on an input that is NOT valid Rust -- and that is
    // the finding rather than a defect in the test. Measured while
    // fault-injecting this file: **removing the boundary check leaves every
    // other case here green**, because a raw string with no hashes and no
    // backslash covers exactly the bytes an ordinary string would, so the two
    // readings are indistinguishable. Only hashes separate them, and
    // `identifier` immediately followed by `#"` does not lex as Rust at all in
    // the 2021 edition (`prefix `our` is unknown`).
    //
    // So the boundary check is **defensive, not load-bearing**: no valid input
    // to this stripper can reach it. It is kept because the cost is one
    // comparison and the alternative is a rule whose scope depends on Rust's
    // lexer continuing to reject a spelling, and it is exercised here on
    // constructed bytes so that "nothing reddens it" is a recorded measurement
    // rather than an untested branch.
    // Read as: `our` and `#` are ordinary bytes, `"a"` is a string emitted
    // whole, and the `//` after it opens a real line comment that runs to the
    // end of the input. Without the boundary check the whole thing is one raw
    // string and ` // b"# y` survives.
    assert_eq!(code_only("x our#\"a\" // b\"# y"), "x our#\"a\" ");
}

#[test]
#[should_panic(expected = "raw string opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_raw_string() {
    // The third panicking arm, on the same reasoning as the other two: a
    // construct the input got wrong must report the stripper and the offset,
    // not silently shorten the corpus and let some unrelated check go red
    // about something unrelated.
    code_only("let x = r#\"and then nothing");
}

/// Every `.rs` under `crates/*/src/`, as `(path relative to the repo root,
/// **raw** text)`.
///
/// Wider than `no_signature_in_tx_rs_hands_out_a_txentry`'s walk, which is
/// scoped to `mochimo-crypto` because its subject is the safe layer built over
/// the bindings. Checks whose subject is "no Rust anywhere does X" need every
/// crate, including ones that do not exist yet: a new crate is picked up by the
/// walk on the day it is added rather than on the day someone remembers to list
/// it.
///
/// Split out of [`crate_sources`] with the raw-string repair, the same shape
/// `test_source_files()`/`test_sources()` already had and for the same reason:
/// one walk with two views, so "the two agree" is structural instead of said.
/// The raw view has one consumer,
/// `no_native_endian_conversions_anywhere_in_the_crate`, which lexes rather
/// than searches and so must not be handed pre-stripped text.
///
/// Note what does **not** apply here. `test_source_files()` must be raw or the
/// check that measures the stripper measures it against its own output
///, and a floor asserts that. This one carries no such hazard: its
/// consumer drops comments in the lexer, so stripping first would be redundant
/// rather than self-comparing. The asymmetry is worth stating precisely because
/// the two helpers now look alike.
fn crate_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let crates = root.join("crates");
    let mut out: Vec<(String, String)> = Vec::new();

    let members = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates.display()));
    for member in members.flatten() {
        let src = member.path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut stack = vec![src];
        while let Some(d) = stack.pop() {
            let entries = std::fs::read_dir(&d)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p)
                        .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                    let name = p
                        .strip_prefix(&root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .into_owned();
                    out.push((name, text));
                }
            }
        }
    }
    out.sort();
    out
}

/// [`crate_source_files`] with comments stripped. The view every consumer that
/// *searches* this set uses; see that function for why the raw one exists.
fn crate_sources() -> Vec<(String, String)> {
    crate_source_files()
        .into_iter()
        .map(|(name, text)| {
            let code = code_only(&text);
            (name, code)
        })
        .collect()
}

/// Every `.rs` under this crate's `tests/`, **comment-stripped** and
/// concatenated in sorted path order. Used by checks whose subject is the suite
/// itself rather than any one vector.
///
/// This is `test_source_files()` joined, rather than a second copy of the same
/// walk. The check that scans this corpus for stripper damage replays "the
/// concatenation exactly as `test_sources()` does", which is an unverifiable
/// claim against a second walk said to agree. One walk makes it structural.
///
/// # The strip
///
/// `test_source_files()` is deliberately still **raw**, because
/// `code_only_understands_every_construct_its_inputs_contain` consumes it
/// precisely to test `code_only` itself -- a stripper cannot be measured
/// through its own output. The asymmetry is load-bearing in both directions:
/// one side strips, its consumer does not, and neither is a copy of the other.
///
/// **This sentence named a test that does not exist** for several
/// sessions: `stripper_damage_is_measured_over_the_corpus_it_is_used_on`
/// appears nowhere in the tree but here. Recorded rather than quietly corrected,
/// because the shape is worth more than the instance. The verification-layer
/// defect class is a comment that has become false; this one's *claim* stayed true the whole
/// time -- the asymmetry really is enforced -- just not by the means it named.
/// A reader checking the claim finds it holds and stops; a reader looking for
/// the named test finds nothing and has no reason to think the property is
/// unguarded. Both readings are wrong in a way that leaves no trace.
///
/// What actually enforces it is the `doc_openers >= 200` floor inside that
/// test: a raw `tests/` corpus has thousands of `///` line starts and a
/// stripped one has none, so routing this walk through `code_only` trips it.
/// Fault-injected with the raw-string repair, not inherited from the strip's word.
///
/// Before the strip this side was raw too, and every existence-by-name guard built on
/// it -- fourteen call sites -- was satisfied by a *commented-out* copy of the
/// test it demanded. `/* fn the_required_test() { .. } */` kept the needle
/// matching while nothing ran. That half is closed here.
///
/// **Those fourteen call sites are gone since the census.** They key on the `census`
/// module now, which asks libtest rather than this corpus, so the paragraph
/// above is history rather than a live account of what depends on the strip.
/// One name lookup remains and it is a different shape:
/// `group_e_constants_stay_anchored` uses `find` to LOCATE a function body it
/// then reads, not to assert that a test exists.
///
/// What still reads this corpus is the source-scanning family --
/// `no_native_endian_conversions_anywhere_in_the_crate`, the fixture-field
/// scans, the `MIRI_DOMAIN` completeness walk -- and for those the strip is
/// doing exactly what it always did.
fn test_sources() -> String {
    let mut out = String::new();
    for (_, text) in test_source_files() {
        out.push_str(&code_only(&text));
        out.push('\n');
    }
    // # This needle is a written literal and matches its own source line. That
    // # is the MECHANISM here, not a defect, and the difference was measured.
    //
    // Anchor B in `ripemd160_faulting_class_is_anchored_by_a_non_reference_oracle`
    // was the identical construct and *was* a defect, since repaired. The two
    // are told apart by one question, and it is a `grep` rather than a
    // judgement: **where does the self-matching text live relative to the
    // check's stated subject?**
    //
    //   this site   subject: "did the walk pick up invariants.rs?"
    //               the matching literal is IN invariants.rs
    //               -> the match is present exactly when the subject is true.
    //                  It CONSTITUTES the claim.
    //
    //   Anchor B    subject: "does another test file still define <name>?"
    //               the matching literal was in invariants.rs, and the corpus
    //               was every file under tests/
    //               -> the match was present whatever the subject file held.
    //                  It SUBSTITUTED for the claim.
    //
    // Confirmed by injection rather than argued, both directions:
    //
    //   * make the walk skip `invariants.rs` -> this fires, with this message.
    //     So it does the job attributed to it.
    //   * rename the named function away -> this stays GREEN, correctly:
    //     its subject is the walk, not that function. A rename of a censused
    //     guard is caught by `censused_rows_are_bound_to_live_guards`, which
    //     is the check whose subject it actually is.
    //
    // **Do not "fix" this by constructing the needle.** Constructing it removes
    // the literal from the corpus, and the only remaining occurrence would be
    // the `fn` at the definition -- which makes the check depend on that one
    // function continuing to exist, a thing it does not claim and the census
    // already owns. TWO checks read this corpus -- `group_e_constants_stay_anchored`
    // and `crosscheck_fields_stay_asserted`, the only two callers of
    // `test_sources()`; every other mention of it in this file is prose. This
    // assertion is what stands between a broken walk and both of them passing
    // over an empty string.
    //
    // **It names no count, on purpose.** A raw `grep -c "test_sources("`
    // counts the comment mentions above as well as the two calls, so a figure
    // taken from one tracks the grep and not the callers. A documentation-only pass corrected the two documents and
    // could not correct this file; a later audit did, and
    // **names the two consumers instead of counting them** -- the grep reads
    // 30 again today, so a number here would re-enter the same defect the
    // moment somebody "checked" it.
    assert!(
        out.contains("fn no_native_endian_conversions_anywhere_in_the_crate"),
        "test_sources() did not pick up invariants.rs; the walk is broken and \
         every check built on it would pass vacuously"
    );
    out
}

// ===========================================================================
// The execution census
// ===========================================================================

/// Did the named test **run**, and did libtest say it passed?
///
/// Every guard above this point that demanded a test asked `test_sources()` for
/// the characters `fn <name>`. That is a claim about a file. What the guards'
/// doc comments promise is a claim about a *run*, and a review round measured the distance:
/// four board reds fall to a colliding name (corrected), and ten
/// green guards are satisfied **today** by a named test with an empty body.
/// This module is the closing move that finding queued.
///
/// # The population is libtest's, and that is the whole point
///
/// Nothing in this module parses Rust. The names come from libtest's own
/// `--list` and the verdicts from libtest's own summary line, because a parser
/// and the runner can disagree about what the suite contains: a test emitted by
/// a macro, or nested in a `cfg`-gated inline module, is a name the runner has
/// and an item walk does not. `execution_census_population_is_libtests_run_list`
/// holds the population to the run list so that a later rewrite cannot quietly
/// swap it for a parsed one.
///
/// # Why the guard drives the run, rather than reading a manifest
///
/// The four mechanisms that were weighed, and what each measured:
///
/// * **An in-process registry** — `OnceLock`, `inventory`, `#[ctor]`. Fails
///   structurally, not for want of a crate: nine of the censused targets live in
///   `miri`, `kat`, `signing`, `cli` and `compile_fail`, which are other
///   **processes**. Nothing a test registers is visible to a guard in
///   `invariants`. Even same-binary registration is order-dependent, because
///   libtest's order within a binary is arbitrary.
/// * **A two-phase run** — one invocation writes a manifest, a second asserts
///   against it. Rejected on staleness: nothing binds a manifest to the tree
///   that produced it short of hashing the world, and a manifest not yet
///   produced turns ten guards red for a reason that is not their subject, which
///   is the rule that "a marker nobody can discharge trains the reader to skim
///   past reds".
/// * **Globbing `target/debug/deps/`** for a sibling binary. Measured at this
///   HEAD: **ten** `invariants-*` and **eight** `native-*` executables are
///   present. The filename hash is a *configuration* hash, not a content hash —
///   touching a test file and rebuilding keeps the same name — so the stale ones
///   are old feature sets, and picking among them by mtime is exactly the
///   ad-hoc-shell prohibition.
/// * **Asking cargo, at test time.** Measured: with an outer `cargo test` in its
///   run phase, a nested `cargo test --workspace --no-run --message-format=json`
///   returns in 0.12 s and does not block. Cargo holds no build lock while it is
///   running test binaries. This is the only mechanism that names the *current*
///   binaries without consulting a timestamp, so it is the one used.
///
/// # What execution alone does not establish
///
/// **An empty `#[test] fn foo() {}` runs, and passes.** Measured, not assumed.
/// A census that stopped at "it ran and libtest said ok" would be green over
/// the empty-body injection exactly, so it would have closed nothing.
///
/// What separates a hollow test from a real one at run time is that every
/// censused target prints a line reporting what it measured. `--show-output`
/// makes that structural rather than a substring hunt: a passing test that
/// printed something gets a `---- <name> stdout ---- ` block, and one that
/// printed nothing gets no block at all.
///
/// # Residue — read this before treating a green census as the property
///
/// This module is the sole mechanism for "the required test ran", so
/// what it cannot see is recorded here:
///
/// * **A substantial body that prints a plausible evidence line is a forgery
///   this cannot detect.** The census raises the accident from *anyone writes a
///   function with a colliding name* to *someone writes a passing test with a
///   colliding name that prints a matching line with a number above the floor*.
///   That is a deliberate act, not an accident, and it is the residue.
/// * **`Tier::Listed` is blind to `#[ignore]`.** Measured: `--list` prints an
///   ignored test as `name: test`, indistinguishable from any other.
///   `Tier::Executed` catches it — an ignored test reports `test result: ok` with
///   `0 passed; 1 ignored`, which is why the verdict parse below counts `passed`
///   and never reads the word `ok`. Suite-wide the case is covered by
///   `no_test_in_the_suite_is_ignored`.
/// * **It says nothing about whether the assertions inside the target are
///   right.** It says they ran.
mod census {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};

    /// Set on every child the census spawns.
    ///
    /// A censused test must never itself census: `group_f_is_specification_not_crosscheck`
    /// requires `group_c_crosscheck_is_an_executed_oracle`, which is a census
    /// caller, and spawning it would nest. The rule is enforced by this variable
    /// rather than remembered — a child that reaches [`executables`] panics —
    /// and the two guard-on-guard edges are declared [`Tier::Listed`] for
    /// exactly that reason.
    const CHILD: &str = "MOCHIMO_CENSUS_CHILD";

    /// How much of libtest's answer a given edge consumes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Tier {
        /// The name is in that binary's own `--list`.
        ///
        /// Defeats a plain non-`#[test]` `fn`, a helper, a `cfg`-out, a
        /// comment-out, a rename and a macro shape no parser recognises. Blind
        /// to `#[ignore]` and to a hollow body. Used only where executing the
        /// target would re-enter the census.
        Listed,
        /// Spawned, `1 passed`, `0 ignored`, and it printed its measurement.
        Executed,
    }

    /// One guard's demand on one test.
    pub struct Row {
        /// The guard that owns this demand. Bound so that renaming a guard out
        /// from under its row is caught rather than silently orphaning it.
        pub guard: &'static str,
        pub target: &'static str,
        /// The cargo *target* name, i.e. `tests/compile_fail.rs` is `compile_fail`.
        pub bin: &'static str,
        pub tier: Tier,
    /// A substring the target must print. Removed from the block before the
        /// integer scan below, so a digit inside the needle itself — `ripemd-160`
        /// contains `160` — cannot satisfy the floor on its own.
        pub evidence: &'static str,
        /// The largest integer the target printed must be at least this. It
        /// catches the target that runs over an empty set and reports `0`, which
        /// executing and passing cannot distinguish from real work.
            /// A floor on the largest integer the target prints.
        ///
        /// # The hazard this creates, stated where the rule lives
        ///
        /// **A floor read out of free text is bounded by the largest thing the test
        /// ever prints — including things printed for a reader.** The drop-witness measurement came within
        /// one design decision of this: the timing proof would naturally have
        /// reported wall-clock nanoseconds, which would have made the largest
        /// integer in its block a six-figure number and cleared a floor of `3`
        /// derived from `port-inventory` §3's three sites. The floor would have gone
        /// on passing while asserting nothing about what it was derived from.
        ///
        /// Neither side is wrong and neither can see the other: nothing here names
        /// a target, and nothing a target would plausibly print mentions a census.
        /// **Anything emitted inside a censused block is an input to this rule.**
        /// Before adding a diagnostic under a censused name, check what it does to
        /// that row's floor.
        ///
        /// The rule is deliberately unchanged — a declared key or a magnitude bound
        /// would be redesigning a working mechanism in the session that tripped
        /// over it, which is the shape this project avoids, aimed at a check.
        pub floor: u64,
    }

    /// Every demand in this file, in one place.
    ///
    /// `censused_rows_are_bound_to_live_guards` asserts each `guard` is a test
    /// libtest actually lists, so this table cannot drift away from the guards
    /// it serves. The floors are two-sided in spirit: each is set
    /// well under the value measured when the census landed, and the measurement is named beside
    /// it so a drift is legible instead of mysterious.
    pub const ROWS: &[Row] = &[
        // --- I6's two compiler-held absences and the drop witness ---------
        Row {
            guard: "secret_has_no_equality_and_nothing_enforces_it",
            target: "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            bin: "compile_fail",
            tier: Tier::Executed,
            evidence: "compile-fail partition:",
            floor: 4, // the largest integer printed is the fail-case total; 18 today
        },
        Row {
            guard: "zeroization_has_no_reference_counterpart",
            target: "secret_bytes_are_gone_after_drop",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "zeroization:",
            floor: 96, // 32 + 64 bytes witnessed across the two widths
        },
        Row {
            guard: "secret_holder_debug_redaction_is_enforced_by_the_scan",
            target: "no_holder_of_key_material_derives_debug",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "Debug-holder scan:",
            floor: 1,
        },
        Row {
            guard: "key_material_copies_are_enforced_by_the_scan",
            target: "no_key_material_is_copied_into_an_unprotected_buffer",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "key-material copy scan:",
            floor: 8, // measured 15 expose() sites the AST walk reaches
        },
        // --- the oracle-class routing over the corpus --------------------
        Row {
            guard: "group_c_crosscheck_is_an_executed_oracle",
            target: "group_rx_is_an_oracle_with_no_reference_side",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "group RX:",
            floor: 10, // measured 26 vectors
        },
        Row {
            guard: "group_f_is_specification_not_crosscheck",
            target: "group_rx_is_an_oracle_with_no_reference_side",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "group RX:",
            floor: 10, // measured 26 vectors
        },
        Row {
            // The one guard-on-guard edge, and the reason Tier::Listed exists.
            // Executing this target would re-enter the census, because the
            // target is itself a census caller.
            guard: "group_f_is_specification_not_crosscheck",
            target: "group_c_crosscheck_is_an_executed_oracle",
            bin: "invariants",
            tier: Tier::Listed,
            evidence: "",
            floor: 0,
        },
        // --- group E's 33 constants, compared to the fixture the C printf'd --
        //
        // The comparison lives in `tests/kat.rs`; this row is what makes the
        // guard demand that it RUNS rather than that its text exists. A
        // `#[cfg]`-ed out checker still contains every constant's name and
        // satisfies a text scan over nothing.
        Row {
            guard: "group_e_constants_stay_anchored",
            target: "group_e_constants_match_the_reference",
            bin: "kat",
            tier: Tier::Executed,
            evidence: "group E constants anchored",
            floor: 32, // every integer the constants block carries but sizeof_TX
        },
        // --- Miri's domain over the native backend --------------------------
        Row {
            guard: "memory_safety_is_established_only_for_the_native_paths_miri_walks",
            target: "native_backend_is_clean_under_miri",
            bin: "miri",
            tier: Tier::Executed,
            evidence: "native functions",
            floor: 26, // two thirds of the 39 of 41 measured on this tree
        },
        // --- the transaction codec, in the binary gated on `native` alone ---
        Row {
            guard: "native_transaction_path_is_checked_on_layout_not_acceptance",
            target: "native_transaction_round_trip_needs_no_reference",
            bin: "txwire",
            tier: Tier::Executed,
            evidence: "C-free transaction round trip:",
            // 45: group D names 49 wire images of which the
            // reference itself rejects 4 (D14's one-byte-long form and D15's
            // three unknown-type cases), so 45 is the accepted population a
            // round trip can cover. A floor on IMAGES ROUND-TRIPPED; the proof
            // test's own stated-count asserts are what hold the number exactly.
            floor: 45,
        },
        // --- I8 ---------------------------------------------------------------
        Row {
            guard: "imported_account_restore_is_checked_in_memory_not_on_disk",
            target: "imported_account_restores_from_stored_seed",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "restore path:",
            floor: 1,
        },
        Row {
            guard: "imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture",
            target: "imported_index_zero_pk_reproduces_the_first_address",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I8 first key:",
            floor: 1, // one imported account whose position-0 pk equals its faddress pk
        },
        // --- I2, I3, I4, I5: the crash-consistency and restore proofs. The ---
        // --- floors are derived from the invariants' own text -- see each  ---
        // --- guard's doc comment for which sentence each number comes from.---
        Row {
            guard: "index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss",
            target: "signature_is_not_released_before_the_index_is_durable",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I2 durability:",
            floor: 1, // at least one injected crash point between persist and return
        },
        Row {
            guard: "spend_state_is_atomic_under_syscall_kill_not_power_loss",
            target: "spend_state_is_never_observed_half_advanced",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I3 atomicity:",
            floor: 4, // temp write, fsync file, rename, fsync dir -- I3's own clause
        },
        Row {
            guard: "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
            target: "startup_refuses_to_start_on_index_divergence",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I4 reconciliation:",
            floor: 2, // local ahead and local behind -- I4's own Test clause
        },
        Row {
            guard: "restore_derives_the_index_within_the_scan_bound_never_from_zero",
            target: "restore_derives_the_index_from_chain_state",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I5 restore scan:",
            // Twenty positions, each found exactly, each by its own restore.
            // The proof names its own walk rather than taking the default,
            // because one restore per position costs n(n+1)/2 derivations and
            // 10,000 of them is about 616 hours in this profile. The floor is
            // the walk the proof is required to drive, not the default.
            floor: 20,
        },
        // --- The acknowledged path I4's report names, executed through
        // the shipped binary under a pty against a loopback ledger. Dispatched
        // behind the `Wallet::open` that refuses on the divergence it was
        // started to reconcile, that path does not exist in the binary at all,
        // and nothing but a census notices.
        // The floor is the prompts the run answers: nine commands, each
        // opening the store once.
        Row {
            guard: "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
            target: "pty::reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty reconcile:",
            floor: 9,
        },
        // --- I6 at rest: the target needs a real store on disk, so it lives
        // beside the keystore's other round-trip tests rather than here.
        Row {
            guard: "imported_roots_and_the_master_seed_are_encrypted_at_rest",
            target: "snapshot_bytes_never_contain_the_imported_root",
            bin: "keystore",
            tier: Tier::Executed,
            evidence: "I6 at rest:",
            floor: 1, // one root witnessed absent from the file and present after restore
        },
        // --- I1, enforced -- four instruments under one guard ---
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "each_wots_key_signs_once_through_the_receipt_gate",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "I1 one signature:",
            floor: 2, // I1's test clause: sign twice at one index, the second refused
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            bin: "compile_fail",
            tier: Tier::Executed,
            evidence: "compile-fail partition:",
            floor: 4, // the four signing_* cases; their own floor is inside the partition
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "raw_signer_is_unreachable_from_a_default_features_dependent",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "downstream probe:",
            floor: 2, // the two spellings of the raw signer a dependent can write
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "no_wallet_visible_fn_hands_out_a_wots_signature",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "raw-signer route scan:",
            floor: 2, // the two ports of the reference's signer the scan must find private
        },
        // --- I1 across accounts ---------------------------
        Row {
            guard: "duplicate_key_streams_are_refused_within_one_keystore_not_across_stores",
            target: "duplicate_key_streams_are_refused_across_kinds_after_reopen",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "I1 stream identity:",
            floor: 2, // both kinds: the two constructors that would carry the identity
        },
        // --- the mesh Reader permission, backed by an executed refusal ------
        Row {
            guard: "mesh_reader_permission_is_backed_by_a_refusing_check",
            target: "attach_refuses_every_mismatched_component",
            bin: "spend",
            tier: Tier::Executed,
            evidence: "attach refusals:",
            floor: 5, // position, public key, signature bytes, public seed, source hash
        },
        // --- The binary's Terminal impl, backed by an executed pty run --------
        //
        // The print ban over `impl Terminal for Tty` in
        // `the_cli_cannot_reach_around_the_wallet` is a text property. What
        // establishes that the impl actually shows the operator anything is
        // this row: the shipped binary, built and driven under script(1)'s
        // pseudo-terminal, answering six prompts across `create` and `create
        // --from-phrase`. The floor is the prompt count the harness reports
        // (3 + 3); it prints no other integer, deliberately.
        Row {
            guard: "the_cli_cannot_reach_around_the_wallet",
            target: "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty create:",
            floor: 6, // measured 6 prompts
        },
        // --- The shared password prompt of the eight store-opening
        // commands, backed by an executed pty run with stderr redirected -----
        //
        // The create finding listed this prompt under "what it cannot see": the row
        // above drives `create`, whose prompts go through the `Tty` impl, and
        // the free `read_secret_line` the other eight prompt through was not
        // driven. It is now the same impl, and this row demands the run that
        // shows the prompt on the screen and not in the stderr file. The
        // floor is the prompt count the test reports (3 for `create`, 1 for
        // `address`); it prints no other integer.
        Row {
            guard: "the_cli_cannot_reach_around_the_wallet",
            target: "pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty password:",
            floor: 4, // measured 4 prompts
        },
    ];

    /// Targets actually spawned this process, for the census's own report.
    static SPAWNED: AtomicUsize = AtomicUsize::new(0);

    pub fn spawned() -> usize {
        SPAWNED.load(Ordering::Relaxed)
    }

    fn repo_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives at <repo>/crates/mochimo-crypto")
            .to_path_buf()
    }

    fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
        let ca = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
        let cb = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
        ca == cb
    }

    /// `target name -> current executable`, straight from cargo.
    ///
    /// Everything here is a panic rather than a soft failure. An instrument that
    /// cannot identify the tree it is measuring must say so; returning "not
    /// found" would arrive at a guard as *the property is unmet*, which is a
    /// different sentence about a different subject.
    pub fn executables() -> &'static BTreeMap<String, Target> {
        static EXES: OnceLock<BTreeMap<String, Target>> = OnceLock::new();
        EXES.get_or_init(|| {
            assert!(
                std::env::var_os(CHILD).is_none(),
                "{CHILD} is set, so this process is a census child, and a \
                 censused test has re-entered the census. Whatever edge led \
                 here must be declared Tier::Listed instead. This is a defect \
                 in the census table, not in the test that tripped it."
            );

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| {
                panic!(
                    "CARGO is unset. Cargo sets it for every test process it \
                     runs, so this test is not being run by cargo and the \
                     census cannot identify the current test binaries. Run the \
                     board with `cargo test`, not by invoking the binary."
                )
            });

            // Match the profile the outer run is using. Getting this wrong is
            // not silent: the identity check below fails, because cargo would
            // name a different `invariants` executable than the one running.
            let me = std::env::current_exe().expect("current_exe");
            let release = me.components().any(|c| c.as_os_str() == "release");

            let mut cmd = Command::new(&cargo);
            cmd.current_dir(repo_root())
                .args(["test", "--workspace", "--no-run", "--message-format=json"]);
            if release {
                cmd.arg("--release");
            }
            let out = cmd
                .output()
                .unwrap_or_else(|e| panic!("could not run `{cargo} test --no-run`: {e}"));
            assert!(
                out.status.success(),
                "`cargo test --workspace --no-run` failed ({}). The census \
                 cannot identify the current test binaries, so no guard built \
                 on it can report anything about its subject.\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );

            let mut map: BTreeMap<String, Target> = BTreeMap::new();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
                    continue;
                }
                if v.get("profile").and_then(|p| p.get("test")).and_then(|t| t.as_bool())
                    != Some(true)
                {
                    continue;
                }
                let (Some(exe), Some(name), Some(manifest)) = (
                    v.get("executable").and_then(|e| e.as_str()),
                    v.get("target").and_then(|t| t.get("name")).and_then(|n| n.as_str()),
                    v.get("manifest_path").and_then(|m| m.as_str()),
                ) else {
                    continue;
                };
                // The package root, which is the directory cargo makes CURRENT
                // when it runs this binary. Carried rather than assumed -- see
                // `run` for the vacuous pass that assuming it produced.
                let pkg_dir = PathBuf::from(manifest)
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf();
                let t = Target {
                    exe: PathBuf::from(exe),
                    pkg_dir,
                };
                if let Some(prev) = map.insert(name.to_owned(), t) {
                    assert_eq!(
                        prev.exe.as_path(),
                        std::path::Path::new(exe),
                        "cargo reported two different executables for target \
                         `{name}`; the census cannot tell which one the board \
                         ran"
                    );
                }
            }
            assert!(
                !map.is_empty(),
                "cargo reported no test executables. Every census result would \
                 be vacuous, so this is a panic and not an empty answer."
            );

            // The staleness cure, and the only one this design needs. If the
            // nested resolution differs from the build actually running -- a
            // different feature set, a different profile, a different target
            // dir -- cargo names a different `invariants-<hash>` and the census
            // stops here rather than measuring some other tree and reporting
            // about this one.
            let theirs = map.get("invariants").unwrap_or_else(|| {
                panic!(
                    "cargo listed no `invariants` test target, but this code is \
                     running inside it. The census cannot establish that it is \
                     looking at the build it is part of."
                )
            });
            assert!(
                same_file(&theirs.exe, &me),
                "cargo resolves the `invariants` test binary to\n  {}\nbut this \
                 process is\n  {}\nso the nested resolution is a different build \
                 configuration from the one running. The sibling paths it \
                 reports would be that other build's, and every census verdict \
                 would be about a tree nobody ran. Re-run the board with the \
                 same features and profile. `./board check` is that board; \
                 `cargo test --all-features` is the usual way to arrive here, \
                 because the nested resolution above does not carry that flag.",
                theirs.exe.display(),
                me.display()
            );
            map
        })
    }

    /// One cargo test target: the binary, and the directory cargo runs it in.
    pub struct Target {
        pub exe: PathBuf,
        /// The owning package's root. **Load-bearing** -- see `run`.
        pub pkg_dir: PathBuf,
    }

    fn exe_for(bin: &str) -> &'static Target {
        executables().get(bin).unwrap_or_else(|| {
            panic!(
                "cargo reported no test executable named `{bin}`. The census \
                 table names it as a binary; either the target was renamed or \
                 removed, or the table is wrong."
            )
        })
    }

    /// libtest's own enumeration for one binary.
    ///
    /// `--list` and not a parser: the runner's names are the population the
    /// guards are checked against, and an item walk can spell a nested or
    /// macro-emitted name differently or miss it.
    pub fn listed(bin: &str) -> BTreeSet<String> {
        static LISTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> = OnceLock::new();
        let cache = LISTS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut g = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hit) = g.get(bin) {
            return hit.clone();
        }
        let t = exe_for(bin);
        let out = Command::new(&t.exe)
            .args(["--list", "--format", "terse"])
            .env(CHILD, "1")
            .output()
            .unwrap_or_else(|e| panic!("could not list tests in {}: {e}", t.exe.display()));
        assert!(
            out.status.success(),
            "`{} --list` failed ({})",
            t.exe.display(),
            out.status
        );
        let names: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_suffix(": test"))
            .map(|s| s.to_owned())
            .collect();
        // No floor here, deliberately, and it took a red to place it right.
        // `listed` is a plain reader over every binary cargo builds, and two of
        // those -- the `mochimo_sys` and `mochimo_crypto` lib unittest targets
        // -- legitimately hold zero tests. A floor here reported that as a
        // broken walk. The floor belongs where an empty list would actually be
        // vacuous, which is a binary the census is about to draw a conclusion
        // from; it is asserted in `check` instead. The census's own question in miniature: the
        // set being floored was not the set being checked.
        g.insert(bin.to_owned(), names.clone());
        names
    }

    /// What libtest said when the target was run on its own.
    #[derive(Clone)]
    pub struct Outcome {
        pub running: usize,
        pub passed: usize,
        pub failed: usize,
        pub ignored: usize,
        /// The `---- <name> stdout ----` block, if the target printed anything.
        pub stdout_block: Option<String>,
        pub raw: String,
    }

    fn parse_outcome(name: &str, text: &str) -> Outcome {
        let mut running = None;
        let (mut passed, mut failed, mut ignored) = (0usize, 0usize, 0usize);
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("running ") {
                // "running 1 test" / "running 0 tests"
                if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
                    running = Some(n);
                }
            }
            if let Some(rest) = line.trim().strip_prefix("test result:") {
                // The LAST two tokens of each segment, not the first two. The
                // opening segment is `ok. 1 passed` -- three tokens, because
                // libtest puts the overall verdict in front of the first count.
                // Taking the first two read `("ok.", "1")`, parsed nothing, and
                // reported `0 passed` for a test that passed. Caught by running
                // it; a boolean `contains("ok")` would have hidden it, and would
                // also have been true for an #[ignore]d test.
                for part in rest.split(';') {
                    let tok: Vec<&str> = part.split_whitespace().collect();
                    let [.., n, what] = tok[..] else { continue };
                    let Ok(n) = n.trim_end_matches('.').parse::<usize>() else {
                        continue;
                    };
                    match what {
                        "passed" => passed = n,
                        "failed" => failed = n,
                        "ignored" => ignored = n,
                        _ => {}
                    }
                }
            }
        }
        // The `--show-output` block. It ends at the next `---- ` marker or at
        // libtest's `successes:` / `failures:` roll-up, whichever comes first.
        let marker = format!("---- {name} stdout ----");
        let block = text.split_once(&marker).map(|(_, after)| {
            after
                .lines()
                .skip(1)
                .take_while(|l| {
                    !l.starts_with("---- ") && *l != "successes:" && *l != "failures:"
                })
                .collect::<Vec<_>>()
                .join("\n")
        });
        Outcome {
            running: running.unwrap_or_else(|| {
                panic!(
                    "libtest printed no `running N tests` line for {name}. The \
                     harness output could not be read, so nothing is known \
                     about whether it ran.\n{text}"
                )
            }),
            passed,
            failed,
            ignored,
            stdout_block: block,
            raw: text.to_owned(),
        }
    }

    /// Run one target on its own and read libtest's verdict.
    pub fn run(bin: &str, name: &str) -> Outcome {
        static RUNS: OnceLock<Mutex<BTreeMap<(String, String), Outcome>>> = OnceLock::new();
        let cache = RUNS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let key = (bin.to_owned(), name.to_owned());
        let mut g = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hit) = g.get(&key) {
            return hit.clone();
        }
        let t = exe_for(bin);
        // Two things about the child's context, and BOTH were found by
        // injection rather than by reasoning.
        //
        // **Environment.** The child inherits this process's, which is cargo's.
        // Load-bearing: `every_ui_case_compiles_or_fails_for_its_pinned_reason` drives
        // trybuild, which shells out to `$CARGO`, and it fails outright when
        // spawned from a bare shell that has no `CARGO` set.
        //
        // **Working directory.** `pkg_dir`, the OWNING PACKAGE's root, because
        // that is the directory cargo makes current when it runs a test binary.
        // The workspace root is not interchangeable with it: as cwd,
        // trybuild finds no cases,
        // compiles nothing and reports `ok` in 0.12 s, where the same binary
        // under cargo's own cwd takes 0.96 s and FAILS. That is a vacuous pass
        // inside the module written to prevent vacuous passes, and it was
        // invisible from the green side -- it surfaced only when a fault
        // row's injection (the pinned `.stderr` stops naming `PartialEq`) was
        // expected red and came back green. **A census that runs a test in a
        // different working directory than cargo does is not measuring that
        // test.**
        let out = Command::new(&t.exe)
            .args(["--exact", name, "--show-output", "--test-threads=1"])
            .env(CHILD, "1")
            .current_dir(&t.pkg_dir)
            .output()
            .unwrap_or_else(|e| panic!("could not run {} --exact {name}: {e}", t.exe.display()));
        SPAWNED.fetch_add(1, Ordering::Relaxed);
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        let outcome = parse_outcome(name, &text);
        g.insert(key, outcome.clone());
        outcome
    }

    /// The largest integer in `block`, with the first occurrence of `needle`
    /// blanked out first.
    ///
    /// The blanking is not fussiness. `ripemd-160 faulting class:` contains
    /// `160`, so without it that row's floor would be satisfied by printing the
    /// needle and nothing else — the check would be reading its own demand back.
    fn max_int(block: &str, needle: &str) -> u64 {
        let scrubbed = if needle.is_empty() {
            block.to_owned()
        } else {
            block.replacen(needle, " ", 1)
        };
        let mut best = 0u64;
        let mut cur = String::new();
        for ch in scrubbed.chars().chain(std::iter::once(' ')) {
            if ch.is_ascii_digit() {
                cur.push(ch);
            } else {
                if !cur.is_empty() {
                    best = best.max(cur.parse().unwrap_or(0));
                    cur.clear();
                }
            }
        }
        best
    }

    fn row(guard: &str, target: &str) -> &'static Row {
        ROWS.iter()
            .find(|r| r.guard == guard && r.target == target)
            .unwrap_or_else(|| {
                panic!(
                    "no census row for ({guard}, {target}). A guard asking for a \
                     target it never declared would otherwise be answered by \
                     silence, which reads exactly like a pass."
                )
            })
    }

    /// The census's answer for one edge.
    ///
    /// `Ok` carries the evidence the target printed, so a guard can put it in
    /// its own output. `Err` carries a sentence naming which of the conditions
    /// failed — never a bare boolean, because "no test of this name" and "the
    /// test ran and printed nothing" are different findings about different
    /// subjects.
    pub fn check(guard: &str, target: &str) -> Result<String, String> {
        let r = row(guard, target);
        let listed = listed(r.bin);
        assert!(
            !listed.is_empty(),
            "`{}` lists no tests at all, and the census is about to draw a \
             conclusion about `{target}` from that binary. Every verdict would \
             be \"absent\", which is the vacuous answer this module exists to \
             prevent -- so it is a panic about the instrument, not a finding \
             about the subject.",
            r.bin
        );
        if !listed.contains(target) {
            return Err(format!(
                "`{target}` is not in the run list of the `{}` test binary. \
                 libtest lists {} tests there and this is not one of them, so \
                 nothing of that name RUNS -- a plain `fn` with the right name, \
                 a helper that is not a `#[test]`, a `cfg`-ed out item or a \
                 commented-out copy all look like this.",
                r.bin,
                listed.len()
            ));
        }
        if r.tier == Tier::Listed {
            return Ok(format!("listed in `{}`", r.bin));
        }

        let o = run(r.bin, target);
        // DEFENSIVE, and labelled so rather than left looking load-bearing.
        //
        // This is the shape that defeated R1's harness -- `--exact <name>` on a
        // name matching nothing prints `running 0 tests`, exits 0, and reads
        // exactly like a pass. It is counted here rather than trusted. But no
        // injection reaches this arm, because the run-list check above uses the
        // same libtest predicate: a name `--exact` would miss is a name `--list`
        // does not print, so the arm above fires first and says something more
        // useful. Every attempt to redden this one landed there instead.
        //
        // Kept because the two are separate calls to separate processes and
        // nothing guarantees they stay the same predicate, and because deleting
        // it would leave the 0-match case reading as a pass if they ever
        // diverge. Not kept as evidence of anything: it has never fired.
        if o.running != 1 {
            return Err(format!(
                "running `{}` with `--exact {target}` matched {} tests, not 1. \
                 A filter that matches nothing exits 0 and reads exactly like a \
                 pass, which is why this is counted rather than trusted.",
                r.bin, o.running
            ));
        }
        if o.ignored != 0 {
            return Err(format!(
                "`{target}` is #[ignore]d: libtest reported `{} passed; {} \
                 ignored` and still printed `test result: ok`. See \
                 no_test_in_the_suite_is_ignored.",
                o.passed, o.ignored
            ));
        }
        if o.passed != 1 || o.failed != 0 {
            return Err(format!(
                "`{target}` ran and did not pass: {} passed, {} failed.\n{}",
                o.passed,
                o.failed,
                o.raw.trim()
            ));
        }
        let Some(block) = o.stdout_block.as_deref().map(str::trim).filter(|b| !b.is_empty())
        else {
            return Err(format!(
                "`{target}` ran and passed but printed nothing. An EMPTY \
                 `#[test]` body runs and passes -- measured -- so execution \
                 alone does not distinguish it from a real test. The target \
                 must report what it measured on stdout, in a line containing \
                 `{}`.",
                r.evidence
            ));
        };
        if !r.evidence.is_empty() && !block.contains(r.evidence) {
            return Err(format!(
                "`{target}` ran and passed and printed, but its output does not \
                 contain `{}`. Either the target stopped reporting what it \
                 measures, or the census row's needle is stale.\nIt printed: {block}",
                r.evidence
            ));
        }
        let n = max_int(block, r.evidence);
        if n < r.floor {
            return Err(format!(
                "`{target}` reported {n} as its largest measurement, under the \
                 floor of {}. A test that runs over an empty set passes exactly \
                 like one that does the work.\nIt printed: {block}",
                r.floor
            ));
        }
        Ok(block.to_owned())
    }
}

/// The census's population is libtest's run list, and this is what says so.
///
/// The census's question, asked of the instrument: *is the set I am counting the
/// set I am checking?* A census that silently fell back to a source parser would
/// still answer every guard, over whatever population the parser happened to
/// reach.
///
/// So the witness is not the total. It is one name the two instruments spell
/// differently: a test inside a `cfg`-gated inline module, which libtest lists
/// under its module path. The body names it and says in the same place why it
/// is a weaker witness than a macro-emitted name would be.
#[test]
fn execution_census_population_is_libtests_run_list() {
    let mut total = 0usize;
    let mut per_bin: Vec<(String, usize)> = Vec::new();
    for bin in census::executables().keys() {
        let n = census::listed(bin);
        total += n.len();
        per_bin.push((bin.clone(), n.len()));
    }
    // 255 is two thirds of the 383 this test prints on this tree, across 16
    // binaries. Two thirds and not a half: the floor's
    // job is to catch a census reading a truncated population, and the loosest
    // floor in this file is the one that catches the least. A third of the
    // suite disappearing is a larger event than any commit should produce, so
    // a floor that tolerates it tolerates the failure it exists to name --
    // while leaving room for a target to be removed without a false red.
    assert!(
        total >= 255,
        "libtest lists {total} tests across {} binaries; it is 383 across 16 \
         on the tree this floor was derived from, and the floor is two thirds \
         of that. Two-sided in spirit: too few and the census is reading a \
         truncated population, and the likeliest cause is that it stopped \
         asking libtest. Re-derive by running this test and reading what it \
         printed, not by arithmetic on the old value: the figure in this \
         message was stale at every one of its previous re-derivations.",
        per_bin.len()
    );

    // The witness that the population is libtest's and not a parse of items.
    // A `proptest!`-emitted name, which no item parser can produce, would be
    // the strongest witness; the suite that carried one is gone. What is left
    // that a naive parse would misread is a test inside a `cfg`-gated inline
    // module: libtest lists it under its module path, and a parser that
    // ignored the gate, or the module, would spell it differently or list a
    // sibling the gate removed. Weaker than the macro witness, and said so.
    const MODULE_PATHED: &str = "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store";
    assert!(
        census::listed("cli").contains(MODULE_PATHED),
        "`{MODULE_PATHED}` is not in the `cli` binary's run list under its \
         module path. libtest prints a nested test as `module::name`; a \
         census reading a parse of items rather than libtest's list would not \
         spell it that way, and a `cfg`-removed module would not appear at all."
    );

    println!(
        "  execution census population: {total} tests across {} binaries \
         (libtest's own --list, not a parse); {} target(s) spawned so far in \
         this process",
        per_bin.len(),
        census::spawned()
    );
}

/// Every census row belongs to a guard that runs, and every row is reachable.
///
/// Two failures this closes, both of which would leave a guard answered by
/// silence rather than by a verdict:
///
/// * a guard renamed out from under its row — `census::check` panics on an
///   unknown pair, but only if it is *called*, and a renamed guard's call site
///   moves with it, so nothing else would notice the orphaned row;
/// * a row naming a binary cargo does not build.
///
/// The floor is the current population, raised when it grew. The measurement was
/// fourteen guards over sixteen edges — two guards demand two targets each, and
/// one target is demanded by two guards -- and then the four crash-consistency and
/// restore invariants, one edge each, giving **eighteen guards over twenty
/// edges**. Raising the floor with the table is the point of it: a floor left at
/// the old value would go on passing over a table that had shed the new rows.
#[test]
fn censused_rows_are_bound_to_live_guards() {
    use std::collections::BTreeSet;

    let rows = census::ROWS;
    assert!(
        rows.len() >= 25,
        "the census table holds {} row(s); this tree's table holds 26, over 20 \
         guards. A table that shrank is \
         guards that stopped being censused.",
        rows.len()
    );

    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for r in rows {
        assert!(
            seen.insert((r.guard, r.target)),
            "duplicate census row for ({}, {}). `census::check` takes the \
             first, so the second would be unreachable and its floor and \
             needle would never be applied.",
            r.guard,
            r.target
        );
        assert!(
            census::executables().contains_key(r.bin),
            "census row ({}, {}) names test binary `{}`, which cargo does not \
             build.",
            r.guard,
            r.target,
            r.bin
        );
    }

    let guards = census::listed("invariants");
    let orphans: Vec<&str> = rows
        .iter()
        .map(|r| r.guard)
        .filter(|g| !guards.contains(*g))
        .collect();
    assert!(
        orphans.is_empty(),
        "these census rows name guards that libtest does not list in the \
         `invariants` binary: {orphans:?}.\n\
         A row whose guard was renamed or deleted is a demand nothing makes any \
         more -- it sits in the table looking like coverage. This is the census's \
         own question asked of itself: the set it counts must be the set \
         it checks."
    );

    let owners: BTreeSet<&str> = rows.iter().map(|r| r.guard).collect();
    println!(
        "  census table: {} edge(s) over {} guard(s), every guard live in \
         libtest's run list",
        rows.len(),
        owners.len()
    );
}

/// I1 — a WOTS+ secret key signs at most once, ever. **Green**,
/// renamed in the clearing commit from `i1_one_signature_per_key`
/// (a discharged marker keeps its useful half), with both of its bounds in the name.
///
/// # Crate-private, and how that is held
///
/// `wots::sign` and `wots::internals` are `pub(crate)`;
/// `backend` is `pub(crate)` unless the `raw-backend` feature is on, which
/// only the test tree turns on through the crate's dev-dependency on itself;
/// and the one public path to a signature is `Keystore::sign_spend`, which
/// consumes an `AdvanceReceipt` -- the keystore's evidence that the key's
/// index advanced and is durable -- and refuses a receipt that does not name
/// the store's live state.
///
/// # The two bounds, which are the name
///
/// **Per keystore.** The receipt gate makes one signature per index within
/// one store. Two stores on one seed -- a directory copied, records moved
/// through `into_records` into a second store, a seed re-derived into a fresh
/// store after it has spent -- each sign position k once and the chain sees
/// two; that is I4's and I5's subject, both still red. And one store can
/// hold one key stream under two tags unless something says so: the interim
/// checks refuse it where the master is at hand, and
/// `duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`
/// closed the half they cannot see, with format v2, by storing the identity in every
/// record.
///
/// **Crate-private, not absent.** In-crate code can call the signer; the test
/// tree reaches it through `backend` under `raw-backend`; and a dependent
/// holding secret bytes through the conspicuous doors (`Secret::expose`,
/// `into_records`) can re-implement WOTS+ against a hash library. What is
/// enforced is that *this crate offers no signer* outside `sign_spend`.
///
/// # What enforces it, and what each row sees
///
/// Four census rows, each a different instrument:
/// * `each_wots_key_signs_once_through_the_receipt_gate` (`tests/signing.rs`)
///   -- the receipt gate, executed: two positions of a fixture-anchored
///   account signed once each under a TypeScript-recorded address, every
///   second receipt at a spent position refused. Floor 2 from I1's own test
///   clause: sign twice at one index, the second refused.
/// * `every_ui_case_compiles_or_fails_for_its_pinned_reason` -- the trybuild
///   partition, whose `signing_*` cases pin `wots::sign` and `wots::internals`
///   private and the receipt consumed and un-`Clone`. Floor 4, the four cases.
/// * `raw_signer_is_unreachable_from_a_default_features_dependent` -- a real
///   `cargo check` of a dependent built WITHOUT `raw-backend`, refusing both
///   spellings of the raw signer with E0603 and compiling the legitimate
///   path. Floor 2, the two spellings. This is the only instrument that sees
///   the wallet build: trybuild inherits the test build's features.
/// * `no_wallet_visible_fn_hands_out_a_wots_signature` -- a `syn` scan over
///   the wallet-visible surface for any route to a signature that no case
///   anticipated. Floor 2, the two ports of `wots.c`'s
///   `wots_sign` it must find and find private.
///
/// # WHAT THIS MARKER CAN AND CANNOT SEE
///
/// * Two keystores on one seed (above). * Whether the pending digest is the
///   transaction actually broadcast -- the builder's. * A refused
///   `sign_spend` consumes its receipt: the key is skipped, never reused
///   (safe direction; `check_spend` exists so a wrong passphrase costs
///   nothing). * In-crate misuse. * A forged measurement: the census sees a
///   line, not a truth. * fsync that lies, power loss -- I2's
///   residue, inherited unchanged.
#[test]
fn key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent() {
    // Anchor A: the raw signer is declared crate-private. Redundant with
    // `ui/fail/signing_raw_signer_is_not_reachable.rs`, and kept because
    // that red arrives under the partition test's misattributed headline;
    // this one names the subject. Needle constructed, terminated.
    const SIGNER: &str = "sign";
    let wots_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/wots.rs"));
    assert!(
        wots_rs.contains(&format!("pub(crate) fn {SIGNER}(")),
        "wots.rs no longer declares `pub(crate) fn {SIGNER}(`. If the raw signer went \
         public again, I1 is unenforced at the source; if it was renamed, this anchor \
         and the compile-fail case both need the new name."
    );
    // Anchor B: the backend seam is crate-private outside the feature.
    // Redundant with the downstream probe, kept for the same reason as A.
    const BACKEND: &str = "backend";
    let lib_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/lib.rs"));
    assert!(
        lib_rs.contains(&format!("pub(crate) mod {BACKEND};")),
        "lib.rs no longer declares `pub(crate) mod {BACKEND};` for the build without \
         `raw-backend`. A public backend is a public raw signer."
    );
    // Anchor C: the manifest. `default` does not carry `raw-backend`, and the
    // dev-dependency on this crate carries it WITH default-features off.
    // Not redundant with anything cheap: the first half is what keeps the
    // feature out of a wallet build, the second what keeps the C-free and
    // Miri configuration from silently regaining the C.
    let manifest: toml::Value = toml::from_str(&read_crate_file("crates/mochimo-crypto/Cargo.toml"))
        .unwrap_or_else(|e| panic!("Cargo.toml does not parse: {e}"));
    let default_features: Vec<String> = manifest["features"]["default"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    assert!(
        !default_features.iter().any(|f| f == "raw-backend"),
        "Cargo.toml's `default` features are {default_features:?} and include `raw-backend`: \
         every dependent, wallet included, would see the raw signer."
    );
    assert!(
        manifest["features"].get("raw-backend").is_some(),
        "Cargo.toml declares no `raw-backend` feature; the test tree's route to the \
         backend is gone, and with it the test tree's route to the native primitives."
    );
    let self_dep = &manifest["dev-dependencies"]["mochimo-crypto"];
    assert_eq!(
        self_dep.get("default-features").and_then(|v| v.as_bool()),
        Some(false),
        "the dev-dependency on mochimo-crypto itself must carry `default-features = false`; \
         without it `cargo test --no-default-features --features native` unifies `default` \
         back in and the C-free build links the C."
    );
    let self_features: Vec<&str> = self_dep
        .get("features")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert!(
        self_features.contains(&"raw-backend"),
        "the dev-dependency on mochimo-crypto itself no longer turns on `raw-backend`: \
         found {self_features:?}. The test tree would lose the backend."
    );

    let mut owed: Vec<String> = Vec::new();
    const GUARD: &str = "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent";
    for (target, what) in [
        (
            "each_wots_key_signs_once_through_the_receipt_gate",
            "the receipt gate executed over a fixture-anchored account: two positions \
             signed once each under a TypeScript-recorded address, every second receipt \
             at a spent position refused; prints `I1 one signature:` with the count of \
             refusals (floor 2)",
        ),
        (
            "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            "the trybuild partition with its four `signing_*` cases (the raw signer and \
             its internals unnameable, the receipt consumed and not Clone); prints \
             `compile-fail partition:` (floor 4)",
        ),
        (
            "raw_signer_is_unreachable_from_a_default_features_dependent",
            "a `cargo check` of a dependent built WITHOUT `raw-backend`: both spellings \
             of the raw signer refused with E0603, the legitimate `sign_spend` path \
             compiled; prints `downstream probe:` (floor 2)",
        ),
        (
            "no_wallet_visible_fn_hands_out_a_wots_signature",
            "the route scan over the wallet-visible surface: no unrestricted `pub` fn \
             outside the allow-list produces a signature or reaches the signer; prints \
             `raw-signer route scan:` (floor 3)",
        ),
    ] {
        if let Err(why) = census::check(GUARD, target) {
            owed.push(format!("\x20 - {target}: {what}.\n\x20   {why}"));
        }
    }

    assert!(
        owed.is_empty(),
        "I1's enforcement has REGRESSED. Once this red meant `wots::sign` was public \
         and no path demanded a receipt; the signing path demoted the signer to `pub(crate)`, put \
         `backend` behind `raw-backend`, and landed `Keystore::sign_spend` behind the \
         `AdvanceReceipt` -- so this firing means one of the four instruments below, or \
         the demotion itself, went away.\n{}\n\
         Two signatures under one WOTS+ key make forgery tractable and there is no repair \
         after the fact. docs/specification.md I1.",
        owed.join("\n")
    );
}

/// The route scan behind I1: no wallet-visible function hands out a WOTS+
/// signature except the one allow-listed signer. The fail-closed absence
/// check an absence property asks for -- a compile-fail case pins a spelling somebody
/// thought of; this ranges over the real surface and allow-lists the
/// permitted routes, so a NEW route to a signature reddens without anyone
/// having guessed its name.
///
/// # The predicate
///
/// A function is flagged when it is **wallet-visible** and either
/// **produces** a signature-bearing value or **reaches the signer**:
///
/// * *wallet-visible*: declared bare `pub`, inside modules that are bare
///   `pub` all the way up **in the wallet view** -- a `mod` declaration under
///   `cfg(feature = "raw-backend")` is dropped and its `cfg(not(..))` twin
///   kept, so `backend` resolves to `pub(crate)` the way a dependent sees it;
///   an impl method needs a bare-`pub` self type; a `pub use` in a visible
///   module lifts what it names.
/// * *produces*: the return type, or a non-`self` `&mut` parameter, mentions
///   a **bearing** type -- the fixpoint from the tokens `SIG_LEN`,
///   `WOTSSIGBYTES` and the literal `2144` through type aliases
///   (`Signature`) and fields (`SpendSignature`, `WotsVal`, `Transaction`).
/// * *reaches the signer*: the body fixpoint from the idents `wots_sign`,
///   `wots_sign_counted`, `sign_spend` and the path `wots::sign`, through
///   every function whose body names a tainted one.
///
/// Allow-list, keyed by file and name, an unused entry being itself a red:
/// `Signer` (exactly one, `Keystore::sign_spend`); `Reader` (functions that
/// hand a signature *back* -- `TxEntry::wots_signature`, the `Transaction`
/// constructors -- each checked mechanically to take no key-material holder
/// and to reach no signer, so a signer cannot be smuggled in as a reader).
///
/// # What it cannot see, said here
///
/// A signer re-implemented from scratch over `backend::native::gen_chain`
/// and `Secret::expose`, returning a `PublicKey`-typed value: the type arm
/// sees `SIG_LEN` spellings, the body arm sees the signer's names, and the
/// two aliases `PublicKey`/`Signature` are one type. That needs in-crate
/// code (`backend` is crate-private outside the feature), and it is the
/// "crate-private, not absent" bound in the I1 marker's name. Also: a
/// function taking its secret as bare `&[u8; 32]` passes the reader check.
///
/// # Its own controls
///
/// The two ports of `wots.c`'s `wots_sign` must be found AND found
/// crate-private; `backend` must resolve Restricted; `Signature` must be
/// bearing; at least 150 signatures examined; and the predicate is run over
/// an embedded control crate in which a visible wrapper over `wots::sign`,
/// a visible `-> Box<[u8; SIG_LEN]>`, and the same under a `pub(crate)`
/// module must flag, flag, and not flag respectively.
/// **The decision layer carries no prose.**
///
/// `cli::outcome` is what a command established; `cli::render` is what the
/// program says about it. The split is only worth having while the first of
/// those cannot quietly become the second, and the way it becomes the second
/// is one variant with a `String` in it -- a page already built, handed
/// through a type that claims to be a decision. One such field and a
/// dependent can no longer tell which variants it may act on and which it may
/// only print.
///
/// So the scan is exact rather than tasteful: **no `String` anywhere in
/// `cli/outcome.rs`**, comments stripped. The module needs none today, and a
/// variant that genuinely needs one is a variant whose data has not been
/// found yet -- which is a conversation to have at this test, not a field to
/// add quietly.
///
/// `&'static str` is not what this catches and should not be: a fixed string
/// is a discriminant with a readable spelling, not a page. Nothing in the
/// module uses one either.
///
/// The paired half is structural and needs no test: `render::outcome`
/// matches `Outcome` exhaustively, so a variant added without a rendering is
/// a compile error rather than a silent blank page.
/// **The platform surface is the files the port touched, and no others.**
///
/// This crate builds for Unix and for Windows and refuses every other target,
/// in `lib.rs` and again in `keystore`. Each platform supplies the three
/// interfaces `lib.rs` names -- the permission model, the device secrets are
/// read from, the entropy source -- and the keystore's storage primitives.
/// Where those sites are is a claim about the whole tree, and while they can
/// be anywhere it is prose checked against nothing: a mode bit or a Win32 call
/// added in a new file leaves both statements reading exactly the same.
///
/// So the surface is enumerated rather than described, one needle per kind of
/// site, over comment-stripped code:
///
/// * `std::os::unix` -- `keystore/perms.rs`, the Unix permission model.
/// * `std::os::windows` and `windows_sys` -- `keystore/perms/windows.rs`, the
///   Windows permission model; `bin/mcm-wallet.rs`, the console and the
///   generator; and, for `windows_sys` alone, `keystore/medium.rs`, which
///   names the two error codes a held file produces on a replacing move.
/// * `/dev/` and `"stty"` -- `bin/mcm-wallet.rs`. The library reaches neither:
///   entropy is a parameter and the prompts go through `cli::create::Terminal`.
/// * `cfg(unix)` and `cfg(windows)` -- the files holding a per-platform arm.
///   `medium.rs` is here though no platform API is named in its Unix arm: its
///   sites are `std::fs` calls that compile everywhere and behave differently,
///   which a scan by API name cannot find, so the arm's attribute is what
///   makes it enumerable at all. `error.rs` is here for its two Windows-only
///   variants. `perms/windows.rs` is not, because it is gated whole at its
///   `mod` line in `perms.rs`.
/// * `cfg(not(any(unix, windows)))` -- `lib.rs` and `keystore/mod.rs`, the two
///   gates that refuse every other target.
///
/// # What this is for
///
/// The upstream tree this one forks from is Unix-only, and its version of
/// this check lists the four files a port would have to touch. This version
/// lists what the port did touch, and the difference between the two is the
/// port's footprint in the source, readable here rather than reconstructed
/// from a diff. A file joining a row is a new place a platform decision lives,
/// and the failure message says where it should have gone instead.
///
/// The test keeps the name it has upstream on purpose. A renamed test is a
/// conflict at every merge that touches it, and the name still says what the
/// check is for.
#[test]
fn the_unix_surface_is_confined_to_the_files_a_port_would_touch() {
    const PERMS: &str = "crates/mochimo-crypto/src/keystore/perms.rs";
    const PERMS_WINDOWS: &str = "crates/mochimo-crypto/src/keystore/perms/windows.rs";
    const MEDIUM: &str = "crates/mochimo-crypto/src/keystore/medium.rs";
    const ERROR: &str = "crates/mochimo-crypto/src/error.rs";
    const BIN: &str = "crates/mochimo-crypto/src/bin/mcm-wallet.rs";
    const LIB: &str = "crates/mochimo-crypto/src/lib.rs";
    const KEYSTORE: &str = "crates/mochimo-crypto/src/keystore/mod.rs";
    const SURFACE: [(&str, &[&str]); 8] = [
        ("std::os::unix", &[PERMS]),
        ("std::os::windows", &[PERMS_WINDOWS, BIN]),
        ("windows_sys", &[PERMS_WINDOWS, MEDIUM, BIN]),
        ("/dev/", &[BIN]),
        ("\"stty\"", &[BIN]),
        ("cfg(unix)", &[PERMS, MEDIUM, BIN]),
        ("cfg(windows)", &[PERMS, MEDIUM, ERROR, BIN]),
        ("cfg(not(any(unix, windows)))", &[KEYSTORE, LIB]),
    ];

    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; an enumeration taken over it is vacuous",
        files.len()
    );

    for (needle, expected) in SURFACE {
        let mut found: Vec<&str> = files
            .iter()
            .filter(|(_, code)| code.contains(needle))
            .map(|(name, _)| name.as_str())
            .collect();
        found.sort_unstable();
        let mut want: Vec<&str> = expected.to_vec();
        want.sort_unstable();
        assert_eq!(
            found, want,
            "the platform surface moved: `{needle}` is named by a different set of files than \
             this check enumerates.\n  found:    {found:?}\n  expected: {want:?}\nA new file \
             here is a new place a platform decision lives. Either put the site behind \
             `keystore::perms` (for the library) or the binary's own terminal and entropy code, \
             or add the file to this list with the reason it cannot go in either."
        );
    }
}

#[test]
fn the_decision_layer_carries_no_prose() {
    let src = code_only(&read_crate_file("crates/mochimo-crypto/src/cli/outcome.rs"));
    assert!(
        src.contains("pub enum Outcome"),
        "the scan did not find `Outcome` in cli/outcome.rs; it is reading the wrong file \
         or the module moved, and a scan that matches nothing holds nothing"
    );
    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("String"))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();
    assert!(
        hits.is_empty(),
        "cli/outcome.rs names `String`, so a decision can carry a page through the type that \
         says it is a decision:\n{}\nPut the value the sentence is made of in the variant and \
         the sentence in `cli::render`.",
        hits.iter()
            .map(|(n, l)| format!("\x20 - line {n}: {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn no_wallet_visible_fn_hands_out_a_wots_signature() {
    let files = crate_source_files();
    assert!(files.len() >= 10, "the walk of crates/*/src found only {} files; vacuous", files.len());
    let a = route_scan::analyse(&files, "crates/mochimo-crypto/src/");

    // Controls over the real tree.
    assert!(a.bearing.contains("Signature"), "`Signature` is not a bearing type; the type arm sees nothing");
    assert_eq!(
        a.modules.get("backend").copied(),
        Some(false),
        "`backend` does not resolve to a restricted module in the wallet view: {:?}",
        a.modules.get("backend")
    );
    // Two ports: the native one and the crate-private wrapper over it, which
    // is what the positive control names.
    for port in ["wots.rs::sign", "backend/native.rs::wots_sign"] {
        assert!(
            a.signers_found.contains(port),
            "the signer port `{port}` was not found; the two ports of wots.c's wots_sign \
             are the scan's positive control, found: {:?}",
            a.signers_found
        );
        assert!(
            !a.visible.contains(port),
            "the signer port `{port}` is wallet-visible; I1's demotion is undone"
        );
    }
    assert!(a.signatures >= 150, "only {} signatures examined; the walk is not reading the tree", a.signatures);

    // The allow-list, keyed `file::Type::fn` (free functions `file::fn`).
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Class {
        Signer,
        Reader,
        /// A wallet-visible function that reaches the signer **only through**
        /// `Keystore::sign_spend`, and therefore inherits its gate rather
        /// than adding a route around it.
        ///
        /// The scan's message offers two outcomes -- reader, or the I1 hole
        /// -- and `Wallet::reserve_and_sign` is neither: it takes a
        /// `KeyAccess` (so it is no reader) and it reaches the signer (so it
        /// is flagged), but the reaching is a call to `sign_spend`, which
        /// consumes an `AdvanceReceipt` this crate minted after the four
        /// durable steps. One receipt, at most one signature, unchanged.
        ///
        /// **It is not a rubber stamp.** A Composer must name `sign_spend`
        /// and must NOT name a raw signer port, both checked mechanically
        /// below, so a "composer" that reached `backend::native::wots_sign`
        /// directly is rejected exactly as an unlisted function is.
        Composer,
        /// A signer that re-produces a signature the store already released,
        /// with **no digest parameter**.
        ///
        /// `Keystore::resign_reserved` is a second signer and there is no
        /// honest way to call it anything else. What makes it safe is not its
        /// call graph but its SIGNATURE: the digest and the position come
        /// from `Pending`, so signing over anything but the reserved digest
        /// is unrepresentable, and WOTS+ determinism makes the output
        /// byte-identical to the signature already released -- one signature
        /// produced twice rather than two signatures under one key.
        ///
        /// The check below is exactly that property: a ReSigner must take NO
        /// 32-byte array parameter and its body must read `pending`. A
        /// "re-signer" that accepted a digest would be the I1 hole.
        ReSigner,
        /// A wallet-visible entry point that reaches the signer **only through
        /// a `Wallet`**, and hands back rendered text rather than anything a
        /// signature can be read out of.
        ///
        /// `cli::run` is the first consumer this crate ships. It is neither a
        /// Reader (it takes the master seed) nor a Composer (it never names
        /// `sign_spend`; it calls `Wallet` methods that do), and calling it
        /// either of those would be widening a permission to fit rather than
        /// stating the one it has.
        ///
        /// **The permission is checked, not granted.** An Entrypoint must name
        /// `Wallet` -- so the gate is on its path -- and must name **neither**
        /// `sign_spend`/`resign_reserved` **nor** a raw signer port, so a
        /// "CLI" that reached past the wallet is rejected exactly as an
        /// unlisted function is. That pairing is the reconciliation precedent: the route
        /// scan gained a class rather than a waiver.
        Entrypoint,
    }
    const ALLOWED: &[(&str, Class, &str)] = &[
        (
            "keystore/sign.rs::Keystore::sign_spend",
            Class::Signer,
            "the one public path to a signature: behind the receipt, re-checking the store's live state",
        ),
        (
            "tx/wire.rs::Transaction::new",
            Class::Reader,
            "assembles a transaction from parts the caller already holds, the WotsVal among them",
        ),
        (
            "tx/wire.rs::Transaction::from_wire",
            Class::Reader,
            "decodes a wire image, signature included, and produces no signature of its own",
        ),
        (
            "keystore/sign.rs::Keystore::resign_reserved",
            Class::ReSigner,
            "re-produces the signature an outstanding reservation already released, from the \
             store's own Pending record. No digest parameter -- checked below -- so it cannot \
             sign anything but the reserved digest, and determinism makes the bytes identical \
             to what sign_spend already emitted. It exists because rolling the index back to \
             the reserved key is correctly forbidden, so this is the ONLY route by which the \
             funds at that key's address can ever move",
        ),
        (
            "wallet.rs::Wallet::resign_pending",
            Class::Composer,
            "the wallet's half of the recovery: rebuilds the plan from the caller's remembered \
             parameters, REQUIRES the rebuilt digest to equal the reserved one, and only then \
             calls resign_reserved. Composer, not ReSigner: it reaches the signer through the \
             gated one rather than beside it",
        ),
        (
            "wallet.rs::Wallet::reserve_and_sign",
            Class::Composer,
            "the wallet's spend path: persist_advance mints the receipt, sign_spend consumes it, \
             attach assembles the image. It reaches the signer through the gate rather than \
             beside it, so I1's one-receipt-one-signature holds through it -- and a second \
             reservation is refused while the first is unresolved. Composer, not Reader: it \
             takes a KeyAccess, and a permission that pretended otherwise would be the \
             smuggling the Reader check exists to stop",
        ),
        (
            "mesh/spend.rs::SignedTransaction::attach",
            Class::Reader,
            "assembles the wire image from an unsigned plan and a SpendSignature the keystore already \
             released; pk_from_sig is a verifier, every parameter is public data, and the \
             permission is backed by an executed refusing check -- \
             mesh_reader_permission_is_backed_by_a_refusing_check censuses \
             spend.rs::attach_refuses_every_mismatched_component",
        ),
        (
            "cli/mod.rs::run",
            Class::Entrypoint,
            "the CLI's one-line entry: `render(decide(..))` and nothing else. It names no              `Wallet` itself and reaches the signer only through `decide`, whose Entrypoint              permission is checked on its own row below; it hands back a Report, which is text              and an exit code and nothing a signature can be read out of. This is the              delegation clause's only user, and the reason the clause exists",
        ),
        (
            "cli/mod.rs::decide",
            Class::Entrypoint,
            "the CLI's dispatch: it opens a Wallet -- which reconciles every account, partitions              them, and refuses outright only when none reconciled -- and calls              the wallet's own methods, so every route to a signature it has is one the gate              already holds. It hands back a Report, which is text and an exit code; nothing a              signature can be read out of. Ten commands return before a Wallet exists              (`address`, `restore`, `discover`, `status`, `reconcile`, `submit` and the four              read-only verbs), and `create` never reaches this function at all because there is              no store to hand it; none of those paths signs --              the_cli_cannot_reach_around_the_wallet checks both halves mechanically",
        ),
    ];
    let mut unlisted: Vec<String> = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    let mut readers_verified = 0usize;
    let mut signers_allowed = 0usize;
    let mut composers_verified = 0usize;
    let mut resigners_verified = 0usize;
    let mut entrypoints_verified = 0usize;
    for f in &a.flagged {
        match ALLOWED.iter().find(|(name, _, _)| name == &f.name) {
            None => unlisted.push(format!("{} -> {} [{}]", f.name, f.output, f.why)),
            Some((name, Class::Signer, _)) => {
                used.push(name);
                signers_allowed += 1;
            }
            Some((name, Class::ReSigner, _)) => {
                used.push(name);
                assert!(
                    !f.takes_digest,
                    "{name} is allow-listed as a ReSigner but takes a 32-byte array parameter. \
                     Its ENTIRE safety argument is that the digest is not an input -- it comes \
                     from the store's reservation -- so a digest parameter makes it the \
                     second-signature-under-one-key hole this scan exists to catch"
                );
                assert!(
                    f.reads_pending,
                    "{name} is allow-listed as a ReSigner but its body never names `pending`; \
                     a ReSigner's permission is that it reads the reservation rather than a \
                     caller's argument"
                );
                resigners_verified += 1;
            }
            Some((name, Class::Composer, _)) => {
                used.push(name);
                assert!(
                    f.names_sign_spend,
                    "{name} is allow-listed as a Composer but its body never names `sign_spend`; \
                     a Composer's whole permission is that it reaches the signer THROUGH the \
                     receipt gate"
                );
                assert!(
                    !f.names_raw_signer,
                    "{name} is allow-listed as a Composer but its body names a RAW signer port; \
                     that is a route around the gate, which is the I1 hole this scan exists to \
                     catch"
                );
                composers_verified += 1;
            }
            Some((name, Class::Entrypoint, _)) => {
                used.push(name);
                assert!(
                    !f.names_sign_spend,
                    "{name} is allow-listed as an Entrypoint but its body names `sign_spend` or                      `resign_reserved` directly. An Entrypoint's permission is that it reaches                      the signer only THROUGH a wallet; one that calls the gate itself is a                      Composer and must be listed as one, with that class's checks."
                );
                assert!(
                    !f.names_raw_signer,
                    "{name} is allow-listed as an Entrypoint but its body names a RAW signer                      port; that is a route around the gate, which is the I1 hole this scan                      exists to catch"
                );
                // **The gate on its path, directly or one call away.**
                //
                // The clause was `body_names_wallet` alone, which was exact
                // while the dispatch and the wallet were the same function.
                // They are not: `run` is `render(decide(..))` now, and it is
                // `decide` that opens the `Wallet`. A dispatch that delegates
                // has the same permission as one that does the work -- the
                // gate is still on its path -- and reading the clause
                // literally would have forced the split to be undone or the
                // route to be waived.
                //
                // So the clause is widened rather than waived, and only as
                // far as the property already reaches: the body must name
                // `Wallet`, or name another function ALLOW-LISTED AS AN
                // ENTRYPOINT, whose own permission is checked by these same
                // three assertions on its own row. A chain of delegations is
                // therefore a chain of checked permissions, and a function
                // that names neither is rejected exactly as before.
                let delegates_to_entrypoint = f.body_idents.iter().any(|id| {
                    ALLOWED.iter().any(|(n, c, _)| {
                        matches!(c, Class::Entrypoint)
                            && n.rsplit("::").next().is_some_and(|short| short == id)
                    })
                });
                assert!(
                    f.body_names_wallet || delegates_to_entrypoint,
                    "{name} is allow-listed as an Entrypoint but its body neither names `Wallet`                      nor calls another allow-listed Entrypoint. The permission rests on the gate                      being ON its path; without that it is an unlisted route to a signature."
                );
                entrypoints_verified += 1;
            }
            Some((name, Class::Reader, _)) => {
                used.push(name);
                assert!(
                    !f.reaches_signer,
                    "{name} is allow-listed as a Reader but its body reaches the signer"
                );
                assert!(
                    f.holder_params.is_empty(),
                    "{name} is allow-listed as a Reader but takes key material: {:?}",
                    f.holder_params
                );
                readers_verified += 1;
            }
        }
    }
    let unused: Vec<&str> = ALLOWED
        .iter()
        .map(|(n, _, _)| *n)
        .filter(|n| !used.contains(n))
        .collect();
    assert!(
        unused.is_empty(),
        "allow-list entries matched nothing: {unused:?}. An entry the scan never reaches is a \
         permission nobody is using -- the function moved, was renamed, or stopped being \
         flagged, and the entry would silently cover a newcomer of the same name. Flagged: {:?}",
        a.flagged.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(signers_allowed, 1, "exactly one wallet-visible signer is permitted; found {signers_allowed}");
    assert!(
        unlisted.is_empty(),
        "a wallet-visible function hands out a WOTS+ signature or reaches the signer and is \
         not allow-listed:\n  {}\nEvery such route is a second signer beside `sign_spend`; \
         either it is a reader (takes no key material, reaches no signer -- add it as one, \
         argued) or it is the I1 hole this scan exists to catch.",
        unlisted.join("\n  ")
    );

    // The embedded control: the predicate over a crate of five files, in which
    // a visible wrapper over the signer and a visible bearing return must flag
    // and the same under a restricted module must not. Runs the SAME
    // `analyse`, so a neutered predicate reddens here before it could pass
    // over the real tree.
    let control: Vec<(String, String)> = vec![
        (
            "ctl/src/lib.rs".to_owned(),
            "pub mod p; pub mod q; pub(crate) mod r; pub mod wots; pub mod consts;".to_owned(),
        ),
        (
            "ctl/src/consts.rs".to_owned(),
            "pub const SIG_LEN: usize = 2144;".to_owned(),
        ),
        (
            "ctl/src/wots.rs".to_owned(),
            "pub type Signature = Box<[u8; crate::consts::SIG_LEN]>; \
             pub(crate) fn sign() -> Signature { todo!() }"
                .to_owned(),
        ),
        (
            "ctl/src/p.rs".to_owned(),
            "pub fn leak(s: &crate::Secret<32>) -> [u8; 32] { let _ = crate::wots::sign(); [0; 32] }".to_owned(),
        ),
        (
            "ctl/src/q.rs".to_owned(),
            "pub fn leak2() -> crate::wots::Signature { todo!() } \
             pub fn fine() -> [u8; 32] { [0; 32] }"
                .to_owned(),
        ),
        (
            "ctl/src/r.rs".to_owned(),
            "pub fn hidden() -> crate::wots::Signature { todo!() }".to_owned(),
        ),
    ];
    let c = route_scan::analyse(&control, "ctl/src/");
    let flagged: Vec<&str> = c.flagged.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        flagged,
        vec!["p.rs::leak", "q.rs::leak2"],
        "the embedded control did not flag exactly the visible wrapper (body arm) and the \
         visible bearing return (type arm): {flagged:?}. `r.rs::hidden` is under a \
         pub(crate) module and must not flag; `q.rs::fine` returns nothing bearing."
    );

    println!(
        "  raw-signer route scan: {} crate-private signer(s) recognised, {signers_allowed} \
         wallet-visible signer allow-listed, {readers_verified} reader(s) verified free of key \
         material, {composers_verified} composer(s) verified to reach the signer only through \
         a gated one, {resigners_verified} re-signer(s) verified to take no digest parameter \
         and to read the reservation, {entrypoints_verified} entrypoint(s) verified to reach \
         the signer only through a Wallet, 0 unlisted route(s)",
        a.signers_found.len()
    );
}

/// The machinery of [`no_wallet_visible_fn_hands_out_a_wots_signature`],
/// factored so the same `analyse` runs over the real tree and over the
/// embedded control crate.
mod route_scan {
    use quote::ToTokens;
    use std::collections::{BTreeMap, BTreeSet};

    pub struct Flagged {
        /// `file::Type::fn` or `file::fn`, the file relative to the src root.
        pub name: String,
        pub output: String,
        pub why: &'static str,
        pub reaches_signer: bool,
        /// Parameter types (rendered) that are key-material holders.
        pub holder_params: Vec<String>,
        /// The body names `sign_spend` -- it goes through the gated signer.
        pub names_sign_spend: bool,
        /// Any parameter is a 32-byte array -- i.e. a digest could be passed
        /// in. A ReSigner permission requires this FALSE: its whole safety
        /// argument is that the digest is not an input but comes from the
        /// store's own reservation.
        pub takes_digest: bool,
        /// The body names `pending` -- it reads the store's reservation
        /// rather than a caller's argument (the other half of a ReSigner
        /// permission).
        pub reads_pending: bool,
        /// The body names `Wallet` — the gate is on its path.
        pub body_names_wallet: bool,
        /// Every identifier the body mentions. Added for the Entrypoint
        /// check's delegation clause, which has to ask whether the body names
        /// another Entrypoint and cannot do that from a fixed set of flags.
        pub body_idents: Vec<String>,
        /// The body names a RAW signer port (`wots::sign` and the two
        /// `backend::*::wots_sign`). A Composer permission requires this
        /// false: reaching the signer through `sign_spend` inherits the
        /// receipt gate, reaching it through a raw port bypasses it, and the
        /// permission must be able to tell them apart.
        pub names_raw_signer: bool,
    }

    pub struct Analysis {
        pub flagged: Vec<Flagged>,
        pub bearing: BTreeSet<String>,
        /// Module path (`a::b`) -> unrestricted in the wallet view.
        pub modules: BTreeMap<String, bool>,
        pub signers_found: BTreeSet<String>,
        pub visible: BTreeSet<String>,
        pub signatures: usize,
    }

    /// `crates/mochimo-crypto/src/keystore/sign.rs` -> (`keystore/sign.rs`, `keystore::sign`).
    fn module_of(rel: &str) -> String {
        let stem = rel.trim_end_matches(".rs");
        if stem == "lib" {
            return String::new();
        }
        let stem = stem.strip_suffix("/mod").unwrap_or(stem);
        stem.replace('/', "::")
    }

    fn idents(tokens: &proc_macro2::TokenStream) -> Vec<proc_macro2::TokenTree> {
        let mut out = Vec::new();
        fn walk(ts: proc_macro2::TokenStream, out: &mut Vec<proc_macro2::TokenTree>) {
            for tt in ts {
                match tt {
                    proc_macro2::TokenTree::Group(g) => walk(g.stream(), out),
                    other => out.push(other),
                }
            }
        }
        walk(tokens.clone(), &mut out);
        out
    }

    fn mentions(tokens: &proc_macro2::TokenStream, names: &BTreeSet<String>) -> bool {
        idents(tokens).iter().any(|t| match t {
            proc_macro2::TokenTree::Ident(i) => names.contains(&i.to_string()),
            proc_macro2::TokenTree::Literal(l) => names.contains(&l.to_string()),
            _ => false,
        })
    }

    /// Does the token stream contain the path `wots :: sign`?
    fn names_wots_sign(tokens: &proc_macro2::TokenStream) -> bool {
        let flat = idents(tokens);
        let texts: Vec<String> = flat.iter().map(|t| t.to_string()).collect();
        texts.windows(3).any(|w| w[0] == "wots" && w[1] == ":" && w[2] == "sign")
            || texts.windows(4).any(|w| w[0] == "wots" && w[1] == ":" && w[2] == ":" && w[3] == "sign")
    }

    /// `#[cfg(...)]` attrs: keep the item in the wallet view unless it is
    /// gated ON `raw-backend`.
    fn kept_in_wallet_view(attrs: &[syn::Attribute]) -> bool {
        for a in attrs {
            if a.path().is_ident("cfg") {
                let text = a.meta.to_token_stream().to_string();
                if text.contains("raw-backend") && !text.contains("not") {
                    return false;
                }
            }
        }
        true
    }

    fn is_pub(vis: &syn::Visibility) -> bool {
        matches!(vis, syn::Visibility::Public(_))
    }

    struct Fn_ {
        name: String,
        module: String,
        vis_pub: bool,
        /// The self type's name for impl methods, checked for `pub`.
        self_ty: Option<String>,
        sig: syn::Signature,
        body: Option<proc_macro2::TokenStream>,
    }

    pub fn analyse(files: &[(String, String)], src_prefix: &str) -> Analysis {
        // Parse everything; a parse failure is a hard stop.
        let mut parsed: Vec<(String, String, syn::File)> = Vec::new();
        for (name, text) in files {
            let rel = name.strip_prefix(src_prefix).unwrap_or(name).to_owned();
            let module = module_of(&rel);
            let ast = syn::parse_file(text).unwrap_or_else(|e| panic!("syn could not parse {name}: {e}"));
            parsed.push((rel, module, ast));
        }

        // --- module visibility in the wallet view ---------------------------
        // declarations: (parent module, name) -> surviving declarations' pub-ness
        let mut decls: BTreeMap<(String, String), Vec<bool>> = BTreeMap::new();
        let mut inline_mods: Vec<(String, bool)> = Vec::new(); // (path, pub)
        fn collect_mods(
            items: &[syn::Item],
            here: &str,
            decls: &mut BTreeMap<(String, String), Vec<bool>>,
            inline_mods: &mut Vec<(String, bool)>,
        ) {
            for item in items {
                if let syn::Item::Mod(m) = item {
                    if !kept_in_wallet_view(&m.attrs) {
                        continue;
                    }
                    let name = m.ident.to_string();
                    match &m.content {
                        None => decls
                            .entry((here.to_owned(), name))
                            .or_default()
                            .push(is_pub(&m.vis)),
                        Some((_, inner)) => {
                            let path = if here.is_empty() { name.clone() } else { format!("{here}::{name}") };
                            inline_mods.push((path.clone(), is_pub(&m.vis)));
                            collect_mods(inner, &path, decls, inline_mods);
                        }
                    }
                }
            }
        }
        for (_, module, ast) in &parsed {
            collect_mods(&ast.items, module, &mut decls, &mut inline_mods);
        }
        let mut modules: BTreeMap<String, bool> = BTreeMap::new();
        modules.insert(String::new(), true);
        // Resolve file modules by path depth, parents first.
        let mut file_modules: Vec<String> = parsed.iter().map(|(_, m, _)| m.clone()).filter(|m| !m.is_empty()).collect();
        file_modules.sort_by_key(|m| m.matches("::").count());
        for m in &file_modules {
            let (parent, name) = match m.rsplit_once("::") {
                Some((p, n)) => (p.to_owned(), n.to_owned()),
                None => (String::new(), m.clone()),
            };
            let survivors = decls.get(&(parent.clone(), name.clone())).cloned().unwrap_or_default();
            assert!(
                survivors.len() <= 1,
                "module `{m}` has {} surviving declarations in the wallet view; the cfg pair is \
                 not exclusive",
                survivors.len()
            );
            let parent_pub = modules.get(&parent).copied().unwrap_or(false);
            let vis = match survivors.first() {
                Some(p) => *p && parent_pub,
                // A file with no surviving declaration is not compiled into
                // the wallet view at all.
                None => false,
            };
            modules.insert(m.clone(), vis);
        }
        for (path, p) in &inline_mods {
            let parent = path.rsplit_once("::").map(|(a, _)| a.to_owned()).unwrap_or_default();
            let parent_pub = modules.get(&parent).copied().unwrap_or(false);
            modules.insert(path.clone(), *p && parent_pub);
        }

        // --- pub use lifting: (target module, name or "*") from visible modules
        let mut lifted: BTreeSet<(String, String)> = BTreeSet::new();
        fn use_paths(tree: &syn::UseTree, prefix: Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
            match tree {
                syn::UseTree::Path(p) => {
                    let mut pre = prefix;
                    pre.push(p.ident.to_string());
                    use_paths(&p.tree, pre, out);
                }
                syn::UseTree::Name(n) => out.push((prefix, n.ident.to_string())),
                syn::UseTree::Rename(r) => out.push((prefix, r.ident.to_string())),
                syn::UseTree::Glob(_) => out.push((prefix, "*".to_owned())),
                syn::UseTree::Group(g) => {
                    for t in &g.items {
                        use_paths(t, prefix.clone(), out);
                    }
                }
            }
        }
        for (_, module, ast) in &parsed {
            if !modules.get(module).copied().unwrap_or(false) {
                continue;
            }
            for item in &ast.items {
                if let syn::Item::Use(u) = item {
                    if !is_pub(&u.vis) || !kept_in_wallet_view(&u.attrs) {
                        continue;
                    }
                    let mut out = Vec::new();
                    use_paths(&u.tree, Vec::new(), &mut out);
                    for (segs, name) in out {
                        let mut segs = segs;
                        let target = match segs.first().map(String::as_str) {
                            Some("crate") => {
                                segs.remove(0);
                                segs.join("::")
                            }
                            Some("self") => {
                                segs.remove(0);
                                if segs.is_empty() {
                                    module.clone()
                                } else if module.is_empty() {
                                    segs.join("::")
                                } else {
                                    format!("{module}::{}", segs.join("::"))
                                }
                            }
                            _ => {
                                if segs.is_empty() {
                                    module.clone()
                                } else if module.is_empty() {
                                    segs.join("::")
                                } else {
                                    format!("{module}::{}", segs.join("::"))
                                }
                            }
                        };
                        lifted.insert((target, name));
                    }
                }
            }
        }

        // --- bearing types ----------------------------------------------------
        let mut bearing: BTreeSet<String> = ["SIG_LEN", "WOTSSIGBYTES", "2144"].iter().map(|s| s.to_string()).collect();
        let mut type_items: Vec<(String, proc_macro2::TokenStream)> = Vec::new();
        fn collect_types(items: &[syn::Item], out: &mut Vec<(String, proc_macro2::TokenStream)>) {
            for item in items {
                match item {
                    syn::Item::Type(t) => out.push((t.ident.to_string(), t.ty.to_token_stream())),
                    syn::Item::Struct(s) => out.push((s.ident.to_string(), s.fields.to_token_stream())),
                    syn::Item::Enum(e) => out.push((e.ident.to_string(), e.variants.to_token_stream())),
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            collect_types(inner, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        for (_, _, ast) in &parsed {
            collect_types(&ast.items, &mut type_items);
        }
        loop {
            let before = bearing.len();
            for (name, tokens) in &type_items {
                if !bearing.contains(name) && mentions(tokens, &bearing) {
                    bearing.insert(name.clone());
                }
            }
            if bearing.len() == before {
                break;
            }
        }
        // Key-material holders: the transitive closure over `Secret` and
        // `Zeroizing`, computed here rather than borrowed from the Debug-holder
        // scan so that this check has no dependency on that one's internals.
        let mut holders: BTreeSet<String> = ["Secret", "Zeroizing"].iter().map(|s| s.to_string()).collect();
        loop {
            let before = holders.len();
            for (name, tokens) in &type_items {
                if !holders.contains(name) && mentions(tokens, &holders) {
                    holders.insert(name.clone());
                }
            }
            if holders.len() == before {
                break;
            }
        }

        // --- every fn, with its module and visibility ------------------------
        let mut fns: Vec<(String, Fn_)> = Vec::new(); // (file rel, fn)
        fn collect_fns(items: &[syn::Item], rel: &str, module: &str, out: &mut Vec<(String, Fn_)>) {
            for item in items {
                match item {
                    syn::Item::Fn(f) => out.push((
                        rel.to_owned(),
                        Fn_ {
                            name: f.sig.ident.to_string(),
                            module: module.to_owned(),
                            vis_pub: is_pub(&f.vis) && kept_in_wallet_view(&f.attrs),
                            self_ty: None,
                            sig: f.sig.clone(),
                            body: Some(f.block.to_token_stream()),
                        },
                    )),
                    syn::Item::Impl(i) => {
                        let self_name = match &*i.self_ty {
                            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
                            _ => None,
                        };
                        // Trait impls: the methods' visibility is the trait's;
                        // a trait method can still be a route, so it is
                        // examined with the trait's name as the self type.
                        for it in &i.items {
                            if let syn::ImplItem::Fn(f) = it {
                                let vis_pub = if i.trait_.is_some() {
                                    true
                                } else {
                                    is_pub(&f.vis) && kept_in_wallet_view(&f.attrs)
                                };
                                out.push((
                                    rel.to_owned(),
                                    Fn_ {
                                        name: f.sig.ident.to_string(),
                                        module: module.to_owned(),
                                        vis_pub,
                                        self_ty: self_name.clone(),
                                        sig: f.sig.clone(),
                                        body: Some(f.block.to_token_stream()),
                                    },
                                ));
                            }
                        }
                    }
                    syn::Item::Trait(t) => {
                        for it in &t.items {
                            if let syn::TraitItem::Fn(f) = it {
                                out.push((
                                    rel.to_owned(),
                                    Fn_ {
                                        name: f.sig.ident.to_string(),
                                        module: module.to_owned(),
                                        vis_pub: is_pub(&t.vis),
                                        self_ty: Some(t.ident.to_string()),
                                        sig: f.sig.clone(),
                                        body: f.default.as_ref().map(|b| b.to_token_stream()),
                                    },
                                ));
                            }
                        }
                    }
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            let path = if module.is_empty() {
                                m.ident.to_string()
                            } else {
                                format!("{module}::{}", m.ident)
                            };
                            collect_fns(inner, rel, &path, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        for (rel, module, ast) in &parsed {
            collect_fns(&ast.items, rel, module, &mut fns);
        }
        // Public item names per module, for the self-type check.
        let mut pub_items: BTreeSet<(String, String)> = BTreeSet::new();
        fn collect_pub_items(items: &[syn::Item], module: &str, out: &mut BTreeSet<(String, String)>) {
            for item in items {
                let (vis, name) = match item {
                    syn::Item::Struct(s) => (&s.vis, s.ident.to_string()),
                    syn::Item::Enum(e) => (&e.vis, e.ident.to_string()),
                    syn::Item::Type(t) => (&t.vis, t.ident.to_string()),
                    syn::Item::Trait(t) => (&t.vis, t.ident.to_string()),
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            let path = if module.is_empty() {
                                m.ident.to_string()
                            } else {
                                format!("{module}::{}", m.ident)
                            };
                            collect_pub_items(inner, &path, out);
                        }
                        continue;
                    }
                    _ => continue,
                };
                if is_pub(vis) {
                    out.insert((module.to_owned(), name));
                }
            }
        }
        for (_, module, ast) in &parsed {
            collect_pub_items(&ast.items, module, &mut pub_items);
        }

        // --- reaches-the-signer: body fixpoint over fn names ------------------
        let mut tainted: BTreeSet<String> = ["wots_sign", "wots_sign_counted", "sign_spend"].iter().map(|s| s.to_string()).collect();
        let mut signers_found: BTreeSet<String> = BTreeSet::new();
        for (rel, f) in &fns {
            if f.name == "wots_sign" || (f.name == "sign" && rel.ends_with("wots.rs")) {
                signers_found.insert(format!("{rel}::{}", f.name));
            }
        }
        loop {
            let before = tainted.len();
            for (rel, f) in &fns {
                if let Some(body) = &f.body {
                    if !tainted.contains(&f.name) && (mentions(body, &tainted) || names_wots_sign(body)) {
                        tainted.insert(f.name.clone());
                        let _ = rel;
                    }
                }
            }
            if tainted.len() == before {
                break;
            }
        }
        // `wots.rs::sign` is tainted by name too, for the visibility set below.
        tainted.insert("sign".to_owned());

        // --- the verdicts ------------------------------------------------------
        let mut flagged = Vec::new();
        let mut visible = BTreeSet::new();
        let mut signatures = 0usize;
        for (rel, f) in &fns {
            signatures += 1;
            let key = match &f.self_ty {
                Some(t) => format!("{rel}::{t}::{}", f.name),
                None => format!("{rel}::{}", f.name),
            };
            let module_visible = modules.get(&f.module).copied().unwrap_or(false);
            // The self type may be defined in a parent module (`Keystore` in
            // `keystore/mod.rs`, its methods in `keystore/sign.rs`), so it is
            // resolved by name across the crate; a name that is `pub` anywhere
            // counts, which errs toward flagging.
            let self_ok = match &f.self_ty {
                Some(t) => pub_items.iter().any(|(_, n)| n == t),
                None => true,
            };
            let lifted_here = lifted.contains(&(f.module.clone(), f.name.clone()))
                || lifted.contains(&(f.module.clone(), "*".to_owned()));
            let wallet_visible = f.vis_pub && self_ok && (module_visible || lifted_here);
            if wallet_visible {
                visible.insert(key.clone());
            }
            let output = match &f.sig.output {
                syn::ReturnType::Type(_, ty) => ty.to_token_stream().to_string(),
                syn::ReturnType::Default => "()".to_owned(),
            };
            // `-> Self` / `-> Result<Self>` inside an impl of a bearing type is
            // a bearing return spelled without the name; resolved through the
            // impl's self type.
            let self_bearing = f.self_ty.as_ref().is_some_and(|t| bearing.contains(t));
            let self_only: BTreeSet<String> = ["Self".to_owned()].into_iter().collect();
            let produces_ret = matches!(&f.sig.output, syn::ReturnType::Type(_, ty)
                if mentions(&ty.to_token_stream(), &bearing) || (self_bearing && mentions(&ty.to_token_stream(), &self_only)));
            let produces_mut = f.sig.inputs.iter().any(|arg| match arg {
                syn::FnArg::Typed(t) => matches!(&*t.ty, syn::Type::Reference(r) if r.mutability.is_some())
                    && mentions(&t.ty.to_token_stream(), &bearing),
                syn::FnArg::Receiver(_) => false,
            });
            let reaches = tainted.contains(&f.name)
                || f.body.as_ref().is_some_and(|b| mentions(b, &tainted) || names_wots_sign(b));
            let why = if produces_ret {
                "returns a signature-bearing type"
            } else if produces_mut {
                "writes a signature-bearing value through &mut"
            } else if reaches {
                "reaches the signer"
            } else {
                continue;
            };
            if !wallet_visible {
                continue;
            }
            let holder_params: Vec<String> = f
                .sig
                .inputs
                .iter()
                .filter_map(|arg| match arg {
                    syn::FnArg::Typed(t) if mentions(&t.ty.to_token_stream(), &holders) => {
                        Some(t.ty.to_token_stream().to_string())
                    }
                    _ => None,
                })
                .chain(f.self_ty.iter().filter(|t| holders.contains(*t)).map(|t| format!("self: {t}")))
                .collect();
            let body_names_sign_spend = f.body.as_ref().is_some_and(|b| {
                idents(b)
                    .iter()
                    .any(|t| matches!(t.to_string().as_str(), "sign_spend" | "resign_reserved"))
            });
            let body_names_raw = f.body.as_ref().is_some_and(|b| {
                names_wots_sign(b)
                    || idents(b).iter().any(|t| t.to_string() == "wots_sign")
            });
            let body_names_wallet = f
                .body
                .as_ref()
                .is_some_and(|b| idents(b).iter().any(|t| t.to_string() == "Wallet"));
            let body_idents: Vec<String> = f
                .body
                .as_ref()
                .map(|b| idents(b).iter().map(|t| t.to_string()).collect())
                .unwrap_or_default();
            let takes_digest = f.sig.inputs.iter().any(|arg| match arg {
                syn::FnArg::Typed(t) => {
                    let rendered = t.ty.to_token_stream().to_string().replace(' ', "");
                    rendered.contains("[u8;32]") || rendered.contains("[u8;HASHLEN]")
                }
                syn::FnArg::Receiver(_) => false,
            });
            let reads_pending = f
                .body
                .as_ref()
                .is_some_and(|b| idents(b).iter().any(|t| t.to_string() == "pending"));
            flagged.push(Flagged {
                name: key,
                output,
                why,
                reaches_signer: reaches,
                body_names_wallet,
                body_idents,
                takes_digest,
                reads_pending,
                holder_params,
                names_sign_spend: body_names_sign_spend,
                names_raw_signer: body_names_raw,
            });
        }
        flagged.sort_by(|a, b| a.name.cmp(&b.name));
        Analysis {
            flagged,
            bearing,
            modules,
            signers_found,
            visible,
            signatures,
        }
    }
}

/// I1 across accounts — **green**, under a name that says which
/// half of the property the green covers.
///
/// # The finding this discharges
///
/// A rotation key is `derive_wots_key(seed, r)`, a function of the 32-byte
/// seed alone. `import_with_unverified_tag` accepted any tag and
/// `Keystore::add` deduped on tag alone, so one root under two tags — or a
/// derived account's seed re-imported under another tag — was two slots with
/// independent indices over ONE key stream, and each `persist_advance` →
/// `sign_spend` passed every check while the same key signed two digests.
/// **Tag uniqueness is not stream uniqueness**, and the verifying import
/// the index decision owed does not close it either: any `(pub_seed, adrs)` pair is
/// reproduced by the root and yields a different tag over the same stream.
///
/// The signing path closed the halves that needed no format change — `add` refuses an
/// imported root constant-time-equal to a stored one, and `sign_spend`'s
/// derived path refuses a derived seed equal to a stored imported root — and
/// could not close the half a **reopen** defeats: `add` holds no master seed,
/// so a reopened store had nothing comparable for a derived account.
///
/// # What discharged it
///
/// Every format-v2 record carries the stream's public identity: the
/// rotation-0 public key's hash (`derive::stream_id`), computed in
/// `Account::derive` from the master and in `Account::import` from the root.
/// `Keystore::add` **recomputes** the incoming account's identity from its own
/// key material — never reads it off the record — and refuses a duplicate
/// across kinds, in either insertion order, through a reopen.
///
/// The old constant-time root comparison stays and is not redundant: it
/// compares the key material rather than a value derived from it, so it holds
/// where a stored identity has been tampered with, and it runs first so that
/// one root under two tags reports the root. A *derived* record's identity
/// cannot be checked at parse time — that needs the master — so `sign_spend`
/// re-derives it and refuses a disagreement (`StreamIdNotReproduced`), which
/// is the only place it is checked at all.
///
/// # THE BOUND IN THE NAME
///
/// **`within_one_keystore_not_across_stores`.** The same stream in two
/// *stores* — a copied directory, `into_records` into a second store, a seed
/// re-derived into a fresh keystore after it spent — is untouched by this and
/// always was: nothing in one store can see another. That is I4's and I5's
/// subject, and the identity this landed is the comparable public value a
/// divergence report will print. `key_signs_once_per_keystore_...` carries
/// the same bound for the same reason.
///
/// Two further residues: a forged measurement is invisible to the census
///; and a stored identity is trusted between `open` and the next
/// signature for the derived kind, which is the keystore's stated threat
/// model — the trailer is integrity, not authenticity.
#[test]
fn duplicate_key_streams_are_refused_within_one_keystore_not_across_stores() {
    // Anchor: the record still carries the identity. `RECORD_LEN` names the
    // stream field by width, so a record that drops it fails here rather than
    // going on to demand a proof of a property nothing could hold.
    let format_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/keystore/format.rs"));
    assert!(
        format_rs.contains("ADDR_TAG_LEN + 1 + 32 + FIRST_KEY_LEN + ADDR_TAG_LEN + 4 + 1 + 4 + 32"),
        "keystore/format.rs's RECORD_LEN no longer carries the second ADDR_TAG_LEN -- the \
         key-stream identity. Without it `Keystore::add` has nothing to compare a derived \
         account against after a reopen and one seed can sit under two tags again; re-read \
         the signing path's and format v2's module docs before treating this as a layout change."
    );
    // And the recomputation is what makes a forged record unable to walk
    // past `add`: the identity of the account being added comes from its own
    // key material, never off a record.
    let keystore_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/keystore/mod.rs"));
    assert!(
        keystore_rs.contains("fn recomputed_stream_id"),
        "Keystore no longer recomputes the incoming account's stream identity; reading it \
         off the record would make the check satisfiable by whoever wrote the file"
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "duplicate_key_streams_are_refused_across_kinds_after_reopen";
    if let Err(why) = census::check(
        "duplicate_key_streams_are_refused_within_one_keystore_not_across_stores",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to derive an account, spend from \
             it, import its seed under another tag, reopen, and show that both `add` and \
             `sign_spend` refuse the duplicate stream in both kinds -- which needs a \
             stream identity carried in the record. It must report how many kinds it \
             drove; the floor is 2.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I1 ACROSS ACCOUNTS has REGRESSED: before format v2 this red meant one key stream could \
         sit under two tags in one keystore -- the same root imported twice, a derived seed \
         re-imported, or one root under a first address built from junk components -- with \
         each slot's index advancing independently while one key signed twice. Format v2 \
         carries the stream's public identity in every record and `Keystore::add` refuses a \
         duplicate across kinds, so this firing means the proof, its census row, or the \
         identity went away.\n{}\n\
         What must still hold: the identity is in the record for both kinds, `add` \
         recomputes it for the incoming account rather than reading it, and the refusal \
         survives a drop-and-reopen in both insertion orders. Two stores over one seed is \
         NOT this -- that is I4's and I5's. The signing path found it, format v2 landed it; \
         docs/specification.md I1.",
        owed.join("\n")
    );
}

// ---------------------------------------------------------------------------
// I2 - I5. The crash-consistency and restore invariants.
//
// The argument that these need a wallet crate that does not exist fails by
// execution: `i1_one_signature_per_key`
// (cleared and renamed to
// `key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent`)
// and `imported_accounts_have_a_restore_path` (cleared and renamed to
// `imported_account_restore_is_checked_in_memory_not_on_disk`) were both
// pre-wallet markers and both red before the wallet layer, so a pre-wallet invariant
// demonstrably can carry one.
//
// **They are a different shape from every other red on this board.** The rest
// fail by producing a wrong byte or a false green, which is what the whole
// differential apparatus exists to catch. These fail by REUSING A WOTS+ KEY:
// nothing computes a wrong answer, nothing goes red, and the loss surfaces later
// as funds that can no longer be moved. The signature scheme's security for that
// key is gone at the moment of reuse, and no subsequent care recovers it.
//
// The specification's I4 and I5 sections hold the decisions and the measurement behind them.
// ---------------------------------------------------------------------------

/// How many files under `crates/*/src` name a durable-write primitive.
///
/// Reported rather than asserted. It is the premise behind I2 and I3 -- *there
/// is no persistence layer in this tree at all* -- and stating it as a measured
/// number in the failure message is the difference between "write a test" and
/// "write a test, and note that the thing it would test does not exist yet".
///
/// A count and not a boolean, because zero is the informative value and a
/// boolean cannot report how far from zero it has moved.
fn files_naming_a_durable_write() -> (usize, Vec<String>) {
    const PRIMITIVES: [&str; 5] = ["sync_all", "sync_data", "fsync", "persist(", "rename("];
    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any count taken over it \
         is vacuous",
        files.len()
    );
    let hits: Vec<String> = files
        .iter()
        .filter(|(_, code)| PRIMITIVES.iter().any(|p| code.contains(p)))
        .map(|(name, _)| name.clone())
        .collect();
    (files.len(), hits)
}

/// I2 -- the key index is durably persisted before a signature is released.
///
/// A crash between signing and persisting leaves the on-disk index pointing at a
/// key that has already signed. The next spend reuses it, and nothing about that
/// failure is visible at the time -- not to the wallet, not to the chain, and
/// not to the user until the funds are gone.
///
/// # This is not I1, and I1 going green does not clear it
///
/// I1 requires that the only public path to a signature advance the index. That
/// is satisfiable by a wallet API advancing an index **in memory**. I2 is the
/// stricter half: the advanced index must be *on disk and flushed* before the
/// signature is handed to the caller. A design that satisfies I1 perfectly and
/// returns the signature before the `fsync` completes violates I2 on every
/// spend, and the two markers are separate so that clearing the easy one cannot
/// look like clearing both.
///
/// # WHAT THIS MARKER CAN AND CANNOT SEE
///
/// It is the sole mechanism for its property, so the residue is stated here
/// rather than nowhere.
///
/// * **There is no oracle behind this and there cannot be one.** The C has no
///   counterpart -- the C reference is a node, not a wallet, and
///   persists a ledger rather than a key index -- so no differential reaches it.
///   The extension's storage layer is not an oracle either: it is a third-party
///   client in the recon tier, and agreeing with it would prove only that we
///   copied it.
/// * **It cannot see whether the required test's assertions are right.** The
///   census establishes that the named test is in libtest's run list, ran alone,
///   passed, was not ignored, and printed a measurement above a floor. A
///   substantial body printing a plausible line is a forgery it cannot detect,
///   and here that residue matters more than anywhere else on this board,
///   because there is nothing else checking.
/// * **It cannot see an `fsync` that lies.** A filesystem or a virtual disk that
///   acknowledges a flush it did not perform violates I2 with every layer above
///   it behaving correctly. That is out of reach of any test this project can
///   write and is recorded so nobody reads a green I2 as a durability proof.
/// # The bound is in the name
///
/// The artefact whose release is gated is the **receipt** — no signer
/// exists yet, and the census row's target name predates the receipt — and
/// the crash model is a **kill at a syscall boundary**, not power loss.
///
/// # What the green claims, and what it cannot
///
/// `signature_is_not_released_before_the_index_is_durable` drives four crash
/// points between the first write and the receipt return, reopens from disk,
/// and shows the previous index unreachable and no receipt escaped. It cannot
/// see power loss, an fsync that lies, or fsyncgate; the keystore's poisoned
/// handle is the answer to the last, and the proof's doc names the rest.
///
#[test]
fn index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss() {
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "signature_is_not_released_before_the_index_is_durable";
    if let Err(why) = census::check("index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to drive a signing call \
             that crashes between the index write and the return, restart from \
             the on-disk state, and assert the previous key is not reachable \
             again -- reporting how many crash points it exercised. Asserting \
             that a persist function was CALLED is not this: the property is \
             ordering plus durability, and a call that is ordered right and \
             never flushed loses the same key.\n\x20   {why}"
        ));
    }

    let (scanned, durable) = files_naming_a_durable_write();

    assert!(
        owed.is_empty(),
        "I2's enforcement has REGRESSED: once this red meant nothing in \
         the tree persisted a key index; src/keystore and the proof landed, \
         so this firing means the proof, its census row, or the keystore went \
         away.\n{}\n\x20 - premise, measured: {} file(s) under \
         crates/*/src, {} of them naming any durable-write primitive{}.\n\
         A signature released before its index reaches stable storage is a key \
         that signs twice across the next crash. WOTS+ leaks secret material \
         with each use and two signatures under one key make forgery tractable, \
         so this is not a recoverable error class -- there is no repair after \
         the fact, only the funds that key holds, exposed. See \
         docs/specification.md I2.",
        owed.join("\n"),
        scanned,
        durable.len(),
        if durable.is_empty() {
            String::new()
        } else {
            format!(" ({})", durable.join(", "))
        }
    );
}

/// I3 -- spend-related state advances atomically.
///
/// Index, keystore metadata and any pending-transaction record must not be able
/// to disagree. A partial write that advances one but not the others is
/// indistinguishable from corruption at the next startup, and the recovery for
/// corruption is not the recovery for a half-completed spend.
///
/// The enforcement the specification prescribes (I3) is the standard four-step:
/// write a temp file in the same directory, `fsync` the file, `rename` over the
/// target, `fsync` the directory. All spend-related state moves in one such
/// write. The floor on the required test is **4** for that reason -- it is the
/// number of interruption points the invariant's own enforcement clause names,
/// derived from the invariant rather than chosen.
///
/// # WHAT THIS MARKER CAN AND CANNOT SEE
///
/// * **No oracle, and no reference counterpart at all.** Same footing as I2.
/// * **It cannot see the set of state that counts as spend-related.** The
///   invariant names three members today; a fourth added later is covered by
///   I3's prose and by nothing mechanical here. A test that atomically writes
///   two of the three passes its own assertions and this marker both.
/// * **It cannot distinguish one atomic write from three atomic writes.** Three
///   individually-atomic writes satisfy every "never torn" assertion and still
///   let the index and the keystore disagree between them, which is precisely
///   what I3 forbids. The required test has to observe *across* the members, and
///   the census cannot tell whether it did.
/// # The crash model is in the name
///
/// The
/// proof interrupts at the four steps I3's clause names by killing at syscall
/// boundaries, reopens, and finds index, pending record and generation
/// fully pre or fully post together. It cannot see power loss or an fsync
/// that lies.
#[test]
fn spend_state_is_atomic_under_syscall_kill_not_power_loss() {
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "spend_state_is_never_observed_half_advanced";
    if let Err(why) = census::check("spend_state_is_atomic_under_syscall_kill_not_power_loss", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to interrupt the spend \
             write at each point in the sequence docs/specification.md I3 names -- \
             temp file written, file fsynced, renamed over the target, directory \
             fsynced -- and assert that what a fresh reader finds on disk is \
             always FULLY pre-spend or FULLY post-spend, across every member of \
             the spend state and not one at a time. It must report the number of \
             interruption points it drove; the floor is 4, which is the count \
             the invariant's own enforcement clause names.\n\x20   {why}"
        ));
    }

    let (scanned, durable) = files_naming_a_durable_write();

    assert!(
        owed.is_empty(),
        "I3's enforcement has REGRESSED: once this red meant there was no \
         spend-state write in the tree; the keystore's atomic commit landed \
         and the proof, so this firing means the proof, its census row, or the \
         commit sequence went away.\n{}\n\x20 - premise, measured: \
         {} file(s) under crates/*/src, {} of them naming any durable-write or \
         atomic-rename primitive{}.\n\
         A half-advanced spend state is indistinguishable from corruption, and \
         the two have different correct recoveries -- one resumes, one refuses. \
         A wallet that cannot tell them apart will guess, and the wrong guess \
         reuses a key. See docs/specification.md I3.",
        owed.join("\n"),
        scanned,
        durable.len(),
        if durable.is_empty() {
            String::new()
        } else {
            format!(" ({})", durable.join(", "))
        }
    );
}

/// I3's proof: interrupt the commit at each of the four steps, reopen from
/// disk, and find every member of the spend state fully pre- or fully
/// post-spend, never mixed.
///
/// # What this establishes, and what it cannot see
///
/// Each interruption is a kill at a syscall boundary: `Instrumented` performs
/// the primitive and then returns an error, and the keystore's error path
/// makes no further filesystem call (asserted from the recorder, not
/// trusted). Everything a completed syscall left is visible to the reopen.
/// **Not driven:** power loss (page cache dropped, journal truncated), an
/// fsync that lies, fsyncgate (after `EIO` the pages may be gone
/// — hence the poisoned handle, never a retry), and rename atomicity on
/// filesystems that do not journal it. The marker this clears carries that
/// bound in its name.
///
/// The recorder holds **arguments**, not just names: an `fsync_file` on the
/// directory instead of the temp keeps every count and every byte
/// assertion green and is visible only in the sequence assertion below —
/// the paired injection recorded with the keystore is what shows that assertion is real.
/// # What an AEAD did and did not do to this proof
///
/// The decision deferring the AEAD predicted that encryption would end this test's byte
/// comparisons and that the proof would have to be rewritten from
/// byte-equality to decrypt-then-compare. **It did not have to be.** The image
/// is still deterministic, because `mochimo-crypto` has no RNG and never
/// wanted one: the salt and the per-open nonce seed are *parameters*
/// (`cli::create`'s precedent), so the harness supplies fixed ones and two
/// stores with identical contents are identical files. Not a line of the walk
/// below changed.
///
/// **But the two observables are no longer worth the same thing, and that is
/// worth knowing before reading them:**
///
/// * the **byte** comparisons (`pre_bytes` / `post_bytes`) are now a claim
///   about the commit AND about the harness's fixed entropy. In production the
///   nonce differs per open, so the same state written twice is two different
///   files. They still catch a target that moved before the rename, which is
///   what they are here for -- but they would not hold outside this harness,
///   and the guard directly below already says so in the one place that
///   matters.
/// * the **state** comparisons -- `view()`, `generation()`, `into_records()`
///   after a reopen -- are the decrypt-then-compare path, and they are what
///   "fully pre or fully post" actually means. They hold whatever the nonce
///   is, because a reopen decrypts. These are the assertions the invariant
///   rests on, and they were already the ones doing the work.
///
/// So the observation path did not become new; it became the *only* one that
/// generalises, and the byte layer above it became a determinism check. The
/// encryption change recorded the prediction and why it was wrong in a way that made the earlier
/// decision to split this session out more right rather than less: the split
/// was correct for the observation-path reason regardless of whether the
/// observable survived.
#[test]
fn spend_state_is_never_observed_half_advanced() {
    use keystore_harness::{
        derived_account, imported_account, ScratchDir, DERIVED_POSITION, DERIVED_TAG, DIGEST,
        FIGURES, IMPORTED_TAG, ROOT,
    };
    use mochimo_crypto::account::{AccountRecord, WotsIndex};
    use mochimo_crypto::keystore::{Call, Disk, Instrumented, Keystore, Pending};

    const STEPS: [&str; 4] = ["write_temp", "fsync_file", "rename", "fsync_dir"];
    /// The digest of the reservation the seed settles and RETAINS, so that
    /// `settled` is a live member of the walk: the interrupted
    /// reservation below moves four durable members at once -- the index,
    /// the generation, `pending` 0 -> 1 and `settled` 1 -> 0.
    const SETTLED_DIGEST: [u8; 32] = [0xD0; 32];
    let retained = Pending {
        spent_index: WotsIndex::ZERO,
        digest: SETTLED_DIGEST,
        figures: Some(FIGURES),
    };
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));

    // Seed a keystore: imported with ONE reservation already settled and
    // retained (index 1, no open reservation, a settled block at 0), derived
    // at position 9 advanced to 5 in memory before it is added (a reset to
    // zero is then visible).
    fn seed(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init())
            .unwrap_or_else(|e| panic!("create: {e}"));
        ks.add(imported_account()).unwrap_or_else(|e| panic!("add imported: {e}"));
        let mut d = derived_account();
        for _ in 0..5 {
            d.advance().unwrap_or_else(|e| panic!("advance: {e}"));
        }
        ks.add(d).unwrap_or_else(|e| panic!("add derived: {e}"));
        let _ = ks
            .persist_advance(&IMPORTED_TAG, &SETTLED_DIGEST, FIGURES)
            .unwrap_or_else(|e| panic!("seed reserve: {e}"));
        ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("seed settle: {e}"));
        ks.medium_mut().reset_calls();
        ks
    }
    // The same store one commit further: the reservation open, for the
    // settle walk.
    fn seed_open(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = seed(dir);
        let _ = ks
            .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
            .unwrap_or_else(|e| panic!("seed open: {e}"));
        ks.medium_mut().reset_calls();
        ks
    }

    // Control run: the uninterrupted reservation commit, its bytes, and its
    // sequence.
    let control = ScratchDir::new("i3-control");
    let mut ks = seed(&control);
    let pre_bytes = control.snapshot_bytes();
    let pre_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    let receipt = ks
        .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
        .unwrap_or_else(|e| panic!("control persist: {e}"));
    assert_eq!(receipt.tag(), IMPORTED_TAG);
    assert_eq!(receipt.index().get(), 2);
    let post_bytes = control.snapshot_bytes();
    let post_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(pre_bytes, post_bytes, "the control commit changed nothing on disk");
    assert_eq!(post_gen, pre_gen + 1);
    let tmp = control.path().join("accounts.mks.tmp");
    let snap = control.path().join("accounts.mks");
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::WriteTemp {
                path: tmp.clone(),
                len: post_bytes.len()
            },
            Call::FsyncFile { path: tmp.clone() },
            Call::Rename {
                from: tmp.clone(),
                to: snap.clone()
            },
            Call::FsyncDir {
                dir: control.path().to_path_buf()
            },
        ],
        "the uninterrupted commit must be exactly the four steps, in order, \
         on these paths -- an fsync on the wrong path is visible only here"
    );
    drop(ks);

    let mut driven = 0usize;
    for k in 1..=4usize {
        let dir = ScratchDir::new("i3-interrupt");
        let mut ks = seed(&dir);
        assert_eq!(
            dir.snapshot_bytes(),
            pre_bytes,
            "seeding is not deterministic; the byte comparisons below are void"
        );
        ks.medium_mut().stop_after(Some(k));
        let err = ks
            .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
            .err()
            .unwrap_or_else(|| panic!("interruption point {k}: persist returned Ok"));
        assert_eq!(
            err,
            mochimo_crypto::Error::Io {
                op: STEPS[k - 1],
                kind: std::io::ErrorKind::Interrupted
            },
            "interruption point {k}: not the injected error"
        );
        assert_eq!(
            ks.medium().calls().len(),
            k,
            "interruption point {k}: the error path made a further medium call"
        );
        let listing = dir.listing();
        let has_tmp = listing.iter().any(|n| n == "accounts.mks.tmp");
        if k < 3 {
            assert!(has_tmp, "interruption point {k}: the temp should still exist: {listing:?}");
            assert_eq!(dir.snapshot_bytes(), pre_bytes, "interruption point {k}: target moved before rename");
        } else {
            assert!(!has_tmp, "interruption point {k}: the temp should have been renamed away: {listing:?}");
            assert_eq!(dir.snapshot_bytes(), post_bytes, "interruption point {k}: target is not the committed image");
        }
        // A handle that saw the error is poisoned; nothing more happens on it.
        assert!(matches!(ks.persist_settled(&IMPORTED_TAG), Err(mochimo_crypto::Error::Poisoned { .. })));
        drop(ks);

        // Restart from the on-disk state -- through the harness's bounded
        // reopen, never a bare `open_with`: the census spawns children beside
        // this proof, and a just-released flock can look held for ~200 µs
        //. Retried on `Locked` alone; every other error is final.
        let ks = keystore_harness::reopen_with("I3 interruption point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("interruption point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("interruption point {k}: imported account vanished"));
        let gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        let index_is_pre = view.wots_index == one;
        let pending_is_pre = view.pending.is_none();
        let settled_is_pre = view.settled.is_some();
        let gen_is_pre = gen == pre_gen;
        assert!(
            index_is_pre == pending_is_pre && pending_is_pre == settled_is_pre && settled_is_pre == gen_is_pre,
            "interruption point {k}: spend state observed HALF-advanced -- index pre={index_is_pre}, \
             pending pre={pending_is_pre}, settled pre={settled_is_pre}, generation pre={gen_is_pre}"
        );
        let expect_pre = k < 3;
        assert_eq!(index_is_pre, expect_pre, "interruption point {k}: wrong side of the commit");
        if expect_pre {
            assert_eq!(view.settled, Some(retained), "interruption point {k}: the pre-spend state lost its retained block");
        } else {
            let p = view.pending.unwrap_or_else(|| panic!("post-spend state without a pending record"));
            assert_eq!(p.spent_index, one);
            assert_eq!(p.digest, DIGEST);
            assert_eq!(p.figures, Some(FIGURES), "interruption point {k}: the figures did not commit with the reservation");
            assert_eq!(view.wots_index.get(), 2);
            assert_eq!(view.settled, None, "interruption point {k}: the retained block survived the reservation that releases it");
        }
        assert!(
            !dir.listing().iter().any(|n| n == "accounts.mks.tmp"),
            "interruption point {k}: reopen left the stale temp in place"
        );
        let derived = ks
            .view(&DERIVED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("interruption point {k}: derived account vanished"));
        assert_eq!(derived.wots_index.get(), 5, "interruption point {k}: the sibling account moved");
        let mut roots = 0;
        for r in ks.into_records().unwrap_or_else(|e| panic!("{e}")) {
            match r {
                AccountRecord::Imported { root, .. } => {
                    assert_eq!(root.expose(), &ROOT, "interruption point {k}: the root did not survive");
                    roots += 1;
                }
                AccountRecord::Derived { account_index, .. } => {
                    assert_eq!(account_index, DERIVED_POSITION);
                }
            }
        }
        assert_eq!(roots, 1);
        driven += 1;
    }
    assert_eq!(driven, 4, "the loop drove {driven} points, not the four I3 names");

    // **The settle commit's own four points** (the version-4 decision asked
    // whether it earns them). Under version 4 a settle is no longer a clear:
    // it writes state 1 -> 2 and applies a two-field memory mutation, and
    // the block it moves is the only record of the one signature that key
    // may ever give. Seeded with the reservation OPEN; at each point a fresh
    // reader finds it fully open (state 1 with figures, no settled block) or
    // fully settled (state 2 with figures, no open reservation), never a mix,
    // and the index never moves.
    let open_block = Pending {
        spent_index: one,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let control2 = ScratchDir::new("i3-settle-control");
    let mut ks = seed_open(&control2);
    let pre2_bytes = control2.snapshot_bytes();
    let pre2_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("control settle: {e}"));
    let post2_bytes = control2.snapshot_bytes();
    assert_ne!(pre2_bytes, post2_bytes, "the control settle changed nothing on disk");
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), pre2_gen + 1);
    assert_eq!(ks.medium().calls().len(), 4, "the settle commit is the same four steps");
    drop(ks);
    for k in 1..=4usize {
        let dir = ScratchDir::new("i3-settle-interrupt");
        let mut ks = seed_open(&dir);
        assert_eq!(dir.snapshot_bytes(), pre2_bytes, "seeding is not deterministic; the byte comparisons below are void");
        ks.medium_mut().stop_after(Some(k));
        let err = ks
            .persist_settled(&IMPORTED_TAG)
            .err()
            .unwrap_or_else(|| panic!("settle point {k}: persist_settled returned Ok"));
        assert_eq!(
            err,
            mochimo_crypto::Error::Io {
                op: STEPS[k - 1],
                kind: std::io::ErrorKind::Interrupted
            },
            "settle point {k}: not the injected error"
        );
        assert_eq!(ks.medium().calls().len(), k, "settle point {k}: the error path made a further medium call");
        if k < 3 {
            assert_eq!(dir.snapshot_bytes(), pre2_bytes, "settle point {k}: target moved before rename");
        } else {
            assert_eq!(dir.snapshot_bytes(), post2_bytes, "settle point {k}: target is not the committed image");
        }
        assert!(matches!(
            ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES),
            Err(mochimo_crypto::Error::Poisoned { .. })
        ));
        drop(ks);
        let ks = keystore_harness::reopen_with("I3 settle point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("settle point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("settle point {k}: imported account vanished"));
        let gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        let open_is_pre = view.pending.is_some();
        let retained_is_post = view.settled.is_some();
        let gen_is_pre = gen == pre2_gen;
        assert!(
            open_is_pre != retained_is_post && open_is_pre == gen_is_pre,
            "settle point {k}: settle observed HALF-done -- open={open_is_pre}, retained={retained_is_post}, generation pre={gen_is_pre}"
        );
        assert_eq!(open_is_pre, k < 3, "settle point {k}: wrong side of the commit");
        if k < 3 {
            assert_eq!(view.pending, Some(open_block), "settle point {k}: the open reservation is not what was sealed");
        } else {
            assert_eq!(view.settled, Some(open_block), "settle point {k}: the settled block is not the reservation, figures included");
        }
        assert_eq!(view.wots_index.get(), 2, "settle point {k}: settle moved the index");
        assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "settle point {k}: reopen left the stale temp in place");
        driven += 1;
    }
    assert_eq!(driven, 8, "the two loops drove {driven} points, not eight");

    // Every integer on this line is a small count; the largest
    // is what the census reads against its floor of 4.
    println!(
        "  I3 atomicity: {driven} interruption point(s) driven -- 4 over the reservation, 4 over \
         the settle -- 4 member(s) observed across each, 2 account(s) reopened at every point"
    );
}

/// I2's proof: the receipt — the gate `Keystore::sign_spend` consumes — is
/// never released for an index that is not durable.
///
/// # What "release" means here, honestly
///
/// The artefact released is the [`AdvanceReceipt`], minted only after the
/// directory fsync with a `Durable` witness constructed at one site. What
/// this green establishes is *no receipt exists for an index that is not on
/// disk*. When it was written there was no signer — `wots::sign` was
/// public and `i1_one_signature_per_key` was red — so the receipt was the
/// whole claim, and the marker's post-discharge name says "receipt", never
/// "signature", on purpose. Now the signer demands the receipt and
/// re-checks it against the store's live state (`tests/signing.rs`);
/// this proof is unchanged, because what it establishes did not move:
/// the signature is withheld *because* the receipt is.
///
/// The post-broadcast/pre-persist ordering — the shipped wallet's defect
/// — is unrepresentable rather than driven: anything
/// standing in for a broadcast takes `&AdvanceReceipt`, and nothing outside
/// the crate can mint one (`ui/fail/account_advance_receipt_is_not_constructible.rs`).
/// Same crash model and residue as the I3 proof above.
#[test]
fn signature_is_not_released_before_the_index_is_durable() {
    use keystore_harness::{derived_account, imported_account, ScratchDir, DIGEST, FIGURES, IMPORTED_TAG};
    use mochimo_crypto::account::{AdvanceReceipt, WotsIndex};
    use mochimo_crypto::keystore::{Disk, Instrumented, Keystore};

    fn broadcast(_r: &AdvanceReceipt) -> &'static str {
        "broadcast requires the receipt; it cannot precede persistence"
    }

    fn seed(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init())
            .unwrap_or_else(|e| panic!("create: {e}"));
        ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
        ks.medium_mut().reset_calls();
        ks
    }

    let mut receipts_escaped = 0usize;
    let mut driven = 0usize;
    for k in 1..=4usize {
        let dir = ScratchDir::new("i2-crash");
        let mut ks = seed(&dir);
        ks.medium_mut().stop_after(Some(k));
        if ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).is_ok() {
            receipts_escaped += 1;
        }
        drop(ks);
        // Bounded reopen, `Locked` alone retried: the census's children make a
        // just-released flock look held for ~200 µs. This is the
        // reopen that failed once in each of two early sessions.
        let mut ks = keystore_harness::reopen_with("I2 crash point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("crash point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("crash point {k}: account vanished"));
        if k >= 3 {
            // Durable before the return: the index advanced, the previous
            // key is not reachable, and the one receipt that would have named
            // it was never released.
            assert_eq!(view.wots_index.get(), 1, "crash point {k}: durable state not advanced");
            ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
            let back = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
            assert!(
                matches!(back, Some(mochimo_crypto::Error::Range { what: "wots index for tag", min: 2, got: 0, .. })),
                "crash point {k}: the previous index was reachable again: {back:?}"
            );
            let equal = ks.persist_advance_to(&IMPORTED_TAG, view.wots_index).err();
            assert!(matches!(equal, Some(mochimo_crypto::Error::Range { .. })));
        } else {
            assert_eq!(view.wots_index.get(), 0, "crash point {k}: pre-commit crash advanced the index");
            let equal = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
            assert!(matches!(equal, Some(mochimo_crypto::Error::Range { .. })));
            let next = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
            let r = ks
                .persist_advance_to(&IMPORTED_TAG, next)
                .unwrap_or_else(|e| panic!("crash point {k}: liveness after a pre-commit crash: {e}"));
            assert_eq!(r.index(), next);
            let _ = broadcast(&r);
            drop(ks);
            let ks = keystore_harness::reopen("I2 liveness", dir.path())
                .result
                .unwrap_or_else(|e| panic!("{e}"));
            let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("vanished"));
            assert_eq!(v.wots_index, next, "the receipt named an index a fresh reopen does not read");
        }
        driven += 1;
    }
    assert_eq!(driven, 4);
    assert_eq!(receipts_escaped, 0, "a receipt escaped an interrupted persist");

    // Control: the uninterrupted run releases exactly one receipt, and it
    // names what a fresh reopen reads.
    let dir = ScratchDir::new("i2-control");
    let mut ks = seed(&dir);
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.tag(), IMPORTED_TAG);
    let _ = broadcast(&r);
    drop(ks);
    let ks = keystore_harness::reopen("I2 control", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("vanished"));
    assert_eq!(v.wots_index, r.index());

    println!(
        "  I2 durability: {driven} crash point(s) driven between the first write and the \
         receipt return, {receipts_escaped} receipt(s) escaped, 1 receipt from the \
         uninterrupted run naming the index a fresh reopen reads"
    );
}

/// `Durable` — the witness `AdvanceReceipt::attesting` demands — is
/// constructed at exactly one non-test site in the crate: the `Ok` arm after
/// the directory fsync in `Keystore::commit`. This is what makes "the receipt
/// is minted only after the four steps" a property of the source rather than
/// a convention. Items under `#[cfg(test)]` are skipped on purpose: the
/// account module's unit tests need a witness to exercise the receipt, and a
/// test-only mint cannot reach a release build.
#[test]
fn durable_witness_has_one_construction_site() {
    use quote::ToTokens;

    fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            let s = a.to_token_stream().to_string().replace(' ', "");
            s.contains("cfg(test)")
        })
    }
    fn count_in(tokens: proc_macro2::TokenStream) -> usize {
        let s = tokens.to_string().replace(' ', "");
        s.matches("Durable(())").count()
    }
    fn walk(items: &[syn::Item], sites: &mut Vec<(String, usize)>, file: &str) {
        for item in items {
            match item {
                syn::Item::Mod(m) => {
                    if is_cfg_test(&m.attrs) {
                        continue;
                    }
                    if let Some((_, inner)) = &m.content {
                        walk(inner, sites, file);
                    }
                }
                syn::Item::Fn(f) => {
                    if !is_cfg_test(&f.attrs) {
                        let n = count_in(f.block.to_token_stream());
                        if n > 0 {
                            sites.push((format!("{file}::{}", f.sig.ident), n));
                        }
                    }
                }
                syn::Item::Impl(im) => {
                    if is_cfg_test(&im.attrs) {
                        continue;
                    }
                    for it in &im.items {
                        if let syn::ImplItem::Fn(f) = it {
                            if !is_cfg_test(&f.attrs) {
                                let n = count_in(f.block.to_token_stream());
                                if n > 0 {
                                    sites.push((format!("{file}::{}", f.sig.ident), n));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let files = crate_source_files();
    assert!(files.len() >= 10, "the walk found only {} files", files.len());
    let mut sites: Vec<(String, usize)> = Vec::new();
    let mut saw_definition = false;
    for (name, text) in &files {
        let parsed = syn::parse_file(text).unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        if text.contains("pub struct Durable(());") {
            saw_definition = true;
        }
        walk(&parsed.items, &mut sites, name);
    }
    assert!(saw_definition, "the Durable witness type is gone; re-read the specification's I2 before deciding what I2 now means");
    let total: usize = sites.iter().map(|(_, n)| n).sum();
    assert_eq!(
        total,
        1,
        "Durable(()) must be constructed at exactly one non-test site (Keystore::commit's Ok arm); found: {sites:?}"
    );
    assert!(
        sites[0].0.ends_with("keystore/mod.rs::commit"),
        "the one construction site moved out of Keystore::commit: {sites:?}"
    );
}

/// **I6 at rest, GREEN.** The imported root — and, since the same
/// session, the master seed — reach the snapshot encrypted.
///
/// # Where the premise arm lives
///
/// Measuring the premise live -- writing a store with a patterned root and
/// asserting the root's bytes **are** in the file at byte offset 43 -- is an
/// arm that depends on the defect existing, so encryption at rest inverts it
/// rather than retiring it. It lives in `keystore.rs::snapshot_bytes_never_contain_the_imported_root`,
/// flipped to assert absence — and offset 43 is the first place that test
/// looks, because *not at 43* and *not anywhere* are different claims and the
/// weaker one is what an encryption bug would satisfy.
///
/// # The anchor moved with it, and changed subject
///
/// The old anchor asserted `format.rs` still contained
/// `image.extend_from_slice(root.secret().expose());` — the plaintext write
/// path — so that the marker could not go green merely because the encoder had
/// been reshaped. That expression is still there and must be: version 3
/// encrypts the *image*, so the record body is still assembled in the clear
/// before it is sealed. What changed is what makes that safe, so the anchor
/// now checks the thing that does it: the body is sealed before it is
/// returned, and the trailer is the AEAD tag rather than a hash.
///
/// # What this does NOT claim
///
/// Not that key material is safe in memory — that is I6's other half, and
/// the encryption change fixed one instance of it (`parse`'s un-zeroized root copy) rather
/// than closing it. Not rollback protection: an older valid snapshot copied
/// back still verifies, which is I4's to detect. And not that the password is
/// strong; `cli::create::MIN_PASSWORD_LEN` is a floor, not a guarantee, and
/// the encryption change states what this transferred rather than removed.
#[test]
fn imported_roots_and_the_master_seed_are_encrypted_at_rest() {
    const PROOF: &str = "snapshot_bytes_never_contain_the_imported_root";

    // Anchor 1: the encoder still SEALS. If encryption were removed the proof
    // would go red on its own, but this fires on the mechanism rather than on
    // the outcome, and says which one moved.
    let format_rs = read_crate_file("crates/mochimo-crypto/src/keystore/format.rs");
    let code = code_only(&format_rs);
    // **Anchored on the CALL, not on its argument list.** The first version of
    // these two spelled the whole call --
    // `crypt::open(key, &header.nonce, &aad, &mut body, tag)` -- and a
    // refactor in this same session broke it: clippy asked for a named type
    // instead of a four-tuple, the destructuring became `f.header.nonce` and
    // `f.tag`, and the anchor went red claiming the AEAD had been removed when
    // it had only been renamed around. That is the class of a needle
    // whose spelling the check does not control -- and the marker catching its
    // own author is the anchor working, not a false alarm. `crypt::seal(` and
    // `crypt::open(` are the property; how their arguments are spelled is not.
    for call in ["crypt::seal(", "crypt::open("] {
        assert!(
            code.contains(call),
            "keystore/format.rs no longer calls `{call}`. If the AEAD was removed, the at-rest \
             property is gone and {PROOF} is the test that should be red; re-read the \
             keystore's and crypt's module docs."
        );
    }
    // Anchor 2: the plaintext record path is still there -- it must be, the
    // body is assembled before it is sealed -- so its presence is not
    // evidence of a defect any more and is checked only so that a reshaped
    // encoder is noticed rather than silently trusted.
    assert!(
        code.contains("image.extend_from_slice(root.secret().expose());"),
        "the encoder no longer writes the root through the path this marker has anchored on \
         since the keystore landed. That may be fine, but it means the proof and the anchor are describing \
         different code; re-derive before trusting either."
    );

    // And the proof runs, passes, and reports what it measured.
    if let Err(why) = census::check("imported_roots_and_the_master_seed_are_encrypted_at_rest", PROOF) {
        panic!(
            "I6 at rest is claimed but unproven: {PROOF} must be in tests/keystore.rs, run, pass \
             and print `I6 at rest:`.\n{why}"
        );
    }
    println!("  I6 at rest: sealed by the AEAD, {PROOF} censused");
}

/// I4 -- startup reconciles local state against the chain and fails closed.
/// **Green**, under a name that carries where the gate is.
///
/// # The decision, made before the wallet layer and implemented rather than reopened
///
/// **The wallet refuses to start** and requires explicit operator action,
/// printing what diverged, by how much, and what to do. The
/// reasoning: divergence has three causes -- a crash between signing and
/// persisting (I2), a restored seed with incomplete history (I5), two wallet
/// instances live on one seed -- with three different correct recoveries, and
/// the divergence alone does not say which occurred. Advancing to match the
/// chain is right for the first and **catastrophic** for the third, where the
/// other instance is still running and will reuse every key skipped past.
///
/// # What discharged it
///
/// `wallet::Wallet::open` is the only constructor and it reconciles every
/// account or refuses, so a `Wallet` that exists is one that was reconciled
/// -- I4's "before any signing operation is permitted, not lazily on first
/// spend" as a type rather than a convention. `recon::reconcile_account` is
/// the comparison; `recon::Divergence`'s `Display` is the report; and
/// `wallet::OperatorAcknowledgement`, which can only be built from a
/// `Divergence`, is the sole route to `persist_advance_to`, so advancing
/// without having read a report is unrepresentable.
///
/// # THE BOUND IN THE NAME
///
/// **`at_the_wallet_layer_not_at_the_keystore`**, and it is exactly I1's
/// shape. The raw `Keystore` is still reachable in-crate and from the test
/// tree, and `persist_advance`/`sign_spend` can still be called directly --
/// the keystore's own proofs must, having no chain to reconcile against.
/// What is enforced is that a **`Wallet`'s** users cannot spend unreconciled.
/// A caller who wants the unreconciled path has to go and get a `Keystore`,
/// which is conspicuous; forgetting to reconcile is not.
///
/// # WHAT NO MECHANISM HERE REACHES
///
/// **Message quality**, which I4's own reasoning makes load-bearing:
/// a refusal that says only "state mismatch" satisfies the letter of this
/// invariant and manufactures the workaround it exists to prevent. The proof
/// asserts the rendered text names the divergence, both indices, the gap and
/// the action -- from a real run, because failure-path text is invisible to a
/// passing suite -- but whether that wording is *good enough for
/// an operator in a panic* is not something any check here sees. Said out
/// loud rather than left to be inferred from a green tick.
///
#[test]
fn startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore() {
    // This guard once anchored on the browser extension's `wotsIndex` field
    // in a vendored TypeScript source. The reference is not in this
    // repository; what the wallet reconciles is its own record's position,
    // specified in docs/specification.md, and the proofs below are the
    // mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "startup_refuses_to_start_on_index_divergence";
    if let Err(why) = census::check(
        "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to construct local \
             state AHEAD of chain state and local state BEHIND it, assert the \
             wallet refuses to start in both directions, and assert the refusal \
             names what diverged, by how much, and what the operator should do. \
             It must report how many divergence cases it drove; the floor is 2, \
             which is both directions and is the minimum that distinguishes \
             fail-closed from a one-sided check. A test that only builds the \
             behind case passes over the direction that means another instance \
             is live.\n\x20   {why}"
        ));
    }

    // The acknowledged path, through the shipped binary.
    // The proof above shows the report names an index; this shows the
    // operator can take the path it names, which a command dispatched behind
    // the refusal it is meant to act on cannot offer.
    const PTY: &str = "pty::reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names";
    if let Err(why) = census::check(
        "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
        PTY,
    ) {
        owed.push(format!(
            "\x20 - {PTY} is not running. It must build the shipped binary, drive it \
             under a pty against a loopback ledger through `balance` (refused, the \
             report naming index 2), `reconcile --advance-to 7` (refused, nothing \
             written), `reconcile --advance-to 2` (advanced), `balance` (in sync), \
             then the far-along search and the verified advance, and print `tty \
             reconcile:` with the prompts it answered (floor 9).\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I4 has REGRESSED: once this red meant nothing reconciled a local \
         key index against chain state and there was no startup path to \
         reconcile in. Reconciliation landed `wallet::Wallet::open`, whose only \
         constructor reconciles every account or refuses, so this firing means \
         the proof, its census row, or the gate went away.\n{}\n\
         What must still hold: both divergence directions refuse (local ahead \
         is the one that means another instance is live), the refusal names \
         what diverged and by how much and what to do, and advancing past a \
         divergence goes through an acknowledgement built FROM the divergence. \
         The policy is NOT open: refuse to start, chosen over advance-and-warn \
         because divergence has three causes with three different correct \
         recoveries and silently advancing is right for the first and loses the \
         keys for the third. It was decided before the wallet layer existed and landed with it; see \
         docs/specification.md I4.",
        owed.join("\n")
    );
}

/// I5 -- restore derives the index from the chain and never assumes zero.
/// **Green**, under a name that carries the bound.
///
/// The likeliest real path to catastrophic reuse in this whole design. A
/// restored wallet that starts at index zero re-signs with every key the
/// original already used, and it happens at exactly the moment a user is
/// stressed and not reading warnings.
///
/// # The shape, decided before the wallet layer and implemented rather than reopened
///
/// **Target-directed**. The chain cannot be asked for a tag's
/// usage history, but it can be asked for the tag's *current address* in one
/// query, so the scan derives addresses and **stops on the match**. It is not
/// an absence scan and could not be one.
///
/// # What discharged it
///
/// `recon::restore_account_index`: resolve the tag, then walk positions
/// `0..SCAN_BOUND` comparing derived addresses to the resolved one. Every
/// failing path is a failure and none is a fallback -- an unreachable chain,
/// a tag the ledger does not hold, an address no position reproduces.
///
/// # THE BOUND IN THE NAME
///
/// **`within_the_scan_bound_never_from_zero`.** Ten thousand positions are
/// tried by default -- the recovery ceiling, `RECOVERY_CEILING`, which the
/// operator can set for one invocation -- and past that the bound reached is
/// reported rather than guessed past. (BIP-44's twenty is a gap limit over
/// unused addresses, which is not the quantity this bounds; 10,000 is
/// what the shipped browser extension walks for the quantity this does
/// bound. The proof below walks twenty at a ceiling it names, because one
/// restore per position is quadratic and ten thousand of them would not
/// finish.) Three things produce that failure and
/// the scan cannot tell them apart: the account has spent that many times or
/// more, this seed does not own this tag, or the wallet is on another chain.
/// (Naming the first and denying it -- *not "the wallet is further along than
/// twenty"* -- denies the one cause a ceiling produces by construction.) Zero is returned only when
/// position 0's address is the one the chain holds, which is a match like any
/// other, never a default.
///
/// # Why there is no gap-scan comparison in the proof
///
/// There is nothing to compare against. `le_find` binary-searches a ledger
/// holding one entry per tag and compares an address prefix, so a full-address
/// query answers *is this the tag's current address* and never *was this
/// address ever used*. Every index except the current one reads as unused --
/// including every index already spent from -- so a gap scan's stopping signal
/// is not a question this chain answers at all. The invariants document of
/// the source repository carried a callout contrasting the two shapes with an
/// example that contradicted the bound; reconciliation cut it to the bare distinction
/// rather than repairing the number.
///
#[test]
fn restore_derives_the_index_within_the_scan_bound_never_from_zero() {
    // The two anchors this guard carried -- that the node's balance handler
    // hands back a tag's whole ledger entry, and that its `OP_RESOLVE` arm is
    // dead -- read the vendored C, which is not in this repository. What
    // they established is stated in docs/specification.md under I5 ("Why the
    // scan has this shape"); the proof below is the mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "restore_derives_the_index_from_chain_state";
    if let Err(why) = census::check(
        "restore_derives_the_index_within_the_scan_bound_never_from_zero",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to restore a seed whose \
             tag already resolves to a known non-zero index and assert the \
             derived index matches; assert restore FAILS rather than proceeding \
             when chain state is unavailable; and assert it never falls back to \
             zero on any path. It must report the scan bound it exercised; the \
             floor is 20 positions, which is what the proof walks at a named \
             ceiling -- not the default recovery ceiling, which is 10,000 and \
             would cost hours of derivation to exhaust.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I5 has REGRESSED: once this red meant nothing derived a restored \
         wallet's key index from chain state. Reconciliation landed \
         `recon::restore_account_index`, so this firing means the proof, its \
         census row, or the scan went away.\n{}\n\
         What must still hold: the scan is TARGET-DIRECTED and stops on the \
         match (the tag's current address is one query away, so it is not an \
         absence scan); the recovery ceiling -- 10,000 by default, settable for \
         one invocation and never silently -- limits only the FAILING search and is \
         reported rather than guessed past, with all three causes of that \
         failure named and none preferred; and restore fails -- never falls \
         back to zero -- when the chain is unreachable, when the ledger does \
         not hold the tag, and when no position under the ceiling reproduces \
         its address. A restore that assumes zero re-signs with every key the \
         original wallet already used. It was decided before the wallet layer existed and \
         landed with it; the module doc records why the gap-scan contrast has no case to \
         make, and the scan-bound findings the message and the ceiling; see docs/specification.md I5.",
        owed.join("\n")
    );
}

// ---------------------------------------------------------------------------
// I4 and I5's proofs. A scriptable chain, because reconciliation's
// cases ARE chain states and a fake is the only way to drive them
// deterministically. Faking at the `Transport` keeps the real codec and the
// real `MeshClient` in every case.
// ---------------------------------------------------------------------------

mod recon_proof {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::addr::{Address, Tag};
    use mochimo_crypto::consts::SEED_LEN;
    use mochimo_crypto::keystore::Keystore;
    use mochimo_crypto::mesh::Transport;
    use mochimo_crypto::recon;
    use mochimo_crypto::{Error, Secret};

    /// `F-address-widths` (`group_f_derivation.json`): master, account 0, and
    /// the recorded `account_tag`. The chain states below are built from this
    /// seed's own derived addresses, so every value in play traces to a
    /// TypeScript-emitted one.
    pub const MASTER: [u8; SEED_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    pub const TAG: Tag = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73,
        0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];

    #[derive(Clone, Copy)]
    pub enum ChainState {
        At(Address, u64),
        Absent,
        Unreachable,
    }

    pub struct Chain {
        pub states: RefCell<BTreeMap<Tag, ChainState>>,
    }

    impl Chain {
        pub fn new(states: &[(Tag, ChainState)]) -> Chain {
            Chain {
                states: RefCell::new(states.iter().copied().collect()),
            }
        }
    }

    impl Transport for Chain {
        fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
            if path != "/call" {
                return Err(Error::MeshResponse { what: "proof: only /call" });
            }
            let req: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| Error::MeshResponse { what: "proof: request" })?;
            let asked = req["parameters"]["tag"]
                .as_str()
                .ok_or(Error::MeshResponse { what: "proof: parameters.tag" })?;
            let tag: Tag = mochimo_crypto::mesh::hex::decode_prefixed(asked, "proof tag")?;
            match self.states.borrow().get(&tag).copied() {
                Some(ChainState::At(address, balance)) => Ok(format!(
                    r#"{{"result":{{"address":"0x{}","amount":{}}},"idempotent":true}}"#,
                    hexs(&address),
                    balance
                )
                .into_bytes()),
                Some(ChainState::Absent) | None => {
                    Ok(br#"{"code":4,"message":"Account not found","retriable":false}"#.to_vec())
                }
                Some(ChainState::Unreachable) => Err(Error::Transport {
                    op: "connect",
                    kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
                }),
            }
        }
    }

    pub fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    pub fn master() -> Secret<SEED_LEN> {
        Secret::new(MASTER)
    }

    pub fn pos(i: u32) -> WotsIndex {
        let mut p = WotsIndex::ZERO;
        for _ in 0..i {
            p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
        }
        p
    }

    pub fn addr_at(i: u32) -> Address {
        recon::derived_address_at(&master(), 0, pos(i))
    }

    pub fn store(dir: &std::path::Path) -> Keystore {
        let mut ks = Keystore::create(dir, &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        ks
    }

    pub use super::keystore_harness::{reopen, ScratchDir};
    // Re-exported so the two proofs below can name them without repeating
    // this module's import list.
    pub use mochimo_crypto::consts::ADDR_TAG_LEN as TAGLEN;
    pub use mochimo_crypto::mesh::MeshClient as MC;
    pub use mochimo_crypto::recon::{
        ChainPosition as CP, Divergence as D, RestoreFailure as RF, ScanScope as SS,
        RECOVERY_CEILING as BOUND,
    };

    /// The ceiling the two proofs below walk, named rather than taken from
    /// the default. `BOUND` is 10,000 -- the bound the shipped
    /// browser extension walks for the same quantity -- and both proofs
    /// drive walks that must EXHAUST it to prove anything, which at the
    /// 44.4 ms a derivation costs in this profile is about 7 m 24 s for one
    /// exhaustion and, for the I5 proof's one-restore-per-position loop,
    /// `n(n+1)/2` of them. The properties hold at any ceiling; the
    /// default's own value is pinned in `tests/recon.rs` without a walk.
    pub const WALK: u32 = 20;
    pub use mochimo_crypto::wallet::Wallet as W;
    pub use mochimo_crypto::recon as recon_api;
}

/// I4's proof: the wallet refuses to start on index divergence, **in both
/// directions**, and the refusal names what diverged, by how much, and what
/// to do.
///
/// # Why both directions, and why the floor is 2
///
/// A test that builds only the *behind* case passes over the direction that
/// means another instance is live — local ahead of the chain is the shape
/// that says a second wallet on this seed already spent keys this one has
/// not, and advancing through it is the catastrophic recovery I4's decision
/// rejects. Both are driven, plus the four other refusal paths the
/// constructor has.
///
/// # What this establishes, and what no mechanism here reaches
///
/// The refusal is asserted **as rendered text**, from a real run:
/// failure-path text is invisible to a passing suite, and message quality is
/// part of I4's requirement rather than a nicety. What the
/// execution census can establish is that this ran and reported; that the
/// *wording* is good enough for an operator in a panic is not mechanically
/// checkable and is said out loud here rather than left to a green tick.
#[test]
fn startup_refuses_to_start_on_index_divergence() {
    use recon_proof::*;

    let m = master();
    let mut cases = 0usize;

    // (1) LOCAL BEHIND: the chain is at index 3, the store at 0. A spend
    // landed that was never recorded here.
    let d1 = ScratchDir::new("i4-behind");
    let ks = store(d1.path());
    let refusal = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))])), Some(&m))
        .expect_err("local behind must refuse");
    let behind_text = format!("{refusal}");
    assert!(
        matches!(refusal.diverged[0], D::IndexMismatch { found: CP::Ahead { gap: 3, .. }, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    cases += 1;

    // (2) LOCAL AHEAD: the store advanced to 3, the chain still at 0. This
    // is the direction a one-sided check passes over.
    let d2 = ScratchDir::new("i4-ahead");
    let mut ks = store(d2.path());
    let _ = ks.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("I4 ahead", d2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal2 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), Some(&m))
        .expect_err("local ahead must refuse");
    let ahead_text = format!("{refusal2}");
    assert!(
        matches!(refusal2.diverged[0], D::IndexMismatch { found: CP::Behind { gap: 3, .. }, .. }),
        "{:?}",
        refusal2.diverged[0]
    );
    cases += 1;

    // (3) the chain holds an address no index of this seed reproduces.
    // Through the reconciler `W::open` calls, at a ceiling this case names,
    // rather than through `open` itself: `open` takes no scope and its
    // default ceiling is 10,000, so an unlocatable address costs
    // ten thousand derivations there -- about 7 m 24 s in this profile. The
    // classification is what this case is about and `reconcile_account_with`
    // is where it is decided; that `open` refuses on whatever the reconciler
    // returns is cases (1), (2), (4), (5) and (6), across five variants.
    // The composition is no longer driven end to end, which is the price of
    // the ceiling and is recorded rather than hidden.
    let d3 = ScratchDir::new("i4-alien");
    let ks = store(d3.path());
    let mut alien = addr_at(0);
    alien[TAGLEN] ^= 0x01;
    let div3 = recon_api::reconcile_account_with(
        &ks,
        &MC::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &mochimo_crypto::keystore::KeyAccess::Master(&m),
        &SS::DIAGNOSTIC.with_ceiling(WALK),
        &recon_api::Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    assert!(matches!(div3, D::IndexMismatch { found: CP::Unlocated { .. }, .. }), "{div3:?}");
    cases += 1;

    // (4) the ledger has no entry for the tag
    let d4 = ScratchDir::new("i4-absent");
    let ks = store(d4.path());
    let refusal4 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::Absent)])), Some(&m))
        .expect_err("an absent tag must refuse");
    assert!(matches!(refusal4.diverged[0], D::TagUnresolved { .. }));
    cases += 1;

    // (5) the chain cannot be reached -- an unreconciled wallet must not sign
    let d5 = ScratchDir::new("i4-unreachable");
    let ks = store(d5.path());
    let refusal5 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::Unreachable)])), Some(&m))
        .expect_err("an unreachable chain must refuse");
    assert!(matches!(refusal5.diverged[0], D::ChainUnreachable { .. }));
    cases += 1;

    // (6) a derived account with no master to derive its addresses from
    let d6 = ScratchDir::new("i4-nomaster");
    let ks = store(d6.path());
    let refusal6 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), None)
        .expect_err("no master must refuse");
    assert!(
        matches!(refusal6.diverged[0], D::NoMasterForDerivedAccount { .. }),
        "a derived account with no master must be refused as unreconcilable, not skipped: {:?}",
        refusal6.diverged[0]
    );
    cases += 1;

    // (7) LOCAL BEHIND, FAR ALONG: the store at 22, the chain at 24 -- a gap
    // of two at a position past the recovery range. Once the diagnostic
    // walked `0..20` absolute and reported this as *this seed does not own
    // this tag*, the case I4's fail-closed posture exists for denied by its
    // own report. The window around local finds it.
    let d8 = ScratchDir::new("i4-far-along");
    let mut ks = store(d8.path());
    let _ = ks.persist_advance_to(&TAG, pos(22)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("I4 far along", d8.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal7 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(24), 1))])), Some(&m))
        .expect_err("a gap of two at position 22 must refuse");
    assert!(
        matches!(refusal7.diverged[0], D::IndexMismatch { found: CP::Ahead { gap: 2, .. }, .. }),
        "a gap of two at position 22 was not located as two ahead: {:?}",
        refusal7.diverged[0]
    );
    cases += 1;

    // -- THE CONTROL: with the chain where the store is, the wallet opens.
    // Without this the seven refusals above are satisfied by a constructor
    // that refuses everything.
    let d7 = ScratchDir::new("i4-control");
    let ks = store(d7.path());
    let w = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 42))])), Some(&m))
        .unwrap_or_else(|e| panic!("the healthy case must open:\n{e}"));
    assert_eq!(w.accounts().len(), 1);

    // -- MESSAGE QUALITY, from the rendered text of a real run.
    for (text, direction) in [(&behind_text, "4"), (&ahead_text, "4")] {
        let _ = direction;
        assert!(text.contains("WALLET WILL NOT START"), "the refusal does not say so:\n{text}");
        assert!(text.contains(&hexs(&TAG)), "the account is not named:\n{text}");
        assert!(text.contains("three causes"), "the reason is not given:\n{text}");
        assert!(text.contains("ACTION:"), "no action is named:\n{text}");
        assert!(
            text.contains("Do not delete local state"),
            "the workaround I4's decision names is not warned against:\n{text}"
        );
    }
    // what diverged, and BOTH indices, and the size of the gap
    assert!(behind_text.contains("local index 0"), "the local index is missing:\n{behind_text}");
    assert!(behind_text.contains("key at index 3"), "the chain's index is missing:\n{behind_text}");
    assert!(behind_text.contains("3 ahead of local"), "the gap is missing:\n{behind_text}");
    assert!(behind_text.contains(&hexs(&addr_at(0))), "the local address is missing");
    assert!(behind_text.contains(&hexs(&addr_at(3))), "the chain's address is missing");
    assert!(ahead_text.contains("local index 3"), "the local index is missing:\n{ahead_text}");
    assert!(ahead_text.contains("3 BEHIND local"), "the direction is missing:\n{ahead_text}");
    assert!(
        ahead_text.contains("advancing local state backwards is never a remedy"),
        "the ahead case does not say what NOT to do:\n{ahead_text}"
    );

    // Every integer on this line is a count of divergence cases.
    println!(
        "  I4 reconciliation: {cases} divergence case(s) driven, both directions among them, \
         1 healthy control that opened"
    );
}

/// I5's proof: restore derives the index from chain state, never assumes
/// zero, and the scan **stops on the match** rather than after a run of
/// misses.
///
/// # The bound, and what it is a bound on
///
/// `RECOVERY_CEILING` positions -- 10,000 of them -- are tried by default
/// and the ordinary case never reaches the last of them. It bounds the *failing* search: a tag that
/// resolves to an address no walked position reproduces is an account further
/// along than the walk, a seed that does not own the tag, or a wallet on
/// another chain -- indistinguishable at this arm, which is why the failure
/// names all three rather than denying one. Both edges are asserted — the last position inside the
/// bound is found, the first outside it is refused with the bound reported.
/// The ceiling this proof walks is named in its body rather than taken from
/// the default, and the raised ceiling is proved in `tests/recon.rs`. The
/// integers below are counts at the walk the census floor of 20 requires,
/// which is what that floor always
/// guarded -- the default's own value is pinned in `tests/recon.rs`, without
/// a walk, because exhausting 10,000 positions costs about seven minutes in
/// this profile.
///
/// # Why there is no gap-scan comparison here
///
/// There is nothing to compare against. Per-index usage is unobservable on
/// this chain (`recon`'s module doc, fact 2), so a gap scan's stopping signal
/// — a run of unused indices — is not a question any query answers.
#[test]
fn restore_derives_the_index_from_chain_state() {
    use recon_proof::*;

    // The ceiling this proof walks is `WALK`, named in `recon_proof` with
    // its reason: this loop runs one whole restore per position, so it
    // costs `n(n+1)/2` derivations and the default's 10,000 would be about
    // 616 hours. The census floor below is that same number.
    let scope = SS::RESTORE.with_ceiling(WALK);

    // (1) every position inside the bound is found EXACTLY, and the scan
    // stops on the match: one query, and the walk is local from there.
    let mut found_at = 0u32;
    for i in 0..WALK {
        let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(i), 1_000 + u64::from(i)))]));
        let r = recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER).unwrap_or_else(|e| {
            panic!("the scan did not reach position {i} inside the bound:\n{e}")
        });
        assert_eq!(r.index, pos(i), "the scan derived the wrong index at position {i}");
        assert_eq!(r.tag, TAG, "the scan derived the wrong tag");
        assert_eq!(r.balance, 1_000 + u64::from(i));
        found_at = i;
    }
    let scan_bound_exercised = found_at + 1;
    assert_eq!(scan_bound_exercised, WALK, "the whole bound was not walked");

    // (2) NEVER ZERO on any failing path. Each of the three is a failure and
    // none is a fallback.
    let mut refusals = 0usize;
    let client = MC::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    assert!(
        matches!(
            recon_api::restore_account_index(&client, &master(), 0),
            Err(RF::ChainUnreachable { .. })
        ),
        "an unreachable chain must fail rather than assume an index"
    );
    refusals += 1;
    let client = MC::new(Chain::new(&[(TAG, ChainState::Absent)]));
    assert!(
        matches!(
            recon_api::restore_account_index(&client, &master(), 0),
            Err(RF::TagUnresolved { .. })
        ),
        "a tag the ledger does not hold must fail rather than assume an index"
    );
    refusals += 1;
    let mut alien = addr_at(0);
    alien[TAGLEN] ^= 0x01;
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(alien, 1))]));
    match recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER) {
        Err(RF::NoIndexReproducesTheAddress { scanned, .. }) => {
            assert_eq!(scanned, WALK, "the bound reported is not the bound walked");
        }
        other => panic!("an unreproducible address must fail: {other:?}"),
    }
    refusals += 1;
    assert_eq!(refusals, 3);

    // (3) the boundary is where it is claimed: the last position INSIDE is
    // found, the first OUTSIDE is refused rather than guessed at.
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALK - 1), 1))]));
    assert_eq!(
        recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER)
            .unwrap_or_else(|e| panic!("the last position INSIDE the bound was not reached:\n{e}"))
            .index,
        pos(WALK - 1)
    );
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALK), 1))]));
    assert!(
        matches!(
            recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER),
            Err(RF::NoIndexReproducesTheAddress { .. })
        ),
        "the first position OUTSIDE the bound was reached; the bound stopped bounding"
    );

    // (4) the failure text says so, read from a real run.
    let client = MC::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    let text = match recon_api::restore_account_index(&client, &master(), 0) {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("must fail"),
    };
    assert!(text.contains("does NOT fall back to index zero"), "{text}");

    // Every integer on this line but the last is a scan position: the
    // bound walked, and the positions found within it. The last is the
    // DEFAULT recovery ceiling, printed because this proof deliberately
    // does not walk it -- an exhausted walk there is minutes of derivation
    // and, for the loop above, hours -- so a reader of the evidence line
    // can see both the number driven and the number shipped.
    println!(
        "  I5 restore scan: {scan_bound_exercised} scan position(s) exercised, every one found \
         exactly, {refusals} failing path(s) that returned no index at all; the shipped default \
         ceiling is {BOUND} and is not walked here"
    );
}

/// `syn` is a dev-dependency and stays one.
///
/// # Read this before assuming what it proves
///
/// The obvious formulation — *`syn` is not in this crate's dependency graph* —
/// is **false at HEAD and was false before the parser was added**. `zeroize`
/// carries `zeroize_derive`, which is a proc macro, which depends on `syn`:
///
/// ```text
/// mochimo-crypto -> zeroize v1.9.0 -> zeroize_derive v1.5.0 (proc-macro) -> syn v2.0.119
/// ```
///
/// That path is build-time only; a proc macro runs in the compiler and is never
/// linked into the produced rlib. Asserting its absence would produce a red for
/// a reason unrelated to the property anyone cares about, and a red that cannot
/// be fixed trains readers to skim.
///
/// # The property actually wanted
///
/// `syn` exists here to make **one check** correct — the I7 signature scan. It
/// must not become reachable from the library's own code. Two assertions, both
/// deterministic and neither needing a `cargo` subprocess:
///
/// 1. **No `syn` in `crates/*/src/`.** Comment-stripped, so the doc comments
///    that explain this rule do not violate it.
/// 2. **`syn` is a direct dependency only under `[dev-dependencies]`**, in
///    every workspace member. Creep from dev into real happens by somebody
///    moving that line, and this is the line.
///
/// The second is the load-bearing one: the first would go green on the day
/// somebody added `syn` to `[dependencies]` and had not yet written a `use`.
///
/// # What it does not cover
///
/// A *transitive* normal dependency that itself pulls `syn` — which is exactly
/// what `zeroize_derive` already is. Distinguishing "arrived via a proc macro"
/// from "arrived as a linked library" needs the resolved graph, i.e. spawning
/// `cargo tree -e normal` from a test, and that is a subprocess with an offline
/// failure mode for a case no dependency in this tree presents. Stated rather
/// than silently omitted.
///
/// # How much of this the compiler already does — the partition by sole detector
///
/// Measured by injection, because "it goes red" is not the same claim
/// as "this check found it":
///
/// | injection | who catches it |
/// | --- | --- |
/// | `syn` moved to `[dependencies]` | **this check, alone** — nothing else objects |
/// | `syn::` in `src/` with `syn` still dev-only | **rustc** — the crate does not resolve `syn` |
/// | `syn` deleted from `[dev-dependencies]` | **rustc** — this very file stops compiling |
///
/// So assertion 1 is only load-bearing in a world where assertion 2 has already
/// been violated — it catches the *second* step of the creep, not the first —
/// and the `dev_declarations == 1` floor is a message attached to a failure the
/// compiler produces anyway, kept because `cannot find module or crate syn` in
/// a test file does not tell a reader that an invariant scan just lost its
/// parser. **Assertion 2's `[dependencies]` arm is the only sole-detector
/// here.** The other two arms are diagnostics, and calling them enforcement
/// would be claiming a needle the check does not control.
#[test]
fn syn_is_confined_to_the_test_targets() {
    // 1. No use from library code.
    let mut users: Vec<String> = Vec::new();
    for (name, code) in crate_sources() {
        if code.contains("syn::") || code.contains("use syn") {
            users.push(name);
        }
    }
    assert!(
        users.is_empty(),
        "these library sources reference `syn`: {users:?}\n\
         It is a dev-dependency, added so that the I7 signature scan \
         parses Rust instead of approximating it. It has no business in the \
         shipped crate. See Cargo.toml's note."
    );

    // 2. Direct-dependency placement, in every workspace member.
    let root = repo_root();
    let crates = root.join("crates");
    let mut members = 0usize;
    let mut dev_declarations = 0usize;
    let entries = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates.display()));
    for member in entries.flatten() {
        let manifest = member.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        members += 1;
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest.display()));
        let doc: toml::Value = text
            .parse()
            .unwrap_or_else(|e| panic!("cannot parse {}: {e}", manifest.display()));
        let name = member.file_name().to_string_lossy().into_owned();
        for table in ["dependencies", "build-dependencies"] {
            assert!(
                doc.get(table).and_then(|t| t.get("syn")).is_none(),
                "{name}/Cargo.toml declares `syn` under [{table}]. It is a \
                 dev-dependency: it exists to make the I7 signature scan parse \
                 Rust rather than approximate it, and it never ships. If a \
                 library genuinely needs it, that is a decision with an errata \
                 entry, not a moved line."
            );
        }
        if doc
            .get("dev-dependencies")
            .and_then(|t| t.get("syn"))
            .is_some()
        {
            dev_declarations += 1;
        }
    }

    // Vacuity guards. A walk that found no manifests, or a `syn` that has
    // silently left the tree, would each make the assertions above pass over
    // nothing -- and the second would mean the I7 scan is no longer parsing.
    assert!(
        members >= 1,
        "found no workspace member manifest under {}; the walk is broken and \
         the placement assertions above ran over nothing",
        crates.display()
    );
    assert_eq!(
        dev_declarations, 1,
        "expected exactly one [dev-dependencies] declaration of `syn` across \
         the workspace, found {dev_declarations}. Zero means the I7 signature \
         scan has lost its parser and is silently back to a substring walk; \
         more than one means a second crate acquired it and this check's \
         reasoning about why it is safe has not been re-done."
    );

    println!(
        "  syn confinement: {members} workspace members checked, \
         {dev_declarations} dev-dependency declaration, 0 library references. \
         NOTE: syn is already in the normal graph via zeroize -> \
         zeroize_derive (proc-macro); see this test's docs."
    );
}

/// Count `#[ignore]` attributes inside a macro invocation's token stream.
///
/// Recursive over nested groups. Matches the shape `#` followed by a
/// bracket-delimited group whose sole token is the ident `ignore` -- which is
/// what an attribute is after tokenization, and which a comment or a string
/// literal cannot produce.
fn ignore_attrs_in_tokens(tokens: proc_macro2::TokenStream) -> usize {
    attrs_in_tokens(tokens, "ignore")
}

/// The `#[test]` counterpart, so the vacuity floor counts the same population
/// the ban walks. A floor computed over a smaller set than the check examines
/// is the counted-but-not-examined defect repeated.
fn count_test_attrs_in_tokens(tokens: proc_macro2::TokenStream) -> usize {
    attrs_in_tokens(tokens, "test")
}

fn attrs_in_tokens(tokens: proc_macro2::TokenStream, want: &str) -> usize {
    let mut found = 0usize;
    let mut prev_was_hash = false;
    for tree in tokens {
        match tree {
            proc_macro2::TokenTree::Punct(ref p) if p.as_char() == '#' => {
                prev_was_hash = true;
                continue;
            }
            proc_macro2::TokenTree::Group(g) => {
                if prev_was_hash && g.delimiter() == proc_macro2::Delimiter::Bracket {
                    let inner: Vec<_> = g.stream().into_iter().collect();
                    if inner.len() == 1 {
                        if let proc_macro2::TokenTree::Ident(id) = &inner[0] {
                            if id == want {
                                found += 1;
                            }
                        }
                    }
                }
                found += attrs_in_tokens(g.stream(), want);
            }
            _ => {}
        }
        prev_was_hash = false;
    }
    found
}

/// No test in this crate's suite is `#[ignore]`d.
///
/// # THIS CHECK IS THE ONLY ENFORCEMENT OF ITS PROPERTY
///
/// Nothing else in the tree consumes libtest's ignored count. The board is read
/// by the *names of its reds* (`AGENT.md`, "check by name, not by
/// count"), and an ignored test is not a failed one — it prints `ignored` in a
/// run whose last line still says `ok`.
///
/// # What made this necessary
///
/// Fourteen call sites assert "the test that proves this property exists" by
/// searching `test_sources()` for `fn <name>`. `i7_txentry_is_never_a_rust_value`
/// says so in its own doc: *"Deleting either test… brings it back red — the
/// only reason it still runs."*
///
/// Deleting is caught. **Disabling was not.** Measured: adding
/// `#[ignore]` to `txentry_interior_pointers_survive_relocation` left `i7`
/// green, left the board at exactly its eight expected reds, and libtest
/// reported `1 ignored` — while the I7 relocation property no longer executed
/// and its guard went on certifying it. The attribute leaves the function's
/// text in the corpus, so `.contains("fn …")` is still satisfied.
///
/// The strip in `test_sources()` closed the *commented-out* variant of
/// the same evasion. This closes the `#[ignore]` variant.
///
/// # Why a suite-wide ban rather than per-guard disqualification
///
/// Excising an `#[ignore]`d function from the corpus so that only *its* guard
/// reddens would need a function-extent parser — attribute to closing brace —
/// which is the line-oriented approximation this whole session exists to stop
/// writing. And it could not have been demonstrated: with zero
/// `#[ignore]` in the tree, a suite-wide backstop would make the precise
/// mechanism unobservable, so the excision parser would ship with no input on
/// which only it can fail.
///
/// "Stricter than needed" costs nothing while the count is zero, and if an
/// ignored test is ever genuinely wanted the red forces the exception to be
/// argued rather than taken silently. That is the mechanism working, not a
/// false positive. The project already holds this position in prose —
/// `kat.rs` records that *an ignored test is invisible debt* — and this is the
/// first thing to enforce it.
///
/// # The domain, measured rather than assumed
///
/// Walking `syn`'s items alone cannot see a `#[test]` written inside a macro
/// invocation: the body is not parseable as Rust items, so `syn` yields
/// `Item::Macro` and stops on it. No test in this tree is written that way, and
/// a ban blind to part of its own domain is the failure this check exists to
/// stop, committed by the check itself -- so the macro arm is walked at the
/// **token** level, which is exact rather than approximate: the tokenizer has
/// already discarded comments, and a string literal containing `"#[ignore]"` is
/// one `Literal`, never the ident `ignore` inside a bracket group. The arm
/// costs nothing while it matches nothing, and it is what would see the next
/// one.
///
/// The count is printed from the run rather than written down here. A
/// *substring* count over these files is a moving target its own documentation
/// perturbs -- this paragraph mentions the attribute and would be counted --
/// which is the second reason the walk is over tokens rather than bytes, and
/// the reason no figure is carried in this comment.
///
/// # WHAT THIS DOES NOT ESTABLISH — read before treating the guards as sound
///
/// The subject is exactly: **no test under `tests/` is ignored.** It is *not*
/// that every named test executes.
///
/// **REWRITTEN with the census, and the paragraph this replaces is the reason.** It read:
/// *"the existence guards are blind to"* renaming, `cfg`-ing out, hollowness and
/// macro emission, and *"the closing move … stays queued"*. The census landed —
/// see the `census` module — so all four of those statements are now false about
/// the sixteen edges it covers, and one of them was the most-read description of
/// the gap in the tree. Correcting it here rather than deleting it, because the
/// drift audit counts instances and a silently corrected instance is one the
/// count never sees.
///
/// What is true now:
///
/// * the fourteen guards the two findings name **do** key on execution: the
///   named test must be in libtest's run list, run alone, pass, and report what
///   it measured;
/// * **this ban is no longer the only thing standing between `#[ignore]` and a
///   green guard.** It was recorded that an ignored test reddens *this ban*
///   and leaves *the guard* green. Measured again with the census in
///   place: `#[ignore]` on a censused target now reddens the guard that names
///   it, reporting `0 passed; 1 ignored` — because the census counts `passed`
///   and never reads the word `ok`, which libtest prints for an ignored test
///   too;
/// * this ban's remaining value is **suite-wide coverage**. The census reaches
///   sixteen edges; the ban reaches every test in the tree, including every one
///   no guard names. Its own floor prints the count it walked.
///
/// Still open, and not closed by either: a test **renamed with its census row
/// updated to match** is green over whatever the new test does. Execution is not
/// correctness, and nothing here reads the assertions inside a target.
#[test]
fn no_test_in_the_suite_is_ignored() {
    let mut ignored: Vec<String> = Vec::new();
    let mut tests = 0usize;
    let mut files = 0usize;

    for (name, text) in test_source_files() {
        files += 1;
        // Parsed, not searched. `#[ignore]` in attribute position and the same
        // characters inside a doc comment or a string literal are different
        // things, and the tree contains the second: `kat.rs` documents its
        // choice to be "deliberately not `#[ignore]`". A needle over raw text
        // reports that as a violation, and a needle over stripped text depends
        // on the stripper this session is not repairing.
        let Ok(ast) = syn::parse_file(&text) else {
            // A test file that does not parse is reported, not skipped: this is
            // an absence property, and a silently dropped file is a hole.
            ignored.push(format!("\x20 - {name}: syn could not parse this file"));
            continue;
        };
        let mut items: Vec<&syn::Item> = ast.items.iter().collect();
        while let Some(item) = items.pop() {
            match item {
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        items.extend(inner.iter());
                    }
                }
                syn::Item::Fn(f) => {
                    if f.attrs.iter().any(|a| a.path().is_ident("test")) {
                        tests += 1;
                        if f.attrs.iter().any(|a| a.path().is_ident("ignore")) {
                            ignored.push(format!("\x20 - {name}::{}", f.sig.ident));
                        }
                    }
                }
                // Macro invocation bodies. Without this arm the collector
                // misses every `#[test]` written inside one. No test in this
                // tree is, and the arm stays because a ban that cannot see part
                // of its domain is the failure this check exists to stop,
                // committed by the check itself.
                //
                // The body is not parseable as items (`args in strategy` is not
                // Rust fn syntax), so it is walked as TOKENS. That is exact
                // rather than approximate: the tokenizer has already discarded
                // comments, and a string literal containing "#[ignore]" is one
                // Literal token, never the ident `ignore` inside a bracket
                // group. A text search over the same bytes has neither property.
                syn::Item::Macro(m) => {
                    let hits = ignore_attrs_in_tokens(m.mac.tokens.clone());
                    tests += count_test_attrs_in_tokens(m.mac.tokens.clone());
                    for _ in 0..hits {
                        ignored.push(format!(
                            "\x20 - {name}: an #[ignore] inside a `{}!` block",
                            m.mac
                                .path
                                .segments
                                .last()
                                .map_or_else(|| "?".to_string(), |s| s.ident.to_string())
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Vacuity guards. A walk that found no files, or a parse that produced no
    // `#[test]` items, would satisfy the assertion below over nothing -- which
    // is the exact failure mode this check was added to close, applied to
    // itself.
    assert!(
        files >= 14,
        "the tests/ walk found only {files} file(s); the tree holds 22 and this \
         floor is two thirds of that, so the walk has lost a third of the \
         suite's files and this check is running over what is left"
    );
    // Floor calibrated against the MEASURED population, and against the same
    // population the ban walks -- item-level `#[test]` plus any inside a
    // macro invocation's body. Measured at 340 across 22 files, with no
    // macro-emitted tests
    // in the tree; the macro arm stays because it is what would see the
    // next one. A substring count drifts as documentation mentioning the
    // attribute is written, which is why this walks tokens.
    assert!(
        tests >= 226,
        "found only {tests} #[test] functions across {files} files; the \
         collector is broken and any result from it is vacuous. Measured at 340 \
         across 22 files, and this floor is two thirds of that."
    );

    assert!(
        ignored.is_empty(),
        "these tests are #[ignore]d:\n{}\n\
         An ignored test is invisible debt: it prints `ignored` in a run whose \
         last line says `ok`, the board is read by the names of its reds, and \
         nothing here consumes libtest's ignored count.\n\
         The second half of this message used to say that fourteen guards would \
         go on certifying an #[ignore]d test, because they searched for \
         `fn <name>` in source. Those fourteen now key on the census, and \
         an ignored censused target reddens its own guard as well as this ban. \
         What this ban still covers, and the census does not, is every test no \
         guard names -- which is most of them.\n\
         If an ignored test is genuinely wanted, that is a decision with an \
         errata entry and an exception argued here, not an attribute.",
        ignored.join("\n")
    );

    println!(
        "  ignored-test ban: {tests} #[test] functions across {files} files, \
         0 ignored. This is EXISTENCE over the whole suite; EXECUTION is the \
         census, and it covers the sixteen edges the guards name rather than \
         all {tests}. See this test's documentation."
    );
}

/// Every group E constant is compared against the fixture the reference
/// printf'd, by a checker that runs.
///
/// This began as a debt marker: nothing compared `fixtures/group_e_net.json`'s
/// constants to anything, so a value transcribed wrong would have agreed with
/// itself and stayed green forever. `kat.rs::group_e_constants_match_the_reference`
/// discharged it by comparing 32 of the 33 to the crate's own literals. Two
/// arms hold that arrangement: the names are read out of the fixture rather
/// than listed here, so a constant added to group E later is owed
/// automatically -- it appears in the fixture, it is absent from the
/// comparison, and this goes red without anyone having to remember the test
/// exists -- and the checker's execution is demanded through the census,
/// because a checker whose text names every constant and whose `#[cfg]`
/// removes it from the build is the first arm's exact blind spot.
///
/// The 33rd, `sizeof_TX`, is excluded by name in [`NOT_THIS_WALLETS_TO_PIN`],
/// the check's own data: a row names the constant and carries the reason the
/// failure message prints, so a second constant cannot join the exclusion
/// without a reason, and two guards refuse a stale row (a name the fixture
/// does not carry -- a permit for nothing) and a lying row (a name the
/// checker compares after all). The packet size is not this wallet's to pin.
///
/// Deliberately not named after a session. This debt went missing in the first
/// place because one sequence number covered two different pieces of work.
/// Constants group E carries that this crate has no literal for, each with
/// the reason it is not this wallet's to pin. See
/// [`group_e_constants_stay_anchored`] for the two guards that hold a row
/// honest.
const NOT_THIS_WALLETS_TO_PIN: [(&str, &str); 1] = [(
    "sizeof_TX",
    "the size of the node's network packet container, 65,664 bytes. This wallet never builds \
     or reads such a packet -- it speaks to the Mesh over HTTP, and the node's own framing is \
     the specification's open item -- and the two ways to pin the number here, a literal \
     transcribed from the fixture or an expression transcribed from the reference's types.h, \
     both compare the fixture to itself.",
)];

#[test]
fn group_e_constants_stay_anchored() {
    // Prose, not values. `valid_op_rule` is the one entry the reference itself
    // records as a sentence; the predicate is handled by tests/net.rs and
    // listed in kat.rs::WEAKLY_ANCHORED, not by a constant comparison.
    let path = repo_root().join("fixtures/group_e_net.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let root: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));

    let consts = root
        .get("constants")
        .and_then(|c| c.as_object())
        .unwrap_or_else(|| panic!("{} has no `constants` object", path.display()));

    // Flatten `constants` and the nested `opcodes`, keeping only names that
    // denote a value. `note` and `valid_op_rule` are prose.
    let mut names: Vec<String> = Vec::new();
    for (k, v) in consts {
        match v {
            serde_json::Value::Object(inner) => names.extend(
                inner
                    .iter()
                    .filter(|(_, v)| v.is_number())
                    .map(|(k, _)| k.clone()),
            ),
            v if v.is_number() => names.push(k.clone()),
            _ => {}
        }
    }
    assert!(
        names.len() > 20,
        "group_e_net.json yielded only {} constant names; the flatten above is \
         probably wrong and this test would pass vacuously",
        names.len()
    );

    // The comparison itself, read as source. Asserting on the harness rather
    // than on values is what makes "every constant is compared" checkable at
    // all: a value assertion cannot see a constant nobody wrote an assertion
    // for, which is precisely the failure this test exists to prevent.
    const CHECKER: &str = "group_e_constants_match_the_reference";
    // `test_sources()` strips, so a second `code_only` here would be a no-op
    // that reads like a precaution.
    //
    // # The needle below is UN-TERMINATED on purpose. The reason was measured.
    //
    // It is the last survivor of audit finding F-11, which is *eleven*
    // `format!("fn {NAME}")` needles missing the closing paren; the census retired the
    // other ten by replacing them with execution census calls. The
    // queue recorded this one as "no defect" without testing it, and "untermin-
    // ated" had been treated as a synonym for "defective" throughout.
    //
    // It is not the F-11 defect, and the reason is structural rather than
    // lucky: **F-11's needles DECIDE, this one LOCATES.** There, a prefix match
    // was the whole verdict, so a suffix rename left a guard green over a test
    // that no longer existed. Here the match only picks a starting offset; the
    // body is then bounded to the next item, floored two-sidedly, and searched
    // for all 33 constant names. Every way the match can go wrong is caught by
    // the measurement that follows it.
    //
    // Measured, both spellings, five injections:
    //
    //   input                                     un-terminated   terminated
    //   ----------------------------------------  --------------  ----------
    //   unmodified                                 green           green
    //   checker suffix-renamed to `_v2`            GREEN, correct  RED, FALSE
    //   prefix-sharing decoy in invariants.rs      RED, false      green
    //   prefix-sharing decoy in a file after kat.rs green           green
    //   one constant dropped from the checker      RED             RED
    //
    // **Neither spelling can produce a false GREEN**, which is what F-11 is
    // about, so this site never had that defect. What the choice actually trades
    // is two false-RED modes, and they are not equally likely. Terminating turns
    // a benign rename into a red whose message says the checker "no longer
    // exists" about a function that does and is still comparing all 33
    // constants. Leaving it un-terminated risks a red only if somebody defines a
    // `fn` sharing this exact 37-character prefix *in a file sorting before
    // `kat.rs`* -- which is `invariants.rs` and nothing else, since the corpus is
    // sorted by path. A decoy in a file sorting after `kat.rs` stays green, so
    // position and not merely existence is what would trigger it.
    //
    // A rename is a refactor somebody performs. The decoy is not something
    // anybody writes. So the needle stays as it is, and this comment is here
    // because the next sweeper will otherwise read the missing paren as the
    // defect the queue said it was.
    let all = test_sources();
    let start = all.find(&format!("fn {CHECKER}")).unwrap_or_else(|| {
        panic!(
            "{CHECKER} no longer exists. It is the only thing comparing group \
             E's constants to the C; without it the fixture is back to agreeing \
             with itself."
        )
    });

    // Scoped to that one function, not to the whole of `tests/`. Searching
    // every test source instead let this check pass while the comparison was
    // missing OP_HASH, because `tests/net.rs` names the opcode for an unrelated
    // reason -- a mention anywhere counted as coverage. Found by deliberately
    // deleting a line and watching this stay green.
    let body = &all[start..];
    // The *nearest* following item boundary, not the first of the two that
    // happens to be found. `.or_else` took `\nfn ` whenever it existed, even
    // when a `\n#[test]` sat closer -- which today differs by eight characters
    // and tomorrow could be the whole rest of the file.
    let end = [body[1..].find("\nfn "), body[1..].find("\n#[test]")]
        .into_iter()
        .flatten()
        .min()
        .map(|i| i + 1)
        .unwrap_or_else(|| {
            // Fail closed. The old fallback was `body.len()`: with no boundary
            // found the slice silently became the rest of the 170KB corpus,
            // and every name would then be "found" somewhere in unrelated
            // code. That is the false-pass direction, and it had no floor --
            // the only assertion here guarded the slice being too *short*.
            panic!(
                "no item boundary follows {CHECKER} in the corpus, so its body \
                 cannot be bounded. Extracting to the end of the corpus would \
                 make every group E constant read as present."
            )
        });
    let checker = &body[..end];
    // Two-sided, and both sides name the measured length so a move says which
    // direction it went. 3,569 characters on this tree.
    assert!(
        (500..8_000).contains(&checker.len()),
        "the {CHECKER} body extracted to {} chars, outside 500..8000; it \
         measures 3,569 on the tree this bound was derived from. Too short and every name \
         reads as missing; too long and the slice has run into neighbouring \
         functions, where a name found is not a name this checker asserts.",
        checker.len()
    );

    // The declared exclusions, each held honest both ways before it excuses
    // anything: a row naming a constant the fixture does not carry is a
    // permit for nothing, and a row naming a constant the checker compares
    // is a lie about the comparison.
    for (name, reason) in NOT_THIS_WALLETS_TO_PIN {
        assert!(
            names.iter().any(|n| n == name),
            "NOT_THIS_WALLETS_TO_PIN excludes `{name}`, which fixtures/group_e_net.json does \
             not carry: a stale exclusion row is a permit for nothing. Remove the row. Its \
             reason read: {reason}"
        );
        assert!(
            !checker.contains(&format!("\"{name}\"")),
            "NOT_THIS_WALLETS_TO_PIN excludes `{name}` -- {reason} -- but {CHECKER} names and \
             compares it after all: an exclusion for a thing that is compared is a lie. Remove \
             the row."
        );
    }
    let excluded = |n: &String| NOT_THIS_WALLETS_TO_PIN.iter().any(|(x, _)| x == n);
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| !excluded(n) && !checker.contains(&format!("\"{n}\"")))
        .collect();

    let n = missing.len();
    assert!(
        missing.is_empty(),
        "{n} of group E's constants are in fixtures/group_e_net.json but not \
         named in {CHECKER}: {missing:?}.\n\
         A constant no assertion mentions is pinned against nothing: the fixture \
         and the crate's literal agree with each other and neither is compared \
         to the other, so a transcription error in it is undetectable. Add it \
         to the comparison in tests/kat.rs -- or, if it is not this wallet's to \
         pin, a row to NOT_THIS_WALLETS_TO_PIN with the reason, which this \
         check prints and holds honest."
    );

    // EXECUTION, not text. The scan above reads the checker's SOURCE, and a
    // checker compiled out by a `#[cfg]` still contains every name. Measured
    // A checker gated out of the build leaves the constants `consts::net`
    // declares compared to the fixture the reference printf'd by nothing that
    // runs, and this arm is what says so. The census row's floor is 32, the count the checker itself
    // asserts; the 33rd integer, `sizeof_TX`, has no native literal.
    if let Err(why) = census::check("group_e_constants_stay_anchored", CHECKER) {
        panic!(
            "group E's {} constants are named by {CHECKER} and compared by nothing that \
             runs: the checker must be in tests/kat.rs's run list, run, pass and print \
             `group E constants anchored` with 32.\n{why}\n\
             Until it runs, `consts::net`'s literals and fixtures/group_e_net.json's \
             `constants` block agree only with themselves.",
            names.len()
        );
    }

    let compared = names.len() - NOT_THIS_WALLETS_TO_PIN.len();
    let excluded_names: Vec<&str> = NOT_THIS_WALLETS_TO_PIN.iter().map(|(n, _)| *n).collect();
    println!(
        "  {} group E constants anchored: {compared} compared by the checker, {} excluded by \
         name with a reason ({}); checker censused",
        names.len(),
        NOT_THIS_WALLETS_TO_PIN.len(),
        excluded_names.join(", ")
    );
}

/// The suite's independence, enforced instead of remembered.
///
/// Every other oracle in this project traces to the same C, so a misreading of
/// the C propagates identically into every fixture derived from it and two
/// C-derived vectors cannot disagree. `crosscheck_typescript_expected` is the
/// single exception: a separate implementation produced that string from the
/// same tag. It equals `base58_of_tag22`, so it reads as a duplicated literal,
/// and deleting it looks like tidying.
///
/// # What this catches, and what it does not
///
/// Two removal paths, and deliberately not the third:
///
/// - *Allow-listing.* Coverage forces every field to be read, so the way to drop
///   a crosscheck without any vector going red is to silence coverage for it.
///   This test reads `METADATA_KEYS` and `PROSE_KEYS` out of the support module
///   and fails if a crosscheck name appears in either.
/// - *Name removal.* Dropping a name from `crosscheck_verdicts`' list is
///   supposed to leave the field mentioned nowhere in `tests/`, which this test
///   fails on. **That holds for five of the nine fields and not for the other
///   four**, so the sentence above is qualified.
///
///   The corpus this arm searches is the whole of `tests/`, including this
///   file. `crosscheck_typescript_executed`, `crosscheck_typescript_expected`,
///   `crosscheck_executed_matches_literal` and `crosschecks_vector` are typed
///   into a required-keys list belonging to a *different* check in this file
///   (the fixture-shape scan, `[..., "source"]`), so their names are present in
///   the corpus whether or not `kat.rs` asserts them at all.
///
///   Measured, not reasoned: deleting `"crosscheck_executed_matches_literal"`
///   from `crosscheck_verdicts` leaves this test **green**. Deleting
///   `"matches_reference_expect_sig"`, which nothing else names, turns it red.
///   Same injection, same arm, opposite results, decided by whether an
///   unrelated check happens to spell the name.
///
///   **For those four fields this arm is decorative, and the mechanism that
///   actually enforces the property is `Ctx::check_coverage`** — the removal
///   leaves the field unread, and `active_groups_replay` goes red naming it.
///   Observed under the injection above, not assumed. The allow-list arm below
///   is unaffected and does enforce what it claims.
///
///   That sentence is the load-bearing part of this paragraph. A reader who
///   takes *this* test as the guarantee would keep it green while deleting
///   coverage, and the four fields would then be pinned by nothing at all. Name
///   the mechanism that works, not the one that is nearby.
///
///   The class, stated: the two remedies — construct the
///   needle, strip the comments — both presuppose that the check controls how
///   the needle is spelled, and a fixture field name is chosen by the artifact.
///   The remedy is therefore not a better needle; it is to check the property
///   directly, or to say which mechanism enforces it. This comment does the
///   second. The first is deliberately **not** done here: it was found while
///   re-verifying this check against a repaired `code_only`, and a needle
///   correction folded into a stripper repair is indistinguishable from the
///   stripper repair afterwards.
/// - *Assertion removal* is **not** caught here, and the attempt to catch it is
///   what makes this test go green under fault injection: deleting the
///   `eq_str` while leaving the enclosing `ctx.has(...)` in place keeps the name
///   present, and a `contains` check cannot tell a mention from an assertion.
///   That path is covered by `Ctx::check_coverage` instead, which reports the
///   field as unread in both C7 and C9 — verified by injection rather than
///   assumed. `has()` deliberately does not record a read, which is precisely
///   what makes that work.
///
/// The division is stated because neither half is sufficient alone and a reader
/// who assumes this test covers all three would be wrong in the direction that
/// matters.
///
/// The domain is read out of the fixtures rather than listed here, so a
/// crosscheck field added later is owed automatically.
#[test]
fn crosscheck_fields_stay_asserted() {
    // Every crosscheck field the fixtures carry, read out of them rather than
    // listed here. A domain derived from the artifact is complete,
    // and one typed into the test narrows the moment a fixture grows.
    let dir = repo_root().join("fixtures");
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut files = 0usize;
    for e in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
    {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));
        let Some(vectors) = root.get("vectors").and_then(|v| v.as_array()) else {
            continue;
        };
        for v in vectors {
            let Some(obj) = v.as_object() else { continue };
            names.extend(
                obj.keys()
                    .filter(|k| k.contains("crosscheck") || k.contains("matches_reference"))
                    // `*_source` is a file:line locator, following the `source`
                    // key every vector already carries. It points at the other
                    // implementation; it is not a value or a verdict from it,
                    // so it is prose and belongs on PROSE_KEYS. Excluded by
                    // suffix rather than by name so that a second crosscheck
                    // locator added later is excluded for the same reason
                    // instead of failing this test until someone lists it.
                    .filter(|k| !k.ends_with("_source"))
                    .cloned(),
            );
        }
    }

    assert!(
        files >= 5 && names.len() >= 5,
        "the fixture walk found {files} json file(s) and {} crosscheck field(s); \
         it is probably broken and this test would pass vacuously",
        names.len()
    );

    // `test_sources()` strips; `support/mod.rs` is read raw here and
    // so still needs its own.
    let harness = test_sources();
    let support = code_only(
        &std::fs::read_to_string(repo_root().join("crates/mochimo-crypto/tests/support/mod.rs"))
            .expect("cannot read tests/support/mod.rs"),
    );

    // The two allow-lists, located once and fail-closed.
    //
    // An `if let Some(start) = support.find(...)` inside the loop below lets
    // a miss *remove* the arm rather than fail it, which looks identical to
    // the arm running and finding nothing. Injected:
    // allow-list `crosscheck_matches` onto `METADATA_KEYS` and this test goes
    // red naming it, as it should; additionally rename the constant, a change
    // that compiles and that nothing else in the suite objects to, and the
    // whole workspace returns to its usual board with an independence anchor
    // silently allow-listed out of coverage. A floor swallowing its signal, in the shape uniformity
    // states it: the question is *did I read the list*, not *does the list have
    // this name in it*.
    let allow_lists: Vec<(&str, &str)> = ["METADATA_KEYS", "PROSE_KEYS"]
        .into_iter()
        .map(|list| {
            let Some(start) = support.find(&format!("const {list}")) else {
                panic!(
                    "tests/support/mod.rs has no `const {list}`. This arm reads \
                     that declaration by name, so not finding it means the arm \
                     does not run at all. If the constant was renamed, rename it \
                     here; do not let the lookup fail quietly."
                )
            };
            let Some(end) = support[start..].find("];").map(|i| start + i) else {
                panic!(
                    "`const {list}` is not terminated by `];` anywhere after it \
                     in tests/support/mod.rs. Falling back to the end of the \
                     file -- which is what this once did -- makes the \
                     span the rest of the module and every crosscheck name read \
                     as allow-listed."
                )
            };
            let span = &support[start..end];
            // Both directions bounded, and both numbers measured rather than
            // guessed: 74 characters over five entries and 271 over eight.
            // A span that has grown into the surrounding module would find
            // names that are not on the list; one that has collapsed would find
            // nothing and say so by passing.
            assert!(
                (20..1_000).contains(&span.len()) && span.matches('"').count() >= 2,
                "the `const {list}` span extracted to {} chars with {} quoted \
                 entr(y/ies); on this tree METADATA_KEYS measures 74 chars over \
                 5 entries and PROSE_KEYS 271 over 8. Outside that range this \
                 arm is reading something other than the declaration.",
                span.len(),
                span.matches('"').count() / 2
            );
            (list, span)
        })
        .collect();

    let mut gone: Vec<String> = Vec::new();
    for name in &names {
        let quoted = format!("\"{name}\"");
        if !harness.contains(&quoted) {
            gone.push(format!("\x20 - {name} is named by no assertion in tests/"));
        }
        // The quiet path. Coverage forces every field to be read, so the way to
        // drop a crosscheck without any vector going red is to silence coverage
        // for it rather than to delete the assertion.
        for (label, span) in &allow_lists {
            if span.contains(&quoted) {
                gone.push(format!("\x20 - {name} has been allow-listed into {label}"));
            }
        }
    }

    assert!(
        gone.is_empty(),
        "the suite's independence has been undone:\n{}\n\
         These are the only oracles in the suite that are not derived from the \
         same C. Two C-derived vectors cannot disagree with each other, so a \
         misreading of the C propagates identically into both; only an \
         independent implementation can catch it. Every one of these fields \
         duplicates a value that is computed elsewhere -- \
         `crosscheck_typescript_expected` equals `base58_of_tag22`, \
         `crosscheck_typescript_executed` equals what the C computes -- and \
         that duplication is the entire point. Removing one reads as deleting a \
         repeated literal and is actually deleting a cross-implementation \
         anchor.\n\
         Note the two are not interchangeable: `_expected` is a literal read \
         out of the upstream test file, `_executed` is a return value from \
         running it. The independence rule was amended because a read literal is the floor \
         and an executed second implementation is the standard.",
        gone.join("\n")
    );
}

// =========================================================================
// Facts the tree states about itself
//
// The family is one sentence with a decision procedure: **a fact the tree
// states about its own CURRENT state that no mechanism verifies.** The
// discriminator is whether the claim becomes false as the tree moves with
// nothing going red. Four members are checked below: the manifest's
// `reference_pin`, every fixture's `reference` block, every fixture's `pin`
// block, and the counts the documents quote about countable artifacts.
//
// The right-hand side of every commit comparison is what the documents
// state -- `AGENT.md`'s corpus section and the specification's Provenance
// section -- because the submodules those commits named are not in this
// repository. Two documents and the corpus must agree, so a fixture
// regenerated from a moved tree, or a document reworded to a different
// commit, is a disagreement rather than a silent drift. What no check here
// can see: whether the commit a document states is the one the generator
// actually ran. That fact left with the generator.
// =========================================================================

/// A 40-hex commit a document states for a named subject, read out of the
/// document at run time.
///
/// `phrase` is the text that introduces the commit -- `"`mochimo-wots` at `"`
/// -- and the commit is the run of hex digits that follows it. Whitespace is
/// collapsed first, because both documents hard-wrap prose at ~80 columns
/// and a phrase can straddle a break. A phrase that occurs nowhere is a
/// panic naming it: a reworded document must move this table, not go quiet.
/// A phrase occurring more than once must introduce the same commit every
/// time, so one document cannot carry two statements of one pin.
fn stated_commit(doc: &str, text: &str, phrase: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut from = 0usize;
    while let Some(i) = flat[from..].find(phrase) {
        let at = from + i + phrase.len();
        let hex: String = flat[at..].chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.len() == 40 {
            found.insert(hex);
        }
        from = at;
    }
    assert!(
        !found.is_empty(),
        "{doc} states no 40-hex commit after {phrase:?}. Either the document was \
         reworded -- move this needle with it -- or the statement was dropped, \
         in which case the corpus's provenance is recorded by one document fewer."
    );
    assert_eq!(
        found.len(),
        1,
        "{doc} states {} different commits after {phrase:?}: {found:?}",
        found.len()
    );
    found.into_iter().next().unwrap_or_default()
}

/// The commits the two documents state, keyed by the name the fixtures use.
///
/// Both documents are read for every key both state, and must agree: a pin
/// corrected in one place and not the other is exactly the drift this family
/// exists to catch. Keys the fixtures carry that no document states are in
/// [`UNDOCUMENTED_PIN_KEYS`], declared rather than skipped.
fn stated_commits() -> BTreeMap<&'static str, String> {
    let root = repo_root();
    let agent_doc = std::fs::read_to_string(root.join("AGENT.md")).expect("cannot read AGENT.md");
    let spec = std::fs::read_to_string(root.join("docs/specification.md"))
        .expect("cannot read docs/specification.md");
    // (fixture key, [(document, phrase)])
    let table: &[(&str, &[(&str, &str)])] = &[
        (
            "mochimo_core",
            &[
                ("AGENT.md", "the Mochimo C reference at commit `"),
                ("docs/specification.md", "`mochimo-core` at commit `"),
            ],
        ),
        (
            "mochimo_wots_ts",
            &[
                ("AGENT.md", "the `mochimo-wots` TypeScript at `"),
                ("docs/specification.md", "`mochimo-wots` at `"),
            ],
        ),
        (
            "mochimo_wallet_commit",
            &[("AGENT.md", "`mochimo-wallet` at `"), ("docs/specification.md", "`mochimo-wallet` at `")],
        ),
        (
            "mochiwallet_commit",
            &[("AGENT.md", "`mochiwallet` at `"), ("docs/specification.md", "`mochiwallet` at `")],
        ),
        ("mesh_api_client_commit", &[("docs/specification.md", "`mochimo-mesh-api-client` at `")]),
    ];
    let mut out = BTreeMap::new();
    for (key, sources) in table {
        let mut agreed: Option<String> = None;
        for (doc, phrase) in *sources {
            let text = if *doc == "AGENT.md" { &agent_doc } else { &spec };
            let c = stated_commit(doc, text, phrase);
            match &agreed {
                None => agreed = Some(c),
                Some(prev) => assert_eq!(
                    prev, &c,
                    "the documents disagree about {key}: one states {prev}, {doc} states {c}"
                ),
            }
        }
        out.insert(*key, agreed.unwrap_or_default());
    }
    // `mochimo_wots_commit` is the pin-block spelling of the reference
    // block's `mochimo_wots_ts`; one document statement covers both.
    let wots = out.get("mochimo_wots_ts").cloned().unwrap_or_default();
    out.insert("mochimo_wots_commit", wots);
    out
}

/// Provenance keys the fixtures carry that no document in this repository
/// states a commit for, with why. Each is still held to two things: every
/// fixture carrying the key agrees with every other, and the value is a
/// 40-hex object id. A key on neither this list nor in [`stated_commits`]
/// stops the run naming it.
const UNDOCUMENTED_PIN_KEYS: &[(&str, &str)] = &[
    (
        "crypto_c",
        "the C reference's `include/crypto-c` submodule; the reference and its submodules are \
         not here, and the documents pin the reference by its own commit only",
    ),
    (
        "extended_c",
        "the C reference's `include/extended-c` submodule, as above",
    ),
    (
        "mochimo_mesh_commit",
        "the Mesh middleware group N was captured against; AGENT.md records group N as a \
         live capture at one block and names the deployment, not the middleware's commit",
    ),
    (
        "go_mcminterface_commit",
        "the Go module that middleware delegates its wire work to; recorded only by group N's \
         pin block",
    ),
];

/// `[corpus] reference_pin` names the mochimo-core commit the corpus came from,
/// and it is the commit the documents state.
///
/// When the reference was a submodule this compared the pin to the gitlink,
/// the checkout and the generator's stamp. None of those three is here; the
/// documents are what remains, and a manifest that disagrees with them is a
/// corpus describing a provenance nobody can reproduce.
#[test]
fn corpus_reference_pin_matches_the_commit_the_documents_state() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("fixtures/manifest.toml"))
        .expect("cannot read fixtures/manifest.toml");

    // Needle assembled rather than written, so this test's own prose cannot
    // satisfy it. Terminated on `=` so a longer key that merely
    // starts with this one cannot match.
    let key = format!("{}_{}", "reference", "pin");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key} ")) || l.trim_start().starts_with(&format!("{key}=")))
        .unwrap_or_else(|| {
            panic!(
                "fixtures/manifest.toml has no `{key}` line. The field is the \
                 corpus's only record of which mochimo-core it was generated \
                 against; removing it does not remove the question."
            )
        });
    let pin = line
        .split('=')
        .nth(1)
        .and_then(|v| v.trim().strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("cannot parse a quoted value out of `{line}`"))
        .to_string();

    assert!(
        pin.len() >= 7 && pin.chars().all(|c| c.is_ascii_hexdigit()),
        "`{key}` is {pin:?}, which is not a hex object id of at least 7 \
         characters. A pin nobody reads is a pin that can name a commit the \
         reference does not have, and every citation resting on it then \
         points at nothing; this arm is what reads it."
    );

    let stated = stated_commits();
    let want = &stated["mochimo_core"];
    assert!(
        want.starts_with(&pin),
        "fixtures/manifest.toml's `{key}` is {pin}, but AGENT.md and the specification \
         both state the C reference at {want}. The corpus and the documents disagree \
         about the corpus's own provenance."
    );

    println!("  reference_pin: {pin} agrees with the commit two documents state");
}

/// Every fixture's `reference` block names the same four commits, and the two
/// the documents state are the ones stated.
///
/// Each C-generated `*.json` carries a `reference` object with four submodule
/// SHAs, written from the generator's `build/refver.h` so that "a fixture can
/// never be silently paired with a different reference version". That is 32
/// recorded facts about the tree's own state. When the submodules were here
/// they were compared to the checkouts; here the comparison is in two parts:
/// every file agrees with every other (so no fixture was generated from a
/// different tree than its siblings), and the two commits the documents state
/// -- the reference and the TypeScript `mochimo-wots` -- are what every file
/// records. The other two keys are declared in [`UNDOCUMENTED_PIN_KEYS`].
///
/// The domain is the directory, not a list: every `*.json` under `fixtures/`
/// is walked. A file carrying **no** `reference` block is not skipped -- it is
/// a failure naming the file, because the TypeScript-sourced groups carry a
/// `pin` block *instead*, and "this fixture declares no provenance" is exactly
/// the state that must not pass quietly.
#[test]
fn fixture_reference_blocks_agree_with_each_other_and_with_the_documents() {
    const KEYS: [&str; 4] = ["mochimo_core", "crypto_c", "extended_c", "mochimo_wots_ts"];
    let stated = stated_commits();
    for key in KEYS {
        assert!(
            stated.contains_key(key) || UNDOCUMENTED_PIN_KEYS.iter().any(|(k, _)| *k == key),
            "`reference.{key}` is neither stated by a document nor declared undocumented"
        );
    }

    let root = repo_root();
    let dir = root.join("fixtures");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    let mut problems: Vec<String> = Vec::new();
    let mut values_checked = 0usize;
    let mut with_pin_instead = 0usize;
    // key -> (value, first file that stated it)
    let mut seen: BTreeMap<&str, (String, String)> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let json: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));

        let Some(block) = json.get("reference").and_then(|r| r.as_object()) else {
            if json.get("pin").is_some() {
                with_pin_instead += 1;
            } else {
                problems.push(format!(
                    "\x20 - {name} carries neither a `reference` block nor a `pin` \
                     block, so it records no provenance at all and cannot be \
                     paired with any version of anything"
                ));
            }
            continue;
        };

        for key in KEYS {
            let Some(value) = block.get(key).and_then(|v| v.as_str()) else {
                problems.push(format!(
                    "\x20 - {name}: `reference` carries no `{key}`, so the \
                     submodule it names went unrecorded for this fixture"
                ));
                continue;
            };
            values_checked += 1;
            if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                problems.push(format!("\x20 - {name}: `reference.{key}` is {value:?}, not a 40-hex object id"));
            }
            match seen.get(key) {
                None => {
                    seen.insert(key, (value.to_owned(), name.to_owned()));
                }
                Some((first, first_file)) if first != value => problems.push(format!(
                    "\x20 - {name}: `reference.{key}` is {value}, but {first_file} records {first}. \
                     Two fixtures were generated from different trees."
                )),
                Some(_) => {}
            }
            if let Some(want) = stated.get(key) {
                if value != want {
                    problems.push(format!(
                        "\x20 - {name}: `reference.{key}` is {value}, but the documents state \
                         {want}. The fixture was generated from a different tree than the \
                         one the documents describe."
                    ));
                }
            }
        }
    }

    assert!(
        problems.is_empty(),
        "fixture provenance blocks disagree with each other or with the documents:\n{}",
        problems.join("\n")
    );
    // Vacuity floor. A walk that stopped matching -- a renamed key, a changed
    // block name -- would report agreement about nothing, which is the state
    // this check exists to make impossible. Stated, not derived: eight
    // C-sourced fixtures (A, AK, B, BK, C, D, E, HS) times four SHAs.
    assert_eq!(
        values_checked, 32,
        "{values_checked} provenance value(s) were compared across {} fixture \
         file(s); the corpus has eight C-sourced fixtures carrying four SHAs \
         each. Fewer means the walk stopped finding the block rather than \
         finding it correct; more means a fixture gained one and this number is \
         owed a deliberate move.",
        files.len()
    );
    println!(
        "  fixture provenance: {values_checked} SHA(s) across {} file(s) agree with each other, \
         2 of 4 keys with the documents; {with_pin_instead} file(s) declare a `pin` block instead",
        files.len()
    );
}

/// Counts a document quotes about a countable artifact agree with the artifact.
///
/// # The member with a demonstrated defect behind it
///
/// `AGENT.md` once carried "176 vectors across 8 groups" while the corpus
/// held 183, correct when written and invalidated nine hours later by a
/// commit in another document. `kat.rs::manifest_counts_match_the_files`
/// asserts the corpus against the fixtures; what was missing is any edge
/// between the prose and that assertion. This is that edge, and here it has
/// three subjects, all in `AGENT.md` and one also in `Cargo.toml`:
///
/// * every "N vectors" claim, against the vectors on disk;
/// * every row of the corpus table, `| group | file | subject | vectors |
///   oracle |`, against that file's `vectors` array;
/// * the absence of the dead `ffi-oracle` feature: no `cfg` attribute and no
///   `cfg!()` read anywhere under `crates/` names it. There are none, so the
///   arm is the check that none returns and that no count of them reappears.
///   The documents state no count any more, and a count claim reappearing
///   in either is itself reported.
///
/// # How the truths are derived
///
/// The vector total is the sum of every fixture's `vectors` array on disk --
/// not `manifest.toml`, which would make this agree with a second statement
/// of the same claim rather than with the artifact. The `cfg` walk lexes
/// every `.rs` under `crates/` and examines each `#[cfg(..)]` and
/// `#![cfg(..)]` attribute and each `cfg!(..)` read; a mention in a comment or
/// a string is not an attribute and cannot count. Its positive control is
/// that the walk finds `cfg` attributes at all -- the tree has ninety-odd --
/// so an empty walk cannot report an absence.
#[test]
fn documented_counts_match_the_artifacts() {
    let root = repo_root();

    // --- the truths, each derived from the artifact ---------------------
    let fx = root.join("fixtures");
    let mut vector_total = 0usize;
    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    for e in std::fs::read_dir(&fx).expect("cannot read fixtures/") {
        let p = e.expect("dir entry").path();
        if p.extension().is_some_and(|x| x == "json") {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&p).expect("read"))
                    .expect("fixture is not JSON");
            let n = v["vectors"].as_array().map_or(0, Vec::len);
            vector_total += n;
            per_file.insert(p.file_name().unwrap_or_default().to_string_lossy().into_owned(), n);
        }
    }
    assert!(per_file.len() >= 10, "the fixture walk found {} file(s)", per_file.len());

    // `#[cfg(..)]` / `#![cfg(..)]` attributes and `cfg!(..)` reads over the
    // token streams of every `.rs` under `crates/`: how many there are at all
    // (the positive control), and how many name the dead feature (must be 0).
    fn cfg_walk(
        tokens: &[proc_macro2::TokenTree],
        file: &str,
        all_attrs: &mut usize,
        named: &mut Vec<String>,
    ) {
        use proc_macro2::TokenTree as T;
        for (i, tree) in tokens.iter().enumerate() {
            let T::Group(g) = tree else { continue };
            let inner: Vec<T> = g.stream().into_iter().collect();
            let punct_at = |k: usize, want: char| {
                matches!(tokens.get(i.wrapping_sub(k)), Some(T::Punct(p)) if p.as_char() == want)
            };
            let attr_position = g.delimiter() == proc_macro2::Delimiter::Bracket
                && (punct_at(1, '#') || (punct_at(1, '!') && punct_at(2, '#')));
            let is_cfg_attr = attr_position && matches!(inner.first(), Some(T::Ident(id)) if id == "cfg");
            let is_cfg_read = g.delimiter() == proc_macro2::Delimiter::Parenthesis
                && punct_at(1, '!')
                && matches!(tokens.get(i.wrapping_sub(2)), Some(T::Ident(id)) if id == "cfg");
            if is_cfg_attr {
                *all_attrs += 1;
            }
            if (is_cfg_attr || is_cfg_read) && names_feature(&inner) {
                let line = g.span().start().line;
                named.push(format!("{file}:{line} ({})", if is_cfg_attr { "attribute" } else { "cfg!() read" }));
            }
            cfg_walk(&inner, file, all_attrs, named);
        }
    }
    fn names_feature(tokens: &[proc_macro2::TokenTree]) -> bool {
        tokens.iter().any(|t| match t {
            proc_macro2::TokenTree::Literal(l) => l.to_string() == "\"ffi-oracle\"",
            proc_macro2::TokenTree::Group(g) => {
                let inner: Vec<_> = g.stream().into_iter().collect();
                names_feature(&inner)
            }
            _ => false,
        })
    }
    let mut cfg_attrs = 0usize;
    let mut naming_the_dead_feature: Vec<String> = Vec::new();
    let mut lexed = 0usize;
    for (name, text) in all_crate_rust_sources_raw() {
        let stream: proc_macro2::TokenStream = text
            .parse()
            .unwrap_or_else(|e| panic!("{name} did not lex as Rust ({e}); the cfg walk cannot examine it"));
        let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
        cfg_walk(&trees, &name, &mut cfg_attrs, &mut naming_the_dead_feature);
        lexed += 1;
    }
    // Positive controls: the walk lexed the tree and saw `cfg` attributes at
    // all. Measured at 84 files and 133 attributes (every
    // `#[cfg(feature = "native")]`, `#[cfg(not(miri))]` and `#[cfg(test)]`);
    // both floors are two thirds of that. A floor guessed
    // "hundreds" and set at 100 was red on its first run, which is what a
    // positive control is for -- and why these two are derived from what the
    // walk reports rather than from an estimate of what it should.
    assert!(
        lexed >= 56,
        "the cfg walk lexed only {lexed} file(s) under crates/; the tree holds 84 and this floor \
         is two thirds of that"
    );
    assert!(
        cfg_attrs >= 88,
        "the cfg walk saw only {cfg_attrs} `cfg` attribute(s) across {lexed} files; the tree \
         carries 133 and this floor is two thirds of that. An absence \
         reported over a walk that finds nothing is not an absence"
    );
    assert!(
        naming_the_dead_feature.is_empty(),
        "the dead `ffi-oracle` feature is named by {} cfg site(s):\n  {}\n\
         The feature is not declared and a \
         site naming it is an `unexpected_cfgs` error under the clippy gates as well.",
        naming_the_dead_feature.len(),
        naming_the_dead_feature.join("\n  ")
    );

    // --- the claims, scanned out of the documents ----------------------
    //
    // LOGICAL LINES, NOT PHYSICAL ONES. These documents are hard-wrapped at
    // ~80 columns, so a claim routinely straddles a break; consecutive prose
    // lines are joined, a table row is its own logical line, and the first
    // physical line of each is carried so a failure names a place.
    fn logical_lines(text: &str) -> Vec<(usize, String)> {
        let mut logical: Vec<(usize, String)> = Vec::new();
        let mut joining = false;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() {
                logical.push((i + 1, String::new()));
                joining = false;
            } else if line.starts_with('|') || line.starts_with('#') {
                logical.push((i + 1, t.to_string()));
                joining = false;
            } else if joining && !is_list_item(t) {
                let last = logical.last_mut().expect("joining implies a previous entry");
                last.1.push(' ');
                last.1.push_str(t);
            } else {
                logical.push((i + 1, t.to_string()));
                joining = true;
            }
        }
        logical
    }
    /// Up to 60 characters either side of byte `at`, so a failure quotes the
    /// claim and not the paragraph around it.
    fn excerpt(line: &str, at: usize) -> String {
        let lo = line[..at].char_indices().rev().nth(60).map_or(0, |(i, _)| i);
        let hi = line[at..].char_indices().nth(60).map_or(line.len(), |(i, _)| at + i);
        line[lo..hi].to_string()
    }
    /// A markdown list item opens its own logical line: `- `, `* `, or `N. `.
    fn is_list_item(t: &str) -> bool {
        t.starts_with("- ")
            || t.starts_with("* ")
            || t.split_once(". ").is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    }
    /// The integer (commas allowed) immediately preceding byte `at` in `line`.
    fn integer_before(line: &str, at: usize) -> Option<usize> {
        let before = line[..at].trim_end();
        let digits: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == ',')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .filter(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }

    let mut problems: Vec<String> = Vec::new();
    let mut vector_claims = 0usize;
    let mut table_rows = 0usize;

    let agent_doc = std::fs::read_to_string(root.join("AGENT.md")).expect("cannot read AGENT.md");
    for (n, line) in logical_lines(&agent_doc) {
        // The corpus table: `| A | `group_a_keygen.json` | subject | 11 | C |`.
        if line.starts_with('|') {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells.len() == 5 {
                let file = cells[1].trim_matches('`');
                if let (Some(&on_disk), Ok(stated)) = (per_file.get(file), cells[3].parse::<usize>()) {
                    table_rows += 1;
                    if stated != on_disk {
                        problems.push(format!(
                            "\x20 - AGENT.md:{n}: the corpus table says {file} has {stated} \
                             vectors; the file has {on_disk}"
                        ));
                    }
                }
            }
            continue;
        }
        // "N vectors" in prose, every occurrence; "N of M" totals included.
        let mut from = 0usize;
        while let Some(i) = line[from..].find(" vectors") {
            let at = from + i;
            if let Some(stated) = integer_before(&line, at) {
                // A per-group figure ("11 vectors") is a table matter; prose
                // only ever quotes the total.
                if stated > 1000 {
                    vector_claims += 1;
                    if stated != vector_total {
                        problems.push(format!(
                            "\x20 - AGENT.md:{n}: claims {stated} vectors ({:?}); the corpus \
                             on disk has {vector_total}",
                            excerpt(&line, at)
                        ));
                    }
                }
            }
            from = at + " vectors".len();
        }
    }

    // "N `cfg` sites" in AGENT.md and Cargo.toml: a count of sites naming the
    // dead feature is a claim about something the tree no longer has, so any
    // integer in front of that phrase is reported. (The phrase without an
    // integer is history and is left alone.)
    //
    // # Where the needle is anchored, and why it was moved
    //
    // The floor below demands the phrase occur at least once, so that the arm
    // cannot go quiet by matching nothing. An occurrence inside prose kept
    // for some other purpose makes the arm's survival depend on that prose,
    // and deleting it fails this check with a message about its own needle at
    // a moment when nothing is wrong.
    //
    // The anchor is a relocated sentence rather than a re-pointed needle:
    // relocating keeps the arm asserting what it asserts -- no count of these
    // sites in either document -- where re-pointing changes the subject to
    // whatever the new needle names. The anchor now
    // sits in AGENT.md under "What holds this document to the code", a
    // paragraph whose subject is this check, so the phrase stays for the
    // reason the check needs it to.
    let cargo = std::fs::read_to_string(root.join("crates/mochimo-crypto/Cargo.toml"))
        .expect("cannot read crates/mochimo-crypto/Cargo.toml");
    let mut cfg_phrases = 0usize;
    for (doc, text) in [("AGENT.md", &agent_doc), ("crates/mochimo-crypto/Cargo.toml", &cargo)] {
        for (n, line) in logical_lines(text) {
            let mut from = 0usize;
            while let Some(i) = line[from..].find(" `cfg` sites") {
                let at = from + i;
                cfg_phrases += 1;
                if let Some(stated) = integer_before(&line, at) {
                    problems.push(format!(
                        "\x20 - {doc}:{n}: claims {stated} `cfg` sites name the dead feature \
                         ({:?}); the tree has none, and no count belongs in a document",
                        excerpt(&line, at)
                    ));
                }
                from = at + " `cfg` sites".len();
            }
        }
    }

    assert!(
        problems.is_empty(),
        "a document quotes a count that disagrees with the artifact:\n{}\n\n\
         This is the drift class: a figure correct when written and invalidated \
         by a change elsewhere. The remedy is to re-derive the number, never to \
         move the artifact to match the sentence.",
        problems.join("\n")
    );
    // Floors, one per claim family, so a scan that stopped matching says which.
    assert!(
        vector_claims >= 2,
        "only {vector_claims} vector-total claim(s) matched in AGENT.md; the scan stopped matching"
    );
    assert!(
        table_rows >= 10,
        "only {table_rows} corpus-table row(s) matched in AGENT.md; the table's shape moved"
    );
    assert!(
        cfg_phrases >= 1,
        "the phrase `cfg` sites occurs nowhere in AGENT.md or Cargo.toml; the count arm's \
         needle stopped matching and a count could reappear unreported. The anchor is the \
         paragraph in AGENT.md under \"What holds this document to the code\", which spells \
         the phrase in a sentence about this check for exactly this reason. Put it back \
         rather than lowering this floor."
    );

    println!(
        "  documented counts: {vector_claims} vector-total claim(s) and {table_rows} table row(s) \
         agree with {vector_total} vectors in {} files; {cfg_attrs} cfg attribute(s) across \
         {lexed} files, 0 naming the dead feature, {cfg_phrases} mention(s) in the documents \
         carrying no count",
        per_file.len()
    );
}

/// Every `.rs` under `crates/`, **comment-stripped**, in sorted path order.
///
/// Wider than [`crate_source_files`] (which is `crates/*/src` only) and than
/// `test_source_files()` (this crate's `tests/` only), because the set it
/// builds is *every `fn` the tree defines* -- and a name cited in `src/` may
/// legitimately be a test, a `ui/` compile-fail case's helper or a downstream
/// probe's. Stripped, and that is the load-bearing half: if the `fn` set were
/// read from raw text, one doc comment naming `fn foo` would satisfy another
/// doc comment citing `foo`, and the check would compare prose to prose. The
/// citations come from the raw view and the definitions from the stripped one,
/// so the two sides cannot be the same source.
fn all_crate_rust_sources() -> Vec<(String, String)> {
    all_crate_rust_sources_raw()
        .into_iter()
        .map(|(name, text)| (name, code_only(&text)))
        .collect()
}

/// [`all_crate_rust_sources`] before the strip: the raw text, for a consumer
/// that lexes rather than searches.
fn all_crate_rust_sources_raw() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // `target/` under a nested manifest (ui/downstream) is build
                // output, not tree.
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    // Sorted: an unsorted `read_dir` makes the corpus vary per run, which is
    // the reason every walk in this file sorts.
    out.sort();
    out
}

/// Lower `snake_case` identifiers of at least `words` underscore-separated
/// segments, as whole tokens.
///
/// The token is the maximal `[A-Za-z0-9_]` run, then filtered -- **not** a
/// search for the shape *inside* a longer run, and that distinction is doing
/// real work in both directions. Two forms in this tree are partial names on
/// purpose, and each drops out because the run it sits in fails a filter
/// rather than because anything enumerated it:
///
/// * `addr.rs` hard-wraps `no_native_endian_conversions_anywhere_in_the_crate`
///   across a line break, so the run ends `..._anywhere_in_` -- a trailing
///   underscore, hence an empty final segment.
/// * `backend/native.rs` writes `..._all_two_byte_inputs`, eliding a shared
///   prefix, so the run is `_all_two_byte_inputs` and does not begin with a
///   lowercase letter.
///
/// A regex for the shape within a run yields `..._anywhere_in` and
/// `all_two_byte_inputs` from those two sites and reports both as names the
/// tree does not define, and the table's own still-cited assertion rejects a
/// row for either, because the scan never produced one.
fn lower_snake_names_of_at_least(words: usize, text: &str) -> BTreeSet<String> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < b.len() {
        if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        let tok = &text[start..i];
        if !tok.starts_with(|c: char| c.is_ascii_lowercase()) {
            continue;
        }
        if tok.bytes().any(|c| c.is_ascii_uppercase()) {
            continue;
        }
        let segments: Vec<&str> = tok.split('_').collect();
        if segments.len() < words || segments.iter().any(|s| s.is_empty()) {
            continue;
        }
        out.insert(tok.to_owned());
    }
    out
}

/// What a row's reason opens with when the row permits history prose rather
/// than a live fixture key, dependency method or lint name. Spelled once, so
/// the rows, the remedy the failure prints and
/// [`MarkerClass::DeclaredName`]'s population cannot drift apart.
const HISTORY_ROW_MARK: &str = "CORRECT HISTORY";

/// Names cited in `crates/*/src/` that name no `fn` in the tree, declared here
/// with the reason each is not a dangling citation.
///
/// # What this table is for
///
/// A marker is renamed when it clears, and every citation of the
/// old name in prose then becomes a claim about a test that does not exist.
/// Most such citations in `docs/` are correct history -- *"X cleared,
/// green as Y"* -- so a bare "a retired name is a defect" rule would flag the
/// record for recording. The defect is narrower: **a live claim under a dead
/// name, in shipped source.** An audit measured five such names in
/// `crates/*/src/`; three asserted an obligation that had already been
/// discharged, one cited a marker under a truncated spelling, and one pointed
/// at a note by a name nothing carried. The fifth, `sign.rs`'s, is correct
/// history and is declared below rather than corrected.
///
/// So the rule is *resolve or declare*, and the declaration is the mechanism:
/// a legitimate citation becomes explicit and argued instead of being
/// indistinguishable from a stale one, and the next rename fails closed --
/// every `src/` citation of the old name reds until it is fixed or a row here
/// says why it stays.
///
/// # WHAT THIS CHECK CANNOT SEE, and it is in the name
///
/// It matches **a name shape, not a resolved path.** `..._matched_by_shape_not_by_path`
/// is the bound: a four-word `snake_case` token is taken as a citation
/// wherever it appears, so the moment a second module defines an ordinary
/// four-word function this table grows a row that is about nothing. The
/// project has already lost three renames to bare-identifier scans -- `send`,
/// `Parsed` and `run`, in `no_wallet_visible_fn_hands_out_a_wots_signature`
/// -- and the remedy there is the same remedy here: key on
/// qualified paths, which is work this check does not do.
///
/// Three further bounds, stated because a check narrows quietly:
///
/// * **`src/` only.** The class occurs in `tests/` too and this does not look:
///   `crate_sources`'s doc named `stripper_damage_is_measured_over_the_corpus_it_is_used_on`,
///   a test that never existed, and a reader was needed to find it.
/// * **Four segments or more.** Shorter names are ordinary vocabulary; at
///   three the population is 86 unresolved rather than 27, almost all of it
///   `std` and dependency methods, and a table nobody can read is a table
///   nobody maintains.
/// * **A definition is any `fn`, anywhere under `crates/`.** It does not check
///   that the cited `fn` is the *right* one, only that the name is not dead.
const DECLARED_UNRESOLVED_SRC_NAMES: &[(&str, &str)] = &[
    (
        "keystore_v3_reserved_snapshot",
        "a testdata file name, `testdata/keystore_v3_reserved_snapshot.bin`: \
         the version-3 capture with a reservation open, embedded by `format.rs`'s version-dispatch \
         test through `include_bytes!`. A file name and no `fn` carries it; a renamed file is a \
         compile error at the `include_bytes!`, not a dangling citation. The three older captures \
         have three-segment names and never reached this table.",
    ),
    (
        "account_literal_is_not_constructible",
        "a trybuild compile-fail case, `ui/fail/account_literal_is_not_constructible.rs`. \
         Case stems are file names and no `fn` carries them; the partition test reads the \
         directory, so a renamed case is caught there rather than here.",
    ),
    (
        "account_wots_index_is_not_assignable",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "broken_intra_doc_links",
        "a rustdoc lint name, in `mochimo-crypto`'s crate-level `deny`. Dependency surface, as \
         with `unsafe_op_in_unsafe_fn` below -- and load-bearing for the same kind of reason: it \
         is what makes a doc link to a deleted item an error instead of plain text that renders \
         and says nothing. It fires under `cargo doc` alone, which neither the board nor clippy \
         runs.",
    ),
    (
        "private_intra_doc_links",
        "a rustdoc lint name, in the same crate-level block, allowed rather than denied. Its \
         argument is written at the site: the links it names resolve, the `deny` above is what \
         makes them resolve, and dropping the brackets to satisfy it would turn the tree's only \
         assertion that those private names exist into prose nothing checks. Dependency surface \
         like the two lints beside it, and visible under `cargo doc` alone.",
    ),
    (
        "base58_to_addr_tag",
        "a fixture field: group C's `base58_to_addr_tag`, quoted in `addr.rs` as the datum the \
         function under discussion refuses. Fixture keys are asserted by the group's own \
         consumer in `kat.rs`, which is what would red if the key were renamed.",
    ),
    (
        "decrypt_in_place_detached",
        "a `chacha20poly1305` method (the `AeadInPlace` trait). Dependency surface: nothing in \
         this tree defines it, and a rename upstream is a compile error, not a dangling citation.",
    ),
    (
        "durable_is_not_constructible",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "encrypt_in_place_detached",
        "a `chacha20poly1305` method, as above.",
    ),
    (
        "eq_ignore_ascii_case",
        "a `std` method on `str`. Dependency surface, as above.",
    ),
    (
        "group_n_mesh_live",
        "a file stem, not a function: `fixtures/group_n_mesh_live.json`. The manifest's file \
         list is asserted against the directory in `kat.rs`.",
    ),
    (
        "hash_password_into_with_memory",
        "an `argon2` method -- the one entry point that survives `default-features = false`, \
         which is why `Cargo.toml` and two keystore modules name it. Dependency surface.",
    ),
    (
        "http_status_as_error",
        "a `ureq` config builder method. Dependency surface.",
    ),
    (
        "mdst_val_rc_name",
        "a fixture field: group D's `mdst_val_rc_name`, quoted in `error.rs` as the reference's \
         own naming of a return code, against which ours is compared. Fixture key, as above.",
    ),
    (
        "medium_steps_are_not_reorderable",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "signing_raw_signer_is_not_reachable",
        "a trybuild compile-fail case, as above -- and the one `wots.rs` cites as the redundant \
         proof that the raw signer is crate-private.",
    ),
    (
        "tx_bot_get_wots",
        "a C function in the reference, `tx.c:212` at the commit AGENT.md states, cited by \
         `backend/native.rs` for the path that writes a public key into a transaction. The \
         reference is not in this repository and its symbols are not this tree's `fn`s.",
    ),
    (
        "unsafe_op_in_unsafe_fn",
        "a rustc lint name, in `mochimo-crypto`'s crate-level `deny`. As above -- and this one \
         is load-bearing: it is what makes every `unsafe` block inside an `unsafe fn` state its \
         own SAFETY.",
    ),
    (
        "from_raw_os_error",
        "a `std::io::Error` constructor, called in `keystore/perms/windows.rs` to carry the \
         status `GetNamedSecurityInfoW` returns, which is an error code and not a flag in \
         `GetLastError`. Dependency surface: nothing in this tree defines it. A rename in `std` \
         is a compile error -- but only in a Windows build, since the file compiles nowhere \
         else, so on a Unix host this row is the one thing that notices the name at all.",
    ),
];

/// Every four-plus-word `snake_case` name cited in `crates/*/src/` names an
/// `fn` somewhere under `crates/`, or is declared in
/// [`DECLARED_UNRESOLVED_SRC_NAMES`] with a reason.
///
/// # Both directions, because one of them is the vacuity guard
///
/// A cited name that resolves to nothing and is undeclared fails, naming the
/// file. **A declared row that now resolves, or that nothing cites, also
/// fails** -- and that half is what keeps the table honest. The CLI
/// scan graded itself on its first run by discovering that `.store_mut(` was
/// forbidding a name nobody could write; forbidding, or permitting, a name
/// that is not there establishes nothing. So a marker that comes back, or a
/// citation that is deleted, reds the row that was speaking for it rather than
/// leaving a permit behind for the next rename to hide under.
///
/// See [`DECLARED_UNRESOLVED_SRC_NAMES`] for what this cannot see. The short
/// form is in the name: **by shape, not by path.**
#[test]
fn names_cited_in_src_resolve_to_a_fn_or_are_declared_matched_by_shape_not_by_path() {
    // Four segments. See the table's doc for why not three.
    const MIN_SEGMENTS: usize = 4;

    // A permit table written as a dict lets a duplicate key silently discard
    // permits. A list of pairs plus this assert is the shape that avoids it, so a repeat survives
    // long enough to be asserted on.
    let mut names: Vec<&str> = DECLARED_UNRESOLVED_SRC_NAMES.iter().map(|(n, _)| *n).collect();
    let declared_rows = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        declared_rows,
        "DECLARED_UNRESOLVED_SRC_NAMES carries a duplicate name. A second row for one \
         name is a permit nobody can see: the reason that reads as governing the \
         citation may be the one that is never consulted."
    );
    for (name, reason) in DECLARED_UNRESOLVED_SRC_NAMES {
        assert!(
            !reason.trim().is_empty(),
            "{name} is declared with an empty reason. The reason IS the declaration; \
             a row without one is a bare permit."
        );
    }

    // The definitions: every `fn` under `crates/`, read from comment-stripped
    // code so that no doc comment can satisfy another doc comment.
    let sources = all_crate_rust_sources();
    let mut defined: BTreeSet<String> = BTreeSet::new();
    for (_, code) in &sources {
        let mut previous_was_fn = false;
        let b = code.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let tok = &code[start..i];
            if previous_was_fn {
                defined.insert(tok.to_owned());
            }
            previous_was_fn = tok == "fn";
        }
    }

    // The citations: the RAW `crates/*/src` view, because the subject is text
    // in doc comments and a stripped view would delete it.
    let src = crate_source_files();
    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (file, text) in &src {
        for name in lower_snake_names_of_at_least(MIN_SEGMENTS, text) {
            cited.entry(name).or_default().insert(file.clone());
        }
    }

    // --- vacuity floors, each over a quantity a broken walk drives to zero ---
    assert!(
        sources.len() >= 40,
        "the crates/ walk found only {} .rs file(s); the `fn` set it builds is the \
         resolving side of this check, so a short walk makes every citation look dead.",
        sources.len()
    );
    assert!(
        defined.len() >= 800,
        "only {} `fn` name(s) were extracted from crates/. The tokenizer stopped \
         recognising definitions, which would report live citations as dangling.",
        defined.len()
    );
    assert!(
        src.len() >= 30 && cited.len() >= 80,
        "the src/ walk found {} file(s) and {} cited name(s). Too few of either and \
         this check passes over an empty corpus rather than over a clean one \
         .",
        src.len(),
        cited.len()
    );

    // --- direction 1: a citation that resolves to nothing must be declared ---
    let declared: BTreeSet<&str> = DECLARED_UNRESOLVED_SRC_NAMES.iter().map(|(n, _)| *n).collect();
    let mut dangling: Vec<String> = Vec::new();
    let mut unresolved_total = 0usize;
    for (name, files) in &cited {
        if defined.contains(name) {
            continue;
        }
        unresolved_total += 1;
        if declared.contains(name.as_str()) {
            continue;
        }
        let mut where_ = files.iter().cloned().collect::<Vec<_>>();
        where_.sort();
        dangling.push(format!("\x20 - {name}\n\x20     cited in: {}", where_.join(", ")));
    }
    // --- direction 2: a declared row must still be a citation that dangles ---
    //
    // The half that makes the table itself the vacuity guard. A row for a name
    // nothing cites is a permit the next rename can hide under; a row for a
    // name that now resolves is a permit that has outlived its subject.
    let mut stale: Vec<String> = Vec::new();
    // The rows whose subject is history, and the files whose sentences keep
    // them alive. Declared in DECLARED_HISTORY_MARKER_SITES as well, because
    // they are debt with an owner rather than a standing permit, and a sweep
    // reading that table would otherwise never learn these exist.
    let mut history_rows: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (name, reason) in DECLARED_UNRESOLVED_SRC_NAMES {
        let short = reason.split_once(". ").map_or(*reason, |(a, _)| a);
        // What a maintainer who hits this red needs, and had to go looking
        // for: a history row is not repaired in place. The sentence it
        // permits and the row itself leave in one change -- delete the
        // sentence alone and the row permits nothing, delete the row alone
        // and the sentence becomes the dangling citation this check exists
        // to catch.
        let remedy = if reason.starts_with(HISTORY_ROW_MARK) {
            format!(
                "\n\x20     this is a {HISTORY_ROW_MARK} row. It permits nothing but the sentence \
                 under src/ that names the retired marker, so the row and that sentence are \
                 removed in one change: delete the sentence alone and the row permits nothing, \
                 delete the row alone and the sentence is the dangling citation this check \
                 exists to catch."
            )
        } else {
            String::new()
        };
        if reason.starts_with(HISTORY_ROW_MARK) {
            // A `BTreeSet` of paths, so the order is the sorted one already.
            let files: Vec<String> = cited
                .get(*name)
                .into_iter()
                .flatten()
                .map(|f| format!("\x20     cited in: {f}"))
                .collect();
            if !files.is_empty() {
                history_rows.insert(*name, files);
            }
        }
        match cited.get(*name) {
            None => stale.push(format!(
                "\x20 - {name}: declared, but no file under crates/*/src cites it.\n\
                 \x20     the row says: {short}.{remedy}"
            )),
            Some(_) if defined.contains(*name) => stale.push(format!(
                "\x20 - {name}: declared as naming no `fn`, but the tree now defines one.\n\
                 \x20     the row says: {short}.{remedy}"
            )),
            Some(_) => {}
        }
    }
    // The table's own staleness is reported first: a row about nothing is a
    // defect in this check's data, and it must not hide behind a red about
    // the tree.
    assert!(
        stale.is_empty(),
        "DECLARED_UNRESOLVED_SRC_NAMES carries a row that is no longer about anything.\n\
         {}\n\n\
         Permitting a name nobody writes establishes nothing, and a permit \
         left behind is what the next stale citation hides under. Delete the row, or say \
         at it what changed.",
        stale.join("\n")
    );

    assert!(
        dangling.is_empty(),
        "a name cited in crates/*/src names no `fn` in the tree and is not declared.\n\
         {}\n\n\
         This is the shape a rename leaves behind: the marker moved, the sentence \
         asserting it did not, and a reader is told an obligation is owed by a test \
         that no longer exists. Either point the sentence at the live name, or add a \
         row to DECLARED_UNRESOLVED_SRC_NAMES saying why the dead one belongs there \
         -- history, a fixture key, a dependency method, a lint. What is not \
         available is leaving it undeclared.",
        dangling.join("\n")
    );

    let declared_history = assert_against_baseline(MarkerClass::DeclaredName, &history_rows);

    println!(
        "  cited-name resolution: {} name(s) of >= {MIN_SEGMENTS} segments across {} src \
         file(s); {} resolve to one of {} `fn`(s) in {} crates/ file(s); {} declared \
         unresolved, all cited and all still dead, {} of them history rows against a \
         baseline of {declared_history}",
        cited.len(),
        src.len(),
        cited.len() - unresolved_total,
        defined.len(),
        sources.len(),
        declared_rows,
        history_rows.values().map(Vec::len).sum::<usize>()
    );
}

/// I8 — an imported account keeps a path back to its key material.
///
/// The extension has two kinds of account and only one of them is derivable.
/// A standard account carries `index` and its seed is a pure function of the
/// master seed at that index, so it can be rebuilt from the mnemonic alone. An
/// imported account carries **`index: undefined`** (
/// spelled as a literal ternary arm) and its `seed` is the only copy of its key
/// material anywhere: it came out of an `.mcm` file, not out of the master seed,
/// and no index reproduces it.
///
/// The consequence is the reason this is an invariant rather than a feature
/// note. A Rust wallet that models an account as "master seed + index" — the
/// obvious model, and the one every group F vector describes — will restore a
/// mnemonic and silently produce **only the standard accounts**. The imported
/// entries vanish from the wallet while remaining perfectly real on chain:
/// funds still addressable at their tag, and the one copy of the key that could
/// move them dropped on the floor. Nothing errors. The user sees a smaller
/// balance and no diagnostic.
///
/// # Why this is not a fixture item
///
/// Group F captures derivation, and derivation is exactly what an imported
/// account does not do. There is no vector to write: the property is that a
/// *non*-derived account survives a restore, which no derivation vector can
/// express. It is a shape the wallet has to have, so it is checked as one.
///
/// # What it holds
///
/// Three
/// reference anchors and a runtime-assembled needle that keep deriving what
/// is demanded — survives, and the name now carries the green's bound the
/// way `native_transaction_path_is_checked_on_layout_not_acceptance` does.
///
/// # What cleared it, and exactly what the green claims
///
/// Two conditions, both required, and the second is the substantive one:
///
/// 1. a Rust account model that names the non-derived variant —
///    `KeyMaterial::Imported` in `src/account.rs`;
/// 2. `imported_account_restores_from_stored_seed`, census-checked: run
///    alone, passing, printing its account counts.
///
/// **The bound is in the name.** The round-trip that test drives is in
/// memory, over the persistent-content types — not through a keystore, not
/// through a disk, not under I2/I3's ordering. A green here says the account
/// *model* cannot lose an imported root on the restore path; durability is
/// the keystore session's obligation and its markers are still red.
#[test]
fn imported_account_restore_is_checked_in_memory_not_on_disk() {
    // The three anchors this guard carried read the browser extension's
    // TypeScript -- the `imported` variant of its account union, the optional
    // `index`, and the import action leaving it undefined -- to hold the
    // premise. The reference is not in this repository; the premise is
    // recorded in docs/specification.md under I8, and the model and the
    // proof below are the mechanism.
    // The variant as Rust would spell it, derived rather than typed.
    let mut needle = String::new();
    for (i, c) in "imported".chars().enumerate() {
        needle.extend(if i == 0 {
            c.to_uppercase().collect::<Vec<_>>()
        } else {
            vec![c]
        });
    }

    let mut owed: Vec<String> = Vec::new();

    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is \
         vacuous",
        files.len()
    );
    let modelled = files
        .iter()
        .any(|(_, code)| code.contains(&format!("{needle},")) || code.contains(&format!("{needle} ")));
    if !modelled {
        owed.push(format!(
            "\x20 - no file under crates/*/src names an account kind spelled \
             `{needle}`. \
             There is no Rust account model at all yet; when there is, it must \
             distinguish an account whose key material is stored from one whose \
             key material is derived."
        ));
    }

    const PROOF: &str = "imported_account_restores_from_stored_seed";
    // EXECUTION, not existence. Before the census this asked `test_sources()` whether
    // the characters `fn <name>` occur somewhere under `tests/`. That is
    // satisfied by a plain `fn`, by a helper that is not a `#[test]`, and --
    // measured -- by a `#[test]` with an EMPTY BODY. `census::check`
    // runs the named test on its own and reads libtest's own verdict and the
    // measurement the test reported. See the `census` module for what it still
    // cannot see.
    if let Err(why) = census::check("imported_account_restore_is_checked_in_memory_not_on_disk", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It has to build a wallet \
             holding one derived and one imported account, round-trip it \
             through restore, and assert the imported account's stored seed \
             comes back byte-identical -- not merely that the account is \
             listed. An enum variant nothing exercises satisfies the check \
             above and loses the funds anyway."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "I8's enforcement has regressed: the account model or its restore \
         proof is gone.\n{}\n\
         An imported account's `seed` is the only copy of its key material in \
         existence -- it came from an .mcm file, not from the master seed, and \
         `index: undefined` (walletActions.ts:374) is how the extension marks \
         that. A wallet modelled as master-seed-plus-index restores the \
         mnemonic, rebuilds the standard accounts, and drops these entries with \
         no error: the funds stay addressable on chain and the key that could \
         move them is gone. See docs/specification.md I8.",
        owed.join("\n")
    );
}

/// The proof test behind I8's marker: an imported account's stored root
/// survives the restore path byte-for-byte.
///
/// # What this establishes, and what it cannot
///
/// **Established:** the account model's restore path — `Account::to_record`
/// into `Account::restore_from_record` — carries an imported root through
/// unchanged, preserves the rotation index, and rebuilds a derived account
/// from its position alone (the derived record has no root field *by type*,
/// which is I8's asymmetry made structural). The root comes back equal to an
/// independent literal written in this test, never to a value read off the
/// pre-restore account — the expected side has its own degree of freedom
///.
///
/// **Not established:** durability. This round-trip is in memory; the record
/// type is the persistent *content*, not an on-disk format, and the keystore
/// session extends this same path through real storage under I2/I3's
/// ordering. Said here because this test is what turned the marker green and
/// its bound must travel with the green. The marker was renamed
/// `imported_account_restore_is_checked_in_memory_not_on_disk` in the same
/// commit for the same reason.
///
/// # Why these values
///
/// The imported account is `F-address-widths` — its account seed as the
/// retained root and its recorded 2208-byte first address as the `faddress`
/// an `.mcm` entry carries — so a restore that manufactures material cannot
/// collide with it (the distinguishing-value concern, now met by a fixture value rather
/// than by a chosen pattern; the constructor verifies the pair, so an
/// arbitrary root is no longer buildable). It is advanced once before the
/// snapshot, so a restore that resets the index to zero fails the index
/// assertion rather than passing over a fresh account.
#[test]
fn imported_account_restores_from_stored_seed() {
    use mochimo_crypto::account::{Account, AccountKind, AccountRecord};

    const ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    const IMPORTED_TAG: [u8; 20] = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];
    const IMPORTED_FIRST_ADDRESS: &[u8; mochimo_crypto::consts::WOTS_ADDR_LEN] =
        include_bytes!("../../../fixtures/F-widths_account_address.bin");
    // The derived account's tag is computed, so master, position
    // and tag are group F's `F-derive-account-1` triple -- a tag the
    // TypeScript emitted, not one read back from `Account::derive`.
    const DERIVED_MASTER: [u8; SEED_LEN] = [
        0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
        0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
        0xc4, 0x9a, 0xcf, 0x70,
    ];
    const DERIVED_POSITION: u32 = 1;
    const DERIVED_TAG: [u8; 20] = [
        0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38,
        0x8e, 0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
    ];

    let mut imported = Account::import(Secret::new(ROOT), IMPORTED_FIRST_ADDRESS)
        .unwrap_or_else(|e| panic!("F-address-widths' root and first address are a pair: {e}"));
    assert_eq!(
        imported.tag(),
        IMPORTED_TAG,
        "Account::import no longer computes the fixture's recorded account tag"
    );
    let advanced = imported
        .advance()
        .unwrap_or_else(|e| panic!("advance from 0 cannot overflow: {e}"));
    assert_eq!(advanced.get(), 1, "advance from a fresh account must yield 1");

    let derived = Account::derive(&Secret::new(DERIVED_MASTER), DERIVED_POSITION);
    assert_eq!(derived.tag(), DERIVED_TAG, "Account::derive no longer reproduces the fixture tag");

    // The restore path under test: content out, account back.
    let restored_imported = Account::restore_from_record(imported.to_record())
        .unwrap_or_else(|e| panic!("the imported record must restore: {e}"));
    let restored_derived = Account::restore_from_record(derived.to_record())
        .unwrap_or_else(|e| panic!("the derived record must restore: {e}"));

    assert_eq!(restored_imported.kind(), AccountKind::Imported);
    assert_eq!(restored_derived.kind(), AccountKind::Derived);
    assert_ne!(
        restored_imported.kind(),
        restored_derived.kind(),
        "a restore that collapses the two kinds is the I8 loss mode"
    );
    assert_eq!(
        restored_imported.wots_index().get(),
        1,
        "restore reset the rotation index; a reset index re-signs a used key"
    );

    match restored_derived.to_record() {
        AccountRecord::Derived {
            tag, account_index, ..
        } => {
            assert_eq!(account_index, DERIVED_POSITION, "derived position lost in restore");
            assert_eq!(tag, DERIVED_TAG, "derived tag lost in restore");
        }
        AccountRecord::Imported { .. } => {
            panic!("derived account restored as imported")
        }
    }

    let mut accounts_round_tripped = 0u32;
    let mut roots_byte_identical = 0u32;
    match restored_imported.to_record() {
        AccountRecord::Imported { tag, root, .. } => {
            assert_eq!(tag, IMPORTED_TAG, "imported tag lost in restore");
            assert_eq!(
                root.expose(),
                &ROOT,
                "the stored root did not come back byte-identical; an \
                 imported account whose root mutates in restore is funds \
                 lost with no diagnostic (docs/specification.md I8)"
            );
            roots_byte_identical += 1;
        }
        AccountRecord::Derived { .. } => {
            panic!("imported account restored as derived")
        }
    }
    accounts_round_tripped += 2;

    // Every integer below is an account count (the census floor
    // reads the largest integer after the needle, so nothing else may print
    // a number here).
    println!(
        "  restore path: {accounts_round_tripped} account(s) round-tripped \
         in memory, {roots_byte_identical} imported root byte-identical, 1 \
         derived rebuilt from its position"
    );
}

/// I8's proof at the first key: an imported account's position-0 key is the
/// one its stored first address names, through a keystore round trip.
///
/// # What the pair is, and what it is not
///
/// `F-address-widths`' account seed and its recorded 2208-byte first address
/// — the shape a `.mcm` entry carries (the import action stores all
/// 2208 bytes as `faddress`), reached here from group F rather than from an
/// `.mcm` file, because nothing in this crate reads one. **That is the bound
/// in the marker's post-discharge name.** The pair is a derived account's,
/// seen from the imported side; no capture of a genuinely imported account
/// exists anywhere in the corpus, and none could be produced without a wallet
/// to export from.
///
/// # What it establishes
///
/// * `Account::import` **refuses** a first address the root does not
///   reproduce, so the tag is computed and not supplied;
/// * the key at `WotsIndex::ZERO` has that address's public key and the
///   account's tag — checked after `add` + drop + reopen, so it is the
///   record that carried the components and not the constructor's memory;
/// * a signature made at position 0 recovers to the same public key, which
///   is the property the funds actually depend on.
///
/// # What it cannot see
///
/// The `.mcm` format. A *wrong choice* of what to store would fail the public
/// key comparison, but a wrong reading of an `.mcm` file is the import
/// session's to catch. And it says nothing about at-rest secrecy -- which is
/// a different sentence since encryption at rest, because the root is no longer plaintext
/// beside the components: the whole record body is sealed, and
/// `imported_roots_and_the_master_seed_are_encrypted_at_rest` is green.
#[test]
fn imported_index_zero_pk_reproduces_the_first_address() {
    use keystore_harness::{imported_account, reopen, ScratchDir, IMPORTED_FIRST_ADDRESS, IMPORTED_TAG, ROOT};
    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::keystore::{KeyAccess, Keystore};
    use mochimo_crypto::{addr, wots};

    const PK_LEN: usize = 2144;

    // (1) the verifying constructor refuses a pair that is not one. One byte
    // of the public key flipped, everything else the recorded pair, so only
    // the reproduction check can fail.
    let mut forged = *IMPORTED_FIRST_ADDRESS;
    forged[0] ^= 0x01;
    assert_eq!(
        Account::import(Secret::new(ROOT), &forged).err(),
        Some(mochimo_crypto::Error::FirstAddressNotReproduced),
        "import accepted a first address the root does not reproduce"
    );

    // (2) the real pair, through a keystore round trip.
    let dir = ScratchDir::new("i8-first-key");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut ks = reopen("I8 first key", dir.path())
        .result
        .unwrap_or_else(|e| panic!("reopen: {e}"));
    let view = ks
        .view(&IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the imported account did not survive the reopen"));
    assert_eq!(view.wots_index, WotsIndex::ZERO, "a never-spent account is at position 0");

    // (3) position 0 signs, and the key it signed with is the stored one.
    let r = ks.persist_advance(&IMPORTED_TAG, &[0xD1u8; 32], keystore_harness::FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let sig = ks
        .sign_spend(&[0xD1u8; 32], r, KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("position 0 after a reopen: {e}"));
    assert_eq!(sig.spent_index, WotsIndex::ZERO);
    let mut adrs = sig.adrs;
    let recovered = wots::pk_from_sig(&sig.signature, &[0xD1u8; 32], &sig.pub_seed, &mut adrs);
    assert_eq!(
        &recovered[..],
        &IMPORTED_FIRST_ADDRESS[..PK_LEN],
        "position 0's signature does not recover the stored first public key"
    );
    let implicit = addr::from_wots(&recovered);
    assert_eq!(
        addr::tag_of(&implicit),
        &IMPORTED_TAG[..],
        "the first key's address is not implicit under the account tag"
    );

    let accounts = 1u32;
    // Every integer on this line is an account count.
    println!(
        "  I8 first key: {accounts} imported account(s) whose position-0 public key is the \
         stored first address's, through a keystore reopen"
    );
}

/// I8 at the first key — **green, under a name that carries what
/// the green does not establish.**
///
/// # The finding this discharges
///
/// An account's first key is `WOTS.generateRandomAddress(_, account_seed,
/// generator)` where the generator is the one `deriveSeed(master,
/// account_index)` left behind: it supplies the 2208 bytes whose tail is the
/// public seed and the hash address. The secret is the account seed; the
/// *public components* are a function of the master seed and the account
/// index, and of nothing an imported account holds. The shipped wallet knows
/// this: `types/account.ts` declares `faddress`, the `.mcm` import stores it
/// verbatim beside `seed`, and the `wotsIndex === -1` selector rebuilds the
/// first key by copying `faddress` into the generator buffer rather than
/// deriving anything.
/// **The funds an imported account held at import time sit at the first
/// address**, so a model holding the root alone could not spend them.
///
/// # What discharged it
///
/// Format v2 carries the 64-byte tail of the `faddress` in the record beside
/// the root, `Account::import(root, first_address)` refuses a pair the root
/// does not reproduce and computes the tag from the verified public key, and
/// `sign_spend` rebuilds position 0 from the stored components — the same
/// thing the shipped selector does. `import_with_unverified_tag` is gone with
/// `Error::FirstKeyUnavailable`, so an imported account with a forged tag or
/// an unreachable position 0 is unconstructible rather than refused.
///
/// Only 64 bytes are stored because the public key is
/// `wots::pkgen(root, pub_seed, adrs)`, and the twelve bytes the shipped
/// format overlays on the address image do not matter: the reference writes
/// address words 5, 6 and 7 before every use, so their incoming values
/// never reach a hash.
/// Measured by execution before the design was written.
///
/// # THE BOUND IN THE NAME
///
/// **`not_against_an_mcm_capture`.** The pair the proof uses is group F's —
/// a *derived* account's seed and first address, seen from the imported side
/// — because no capture of a genuinely imported account exists in the corpus
/// and none could be produced without a wallet to export from. What is
/// checked is that the model holds the right *kind* of thing and reproduces
/// it; that an `.mcm` file is parsed into that pair correctly is the import
/// session's, and this marker never saw it.
///
/// One further residue: this says nothing about at-rest secrecy — which is
/// no longer the same admission it was. Since encryption at rest the root is not plaintext
/// beside the components; the body is sealed and
/// `imported_roots_and_the_master_seed_are_encrypted_at_rest` is green. The
/// sentence here asserted plaintext storage and a "still-red" marker under its
/// pre-rename name for a session after it was sealed.
#[test]
fn imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture() {
    // The two anchors this guard carried read the browser extension's
    // TypeScript -- the `wotsIndex === -1` selector rebuilding the first key
    // from `faddress`, and the account type declaring it. The reference is
    // not in this repository; the premise is recorded in
    // docs/specification.md under I8, and the proof below is the mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "imported_index_zero_pk_reproduces_the_first_address";
    if let Err(why) = census::check(
        "imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to build an imported \
             account from a 32-byte root AND a 2208-byte first address (the \
             .mcm entry's pair), through a constructor that refuses a first \
             address the root does not reproduce; assert the key at \
             WotsIndex::ZERO has that address's public key and the account's \
             tag; and assert the same after a keystore round trip. It must \
             report how many such accounts it drove; the floor is 1.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I8 at the first key has REGRESSED: before format v2 this red meant an \
         imported account's position-0 key was unreachable -- its public seed \
         and hash address came from the master seed's generator and were not \
         in the stored root, so the funds it was imported holding could not \
         be moved. Format v2 stores those 64 bytes beside the root and \
         `Account::import` verifies them against it, so this firing means the \
         proof, its census row, or the stored components went away.\n{}\n\
         What must still hold: the record carries the components, the \
         constructor refuses a first address the root does not reproduce, and \
         the key at WotsIndex::ZERO is the one that address names -- after a \
         keystore reopen, not just in memory. The index decision found it, the signing \
         path settled that the components must be stored, format v2 landed it.",
        owed.join("\n")
    );
}

/// Group F is a specification capture. It must not become an oracle.
///
/// Most fixtures in this corpus are derived from the vendored C, which is what
/// makes a crosscheck valuable: two C-derived vectors cannot disagree, because
/// a misreading of the C propagates identically into both. Group F is derived
/// from the TypeScript, and there is exactly one implementation of that
/// derivation in existence. A Rust port agreeing with these vectors proves the
/// port matches the extension — which is the entire requirement — and proves
/// nothing whatever about whether the extension is right.
///
/// # Two classes, one walk
///
/// Since `group_c_crosscheck.json` landed, a non-C fixture can legitimately be
/// either kind, so this walk routes on `oracle.class` and an unrecognised class
/// is a failure rather than a pass. It keeps the `specification-capture` arm;
/// `group_c_crosscheck_is_an_executed_oracle` owns the other. Routing rather
/// than ignoring is the point — a class nobody checks is a fixture nobody
/// checks.
///
/// The distinction is easy to lose. A future session sees a fixture whose
/// values came from somewhere other than the C, and "independent oracle" is the
/// nearest available concept. Erosion looks like adding a `crosscheck_`-named
/// field to a group F vector, at which point
/// `crosscheck_fields_stay_asserted` starts counting it among the suite's
/// independent anchors and the count of them silently goes from one to several.
///
/// # The domain's two questions
///
/// - *What makes this domain complete?* The domain is derived, not listed:
///   every fixture carrying its own `pin` block is by construction outside
///   `manifest.toml`'s single `reference_pin`, hence not C-derived, hence owed
///   an `oracle` declaration. A second non-C fixture added later is covered on
///   the day it lands.
/// - *What would expand the domain without expanding the check?* A non-C
///   fixture that pins nothing at all. It would carry no `pin` block, so this
///   walk would not see it — but it would also be a fixture pinned against
///   nothing, which is the defect `group_e_constants_stay_anchored` exists for.
///   The two checks meet there rather than leaving a gap.
#[test]
fn group_f_is_specification_not_crosscheck() {
    let dir = repo_root().join("fixtures");
    // Counts fixtures that make a provenance claim of *either* kind -- a `pin`
    // block or an `oracle` block. Not "fixtures that are fully declared": that
    // would count a different thing, and injection shows the difference
    // matters. Deleting the `oracle` block from group F leaves the count at zero, so the
    // vacuity floor fired first and reported "the walk found no `pin` block"
    // for a file that plainly had one -- the precise arm below, which is the
    // whole point of the check, never got to speak. A vacuity floor is supposed
    // to distinguish a broken walk from a clean corpus; one that also fires on
    // the defect being hunted mistranslates it.
    let mut claims = 0usize;
    let mut files = 0usize;
    let mut problems: Vec<String> = Vec::new();

    // Files this test's own arm is responsible for: pinned, and not routed away
    // to the executed-crosscheck test. Counted loosely on purpose.
    // A file whose `oracle` block was deleted still counts here, because its
    // class is absent rather than `executed-crosscheck` — so the floor below
    // cannot fire on the very defect the arm exists to report, which is exactly
    // the mistranslation the comment above records having already happened once.
    let mut spec_arm = 0usize;
    let mut routed = 0usize;

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();

    for p in &paths {
        files += 1;
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));

        let has_pin = root.get("pin").is_some_and(|v| v.is_object());
        let oracle = root.get("oracle");
        if has_pin || oracle.is_some() {
            claims += 1;
        }

        // Both directions. A `pin` without an `oracle` is an undeclared
        // non-C fixture; an `oracle` without a `pin` is a declaration about a
        // provenance nothing records.
        if !has_pin {
            if oracle.is_some() {
                problems.push(format!(
                    "\x20 - {name} declares an `oracle` block but pins nothing. \
                     A statement about where these values came from is worth \
                     something only next to a record of what produced them."
                ));
            }
            continue;
        }

        // Routing, read before the `oracle` block is required to be well formed
        // so that a deleted block routes here rather than nowhere.
        let class = oracle
            .and_then(|v| v.get("class"))
            .and_then(serde_json::Value::as_str);
        if class == Some(EXECUTED_CROSSCHECK) || class == Some(EXECUTED_CROSSCHECK_NO_REFERENCE) {
            // Owned by group_c_crosscheck_is_an_executed_oracle and
            // group_rx_is_an_oracle_with_no_reference_side, which are real
            // tests and not promises: the existence of each is asserted at the
            // end of this function, so neither branch can become a way to opt a
            // fixture out of being checked at all.
            routed += 1;
            continue;
        }
        spec_arm += 1;

        let Some(oracle) = oracle.and_then(|v| v.as_object()) else {
            problems.push(format!(
                "\x20 - {name} carries its own `pin` block, so it is not covered \
                 by manifest.toml's reference_pin and is not derived from the \
                 vendored C -- but it declares no `oracle` block saying what it \
                 is instead. Every non-C fixture must state whether it is an \
                 independent oracle or a specification capture, because the \
                 next reader will otherwise decide by guessing."
            ));
            continue;
        };

        let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
        // Fail-closed routing. Anything that is not the one class routed away
        // above must be a specification capture; an invented third class lands
        // here and is reported, rather than quietly matching no arm.
        if class != Some(SPECIFICATION_CAPTURE) {
            problems.push(format!(
                "\x20 - {name}: oracle.class is {:?}. The only classes with a \
                 test behind them are {SPECIFICATION_CAPTURE:?} (this test), \
                 {EXECUTED_CROSSCHECK:?} \
                 (group_c_crosscheck_is_an_executed_oracle) and \
                 {EXECUTED_CROSSCHECK_NO_REFERENCE:?} \
                 (group_rx_is_an_oracle_with_no_reference_side). A fourth class \
                 is a fixture making a provenance claim nothing checks.",
                oracle.get("class")
            ));
        }
        if flag("is_independent_oracle") != Some(false) {
            problems.push(format!(
                "\x20 - {name}: oracle.is_independent_oracle is {:?}, not false",
                oracle.get("is_independent_oracle")
            ));
        }
        if flag("second_implementation_exists") != Some(false) {
            problems.push(format!(
                "\x20 - {name}: oracle.second_implementation_exists is {:?}, not \
                 false",
                oracle.get("second_implementation_exists")
            ));
        }
        // The reasoning, not just the flags. Three booleans with nothing behind
        // them are three booleans a later session flips.
        let why = oracle.get("why").and_then(serde_json::Value::as_str).unwrap_or("");
        if why.len() < 200 {
            problems.push(format!(
                "\x20 - {name}: oracle.why is {} chars. It has to carry the \
                 argument, because the flags above are only as durable as the \
                 reason next to them.",
                why.len()
            ));
        }

        // The erosion path. A crosscheck-named field here would be collected by
        // crosscheck_fields_stay_asserted, which would then be guarding a
        // "cross-implementation anchor" that has only one implementation behind
        // it. Same two substrings that check uses, so the two cannot drift.
        if let Some(vectors) = root.get("vectors").and_then(|v| v.as_array()) {
            for v in vectors {
                let Some(obj) = v.as_object() else { continue };
                let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
                for k in obj.keys() {
                    if k.contains("crosscheck") || k.contains("matches_reference") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} carries `{k}`. There is no \
                             second implementation of this derivation, so \
                             nothing here can be a crosscheck; naming a field \
                             this way makes crosscheck_fields_stay_asserted \
                             count it as one of the suite's independent anchors."
                        ));
                    }
                }
            }
        }
    }

    // Vacuity floor: with no such fixture found, every assertion
    // above is skipped and the test reports agreement about nothing.
    assert!(
        files >= 5,
        "the fixture walk found {files} json file(s); it is broken and this \
         check would pass vacuously"
    );
    assert!(
        claims >= 1,
        "no fixture under {} carries a `pin` block or an `oracle` block. \
         group_f_derivation.json is supposed to carry both -- it is one of two \
         groups not derived from the vendored C, and those blocks are how that \
         is recorded. Either they were removed or this walk stopped finding \
         them; both are failures, neither is agreement.",
        dir.display()
    );
    assert!(
        spec_arm >= 1,
        "the walk found {claims} pinned fixture(s) but routed every one of them \
         away as an executed crosscheck, so the specification-capture arm below \
         ran against nothing. group_f_derivation.json is supposed to land in it.",
    );

    // The routing arm is only honest if what it routes to exists. Without this,
    // deleting group_c_crosscheck_is_an_executed_oracle would turn `continue`
    // above into a silent exemption -- the fixture would declare a class, this
    // test would skip it on the strength of another test's name, and that test
    // would not be there.
    //
    // The needle is composed at run time rather than written as one literal,
    // and that is load-bearing rather than stylistic.
    //
    // `test_sources()` concatenates every .rs under tests/, **this file
    // included**. So a check that spells the needle out as a single string
    // literal is satisfied by its own argument: rename the target test away and
    // the assertion still finds the characters it is made of. Not a
    // hypothetical -- it was written that way, injection renamed the test, and
    // it stayed green. Built from the const, the sought characters occur
    // nowhere in this file as one run, so only a real `fn` can match.
    //
    // The same trap then caught the *comment*: the paragraph explaining the bug
    // quoted the needle verbatim, which put it back into the file and made the
    // check green a second time. Prose in a file the check reads is not inert.
    //
    //
    // The trailing `(` is not cosmetic. `contains` is substring matching and has
    // no notion of where an identifier ends, so without it a target renamed to
    // `<name>_v2` -- or a helper that merely shares the prefix -- still contains
    // `fn <name>`, and the check passes while the test it names is gone. Found
    // by injection: the first rename attempt appended a suffix and stayed green,
    // and the cause was this, not the self-match described above. With the paren
    // the match runs into the parameter list, so only that exact `fn` satisfies
    // it.
    // Both routings now key on libtest rather than on source text -- see the
    // `census` module. The two edges get DIFFERENT tiers, and the difference is
    // structural rather than a judgement call:
    //
    // * `EXECUTED_CROSSCHECK_TEST` is `group_c_crosscheck_is_an_executed_oracle`,
    //   which is itself a census caller. Executing it would re-enter the census,
    //   so it is `Tier::Listed` -- libtest lists it, therefore it runs. That
    //   tier is blind to `#[ignore]`, which `no_test_in_the_suite_is_ignored`
    //   covers suite-wide; it is not blind to any of the four routes an
    //   existence guard is blind to, because a plain `fn`, a `cfg`-out, a comment-out and a rename all
    //   leave the name out of the run list.
    // * `NO_REFERENCE_TEST` is an ordinary test, so it is executed and its
    //   reported vector count is read.
    if let Err(why) = census::check(
        "group_f_is_specification_not_crosscheck",
        EXECUTED_CROSSCHECK_TEST,
    ) {
        panic!(
            "this test routes {routed} fixture(s) with oracle.class == \
             {EXECUTED_CROSSCHECK:?} to {EXECUTED_CROSSCHECK_TEST}, and that \
             test does not run. The routing is now an exemption.\n\x20  {why}"
        );
    }
    if let Err(why) = census::check("group_f_is_specification_not_crosscheck", NO_REFERENCE_TEST) {
        panic!(
            "this test routes fixture(s) with oracle.class == \
             {EXECUTED_CROSSCHECK_NO_REFERENCE:?} to {NO_REFERENCE_TEST}, and \
             that test does not run and report. The routing is now an \
             exemption.\n\x20  {why}"
        );
    }

    assert!(
        problems.is_empty(),
        "a specification capture is being treated as an oracle:\n{}\n\
         Group F records what the published extension's TypeScript does. There \
         is one implementation of that derivation and no second opinion \
         anywhere, so these vectors carry none of a second implementation's error-detecting \
         power: a Rust port agreeing with them proves it matches the extension, \
         not that the extension is right. The suite's cross-implementation \
         anchor is group_c_crosscheck.json, where the second implementation is \
         executed rather than read; group F is not it and shares none of its \
         error-detecting power just by being TypeScript too.",
        problems.join("\n")
    );

    println!(
        "  {claims} non-C fixture(s): {spec_arm} specification capture(s), \
         {routed} routed to the executed-crosscheck test"
    );
}

/// The two `oracle.class` values that have a test behind them.
///
/// Named here rather than spelled inline in two files, because the routing in
/// `group_f_is_specification_not_crosscheck` and the selection in
/// `group_c_crosscheck_is_an_executed_oracle` have to agree exactly. If they
/// drift, a fixture is routed away by the first and not picked up by the
/// second, and lands in the one state neither test reports.
const SPECIFICATION_CAPTURE: &str = "specification-capture";
const EXECUTED_CROSSCHECK: &str = "executed-crosscheck";

/// The third class, added with the crosscheck widening, and the reason it is a class rather than a
/// flag on the second.
///
/// Group RX records `@noble/hashes`' RIPEMD-160 for the input lengths where the
/// vendored implementation overflows its stack. There is no C side
/// and there cannot be one: asking the reference ends the process. So it is an
/// executed crosscheck whose *other* side is not the C but this port, and the
/// claim "the C computed the values in the file this derives from" -- which
/// `EXECUTED_CROSSCHECK` carries -- is simply false of it.
///
/// Folding it into `EXECUTED_CROSSCHECK` would have been the easy move and the
/// wrong one: the class would then make a statement true of some members and
/// false of others, which is the erosion this whole family of tests exists to
/// stop.
const EXECUTED_CROSSCHECK_NO_REFERENCE: &str = "executed-crosscheck-no-reference";

/// The test that owns the `executed-crosscheck` class.
///
/// A const rather than a literal at the use site so that the string
/// `fn <this name>` never appears in this file — see the comment on the
/// assertion that uses it.
const EXECUTED_CROSSCHECK_TEST: &str = "group_c_crosscheck_is_an_executed_oracle";

/// The test that owns the `executed-crosscheck-no-reference` class. Same
/// construction and the same reason: routing away to a test that does not exist
/// is an exemption wearing a test's name.
const NO_REFERENCE_TEST: &str = "group_rx_is_an_oracle_with_no_reference_side";

/// Group CX is an executed crosscheck. It must not decay into a transcription.
///
/// # What the independence rule got generous about
///
/// The independence rule once named `crosscheck_typescript_expected` on C7 and C9 as the suite's
/// one independent oracle. The *property* was right and the *mechanism* was
/// weak: those strings were literals read out of the TypeScript package's
/// committed test file and typed into the C generator. A read literal pins what
/// the reader believed the TypeScript would return. It cannot notice a stale
/// upstream test, a transcription slip, or a behaviour change the upstream test
/// was never updated for.
///
/// `fixtures/group_c_crosscheck.json` is generated by *running* the TypeScript.
/// This test is what stops it from sliding back: an executed crosscheck whose
/// values were pasted in would satisfy every field-shape check and none of the
/// provenance ones, so the provenance is what is checked here.
///
/// # The domain's two questions
///
/// - *What makes this domain complete?* It is derived: every fixture declaring
///   `oracle.class == "executed-crosscheck"` is selected, and
///   `group_f_is_specification_not_crosscheck` independently guarantees that
///   every pinned fixture declares one of exactly two classes. A second
///   executed crosscheck added later is checked on the day it lands, and a
///   fixture that declares no class at all is caught by the other test rather
///   than falling between them.
/// - *What would expand the domain without expanding the check?* A crosscheck
///   whose second implementation is not TypeScript — a second C build, say.
///   `crosscheck_typescript_executed` is spelled into the required field names
///   below, so such a fixture fails here loudly instead of being waved through,
///   and whoever adds it has to generalise this test deliberately.
#[test]
fn group_c_crosscheck_is_an_executed_oracle() {
    let dir = repo_root().join("fixtures");
    let mut problems: Vec<String> = Vec::new();
    let mut found = 0usize;
    let mut vectors_checked = 0usize;
    let mut literals = 0usize;

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();

    // Every fixture, so that the reverse erosion is caught too: a file may not
    // claim `is_independent_oracle: true` without also declaring the class that
    // brings this test's checks with it.
    for p in &paths {
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));

        let oracle = root.get("oracle").and_then(|v| v.as_object());
        let class = oracle
            .and_then(|o| o.get("class"))
            .and_then(serde_json::Value::as_str);
        let claims_independence = oracle
            .and_then(|o| o.get("is_independent_oracle"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);

        if class != Some(EXECUTED_CROSSCHECK) {
            // A file may claim independence only if SOME test checks the claim.
            // The crosscheck widening added a second such class, so the condition is "has an
            // owner", not "is this test's class" -- but it is still an
            // allow-list, and a file inventing a class still lands here.
            // EXECUTION, not existence -- see the `census` module. "Some test
            // checks the claim" is a statement about a test that RUNS; a name
            // in a file is not one. `census::check` is memoised per target, so
            // asking inside this loop spawns at most one child.
            let owned_elsewhere = class == Some(EXECUTED_CROSSCHECK_NO_REFERENCE)
                && census::check("group_c_crosscheck_is_an_executed_oracle", NO_REFERENCE_TEST)
                    .is_ok();
            if claims_independence && !owned_elsewhere {
                problems.push(format!(
                    "\x20 - {name} declares is_independent_oracle: true with \
                     oracle.class {class:?}. Independence is the strongest claim \
                     in the suite and every file making it must be checked by \
                     some test. This one reaches {EXECUTED_CROSSCHECK:?} \
                     (here) and {EXECUTED_CROSSCHECK_NO_REFERENCE:?} \
                     ({NO_REFERENCE_TEST}); {name} matches neither, or matches \
                     the second while that test no longer exists."
                ));
            }
            continue;
        }
        found += 1;

        let Some(oracle) = oracle else { continue };
        let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
        // The three claims, each of which is false of a specification capture.
        // Flipping any one of them is how this file would quietly become one.
        if flag("is_independent_oracle") != Some(true) {
            problems.push(format!(
                "\x20 - {name}: oracle.is_independent_oracle is {:?}, not true",
                oracle.get("is_independent_oracle")
            ));
        }
        if flag("second_implementation_exists") != Some(true) {
            problems.push(format!(
                "\x20 - {name}: oracle.second_implementation_exists is {:?}, \
                 not true",
                oracle.get("second_implementation_exists")
            ));
        }
        let why = oracle.get("why").and_then(serde_json::Value::as_str).unwrap_or("");
        if why.len() < 200 {
            problems.push(format!(
                "\x20 - {name}: oracle.why is {} chars. The flags are only as \
                 durable as the argument written next to them.",
                why.len()
            ));
        }
        // What is *not* an oracle has to be written down too. The Python
        // hashlib check on the addr_from_wots vector is the same two primitives
        // in the same order; recording it as a third implementation would
        // inflate the suite's anchor count with a self-comparison.
        if oracle
            .get("not_an_oracle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .len()
            < 100
        {
            problems.push(format!(
                "\x20 - {name}: oracle.not_an_oracle is missing or too short. An \
                 executed crosscheck attracts near-misses -- a second call to \
                 the same primitives, a value read out of a test file -- and the \
                 file has to say which of its neighbours are not oracles, or the \
                 next reader counts them."
            ));
        }

        // Provenance: the generator must be the TypeScript one, and the file it
        // crosschecks must exist. `derived_from` is what makes the domain
        // derived rather than typed, so a dangling value is a real failure.
        let generator = root
            .get("generator")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !generator.ends_with(".ts") {
            problems.push(format!(
                "\x20 - {name}: generator is {generator:?}, not a TypeScript \
                 program. An executed crosscheck is executed by something; if \
                 the generator is the C, the second implementation is the first."
            ));
        }
        match root.get("derived_from").and_then(serde_json::Value::as_str) {
            Some(src) if dir.join(src).exists() => {}
            other => problems.push(format!(
                "\x20 - {name}: derived_from is {other:?}, which is not a fixture \
                 on disk. The whole domain of this crosscheck is read out of that \
                 file; without it the generator is choosing its own inputs."
            )),
        }

        // Per vector: the executed value, the transcribed literal, and the
        // verdict that they agree. All three are required. Dropping the literal
        // would remove the only check on the transcription; dropping the
        // executed value would leave a transcription calling itself an oracle.
        let Some(vs) = root.get("vectors").and_then(|v| v.as_array()) else {
            problems.push(format!("\x20 - {name} has no vectors array"));
            continue;
        };
        for v in vs {
            let Some(obj) = v.as_object() else { continue };
            let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
            vectors_checked += 1;
            for k in [
                "crosscheck_typescript_executed",
                "crosschecks_vector",
                "source",
            ] {
                if !obj.contains_key(k) {
                    problems.push(format!("\x20 - {name} vector {id} has no `{k}`"));
                }
            }

            // The transcription leg, conditional since the widening and fail-closed in
            // both directions.
            //
            // Before the widening every vector here carried a literal, because carrying
            // one was how the generator SELECTED it -- so requiring all three
            // fields unconditionally cost nothing. Widening the domain to all of
            // group C means most vectors have no literal: nobody ever typed one
            // out of the upstream test file for them.
            //
            // The requirement therefore becomes an exclusive or, not a
            // relaxation. Either the vector carries a literal and the verdict
            // saying it agrees with the executed value, or it declares
            // `literal_absent` and carries neither. A vector with both, or with
            // neither, is reported -- which is what keeps "the literal quietly
            // stopped being compared" distinguishable from "there was never a
            // literal here".
            let has_literal = obj.contains_key("crosscheck_typescript_expected");
            let declares_absent = obj.get("literal_absent").and_then(serde_json::Value::as_bool)
                == Some(true);
            match (has_literal, declares_absent) {
                (true, false) => {
                    if !obj.contains_key("crosscheck_executed_matches_literal") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} carries a transcribed \
                             literal but no `crosscheck_executed_matches_literal`. \
                             The verdict is the only record that the \
                             transcription was ever checked."
                        ));
                    } else if obj
                        .get("crosscheck_executed_matches_literal")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                    {
                        problems.push(format!(
                            "\x20 - {name} vector {id}: the executed TypeScript \
                             and the literal transcribed into group C disagree. \
                             Regenerating did not paper over it, which is the \
                             point."
                        ));
                    }
                    literals += 1;
                }
                (false, true) => {
                    if obj.contains_key("crosscheck_executed_matches_literal") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} declares `literal_absent` \
                             and carries a verdict about a literal it does not \
                             have."
                        ));
                    }
                }
                (true, true) => problems.push(format!(
                    "\x20 - {name} vector {id} both carries a transcribed \
                     literal and declares `literal_absent`."
                )),
                (false, false) => problems.push(format!(
                    "\x20 - {name} vector {id} has neither a transcribed literal \
                     nor `literal_absent`. One must hold: silence here is how a \
                     literal that stopped being asserted would look."
                )),
            }
            // The second implementation must be the other implementation. A
            // `source` pointing into the vendored C would make this a fixture
            // where the C crosschecks itself.
            // The second implementation must be a DIFFERENT implementation.
            // Stated as an allow-list of provenances rather than as "not the
            // C", because "not the C" is satisfied by a source naming nothing
            // at all, and an empty string is not a provenance.
            //
            // `bs58` joined the list with the widening. It is the Base58 codec
            // `addrTagToBase58` itself calls, and the vectors that reach it
            // directly are the ones the tag encoder cannot answer -- lengths
            // other than 20, and the all-'1' class where the reference faults.
            // It is third-party and shares no code with the C reference,
            // which is the property this check is really about.
            const SECOND_IMPLEMENTATIONS: [&str; 2] = ["reference/mochimo-wots", "bs58 6.0.0"];
            let source = obj.get("source").and_then(serde_json::Value::as_str).unwrap_or("");
            if !SECOND_IMPLEMENTATIONS.iter().any(|k| source.contains(k)) {
                problems.push(format!(
                    "\x20 - {name} vector {id}: source is {source:?}, which names \
                     none of {SECOND_IMPLEMENTATIONS:?}. Two vectors derived from \
                     one implementation cannot disagree, so a crosscheck against \
                     it detects nothing."
                ));
            }
            if source.contains("reference/mochimo-core") {
                problems.push(format!(
                    "\x20 - {name} vector {id}: source names \
                     reference/mochimo-core. That is the implementation this \
                     group exists to be independent OF."
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "the executed crosscheck is not one:\n{}\n\
         fixtures/group_c_crosscheck.json is the suite's independent oracle in \
         its strong form -- a second implementation that was run, not read. \
         Every problem above turns it back into something weaker while leaving \
         the word \"crosscheck\" on it.",
        problems.join("\n")
    );

    // Vacuity floors, and they come *after* the report above rather than before
    // it. A floor placed where it swallows its signal, learned here rather than recalled: written floor-first,
    // changing `oracle.class` to an invented value made `found` zero, so the
    // floor fired with "either the file was removed or its class was changed"
    // and the precise finding two lines up -- "declares is_independent_oracle:
    // true with class \"lightly-checked\", so it claims the strongest thing in
    // the suite and is checked by nobody" -- never got to speak. A floor placed
    // where it can swallow the signal it protects turns a specific finding into
    // a generic one.
    //
    // The order is safe because a non-empty `problems` is itself proof the walk
    // is not vacuous; only a clean run needs a floor at all. It is the same
    // ordering, for the same reason, as kat.rs's `fields_total` floor.
    assert!(
        found >= 1,
        "no fixture under {} declares oracle.class == {EXECUTED_CROSSCHECK:?}, \
         and nothing above objected. The suite's independence would then rest \
         entirely on literals read out of an upstream test file, which is the \
         floor the independence rule was amended to stop treating as the standard. \
         group_c_crosscheck.json was removed, or the walk stopped finding it.",
        dir.display()
    );
    // The transcriptions must survive the domain widening. It took this group
    // from three vectors to twenty-two, and every one of the nineteen new ones
    // has no literal -- so a floor on `vectors_checked` alone would be entirely
    // satisfied by the new vectors while the three that carry the only check on
    // the transcription quietly vanished. That is the shape where the check
    // can fail, it just could not fail for this.
    assert_eq!(
        literals, 3,
        "the crosscheck carries {literals} transcribed literal(s), expected 3 \
         (C7, C9, C-addr-from-wots-fill42). Those literals are the ONLY thing \
         in the suite that checks the transcription itself -- whether the \
         strings someone read out of the upstream test file were read \
         correctly. The executed values cannot check them, because a \
         transcription error and a correct transcription produce the same \
         executed value."
    );
    assert!(
        vectors_checked >= 2,
        "the executed crosscheck holds {vectors_checked} vector(s). One vector \
         is a check that a single value round-trips; the file exists to cover \
         every group C vector carrying a transcribed literal, and there is more \
         than one of those."
    );

    println!("  {found} executed crosscheck(s), {vectors_checked} vectors, all independent");
}

// -------------------------------------------------------------------------
// Oracle-blind properties
//
// No fixture can decide these: each is about an *absence* -- nothing was left
// in memory, no comparison trait exists, no holder prints its secret -- and a
// recorded value cannot witness an absence. Each guard names the mechanism
// that decides it and demands that mechanism's execution through the census.
// -------------------------------------------------------------------------

/// `crates/mochimo-crypto/src/secret.rs`, comments stripped.
///
/// Comments must go: the type's own doc comment states that `PartialEq` is
/// deliberately absent, so a raw substring search for `PartialEq` in this file
/// finds the *explanation* and cannot distinguish it from a derive. That is
/// a check reading its own prose in its original form, and `code_only` is the existing answer to it.
fn secret_rs_code() -> String {
    let p = repo_root().join("crates/mochimo-crypto/src/secret.rs");
    let text =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    code_only(&text)
}

/// The `ui/fail` trybuild cases, by file stem.
///
/// Two of the markers below clear with a compile-fail case rather than a test
/// function, so their needle is a filename in `ui/fail/` and not a symbol in
/// `test_sources()`. That is deliberate on both sides: `ui/` is outside the
/// `tests/` walk precisely so its intentionally-broken contents do not pollute
/// symbol searches (see tests/compile_fail.rs), which also means a
/// marker keyed on it cannot satisfy itself by discussing itself.
fn ui_fail_stems() -> Vec<String> {
    let dir = repo_root().join("crates/mochimo-crypto/ui/fail");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect();
    out.sort();
    // Vacuity floor. An empty directory would make both trybuild-keyed markers
    // below report "the case is missing" for the wrong reason, and would mean
    // I7's own compile-fail half had silently stopped existing.
    assert!(
        out.len() >= 4,
        "ui/fail holds {} cases; I7's four are the floor. An empty or moved \
         directory makes every marker keyed on this walk report a missing case \
         when the real finding is that the walk broke.",
        out.len()
    );
    out
}

/// Zeroization is an absence property; the C has no counterpart to compare to.
///
/// `Secret<N>` wraps `Zeroizing`, so the bytes are overwritten on drop. Nothing
/// in the reference does this, so there is no C behaviour to diff against — and
/// even against a Rust reimplementation the diff would be empty, because the
/// observable being asserted is that a freed stack frame *no longer contains*
/// something. Safe Rust cannot look at it.
///
/// # What clears it
///
/// A drop-witness test: place the secret at a known address, drop it, and read
/// that address back through a raw pointer, with the read confined to the one
/// `unsafe` block the test needs. This is genuinely delicate — the compiler is
/// entitled to elide a store nothing reads, which is the reason `zeroize` uses
/// volatile writes and a fence — so the test is as much a check on the crate's
/// guarantee surviving optimisation as on our use of it. Run it in release too;
/// a debug-only pass proves the least interesting case.
#[test]
fn zeroization_has_no_reference_counterpart() {
    // Anchor A: our side of the property still exists.
    assert!(
        secret_rs_code().contains("Zeroizing<[u8; N]>"),
        "Secret no longer wraps Zeroizing. This marker demands evidence that \
         key bytes are cleared on drop; if the mechanism was removed, the \
         finding is the removal, not the missing test."
    );
    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "secret_bytes_are_gone_after_drop";
    // EXECUTION, not existence. Before the census this asked `test_sources()` whether
    // the characters `fn <name>` occur somewhere under `tests/`. That is
    // satisfied by a plain `fn`, by a helper that is not a `#[test]`, and --
    // measured -- by a `#[test]` with an EMPTY BODY. `census::check`
    // runs the named test on its own and reads libtest's own verdict and the
    // measurement the test reported. See the `census` module for what it still
    // cannot see.
    if let Err(why) = census::check("zeroization_has_no_reference_counterpart", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It must observe the memory a \
             Secret occupied AFTER the drop and show the key bytes are not \
             there. Asserting that `Zeroizing` is in the type is not evidence: \
             that is a claim about our source, and the property is about what \
             the optimiser left behind."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "Zeroization is oracle-blind and unwitnessed.\n{}",
        owed.join("\n")
    );
}

/// The bytes a `Secret` held are gone from its storage after the drop.
///
/// The proof `zeroization_has_no_reference_counterpart` demands. It lived in
/// It is not a differential -- there is nothing to diff a freed frame
/// against -- so it lives here beside its guard.
///
/// # The construction is the delicate part, and the obvious one is wrong
///
/// The guard's doc comment proposes *"place the secret at a known address,
/// drop it, and read that address back through a raw pointer"*. An earlier
/// session refused to ship that because reading a dead local is undefined
/// behaviour. **Measured, it is also wrong for a second and more
/// embarrassing reason:** `drop(x)` *moves* `x` into `drop`, so the zeroing
/// happens in the callee's frame and the original address still holds the
/// pattern. Run under Miri, that version reports **32 of 32 bytes still
/// matching** -- a false negative about a `Secret` that was correctly cleared.
///
/// So the witness owns the storage explicitly. See
/// `tests/support/drop_witness.rs` for the four soundness claims and
/// `tests/miri.rs::secret_drop_witness_is_sound_under_miri` for the only thing
/// that can adjudicate them.
///
/// # What a green here does NOT mean
///
///   * **One allocation was observed.** Register spills, temporaries made
///     moving the `Secret` into the slot, and the witness's own `pattern` array
///     all still hold the bytes and are invisible to it.
///   * **Nothing inside the ladder is covered.** `expand_seed`'s output and
///     every chain intermediate are separate allocations with their own
///     `Zeroizing`; none is witnessed.
///   * It shows `Drop` ran and cleared **that storage**. It does not show that
///     no copy of the secret survives in the process, which is what a reader is
///     most likely to take a green for.
#[test]
fn secret_bytes_are_gone_after_drop() {
    // Two widths, because the property is over `Secret<N>` and a single N could
    // be satisfied by an implementation that special-cased it.
    let a = drop_witness::observe_secret_drop::<32>();
    let b = drop_witness::observe_secret_drop::<64>();

    let mut witnessed = 0usize;
    for obs in [&a, &b] {
        assert!(
            obs.pattern_seen_before_drop,
            "the witness did not see the pattern in the Secret's storage BEFORE \
             the drop, so it is reading the wrong bytes and nothing it says \
             about the state afterwards is about the right memory. Either \
             `Secret` stopped being a transparent wrapper over `[u8; N]` -- \
             which the witness checks with size_of -- or the read is misaligned."
        );
        assert!(
            obs.all_zero_after_drop,
            "{} of {} bytes still match the pattern after the drop. `Secret` \
             wraps `Zeroizing`, whose Drop writes zeros with volatile stores; \
             if this is red either that mechanism is gone or the optimiser \
             removed it.",
            obs.surviving_pattern_bytes,
            obs.bytes
        );
        assert_eq!(
            obs.surviving_pattern_bytes, 0,
            "a partial clear is not a clear"
        );
        witnessed += obs.bytes;
    }

    // The pattern carries no zero byte, so "all zero afterwards" cannot be
    // satisfied by bytes that were already zero. Stated as an assertion rather
    // than a comment so a future change to the generator is caught here.
    assert_eq!(
        witnessed, 96,
        "expected 32 + 64 bytes witnessed across two widths; got {witnessed}"
    );

    // Every integer on this line is a byte count; the census
    // reads the largest against its floor of 96.
    println!(
        "  zeroization: {witnessed} bytes witnessed across 2 widths, \
         {} surviving. Storage owned by the test; Miri adjudicates the \
         construction in tests/miri.rs.",
        a.surviving_pattern_bytes + b.surviving_pattern_bytes
    );
}

/// The absence of `PartialEq` on `Secret` needs a compile-fail case, not a KAT.
///
/// `secret.rs` states the rule in prose: a derived comparison over key material
/// short-circuits on the first differing byte, so if secrets are ever compared
/// it goes through `subtle::ConstantTimeEq`. Prose is not enforcement — a
/// future `#[derive(PartialEq)]` would be a one-word change that no runtime
/// assertion can see, because the property is that a program *does not compile*.
///
/// # What clears it
///
/// A `ui/fail` case that tries `secret_a == secret_b` and a checked-in
/// `.stderr` naming `PartialEq` and `Secret`. The crate already depends on
/// trybuild and `compile_fail.rs` already registers everything
/// in `ui/fail/*.rs`, so the case is picked up by the existing run the moment
/// it lands; no new harness is owed, only the case and its pinned output.
///
/// # A collision in the anchor below, recorded before anyone trips it
///
/// **`"ConstantTimeEq"` contains `"Eq"`.** The anchor bans four substrings in
/// `secret.rs`'s code, and one of them is a proper substring of the name of the
/// trait this marker's own doc comment recommends. Write
/// `impl ConstantTimeEq for Secret<N>` — the correct fix for a variable-time
/// comparison — and the anchor fires, reporting *"this is the violation"* about
/// the construct that is the violation's remedy.
///
/// `PartialEq` and `ConstantTimeEq` are contrary facts: one is the
/// short-circuiting comparison this marker exists to forbid, the other is the
/// constant-time comparison it exists to steer people toward. A `contains`
/// cannot tell them apart, because the spelling of the second is chosen by the
/// `subtle` crate and not by us. **That is the class** — a source-scanning check
/// satisfied, or here *tripped*, by a needle whose spelling it does not control.
/// The usual remedies do not reach it: the needle here is constructed and the
/// domain is bounded, and neither helps, because the defect is in what the
/// spelling collides with rather than in how it was assembled.
///
/// This was deliberately **not** fixed by loosening the anchor. Discovered in
/// while planning a WOTS+ port whose secret handling the brief required to
/// go through `ConstantTimeEq`; the port turned out to need no comparison on
/// secret material at all, so nothing in the tree was blocked then. Editing an
/// anchor inside the session that would benefit from the edit is
/// indistinguishable from breaking the rule it anchors, and the collision was
/// worth more written down than silently accommodated.
///
/// **The signing path needs one comparison of key material, and that is what
/// makes the anchor's shape matter.**
/// It needs one comparison of key material -- a root or seed
/// against every stored imported root, so that two accounts cannot sit over
/// one key stream -- and `Secret::ct_eq` over
/// `subtle::ConstantTimeEq` is the remedy `secret.rs`'s own doc names. The
/// A substring anchor fires on the word `ConstantTimeEq`, so the
/// anchor below parses `secret.rs` and matches the **item forms that grant
/// comparison** -- a `derive(..)` naming `PartialEq`/`Eq`/`PartialOrd`/`Ord`
/// on any item (inside `cfg_attr` too), or an `impl` of one of those traits
/// for any type -- and nothing else. `impl ConstantTimeEq` and a method named
/// `ct_eq` are not comparison in the forbidden sense and pass.
/// `ui/fail/secret_is_not_partial_ord.rs` joins `secret_is_not_partial_eq.rs`
/// so both operator families are pinned by the compiler, not only by this
/// scan. Fault-injected: `#[derive(PartialEq)]` on `Secret` and a
/// hand-written `impl PartialEq for Secret<N>` each redden this arm naming
/// the form; the `ConstantTimeEq` use in the tree stays green, which is the
/// whole point of the repair.
#[test]
fn secret_has_no_equality_and_nothing_enforces_it() {
    // Anchor with teeth: this is not just "the marker's subject moved", it is
    // the property itself. If a derive or an impl of a comparison trait lands,
    // this fires immediately and says the rule was broken rather than that a
    // test is missing. Parsed, not searched: the trait this marker steers
    // toward, `ConstantTimeEq`, contains `Eq` as a substring (the collision
    // the doc comment records), so the anchor matches the item forms that
    // actually grant comparison.
    const COMPARISON_TRAITS: [&str; 4] = ["PartialEq", "Eq", "PartialOrd", "Ord"];
    let raw = read_crate_file("crates/mochimo-crypto/src/secret.rs");
    let ast = syn::parse_file(&raw).unwrap_or_else(|e| panic!("secret.rs does not parse: {e}"));
    let mut granted: Vec<String> = Vec::new();
    let mut items_seen = 0usize;
    for item in &ast.items {
        items_seen += 1;
        // Derives, including `#[cfg_attr(.., derive(..))]`: the attribute's
        // whole token stream is searched for `derive` followed by a group
        // naming a comparison trait.
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Struct(s) => &s.attrs,
            syn::Item::Enum(e) => &e.attrs,
            syn::Item::Union(u) => &u.attrs,
            syn::Item::Type(t) => &t.attrs,
            _ => &[],
        };
        for a in attrs {
            use quote::ToTokens;
            // Only the attribute forms that can grant a derive: `derive(..)`
            // itself and `cfg_attr(.., derive(..))`. Doc comments are
            // attributes too (`#[doc = ".."]`), and secret.rs's doc names
            // `PartialEq` in the sentence forbidding it -- found by this
            // anchor's first run, which read the prose as a derive.
            if !(a.path().is_ident("derive") || a.path().is_ident("cfg_attr")) {
                continue;
            }
            let text = a.meta.to_token_stream().to_string();
            if text.contains("derive") {
                for t in COMPARISON_TRAITS {
                    // The derive list is a comma-separated group; match the
                    // ident as a whole word so `PartialEq` does not also fire
                    // as `Eq`.
                    let words: Vec<String> = text
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .map(str::to_owned)
                        .collect();
                    if words.iter().any(|w| w == t) {
                        granted.push(format!("derive({t})"));
                    }
                }
            }
        }
        if let syn::Item::Impl(i) = item {
            if let Some((_, path, _)) = &i.trait_ {
                if let Some(last) = path.segments.last() {
                    let name = last.ident.to_string();
                    if COMPARISON_TRAITS.contains(&name.as_str()) {
                        use quote::ToTokens;
                        granted.push(format!("impl {name} for {}", i.self_ty.to_token_stream()));
                    }
                }
            }
        }
    }
    assert!(items_seen >= 3, "secret.rs parsed to {items_seen} items; the walk is not reading the file");
    assert!(
        granted.is_empty(),
        "secret.rs grants comparison: {granted:?}. Comparison over key material is \
         variable-time and short-circuits; secret.rs's own doc comment says so, and it \
         names the remedy -- `subtle::ConstantTimeEq`, which this anchor deliberately \
         does not match. This is the violation, not a missing test."
    );

    let mut owed: Vec<String> = Vec::new();
    const CASE: &str = "secret_is_not_partial_eq";
    let stems = ui_fail_stems();
    if !stems.iter().any(|s| s == CASE) {
        owed.push(format!(
            "\x20 - ui/fail/{CASE}.rs does not exist. The rule currently holds \
             by nobody having broken it, which is indistinguishable from it \
             being enforced right up until someone does. The case must compare \
             two Secrets with `==` and pin a .stderr naming the missing trait."
        ));
    } else if !repo_root()
        .join(format!("crates/mochimo-crypto/ui/fail/{CASE}.stderr"))
        .is_file()
    {
        owed.push(format!(
            "\x20 - ui/fail/{CASE}.rs has no .stderr beside it, so it asserts \
             only that something failed to compile -- a typo in the case would \
             satisfy it just as well as the missing trait."
        ));
    }

    // The third condition, and the one that changes what this marker means.
    //
    // The two above are claims about the FILESYSTEM: a `.rs` and a `.stderr`
    // exist. What that misses was measured by injection: with the case
    // typo'd into a no-op, or its pinned `.stderr` no longer naming
    // `PartialEq`, trybuild goes RED and this marker stayed GREEN. Both are the
    // case decaying into a case that proves nothing, and file existence cannot
    // see either -- it was never the enforcement, only the reminder.
    //
    // What enforces the property is trybuild, and specifically the pinned
    // `.stderr`, because a `compile_fail` case passes on any compilation
    // failure whatsoever. So the marker now keys on that run: the test that
    // registers `ui/fail/*.rs` must itself RUN, PASS, and report how many cases
    // it registered. Under the two fault rows that empty it, it fails, and this marker
    // fails with it. That is the operational fix for a needle a check does not control -- say what
    // enforces the property, and say so where it is read.
    if let Err(why) = census::check(
        "secret_has_no_equality_and_nothing_enforces_it",
        "every_ui_case_compiles_or_fails_for_its_pinned_reason",
    ) {
        owed.push(format!(
            "\x20 - the trybuild run that compiles ui/fail/{CASE}.rs did not run \
             and pass. The case file existing is a claim about the filesystem; \
             this is the claim that the compiler was actually asked, and \
             refused.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "The no-comparison rule on Secret is documented but unenforced.\n{}\n\
         Note that the anchor above is passing: \
         the rule HOLDS today. What is owed is the thing that would notice if \
         it stopped.",
        owed.join("\n")
    );
}

/// No secret may reach a `Debug` output, including through a holder struct.
///
/// `Secret` has a hand-written `Debug` that redacts, and `secret.rs`'s own unit
/// test pins its exact rendering. That covers the type. It does not cover the
/// struct that *holds* one: a `#[derive(Debug)]` on an account, a keypair or a
/// wallet entry would print whatever its fields print, and today it would print
/// `Secret<32>(<redacted>)` only because `Secret`'s manual impl happens to be
/// the one reached. A holder that stores raw `[u8; 32]` beside a `Secret`, or
/// one that derives `Debug` over a field the redaction does not cover, is not
/// visible to any existing check.
///
/// # What supplies its subject
///
/// `src/account.rs` supplies it
/// (`ImportedRoot`, plus the holders around it) and
/// `no_holder_of_key_material_derives_debug` supplied the scan, so the
/// marker is green and renamed in the clearing commit (a discharged marker
/// keeps its useful half) to the claim it now makes.
///
/// # What the green claims, and what it cannot
///
/// The census-checked scan walks `crates/*/src`, closes transitively over
/// holders of `Secret`/`Zeroizing`, rejects derived `Debug`, and asserts it
/// found at least one direct struct holder — so it cannot go vacuous the way
/// a designed red warned. What no scan sees: whether a hand-written `Debug`
/// actually redacts. That half is pinned per type by the
/// `debug_never_reveals_*` unit tests beside each impl.
#[test]
fn secret_holder_debug_redaction_is_enforced_by_the_scan() {
    // Anchor: the redaction this marker extends still exists.
    assert!(
        secret_rs_code().contains("impl<const N: usize> fmt::Debug for Secret<N>"),
        "Secret no longer hand-writes Debug. The holder obligation below is an \
         extension of that redaction; if the base was removed or derived, that \
         is the finding."
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "no_holder_of_key_material_derives_debug";
    // EXECUTION, not existence. Before the census this asked `test_sources()` whether
    // the characters `fn <name>` occur somewhere under `tests/`. That is
    // satisfied by a plain `fn`, by a helper that is not a `#[test]`, and --
    // measured -- by a `#[test]` with an EMPTY BODY. `census::check`
    // runs the named test on its own and reads libtest's own verdict and the
    // measurement the test reported. See the `census` module for what it still
    // cannot see.
    if let Err(why) = census::check("secret_holder_debug_redaction_is_enforced_by_the_scan", PROOF) {
        let owes = format!(
            // Not glob-spelled, and the reason has EXPIRED -- kept as a record,
            // not as a live constraint.
            //
            // A `code_only` that treats a `/` followed by `*` as a
            // block-comment opener wherever it occurs, including inside a
            // string literal, swallows a region belonging to whichever check
            // reads the corpus next -- turning
            // `crosscheck_fields_stay_asserted` and
            // `group_e_constants_stay_anchored` red with failure messages
            // about independence and group E that point nowhere near the cause.
            //
            // The repair: string literals are now emitted
            // verbatim with no comment token inside them interpreted, and
            // `stripper_does_not_open_a_comment_inside_a_string` pins exactly
            // this case. So a glob here would be harmless today. The spelling is
            // left alone because changing it buys nothing, and the paragraph is
            // rewritten because a comment asserting in the present tense that a
            // repaired bug is still live is worse than no comment: the next
            // reader inherits a workaround for a hazard that no longer exists
            // and has no way to tell it expired.
            "\x20 - no test named {PROOF} exists. It must walk every crate's \
             src/ directory, identify structs with a field typed Secret<..> or \
             Zeroizing<..>, and reject a derived Debug on them. It must also \
             assert it found \
             at least one such struct: with none in the tree it would pass over \
             an empty set and read as coverage."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "Debug-leakage enforcement has REGRESSED. Once this red \
         meant a designed absence — no holder existed yet. That \
         state is over: the account model landed src/account.rs's holders and the scan, so \
         this firing now means the scan, the census row, or the holders \
         themselves went away.\n{}\n\
         Do not clear it by \
         weakening the scan's at-least-one clause — that produces the \
         green-over-an-empty-set this marker exists to prevent.",
        owed.join("\n")
    );
}

/// The proof test behind the Debug-holder marker: every holder of key
/// material hand-writes `Debug`, and at least one holder exists to prove the
/// scan is scanning something.
///
/// # The domain, and why it is wider than the marker demands
///
/// The marker's text demands structs with a field typed `Secret<..>` or
/// `Zeroizing<..>`. This scan covers **enums too, and closes transitively**:
/// an item is a holder if any field or variant type mentions `Secret` or
/// `Zeroizing`, or mentions a type already found to be a holder. Direct-only
/// matching would exempt every wrapper — `Account` holds key material through
/// `KeyMaterial` through `ImportedRoot`, and a derived `Debug` at any level
/// prints the whole chain (derive the domain from the artifact; a wrapper is
/// the general defeat for a mention check).
///
/// # What this establishes, and what it cannot
///
/// A derived `Debug` on a holder is rejected; a hand-written one is trusted.
/// Whether a hand-written impl actually redacts is established per type by
/// its own pinned unit test (`secret.rs` and `account.rs`
/// `debug_never_reveals_*`), not here — a scan can see the derive, not the
/// rendering.
#[test]
fn no_holder_of_key_material_derives_debug() {
    use quote::ToTokens;

    // Types permitted to derive Debug while holding key material. Empty, and
    // the unused-entry direction is enforced below: a row naming no holder in
    // the tree is itself a failure, so a stale permission cannot linger
    // (the unsafe allow-list's posture). The first real entry must argue its
    // redaction story here, where its siblings are asserted.
    const ALLOWED_DERIVED_DEBUG_HOLDERS: &[(&str, &str)] = &[];

    let files = crate_source_files();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is vacuous",
        files.len()
    );

    struct Holder {
        file: String,
        name: String,
        field_type_idents: Vec<String>,
        derives_debug: bool,
        is_struct: bool,
    }

    fn ident_tokens(ty: &syn::Type) -> Vec<String> {
        ty.to_token_stream()
            .into_iter()
            .flat_map(|t| match t {
                proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                proc_macro2::TokenTree::Group(g) => g
                    .stream()
                    .into_iter()
                    .filter_map(|t| match t {
                        proc_macro2::TokenTree::Ident(i) => Some(i.to_string()),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            })
            .collect()
    }

    fn attr_derives_debug(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            let idents: Vec<String> = a
                .to_token_stream()
                .into_iter()
                .flat_map(|t| match t {
                    proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                    proc_macro2::TokenTree::Group(g) => g
                        .stream()
                        .into_iter()
                        .flat_map(|t| match t {
                            proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                            proc_macro2::TokenTree::Group(g2) => g2
                                .stream()
                                .into_iter()
                                .filter_map(|t| match t {
                                    proc_macro2::TokenTree::Ident(i) => Some(i.to_string()),
                                    _ => None,
                                })
                                .collect(),
                            _ => vec![],
                        })
                        .collect(),
                    _ => vec![],
                })
                .collect();
            // Matches #[derive(.., Debug, ..)] and
            // #[cfg_attr(.., derive(.., Debug, ..))]. Over-matching an
            // attribute that merely names both idents fails red, which is the
            // safe direction.
            idents.iter().any(|i| i == "derive") && idents.iter().any(|i| i == "Debug")
        })
    }

    let mut items: Vec<Holder> = Vec::new();
    for (name, text) in &files {
        let parsed = syn::parse_file(text)
            .unwrap_or_else(|e| panic!("{name} does not parse as Rust: {e}"));
        let mut stack: Vec<&syn::Item> = parsed.items.iter().collect();
        while let Some(item) = stack.pop() {
            match item {
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        stack.extend(inner.iter());
                    }
                }
                syn::Item::Struct(s) => {
                    let mut idents = Vec::new();
                    for f in &s.fields {
                        idents.extend(ident_tokens(&f.ty));
                    }
                    items.push(Holder {
                        file: name.clone(),
                        name: s.ident.to_string(),
                        field_type_idents: idents,
                        derives_debug: attr_derives_debug(&s.attrs),
                        is_struct: true,
                    });
                }
                syn::Item::Enum(e) => {
                    let mut idents = Vec::new();
                    for v in &e.variants {
                        for f in &v.fields {
                            idents.extend(ident_tokens(&f.ty));
                        }
                    }
                    items.push(Holder {
                        file: name.clone(),
                        name: e.ident.to_string(),
                        field_type_idents: idents,
                        derives_debug: attr_derives_debug(&e.attrs),
                        is_struct: false,
                    });
                }
                _ => {}
            }
        }
    }

    // Transitive taint closure, seeded on the two key-material types.
    let mut tainted: BTreeSet<String> =
        ["Secret".to_string(), "Zeroizing".to_string()].into();
    let direct: BTreeSet<String> = items
        .iter()
        .filter(|i| i.field_type_idents.iter().any(|t| tainted.contains(t)))
        .map(|i| i.name.clone())
        .collect();
    loop {
        let before = tainted.len();
        for item in &items {
            if item.field_type_idents.iter().any(|t| tainted.contains(t)) {
                tainted.insert(item.name.clone());
            }
        }
        if tainted.len() == before {
            break;
        }
    }

    let holders: Vec<&Holder> = items.iter().filter(|i| tainted.contains(&i.name)).collect();
    let direct_structs = holders
        .iter()
        .filter(|h| h.is_struct && direct.contains(&h.name))
        .count();
    assert!(
        direct_structs >= 1,
        "the scan found no struct holding Secret<..> or Zeroizing<..> under \
         crates/*/src. With nothing to scan this test passes over an empty \
         set, which is the vacuity the marker forbids clearing through \
         ; if the holders were renamed or moved, re-derive the \
         taint seed before trusting any green here."
    );

    let violations: Vec<String> = holders
        .iter()
        .filter(|h| h.derives_debug)
        .filter(|h| {
            !ALLOWED_DERIVED_DEBUG_HOLDERS
                .iter()
                .any(|(allowed, _)| allowed == &h.name)
        })
        .map(|h| format!("  - {} in {}", h.name, h.file))
        .collect();
    assert!(
        violations.is_empty(),
        "these types hold key material (directly or through another holder) \
         and derive Debug, which is how a root reaches a log file \
         (docs/specification.md I6):\n{}\n\
         Hand-write the impl and pin its rendering with a unit test, the way \
         secret.rs and account.rs do.",
        violations.join("\n")
    );
    let unused: Vec<&str> = ALLOWED_DERIVED_DEBUG_HOLDERS
        .iter()
        .filter(|(allowed, _)| !holders.iter().any(|h| &h.name == allowed))
        .map(|(allowed, _)| *allowed)
        .collect();
    assert!(
        unused.is_empty(),
        "these allow-list rows name no holder in the tree: {unused:?}. An \
         unused permission is a hole waiting for an occupant; remove the row."
    );

    // Every integer below is a holder count (the census floor
    // reads the largest integer after the needle; the file floor above is an
    // assert, not a print, for exactly that reason).
    println!(
        "  Debug-holder scan: {} holder(s) of key material ({} direct \
         struct(s)), 0 derived Debug",
        holders.len(),
        direct_structs
    );
}

/// I6's fourth guarantee, and the last one that was per-site convention:
/// key material that leaves a `Secret` or a `Zeroizing` does not land in a
/// buffer nothing scrubs.
///
/// # Why a scan and not a type
///
/// The other three guarantees are held by something that is not a person.
/// `Debug` redaction by the holder scan beside this one; the absent
/// `PartialEq` and `PartialOrd` by `ui/fail` cases the compiler adjudicates;
/// the clearing itself by a `MaybeUninit` witness read under Miri. The fourth
/// cannot be spelled as a type, because `[u8; 32]` is the same type whether
/// the bytes are a seed or a block hash. No signature separates them and no
/// trait bound refuses the copy, so what is left is to watch the one place
/// the bytes get out.
#[test]
fn key_material_copies_are_enforced_by_the_scan() {
    // Anchor: the chokepoint the scan reads still exists. `expose` is the only
    // way to a `Secret`'s bytes, and it is a named method for that reason --
    // if it were renamed or widened, the scan below would walk a tree with
    // nothing in it and report coverage.
    assert!(
        secret_rs_code().contains("pub fn expose(&self)"),
        "Secret no longer exposes its bytes through `expose`. The scan below \
         keys on that name as the one route out of a Secret; if the route was \
         renamed or a second one was added, the scan is measuring a chokepoint \
         that is no longer the chokepoint."
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "no_key_material_is_copied_into_an_unprotected_buffer";
    if let Err(why) = census::check("key_material_copies_are_enforced_by_the_scan", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It must walk every crate's \
             src/ directory and reject an owning copy taken from a `Secret` \
             through `expose`, or from a binding known to be `Zeroizing`, \
             into a buffer that is neither. It must also report how many \
             `expose` sites it examined: with none it would pass over an \
             empty set and read as coverage.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "the zeroization scan has REGRESSED. The property it holds is the one \
         guarantee of the four that no compiler and no interpreter can reach, \
         so its absence is not a smaller gap than the others -- it is the only \
         one where nothing else is watching.\n{}",
        owed.join("\n")
    );
}

/// The proof behind the copy marker: no owning copy of key material lands in
/// an unprotected buffer, and the scan reports the population it examined.
///
/// # The two shapes, and why these two
///
/// **Out of a `Secret`, through `expose`.** `Secret` has no `Display`, no
/// `AsRef` and no way to read its bytes but the named method, which is the
/// type's whole convention. So `s.expose().to_vec()` is the complete
/// vocabulary for getting an owned copy out of one, and `let b = *s.expose()`
/// is the same thing spelled as a deref of the fixed-width array.
///
/// **Out of a `Zeroizing` binding.** `Zeroizing<T>` derefs to `T`, so a local
/// annotated or constructed as one hands out `to_vec`, `to_owned`, `clone`
/// and `to_string` on the inner value without any named step at all. Those
/// bindings are tracked per function body and the same conversions rejected
/// on them.
///
/// A copy is accepted when it is placed straight into a `Zeroizing` or a
/// `Secret` -- syntactically inside `Zeroizing::new(..)` or a `Secret::..`
/// call, or the initializer of a `let` annotated with either. That is the
/// correct spelling, and it is what the tree already does at every site.
///
/// # What this establishes, and what it does not
///
/// Stated because a scan that is trusted past its reach is worse than none.
///
/// * It reads **`crates/*/src` only**, which is where the wallet lives.
///   `tests/` is not walked, so a test that copies a seed into a bare `Vec`
///   is not caught here.
/// * It is **syntactic, not a dataflow analysis**. Key material passed
///   through a function and copied on the far side is invisible to it: the
///   receiver there is a parameter, and nothing in the signature says the
///   bytes are a secret.
/// * It knows key material by **`Secret` and `Zeroizing` alone**. A buffer
///   filled straight from an entropy source without passing through either is
///   outside its domain -- the tree has no such site today, because
///   `os_bytes` and `os_create_entropy` both return `Zeroizing`, and that is
///   a property of those two functions rather than anything asserted here.
/// * It tracks a `Zeroizing` binding by the **name bound in that function
///   body**. A secret moved into a field, a tuple or a closure capture and
///   copied from there is not followed.
/// * **It does not see inside a macro invocation**, and this one is measured
///   rather than suspected. `syn` parses a macro body as an opaque token
///   stream, so nothing within `assert_eq!`, `assert!`, `matches!` or
///   `format!` is walked. Of the 21 `expose` calls a text search finds under
///   `crates/*/src`, this walk reaches 15; the six it cannot are in exactly
///   those four macros. Five are in `cfg(test)` modules and the sixth is
///   `cli/create.rs`'s deliberate rendering of the phrase to the terminal,
///   so the blind spot hides nothing today -- but a copy written inside an
///   `assert_eq!` would not be reported, and that is the shape to watch.
///
/// What it does catch is the shape that actually appears when someone reaches
/// for the bytes: a named `expose`, or a local everybody can see is a
/// `Zeroizing`, followed by the conversion that copies.
#[test]
fn no_key_material_is_copied_into_an_unprotected_buffer() {
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    // Functions permitted to take an unprotected copy. Empty, and the
    // unused-entry direction is enforced below: a row naming a function the
    // scan finds nothing in is itself a failure, so a stale permission cannot
    // linger. The first real entry argues here why its copy is not key
    // material, or why it cannot be a `Zeroizing`.
    const ALLOWED_UNPROTECTED_COPIES: &[(&str, &str)] = &[];

    // The conversions that take a borrow and return a value owning a copy of
    // the bytes. `to_string` is here for `Phrase`, which is a
    // `Zeroizing<String>`: a copy of one is a recovery phrase in a plain
    // `String`, which is the worst of the four to leave lying around.
    const OWNING: &[&str] = &["to_vec", "to_owned", "clone", "to_string"];

    let files = crate_source_files();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is vacuous",
        files.len()
    );

    fn mentions_protector(ty: &syn::Type) -> bool {
        use quote::ToTokens;
        ty.to_token_stream()
            .into_iter()
            .any(|t| matches!(&t, proc_macro2::TokenTree::Ident(i) if i == "Zeroizing" || i == "Secret"))
    }

    fn is_expose(e: &syn::Expr) -> bool {
        matches!(e, syn::Expr::MethodCall(m) if m.method == "expose" && m.args.is_empty())
    }

    // `Zeroizing::new(..)`, `Secret::new(..)`, and the qualified spellings of
    // both. A path naming either type is enough: every constructor of either
    // returns the protecting wrapper, so there is no arm that names one and
    // hands back bare bytes.
    fn is_protecting_call(f: &syn::Expr) -> bool {
        matches!(f, syn::Expr::Path(p)
            if p.path.segments.iter().any(|s| s.ident == "Zeroizing" || s.ident == "Secret"))
    }

    fn bare_ident(e: &syn::Expr) -> Option<String> {
        match e {
            syn::Expr::Path(p) if p.qself.is_none() => p.path.get_ident().map(|i| i.to_string()),
            _ => None,
        }
    }

    fn bound_name(p: &syn::Pat) -> Option<String> {
        match p {
            syn::Pat::Ident(i) => Some(i.ident.to_string()),
            syn::Pat::Type(t) => bound_name(&t.pat),
            _ => None,
        }
    }

    struct Scan {
        file: String,
        in_fn: String,
        protected: usize,
        tracked: std::collections::BTreeSet<String>,
        expose_sites: usize,
        protected_bindings: usize,
        candidates: Vec<(String, String)>,
    }

    impl Scan {
        fn scoped<F: FnOnce(&mut Self)>(&mut self, name: String, f: F) {
            let outer_tracked = std::mem::take(&mut self.tracked);
            let outer_fn = std::mem::replace(&mut self.in_fn, name);
            f(self);
            self.tracked = outer_tracked;
            self.in_fn = outer_fn;
        }
        fn flag(&mut self, line: usize, what: &str) {
            let site = format!("\x20 - {}:{} in `{}`: {}", self.file, line, self.in_fn, what);
            self.candidates.push((self.in_fn.clone(), site));
        }
    }

    impl<'ast> Visit<'ast> for Scan {
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_item_fn(s, f));
        }
        fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_impl_item_fn(s, f));
        }
        fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_trait_item_fn(s, f));
        }

        fn visit_local(&mut self, l: &'ast syn::Local) {
            let annotated = matches!(&l.pat, syn::Pat::Type(t) if mentions_protector(&t.ty));
            let constructed = l.init.as_ref().is_some_and(|i| match &*i.expr {
                syn::Expr::Call(c) => is_protecting_call(&c.func),
                _ => false,
            });
            if annotated || constructed {
                if let Some(n) = bound_name(&l.pat) {
                    self.tracked.insert(n);
                }
                self.protected_bindings += 1;
            } else if let Some(i) = &l.init {
                // `let b = *s.expose();` -- the fixed-width array is `Copy`, so
                // the deref is a copy of every byte into a bare array.
                if let syn::Expr::Unary(u) = &*i.expr {
                    if matches!(u.op, syn::UnOp::Deref(_)) && is_expose(&u.expr) {
                        let line = i.expr.span().start().line;
                        self.flag(line, "a deref copy of `expose()` into an unprotected binding");
                    }
                }
            }
            if annotated {
                self.protected += 1;
                visit::visit_local(self, l);
                self.protected -= 1;
            } else {
                visit::visit_local(self, l);
            }
        }

        fn visit_expr(&mut self, e: &'ast syn::Expr) {
            match e {
                syn::Expr::Call(c) if is_protecting_call(&c.func) => {
                    self.protected += 1;
                    visit::visit_expr(self, e);
                    self.protected -= 1;
                    return;
                }
                syn::Expr::MethodCall(m) if m.method == "expose" && m.args.is_empty() => {
                    self.expose_sites += 1;
                }
                syn::Expr::MethodCall(m)
                    if OWNING.iter().any(|o| m.method == o) && m.args.is_empty() =>
                {
                    let from_expose = is_expose(&m.receiver);
                    let from_tracked =
                        bare_ident(&m.receiver).is_some_and(|n| self.tracked.contains(&n));
                    if self.protected == 0 && (from_expose || from_tracked) {
                        let line = m.span().start().line;
                        let src = if from_expose { "`expose()`" } else { "a `Zeroizing` binding" };
                        let what = format!("`.{}()` takes an owning copy from {src}", m.method);
                        self.flag(line, &what);
                    }
                }
                _ => {}
            }
            visit::visit_expr(self, e);
        }
    }

    let mut expose_sites = 0usize;
    let mut protected_bindings = 0usize;
    let mut candidates: Vec<(String, String)> = Vec::new();
    for (name, text) in &files {
        let parsed =
            syn::parse_file(text).unwrap_or_else(|e| panic!("{name} does not parse as Rust: {e}"));
        let mut scan = Scan {
            file: name.clone(),
            in_fn: "<item scope>".to_string(),
            protected: 0,
            tracked: std::collections::BTreeSet::new(),
            expose_sites: 0,
            protected_bindings: 0,
            candidates: Vec::new(),
        };
        scan.visit_file(&parsed);
        expose_sites += scan.expose_sites;
        protected_bindings += scan.protected_bindings;
        candidates.extend(scan.candidates);
    }

    // Vacuity, both halves. A scan that found no chokepoint and no protected
    // binding has nothing to be right about, and would report zero violations
    // over an empty set exactly as it does over a clean one.
    assert!(
        expose_sites >= 8,
        "the scan found {expose_sites} `expose()` call site(s) under crates/*/src; \
         this walk sees 15. Under the floor the zero below is not a finding \
         about the tree, it is a finding about the scan -- `expose` renamed, or \
         the walk pointed somewhere else. (A text search finds 21. The six it \
         finds and this does not are each inside a macro invocation, which is \
         the bound the doc above states rather than a miscount here.)"
    );
    assert!(
        protected_bindings >= 5,
        "the scan tracked {protected_bindings} protected binding(s); this tree \
         carries more. The `Zeroizing` half of the scan is reporting about \
         nothing."
    );

    let violations: Vec<String> = candidates
        .iter()
        .filter(|(f, _)| !ALLOWED_UNPROTECTED_COPIES.iter().any(|(a, _)| a == f))
        .map(|(_, site)| site.clone())
        .collect();
    assert!(
        violations.is_empty(),
        "key material is copied into a buffer that is never scrubbed \
         (docs/specification.md I6):\n{}\n\
         Put the copy in a `Zeroizing` -- `Zeroizing::new(x.expose().to_vec())` \
         -- or keep the borrow and drop the copy. A bare `Vec` or array holding \
         a seed is returned to the allocator with the bytes still in it.",
        violations.join("\n")
    );
    let unused: Vec<&str> = ALLOWED_UNPROTECTED_COPIES
        .iter()
        .filter(|(a, _)| !candidates.iter().any(|(f, _)| f == a))
        .map(|(a, _)| *a)
        .collect();
    assert!(
        unused.is_empty(),
        "these allow-list rows name a function the scan finds no copy in: \
         {unused:?}. An unused permission is a hole waiting for an occupant; \
         remove the row."
    );

    // Both integers are population counts, which is what the census floor
    // reads. Nothing else is printed here for that reason -- see `Row::floor`.
    println!(
        "  key-material copy scan: {expose_sites} expose() call site(s) and \
         {protected_bindings} protected binding(s) examined, 0 unprotected copies"
    );
}

/// Memory-safety is established for the native paths Miri walks, and no further.
///
/// # Why equivalence is not the property
///
/// The C reads fixed-size buffers through raw pointers, so
/// an over-read runs into adjacent memory and returns a wrong answer or nothing
/// observable; the Rust port indexes slices, where the same bug panics. Feeding
/// both a malformed input and comparing outputs cannot decide it — the two
/// failure modes are not the same kind of thing. No volume of differential
/// testing reaches the property, which is why it was a marker and not a test.
///
/// Cleared. Renamed rather than deleted: the useful half is
/// the domain derivation below, which acquires new obligations on its own, and
/// a marker deleted on the day it passes takes that with it.
///
/// # What is actually claimed now, and what is not
///
/// **Claimed:** the functions `tests/miri.rs::MIRI_DOMAIN` marks covered execute
/// under Miri without it reporting undefined behaviour.
///
/// **Not claimed:** that this crate is memory-safe. A green Miri run reads as
/// the second sentence and means the first, and with `crate::base58`, two thirds
/// of `crate::bytes`, `addr::sha3`, the whole transaction surface and the three
/// diagnostic-string functions panicking on entry in the only configuration Miri
/// can run, those are different claims. This test's name carries the
/// qualification so it cannot be quoted without it — the domain rule applied to a
/// tool's output rather than a check's input.
///
/// # What makes the domain complete
///
/// Every `pub fn` defined in `src/backend/native.rs` has a row in
/// `MIRI_DOMAIN`, covered or excluded with a reason. The left side of that comparison is parsed out of the backend
/// itself, so a function added there is undeclared — and this test red — until
/// someone decides its Miri status. Nothing expands the backend without
/// expanding the domain.
///
/// The split of labour is deliberate and the halves are in different files. Here
/// the question is *is every function declared*; in `miri.rs` it is *does every
/// function declared covered actually run*, asserted at runtime as a set
/// equality against what the walk recorded. That second one would be a
/// self-comparison on its own, since the table and the calls share a file, which
/// is why it is not on its own.
///
/// # What enforces it, said plainly
///
/// **Nothing in `cargo test` runs Miri.** This test asserts that the harness
/// exists and that its domain is complete; the run is
///
/// ```sh
/// cargo +nightly miri test -p mochimo-crypto
/// ```
///
/// and it is a step someone takes, recorded in `AGENT.md`. The rule is
/// about mechanisms that read as enforcement while something else does the
/// enforcing, so the distinction is stated rather than left to be inferred from
/// a green tick.
#[test]
fn memory_safety_is_established_only_for_the_native_paths_miri_walks() {
    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "native_backend_is_clean_under_miri";
    // EXECUTION, not existence. Before the census this asked `test_sources()` whether
    // the characters `fn <name>` occur somewhere under `tests/`. That is
    // satisfied by a plain `fn`, by a helper that is not a `#[test]`, and --
    // measured -- by a `#[test]` with an EMPTY BODY. `census::check`
    // runs the named test on its own and reads libtest's own verdict and the
    // measurement the test reported. See the `census` module for what it still
    // cannot see.
    if let Err(why) = census::check("memory_safety_is_established_only_for_the_native_paths_miri_walks", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It must exercise the native \
             primitives under `cfg(miri)` with the ffi backend's feature \
             switched off, since Miri cannot execute the linked C. Running the \
             existing KATs under Miri unchanged would fail on the ffi calls and \
             say nothing about the port."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    // The domain, derived from the backend rather than from the table.
    let harness = read_crate_file("crates/mochimo-crypto/tests/miri.rs");
    // Whitespace removed before matching. A `MIRI_DOMAIN` row is written on one
    // line when it is short and across four when its reason is long, and a
    // needle that only saw the first form reported nine present rows as missing
    // the first time this ran. The needle stays anchored on `("` and terminated
    // by `",` — constructed, not written — and it is the *layout* that is normalised away, not
    // either end of the match.
    let declared: String = code_only(&harness)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut undeclared: Vec<String> = Vec::new();
    let mut surface = 0usize;
    // `backend/native.rs`, the one backend module.
    for file in ["backend/native.rs"] {
        let text = read_crate_file(&format!("crates/mochimo-crypto/src/{file}"));
        // Raw text, not `code_only`'s output: syn handles comments itself, and
        // feeding it stripped source would put this domain back behind the
        // stripper -- including the raw-string defect deferred to its own
        // session.
        for name in public_fn_names(&text) {
            surface += 1;
            // Constructed and terminated: the row's opening tuple, not the bare
            // name, which would match the function's own mention anywhere.
            if !declared.contains(&format!("(\"{name}\",")) {
                undeclared.push(format!(
                    "\x20 - {file}::{name} has no row in tests/miri.rs::MIRI_DOMAIN. \
                     Every backend function is either walked under Miri or \
                     excluded with a reason; there is no third state."
                ));
            }
        }
    }
    assert!(
        surface >= 30,
        "parsed only {surface} public functions out of the native backend \
         module; this tree's `backend/native.rs` declares 41 bare-`pub` \
         functions at item level, and this floor sits above two thirds of that \
         rather than at it -- the measurement moved by nothing across this \
         re-derivation, and a floor is not lowered to meet a rule. The walk \
         that derives this domain is broken, and every name it failed to see \
         would have read as declared."
    );
    owed.extend(undeclared);

    assert!(
        owed.is_empty(),
        "Miri's domain over the native backend is incomplete.\n{}\n\
         {surface} public backend functions were parsed.",
        owed.join("\n")
    );
}

/// The little-endian decision, enforced for the first time.
///
/// # THIS CHECK IS THE ONLY ENFORCEMENT OF ITS PROPERTY
///
/// Read this before touching the needle, the walk, or the forbidden set.
///
/// Nothing else in the tree can see a native-endian conversion **on this host**.
/// Any test that compares `put32`'s output to a recorded value stays green
/// under a `to_ne_bytes` injection, because on a little-endian host
/// `to_le_bytes` and `to_ne_bytes` compile to the same thing. That is measured
/// rather than assumed, and it is why this check reads the source instead of
/// comparing outputs.
///
/// The generator calls `put32` and `group_d_tx.json` records the bytes as
/// `identity.adrs_tail12`, so `put32` has the C8-shaped anchor and lacks the
/// CX-C9-shaped one, so a `to_be_bytes` port is caught by a fixture and a
/// `to_ne_bytes` port is caught **only here**. Narrowed, not retired — and this
/// check is still the sole enforcement for `get32`, which no fixture records at
/// all, and for byte order written out by hand in any spelling.
///
/// So a defect here is not caught downstream, because there is no downstream.
/// This check had one within an hour of being written: its first needle required
/// a leading dot and could not see `u32::from_ne_bytes(*bytes)`, the idiomatic
/// spelling of the very function it protects. Nothing about writing
/// it felt different from writing any other source scan, which is the point —
/// the fact that made it critical lived in another file.
///
/// # The rule, and why it needs a check at all
///
/// The decision settles the host-endianness question for all three sites it found
/// — the `adrs` conversion, `put16`, and SHA3's state read — and stated the
/// consequence in bold: **"No `from_ne_bytes` or `to_ne_bytes` anywhere in the
/// crate."** That was a decision in a document. Nothing asserted it, and a
/// decision nothing asserts is a decision the next `to_ne_bytes` does not meet.
///
/// The gap was found while adding `put32`, which is exactly the site where it
/// would have mattered: the differential against `ffi::put32` is *structurally
/// unable* to tell the two apart on a little-endian host, so a `to_ne_bytes`
/// there would have shipped green. The rule is to say which mechanism
/// actually enforces a property. Until this test, the honest answer for the
/// decision was "nobody".
///
/// # Why the needle can be a literal here
///
/// Needles are constructed rather than written, because a needle
/// written literally into a check can be satisfied by the check's own comments.
/// This scan reads a **token stream**, in which a doc comment is a `#[doc =
/// "…"]` attribute carrying a string *literal* and a `//` comment is not there
/// at all — so a mention in this file's prose is not an `Ident` and cannot
/// satisfy anything. The paragraph above deliberately spells both names out to
/// prove it. That is stronger than comment-stripping, which leaves a name
/// inside a string literal able to match.
///
/// # Two needles have been wrong here, and injection said so both times
///
/// The first was `format!(".{needle}(")` — anchored on a leading dot, on the
/// reasoning that a method call is how these are written. `u32::from_ne_bytes(
/// *bytes)` is a path call, matches no dot, and is *the* idiomatic spelling for
/// exactly the function this scan was written to protect. Injecting it left the
/// scan **green**.
///
/// The second was its replacement, `format!("{needle}(")` over comment-stripped
/// text. It required the `(` to be the very next byte, so **three classes go
/// unseen**, all three measured by execution
/// with the raw-string repair rather than reasoned about:
///
/// | injected | old needle | now |
/// | --- | --- | --- |
/// | `x.to_ne_bytes ()` — one space before the paren | green | RED |
/// | `xs.map(u32::to_ne_bytes)` — not in call position at all | green | RED |
/// | `#[cfg(target_endian = "big")]` — a per-host pair | green | RED |
///
/// The third is not a parsing miss and it is worth separating: `target_endian`
/// was simply **not in the forbidden set**. The decision is to
/// *normalize*, and a `cfg(target_endian)` pair is the most direct possible way
/// to reproduce the reference's host dependence instead — the violation the
/// decision is about, spelled without either forbidden identifier.
///
/// # Why this became a token walk and `code_only` is no longer in the path
///
/// All three classes are the same defect: approximating Rust's grammar with
/// string operations. `proc_macro2` lexes it instead, which is not a better
/// needle but a different kind of mechanism — spacing is not representable in a
/// token stream, an `Ident` is an `Ident` wherever it stands, and `Ident` and
/// `Literal` are different things, so `"to_ne_bytes"` in a string cannot match
/// while `to_ne_bytes` in any position does.
///
/// It also takes this check off `strip_comments`, which is the point about
/// sole enforcement: `code_only` had four demonstrated defects
/// including one that silently deleted code, and the one check standing alone
/// behind a load-bearing property should not be reading through it. This scan
/// is now insensitive to whether its input was stripped at all.
///
/// The cost is stated rather than discovered later: `proc_macro2` must lex every
/// file, so a file that does not lex is a hard failure here. That is
/// deliberate — skipping it would silently shrink the domain — and it is a real
/// dependency on the crate's sources being syntactically valid Rust, which they
/// are because they compile.
///
/// # What this still cannot see — read before relying on it
///
/// The three classes above are closed. The residue is **unchanged**, and it is
/// what makes this a named thin spot rather than a solved problem: the check
/// matches identifiers, so it sees a violation only when the violation is
/// spelled with one of the three names it knows. It does not see:
///
/// * `core::mem::transmute::<[u8; 4], u32>(..)`;
/// * byte-order arithmetic written by hand — `(b[3] as u32) << 24 | ..` is
///   big-endian and contains no forbidden name;
/// * a cast through `bytemuck`, `zerocopy`, a union, or a raw pointer;
/// * anything reached through a rename, a type alias, or a helper wrapping the
///   call in another crate.
///
/// None of those is hypothetical-but-unlikely: hand-written byte assembly is how
/// the *reference* does this, so it is the first thing a porter reaches for.
/// **Stated in the specification's standing properties** rather than left to
/// be discovered, because a scan that reads as "endianness is enforced" while
/// covering three names is precisely a needle the check does not control.
///
/// # This check is the sole enforcement of the little-endian decision
///
/// Stated here, because
/// sources do not get read at the moment somebody is editing a needle and the
/// check's own doc comment is where they are looking. A differential
/// against the FFI **cannot** catch a native-endian conversion: on a
/// little-endian host `to_le_bytes` and `to_ne_bytes` compile to the same
/// instruction, so 100,000 cases pass either way. `native_put32_matches_the_
/// recorded_generator_bytes` narrowed that for one function — it
/// catches a `to_be_bytes` on any host — and left the `to_ne_bytes` case, and
/// `get32`, and hand-written assembly, here and nowhere else.
#[test]
fn no_native_endian_conversions_anywhere_in_the_crate() {
    // `target_endian` joins the two `core` names. The
    // first two are conversions; this one is the `cfg` that selects between two
    // of them per host, which reproduces the reference's host dependence
    // without spelling either.
    const FORBIDDEN: [&str; 3] = ["from_ne_bytes", "to_ne_bytes", "target_endian"];

    fn idents(stream: proc_macro2::TokenStream, out: &mut Vec<proc_macro2::Ident>) {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(id) => out.push(id),
                proc_macro2::TokenTree::Group(g) => idents(g.stream(), out),
                // Punct and Literal cannot be an identifier, and a Literal
                // holding one of these names as text is exactly the false
                // positive a text search would have taken.
                _ => {}
            }
        }
    }

    let mut found: Vec<String> = Vec::new();
    let mut per_file: Vec<(String, usize)> = Vec::new();
    let mut examined = 0usize;
    for (name, text) in crate_source_files() {
        // Fail closed. Skipping a file that will not lex would shrink the
        // domain of the one mechanism standing behind this property, and it
        // would do it silently -- which is the shape this whole file is about.
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This scan is the sole \
                 enforcement of the little-endian decision and it examines tokens, so a file it \
                 cannot read is a file nothing checks. It is not skipped."
            )
        });
        let mut ids = Vec::new();
        idents(stream, &mut ids);
        examined += ids.len();
        per_file.push((name.clone(), ids.len()));
        for id in ids {
            let spelled = id.to_string();
            if FORBIDDEN.contains(&spelled.as_str()) {
                let at = id.span().start();
                found.push(format!("\x20 - {name}:{} names `{spelled}`", at.line));
            }
        }
    }

    // The floor counts identifiers EXAMINED, not files walked or bytes read.
    // A floor over a population the check does not inspect can rise
    // as the blind spot grows. The predecessor asserted `bytes > 50_000` of
    // comment-stripped text while the needle inspected only byte runs ending in
    // `(`, so every byte the needle could not reach still counted toward its
    // confidence. These are the same set now: one increment per token compared.
    let breakdown = per_file
        .iter()
        .map(|(n, c)| format!("\x20 - {c:>5}  {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let empty: Vec<&str> = per_file
        .iter()
        .filter(|(_, c)| *c == 0)
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        empty.is_empty(),
        "these file(s) lexed to zero identifiers: {empty:?}. A .rs file that \
         yields no identifier was not read; the total floor below cannot see \
         one file going empty among fifteen, which is the population question \
         the census's own question applied per member."
    );
    assert!(
        per_file.len() >= 25 && examined >= 24_400,
        "the walk saw {} file(s) and compared {examined} identifier(s):\n{breakdown}\n\
         Both are far below the tree's real size, so this is the walk or the \
         lexer failing, not the crate being clean -- and a search over nothing \
         finds nothing, which is also what a compliant crate looks like.\n\
         \n\
         This tree measures 36,640 identifiers across 38 files, and both floors \
         are two thirds of that. Two thirds also settles the single-file \
         question the old floor argued separately: the largest file here is \
         `keystore/format.rs` at 4,873 identifiers, an eighth of the total, so \
         no walk that found one file can reach this floor. Re-derive both if \
         the tree grows; do not lower either to make a run pass.",
        per_file.len()
    );

    assert!(
        found.is_empty(),
        "native-endian conversions are forbidden by decision and these were \
         found:\n{}\n\
         \n\
         The decision was to NORMALIZE, not to reproduce the reference's host \
         dependence: `from_le_bytes`/`to_le_bytes`, everywhere, so the wallet \
         is byte-identical on every host rather than bug-compatible on the one \
         it was built on. Big-endian serialisation is retained only inside \
         `addr_to_bytes`, where the reference put it explicitly.\n\
         \n\
         Read `backend::native::put16`'s doc before changing this. In particular: a differential \
         against the FFI CANNOT catch a native-endian conversion, because on a \
         little-endian host the two produce identical bytes. This scan is the \
         only mechanism that can.",
        found.join("\n")
    );

    println!(
        "  endianness scan: {} files, {examined} identifiers \
         compared against {} forbidden name(s), 0 native-endian conversions",
        per_file.len(),
        FORBIDDEN.len()
    );
}

/// Every construct in `crates/*/src` that can end execution — panic-family
/// macros, `.unwrap()`/`.expect()`, `handle_alloc_error` — declared here with
/// the reason it stays, so the panic surface cannot grow silently.
///
/// Each row is `(file, construct, count, reason)`. The reason column is the
/// decision record: the hardening pass classified every site by execution (all four seam
/// `assert!`s fire in release too — they are `assert!`, not `debug_assert!`)
/// and decided which stay. A construct found but not declared fails naming the
/// site; a declared row the walk cannot find fails naming the row — the second
/// direction is what makes the table itself the vacuity guard, since a broken
/// walk reports every row missing rather than passing over nothing.
const DECLARED_PANIC_SITES: &[(&str, &str, usize, &str)] = &[
    (
        "crates/mochimo-crypto/src/backend/native.rs",
        "assert!",
        3,
        "ull_to_bytes's empty-out guard and base_w's geometry guard: contract \
         guards on the caller's own buffer geometry -- no path from network or \
         disk bytes chooses these lengths, so a failure here is a caller \
         defect and never an input, and a Result would put a branch at every \
         call site for a condition no input can reach. The \
         third is the `const _` width assertion over the chunked chain loops: \
         const-evaluated, so it fails a build and can never fail a run. It is \
         counted here rather than parsed around, because a construct the \
         census cannot see is one nobody is told about.",
    ),
    (
        "crates/mochimo-crypto/src/backend/native.rs",
        "assert_eq!",
        1,
        "expand_seed_into's out.len() == PK_LEN, a private helper whose three \
         callers all pass constant-sized buffers; it fires only on constant \
         drift.",
    ),
    (
        "crates/mochimo-crypto/src/error.rs",
        "unimplemented!",
        3,
        "the three diagnostic-string functions (ve2str, errno_name, \
         errno_text), knowledge not debt -- see DECLARED_UNIMPLEMENTED. \
         Counted by unimplemented_sites_are_declared_with_a_reason \
         too; this census sees the same three through a different instrument.",
    ),
    (
        "crates/mochimo-crypto/src/secret.rs",
        "assert!",
        1,
        "inside the #[cfg(test)] unit-test module. Test-only; kept in the \
         census rather than parsed around, because a skip is a blind spot and \
         a row is visible.",
    ),
    (
        "crates/mochimo-crypto/src/secret.rs",
        "assert_eq!",
        1,
        "same #[cfg(test)] module.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        ".expect()",
        4,
        "inside the #[cfg(test)] unit-test module: unwrapping \
         `Account::import` on `F-address-widths`' recorded pair, which the \
         constructor verifies, and `restore_from_record` on records this \
         module just built. Test-only; kept in the census rather than parsed \
         around, same reasoning as secret.rs's rows. The account module's \
         NON-test code still contains no panicking construct at all -- \
         `import` and `restore_from_record` return Result rather than \
         asserting the pair, which is the whole shape of format v2.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert!",
        3,
        "inside the #[cfg(test)] unit-test module (the Debug-redaction \
         negative-containment checks, and format v2's control that an untouched \
         imported record still restores). Test-only; kept in the census \
         rather than parsed around, same reasoning as secret.rs's rows.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert_eq!",
        36,
        "same #[cfg(test)] module: pinned Debug renderings, advance \
         monotonicity, receipt binding, the in-module record round-trip, \
          the ten edge assertions of the shipped-index mapping, and \
          the import verification's two refusals, the aliasing case's \
         stream equality and the restore refusals; plus the two of the \
         ceiling test: the whole Range the refusal at \
         u32::MAX carries, and the position below it advancing to it.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert_ne!",
        1,
        "same #[cfg(test)] module: a first address built from junk \
         components yields a DIFFERENT tag over the same key stream -- the \
         one assertion that says why a verifying import does not close the \
         aliasing.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "panic!",
        3,
        "same #[cfg(test)] module: the two wrong-variant arms of the \
         round-trip test, where the test must fail loudly if a restored \
         account comes back as the other kind; and the ceiling test's \
         `unwrap_or_else(|e| panic!(..))` on the advance that must succeed.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "unreachable!",
        2,
        "same #[cfg(test)] module: the derived arms of two matches on \
         a record this module built as imported three lines above. Not a \
         wildcard -- the match is exhaustive and the arm states that the \
         other kind cannot occur here, which is the same reason the module \
         doc gives for refusing `#[non_exhaustive]`.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "assert_eq!",
        3,
        "inside the #[cfg(test)] unit-test module: the \
         premise generation, the generation a fresh open reads after the \
         failed application, and the position it reads.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "assert!",
        2,
        "same #[cfg(test)] module: the application's refusal is the Range \
         `advance_to` gives, and the handle's next call is Poisoned -- the \
         assertion the item exists for.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "assert!",
        41,
        "inside the #[cfg(test)] parser tests: the help \
         spellings recognised before the verb, and refused by name after it; \
         the repeated-flag test's control, each flag once parsing; the \
         `--ref` test's four: a refusal names the flag \
         and the value, carries the rule's words, a seventeenth character and \
         a non-ASCII value are refused by their own reasons; nine \
         over the destination list -- the odd-token and duplicate refusals \
         and their words, the 257th destination, `--ref` and `all` each \
         refused with several, `all` parsing as an unknown amount, and the \
         file parser's four refusals by line. Six over the explorer verbs: \
         the count flag's default, its ceiling and its two refusals carrying the \
         endpoint's own reason; `block 0` refused as the tip's index; and a short \
         hash refused. Four over `discover`'s `--to`: the refusal named \
         across three bad values, and the flag held to the parser's own \
         rules -- given twice, given without a value, and a positional \
         argument where the flag belongs. Its fifth asserted ONE reason for \
         both ends of that range, which is exactly the defect a live run \
         found, and it is eight now: four per arm, \
         being the bounds with the value echoed, that arm's own reason, the \
         sentence saying what to do about it or what already answers it, and \
         the ABSENCE of the other arm's reason -- the assertion the defect \
         needed and the one that was not being made. Five more over the \
         plaintext-node gate: the seven spellings it lets through, and per \
         refused spelling the flag named, the decisions the link carries, the \
         balance a spend is laid out against, and the flag clearing it.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "assert_eq!",
        29,
        "same #[cfg(test)] module: the repeated-flag refusal, named flag by \
         flag; `address --account N`'s parsed shape and its missing-value \
         refusal; the `--ref` test's two: the \
         node's examples laid out NUL-padded, and the zero field without the \
         flag; and fifteen over the destination list -- three pairs \
         parsed in order with their amounts and tags, the fee defaulting to \
         the floor for three and to 500 for one, the single-destination \
         shape `all` parses to, and the file's three columns line by line. Six more: the two default counts, the ceiling \
         taken, `block 1` and the two hash spellings parsed. Three over \
         `discover`'s default `--to`, its ceiling and its floor, each parsed \
         to the `Command` it should be.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "panic!",
        20,
        "same #[cfg(test)] module: `refusal`'s arm for argv that parsed when \
         the case expected a refusal; the `--ref` test's four, the \
         arms for a value that parsed to another command, was refused, or \
         read as help when the case expected a spend; and three more -- \
         `sent`'s two arms, for argv that parsed to another command or did \
         not parse at all, and the file parser's arm for text that was \
         expected to parse. Nine over the explorer parser tests: the arms for \
         argv that parsed to another command or did not parse at all. Three \
         more over `discover`'s \
         default, ceiling and floor.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "panic!",
        7,
        "same #[cfg(test)] module: `unwrap_or_else(|e| panic!(..))` on the \
         steps that must succeed around the one that must fail -- create, \
         add, the generation reads, the reopen and the view.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        ".expect()",
        40,
        "inside the #[cfg(test)] KAT module: unwrapping encode/parse on the \
         known-good image, and `Account::import` on the fixture pair the KAT \
         builds its imported record from. Encryption at rest added ten, all in the \
         encryption tests: deriving the module's cached test key, sealing and \
         opening in the KAT and the RFC 8439 replay, the Argon2 parameter \
         arms, and `reseal`'s four -- which decrypts, edits the plaintext and \
         seals it again, because reaching a canonicality check now means \
         producing a file a legitimate writer could have produced. The anchors added fourteen, all in the anchor and provenance tests: the RFC 9106 replay's one, the bridge test's two, and eleven in `published_vector_literals_match_the_vendored_rfc_text` and its helpers -- two `from_utf8` on the vendored texts, and unwraps behind counts the same function has just asserted (`rfc_section`, `hex_run_between`, `hex_run_to_end`, the tag line). The encoder refusal added three: the image-cap test's `image_len(MAX_ACCOUNTS + 1)` (one record past the cap does not overflow), and the encode-refusal test's parse of a consistent reservation and its slot lookup. Format version 4 added nine, net: `captured_key`'s one (the KDF over the version-3 reservation capture's header, at CHEAP_FOR_TESTS -- hours under Miri otherwise); three in the dispatch test's new arms (the v3 capture's header and its parse, the v4-image-under-a-forged-3 open); `reseal`'s four moved into `reseal_with` (which takes the key, so the v3 capture can be re-sealed too) and `reseal` became a call to it, -3 +3; four in the encode-refusal test's new round trips (a reservation with figures, the migrated shape, a settled block); and one in the both-blocks refusal test's account derivation. Test-only; kept in the census rather than parsed \
         around. The format's non-test code contains no panicking construct \
         -- every read goes through a bounded cursor and every failure is a \
         Result, and that is unchanged by the AEAD: `crypt`'s \
         two entry points return `Result` and its one unreachable arm is a \
         zero rather than a panic.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert!",
        32,
        "same #[cfg(test)] KAT module: the malformation rows (each prefix \
         truncation and the variant-specific refusals), which format v2 grew by \
         the derived first-key padding, the two imported-record \
         reproductions, the kind domain, the pending-flag domain and the \
         v1 file's third arm. Encryption at rest moved this DOWN by one \
         and the direction is the point: the malformation table's rows that \
         mutated an image and recomputed a hash became `assert_eq!` rows \
         against one `WrongPassword`, because the AEAD gives every \
         unauthenticated change the same answer. What is left is the AAD-tamper \
         refusal, the m_cost cap and the canonicality rows that re-seal. The anchors added seven, all in `published_vector_literals_match_the_vendored_rfc_text` and its `hex_tokens` helper: the version and parameter-line needles, the README's copy of each hash, the RFC 8439 hexdump rows, the two-hex-digit token guard and its non-empty floor, and the tag-line token guard. The encoder refusal added four: the image-cap test's one-record-more arm and its two gate probes (a zeroed buffer of exactly `MAX_IMAGE_LEN` bytes passes the length gate to the magic check; one byte more is `Range` naming both bounds), and the encode-refusal test's loop over four inconsistent reservations. Format version 4 added nine: the malformation table's seven new rows -- the state byte's domain (`bad_state`), the relation in the settled state (`settled_relation`), the figures byte's domain (`bad_figures`), the two `figures == 0 => zeros` rows (a dirty balance, a dirty block-to-live), the state-0 zero rule over the figures flag (`figures_without_block`) and the version-3 arm refusing state 2 on the real capture (`v3_state_2`) -- the dispatch test's forged-word arm over the v4 image (`WrongPassword`, because the version word is inside the AAD), and the both-blocks refusal test's `matches!` on the variant.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert_eq!",
        66,
        "same #[cfg(test)] KAT module: the hand-assembled image against \
         encode, the parsed fields against the literals, and the \
         image length against the closed formula plus the captured v1 \
         file's shape and its two version-dispatch verdicts. Encryption at rest added \
         eight: the hand-assembled v3 header, the plaintext body through a \
         decryption, RFC 8439's ciphertext and tag, the KDF's determinism \
         arm, the version-2 upgrade verdict, and the malformation table's \
         five-into-one collapse onto `WrongPassword`. The 28th is \
         `the_nonce_does_not_repeat_across_a_forked_store`'s closing arm, \
         asserting `nonce_for` is a function at all -- without it the two \
         inequalities above it are satisfied by a nonce that simply varies, \
         and nothing repeatable was shown. The anchors added eighteen: the RFC 9106 tag through `crypt::argon2id_v13`, the bridge's agreement, and sixteen in the provenance test and its helpers -- two file hashes, two column-zero heading counts, three label-uniqueness counts, the one-vector and one-tag floors, five RFC 9106 byte runs, the RFC 8439 tag count and its parsed tag. The encoder refusal added four: `image_len(MAX_ACCOUNTS) == MAX_IMAGE_LEN` -- the arm the image-cap defect fails, and the reason the test exists -- and `image_len(0) == MIN_IMAGE_LEN`; and the encode-refusal test's round trip of a consistent reservation, `wots_index` and `pending` each read back. The version refusal added one: the captured version-2 file's verdict -- `UnsupportedVersion` naming its first account -- beside the forged-word arm that names none. Format version 4 added fifteen: nine in the dispatch test -- `read_header` on the v3 pin (version 3, `Kdf::RECOMMENDED`) and the reserved capture read through the public parser (its generation, one derived slot, index 1, the open reservation with `figures: None`, no settled block) -- five in the encode-refusal test's round trips (the figures read back, the migrated shape's `None`, the settled block and both index fields), and one in the both-blocks test (each half alone seals and reads back as itself).",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert_ne!",
        6,
        "Same #[cfg(test)] module, and every one is a NEGATIVE control \
         rather than an assertion about a value: the ciphertext is not the \
         plaintext (which is what would catch an encoder that forgot to call \
         the AEAD at all), and the KDF's three arms showing that the \
         password, the salt and the parameters each change the key. A test \
         that only asserted equalities would be satisfied by a KDF that \
         ignored its inputs. The last two are \
         `the_nonce_does_not_repeat_across_a_forked_store`'s, and they are \
         the reason that test exists rather than decoration: a fault-injection \
         row found that `expected_header` computed the KAT's nonce with \
         `crypt::nonce_for` -- the same function the encoder calls -- so a \
         bare generation counter substituted for the hash left the KAT green. \
         The literal `KAT_NONCE` closed that, and these two arms are what now \
         holds `nonce_for` itself: a nonce differing across two opens of a \
         forked store at ONE generation, and differing across generations \
         within one open. The first is the keystream-reuse hazard the AEAD \
         introduced and is exactly what a counter breaks. Test-only, and \
         negative by construction; the format's non-test code still contains \
         no panicking construct, and the v2-to-v3 migration refusal is NOT \
         among these -- it is `Error::UnsupportedVersion` returned from \
         `read_header`, a Result and not a panic, because a v2 store carries \
         no master seed and an upgrade would produce a v3 file that opens and \
         then refuses every command needing one.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "panic!",
        2,
        "The first `panic!` in this file and both inside the #[cfg(test)] \
         module: `encode_refuses_both_an_open_and_a_settled_block_in_one_record`'s control, \
         which seals each half of the refused pair alone and names the half in its message \
         (`unwrap_or_else(|e| panic!(..))`, the harness's idiom, so a failing control says \
         which half rather than `called Result::unwrap()`). The format's non-test code still \
         contains no panicking construct; the both-blocks refusal itself is `Error::Corrupt` \
         returned from `encode`.",
    ),
    (
        "crates/mochimo-crypto/src/derive.rs",
        "assert!",
        8,
        "inside the #[cfg(test)] unit-test module: the Debug-redaction \
         negative-containment checks for the four secret holders. Test-only; \
         kept in the census rather than parsed around, same reasoning as \
         secret.rs's rows. The derivation's non-test code contains no \
         panicking construct; its two implicit panic classes -- constant slice \
         indexing and copy_from_slice over fixed-width buffers -- are declared \
         at the module head.",
    ),
    (
        "crates/mochimo-crypto/src/derive.rs",
        "assert_eq!",
        3,
        "same #[cfg(test)] module: the pinned generator Debug rendering and \
         the zero-length fill's state count.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert!",
        8,
        "inside the #[cfg(test)] unit-test module: wordlist order, the \
         Phrase redaction, and the six refusal-by-variant matches (entropy \
         width, word count, unknown word, checksum, non-ASCII phrase, \
         non-ASCII passphrase). Test-only; the module's non-test code \
         returns Result everywhere. Counted two ways (a script over the \
         file and this census) before the row was written.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert_eq!",
        4,
        "same #[cfg(test)] module: the wordlist length, the pinned Phrase \
         rendering, the seed being a pure function of (phrase, passphrase), \
         and one rendered refusal message.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert_ne!",
        1,
        "same #[cfg(test)] module: a non-empty passphrase changes the seed \
         -- the one place the parameter is shown to reach the salt.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "panic!",
        7,
        "same #[cfg(test)] module: unwrapping known-good phrases and seeds \
         in the three tests that need them, loudly rather than through \
         .unwrap().",
    ),
];

/// The walk behind [`DECLARED_PANIC_SITES`]: every ident-followed-by-`!` whose
/// name is a panic-family macro, every `.unwrap()`/`.expect(..)` method call,
/// and every appearance of `handle_alloc_error`, over the token stream of each
/// file in `crates/*/src`.
///
/// # Domain, stated rather than implied
///
/// * **`crates/*/src` only.** The test tree is not censused: a panic in a
///   test is the test failing.
/// * **Tokens, not text.** A `Literal` or a comment spelling `unwrap` is
///   exactly the false positive a text search would take; the lexer never
///   sees either.
/// * **What this census cannot count**: slice indexing and overflowing
///   arithmetic. Every `[i]` and `+` in the crate would enrol, so that half of
///   the hardening survey is knowledge, not a table, and the
///   load-bearing sites (`wots_checksum`'s wrapping accumulator, the
///   consts-derived ranges) argue themselves where they stand.
#[test]
fn panicking_constructs_are_declared_at_their_sites() {
    const MACROS: [&str; 10] = [
        "panic",
        "unreachable",
        "todo",
        "unimplemented",
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
    ];
    const METHODS: [&str; 2] = ["unwrap", "expect"];

    // (file, construct) -> lines found at. Lookahead over a flattened
    // Vec<TokenTree> per group, recursing into groups, so `assert !` and
    // `.unwrap ()` are matched as shapes rather than as spellings.
    fn walk(
        trees: &[proc_macro2::TokenTree],
        file: &str,
        hits: &mut Vec<(String, String, usize)>,
        examined: &mut usize,
    ) {
        use proc_macro2::TokenTree as T;
        for (i, tree) in trees.iter().enumerate() {
            *examined += 1;
            match tree {
                T::Ident(id) => {
                    let name = id.to_string();
                    let line = id.span().start().line;
                    let next_is = |what: char| {
                        matches!(trees.get(i + 1), Some(T::Punct(p)) if p.as_char() == what)
                    };
                    if MACROS.contains(&name.as_str()) && next_is('!') {
                        hits.push((file.to_string(), format!("{name}!"), line));
                    }
                    if name == "handle_alloc_error" {
                        hits.push((file.to_string(), name.clone(), line));
                    }
                    // `.unwrap()` / `.expect(..)`: a dot before, parens after.
                    if METHODS.contains(&name.as_str()) {
                        let dot_before = i > 0
                            && matches!(&trees[i - 1], T::Punct(p) if p.as_char() == '.');
                        let parens_after = matches!(
                            trees.get(i + 1),
                            Some(T::Group(g))
                                if g.delimiter() == proc_macro2::Delimiter::Parenthesis
                        );
                        if dot_before && parens_after {
                            hits.push((file.to_string(), format!(".{name}()"), line));
                        }
                    }
                }
                T::Group(g) => {
                    let inner: Vec<proc_macro2::TokenTree> = g.stream().into_iter().collect();
                    walk(&inner, file, hits, examined);
                }
                _ => {}
            }
        }
    }

    let mut hits: Vec<(String, String, usize)> = Vec::new();
    let mut examined = 0usize;
    let mut files = 0usize;
    for (name, text) in crate_source_files() {
        // Fail closed, as the endian scan does: a file that will not lex is a
        // file nothing censuses, and it must not shrink the domain silently.
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This census is the sole \
                 mechanism keeping the panic surface enumerated, so a file it \
                 cannot read is not skipped."
            )
        });
        let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
        walk(&trees, &name, &mut hits, &mut examined);
        files += 1;
    }

    assert!(
        files >= 25 && examined >= 77_200,
        "the walk saw {files} file(s) and {examined} token(s); both are far \
         below the tree's real size, so this is the walk failing, not the \
         crate being clean. This tree measures 115,827 tokens across 38 files \
         and both floors are two thirds of that. The file floor matches the \
         endianness scan's because the corpus is the same 38 files; the other \
         one cannot, because that scan counts identifiers and this one counts \
         every token."
    );
    assert!(
        !DECLARED_PANIC_SITES.is_empty(),
        "the declared table is empty; the crate is not panic-free (error.rs \
         carries three declared unimplemented! sites at minimum), so an empty \
         table means the table was emptied, not that the surface closed."
    );

    // Aggregate to (file, construct) -> count and compare in both directions.
    let mut counted: std::collections::BTreeMap<(String, String), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (file, construct, line) in hits {
        counted.entry((file, construct)).or_default().push(line);
    }

    let mut problems: Vec<String> = Vec::new();
    for ((file, construct), lines) in &counted {
        match DECLARED_PANIC_SITES
            .iter()
            .find(|(f, c, _, _)| f == file && c == construct)
        {
            None => problems.push(format!(
                "\x20 - {file} uses {construct} at line(s) {lines:?} and no row \
                 declares it. Either remove it or add a row stating why it \
                 stays -- a panic on input the crate did not choose is a \
                 denial of service in a wallet."
            )),
            Some((_, _, count, _)) if *count != lines.len() => problems.push(format!(
                "\x20 - {file}: {construct} declared {count} time(s), found {} \
                 (line(s) {lines:?}). The census and the table must move \
                 together.",
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for (file, construct, count, _) in DECLARED_PANIC_SITES {
        if !counted.contains_key(&((*file).to_string(), (*construct).to_string())) {
            problems.push(format!(
                "\x20 - the table declares {count} x {construct} in {file} and \
                 the walk found none. If the construct was removed, remove the \
                 row with it; if the walk broke, every row goes missing at \
                 once, which is what you are looking at."
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "the panic-surface census disagrees with DECLARED_PANIC_SITES \
         :\n{}",
        problems.join("\n")
    );

    let total: usize = DECLARED_PANIC_SITES.iter().map(|(_, _, c, _)| c).sum();
    println!(
        "  panic-surface census: {files} files, {examined} tokens, \
         {total} declared construct(s) across {} row(s), 0 undeclared",
        DECLARED_PANIC_SITES.len()
    );
}

/// `unsafe` lives nowhere under `src/` — most load-bearingly, **not in
/// `backend/native.rs`**.
///
/// The allow-list held six files while the foreign-function backend was
/// here: the binding itself, the `TXENTRY` handle in `tx.rs`, the diagnostic
/// strings in `error.rs`, `word16_max`'s shim call in `lib.rs`, and the two
/// class-routed calls in `addr.rs` and `base58.rs`. Every one of those sites
/// went with the C. What the list holds is the Windows boundary -- files
/// compiled only on Windows, each argued at its row -- so any `unsafe`
/// keyword anywhere else under `src/` is a red naming the file. It keeps its
/// file floor so an empty walk cannot pass, and its positive control is the
/// fault-injection row that puts one `unsafe {}` back.
///
/// The native half is the one with consequences: `miri.rs` establishes memory
/// safety **for the native paths Miri walks**, and an `unsafe` block appearing
/// in `native.rs` would not widen what Miri checks — it would quietly change
/// what "native is clean under Miri" means. That failure message carries the
/// argument.
///
/// Token walk, not text search: `unsafe` in a SAFETY comment or a doc string
/// is prose about the subject, and only the keyword the lexer sees is the
/// subject itself.
#[test]
fn unsafe_is_confined_to_declared_files() {
    // Every row the foreign-function backend brought went with it. A row
    // added here needs the argument its predecessors carried: which boundary,
    // and why Miri cannot walk it.
    //
    // The first row is the Windows permission model, and it is a permanent
    // delta of the tree that runs on Windows, recorded in `FORK.md`'s table.
    // The boundary is Win32's security API, which `std` does not wrap: `std`
    // neither reads a security descriptor nor creates a file under one, so
    // the access-list check and the owner-only creation are foreign calls or
    // they are nothing. Miri cannot walk them -- it interprets Rust, and a
    // foreign call is the edge of what it can see -- and the Miri run is on a
    // Unix host, where the file is not compiled at all. So a green Miri run
    // says nothing about this file in either direction, and the file's own
    // head says what does establish it: at present, a compile and clippy for
    // the Windows target, and nothing that has run.
    //
    // The second row is the binary's Windows console, on the same two
    // grounds. `std` offers no console mode, so echo cannot be turned off
    // without `SetConsoleMode`; it reads a console only through its own
    // global stdin, whose buffer lives as long as the process and is not
    // this program's to zeroize; and it has no interface to the system
    // generator. The `unsafe` sits in one `cfg(windows)` module at the foot of
    // the file, and the Unix arm above it holds none.
    const ALLOWED: [(&str, &str); 2] = [
        (
            "crates/mochimo-crypto/src/keystore/perms/windows.rs",
            "the Windows permission model's Win32 security calls",
        ),
        (
            "crates/mochimo-crypto/src/bin/mcm-wallet.rs",
            "the binary's Windows console and generator, in its `console` module",
        ),
    ];

    fn count_unsafe(stream: proc_macro2::TokenStream, lines: &mut Vec<usize>) {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(id) => {
                    if id == "unsafe" {
                        lines.push(id.span().start().line);
                    }
                }
                proc_macro2::TokenTree::Group(g) => count_unsafe(g.stream(), lines),
                _ => {}
            }
        }
    }

    let mut problems: Vec<String> = Vec::new();
    let mut per_allowed: Vec<(String, usize)> = Vec::new();
    let mut files = 0usize;
    for (name, text) in crate_source_files() {
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This walk is the sole \
                 enforcement of where unsafe may live, so an unreadable file \
                 is not skipped."
            )
        });
        let mut lines = Vec::new();
        count_unsafe(stream, &mut lines);
        files += 1;

        match ALLOWED.iter().find(|(f, _)| *f == name) {
            Some(_) => per_allowed.push((name, lines.len())),
            None if lines.is_empty() => {}
            None => {
                let miri_note = if name.ends_with("backend/native.rs") {
                    "\n    This file is what the Miri run interprets, and its \
                     having NO unsafe is part of what that run's green means: \
                     `memory_safety_is_established_only_for_the_native_paths_miri_walks` \
                     claims safe code checked by an interpreter, not unsafe \
                     code vouched for by its author. Do not move the boundary \
                     by adding a row here; whatever needs unsafe belongs on \
                     the ffi side of the seam."
                } else {
                    ""
                };
                problems.push(format!(
                    "\x20 - {name} contains `unsafe` at line(s) {lines:?} and \
                     is not on the allow-list.{miri_note}"
                ));
            }
        }
    }

    // The other direction: an allow-listed file with zero occurrences means
    // the row is stale, and a stale row is a standing permission nobody is
    // using -- exactly what a later session would exploit by accident.
    for (file, why) in ALLOWED {
        match per_allowed.iter().find(|(f, _)| f == file) {
            None => problems.push(format!(
                "\x20 - allow-listed file {file} was not walked at all; the \
                 corpus shrank under this check"
            )),
            Some((_, 0)) => problems.push(format!(
                "\x20 - {file} is allow-listed for {why} but contains no \
                 `unsafe` any more. Remove its row; an unused permission is a \
                 hole waiting for an occupant."
            )),
            Some(_) => {}
        }
    }

    assert!(
        files >= 10,
        "the walk saw {files} file(s), far below the tree's real size"
    );
    assert!(
        problems.is_empty(),
        "`unsafe` has moved relative to the declared boundary:\n{}",
        problems.join("\n")
    );

    println!(
        "  unsafe confinement: {files} files walked, {} allow-listed file(s), \
         0 `unsafe` keywords outside the allow-list",
        per_allowed.len()
    );
}

/// Every `pub fn sha3*` takes one `&[u8]` and returns a fixed-size array — so
/// no caller-controlled `outlen` is expressible on the SHA3 surface.
///
/// The reference's `sha3_init` computes `rsiz = 200 - 2*outlen` with no range
/// check; from `outlen == 100` the final-block write is out of bounds, which
/// is a defect of the reference this crate does not reproduce. The width is
/// part of the *type* here -- four fixed-width functions over one private
/// funnel -- so an unsupported width is a name that does not exist rather
/// than a value reaching `sha3_init`, and `addr.rs`'s own doc carries that
/// argument. This check is what keeps the shape closed: nothing else in the
/// tree asserts the number 100, and a `pub fn sha3(input: &[u8], out: &mut
/// [u8])` added to `native.rs` and `addr.rs` together would satisfy every
/// other check in this file.
///
/// Two arms, one of them gone:
/// * **shape** — `syn` over the two files with a sha3-named public surface:
///   every `pub fn` whose name starts with `sha3` has exactly one parameter,
///   that parameter is `&[u8]` (immutable), and the return type is an array.
///   A width that is caller data has to arrive through a parameter or an
///   out-buffer; a signature with neither cannot carry one.
/// * **bindings** — an arm reading a bindgen allow-list, which is not in this
///   repository and so is not here either.
#[test]
fn sha3_width_is_a_type_not_a_parameter() {
    // The foreign-function backend carried the same four wrappers; it is not
    // in this repository, and the property is about the surface a caller can
    // reach.
    const FILES: [&str; 2] = [
        "crates/mochimo-crypto/src/backend/native.rs",
        "crates/mochimo-crypto/src/addr.rs",
    ];

    let mut problems: Vec<String> = Vec::new();
    let mut found = 0usize;
    for rel in FILES {
        let text = read_crate_file(rel);
        let ast = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("{rel} did not parse as Rust: {e}"));
        let mut here = 0usize;
        for item in &ast.items {
            let syn::Item::Fn(f) = item else { continue };
            if !matches!(f.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let name = f.sig.ident.to_string();
            if !name.starts_with("sha3") {
                continue;
            }
            here += 1;

            if f.sig.inputs.len() != 1 {
                problems.push(format!(
                    "\x20 - {rel}::{name} takes {} parameters. One `&[u8]` is \
                     the whole legal surface; a second parameter is where a \
                     runtime width would live.",
                    f.sig.inputs.len()
                ));
            }
            for arg in &f.sig.inputs {
                let syn::FnArg::Typed(pt) = arg else { continue };
                match &*pt.ty {
                    syn::Type::Reference(r) if r.mutability.is_none() => {}
                    other => problems.push(format!(
                        "\x20 - {rel}::{name} takes `{}`, not an immutable \
                         reference. An out-buffer parameter is how the \
                         old signature let every caller name an outlen, \
                         including >= 100.",
                        quote::ToTokens::to_token_stream(other)
                    )),
                }
            }
            match &f.sig.output {
                syn::ReturnType::Type(_, ty) if matches!(**ty, syn::Type::Array(_)) => {}
                other => problems.push(format!(
                    "\x20 - {rel}::{name} returns `{}`, not a fixed-size \
                     array. The width being in the return TYPE is the \
                     mechanism; a Vec or a slice would put it back in a value.",
                    quote::ToTokens::to_token_stream(other)
                )),
            }
        }
        if here < 4 {
            problems.push(format!(
                "\x20 - {rel} declares {here} public sha3-named fn(s); the four \
                 widths of `sha3.h:44` are 224/256/384/512, so fewer than 4 \
                 means the surface shrank or the parse saw the wrong file."
            ));
        }
        found += here;
    }

    // The bindings arm this check carried -- that the bindgen allow-list bound
    // `sha3` and not the streaming `sha3_init`/`sha3_update`/`sha3_final` --
    // read a build script that is not in this repository. Nothing here
    // reaches the reference's streaming API because nothing here reaches the
    // reference.
    assert!(
        found >= 8,
        "the shape arm examined {found} public sha3-named fn(s) across two \
         files; 8 is the floor (four widths x two files), so the walk or \
         the parse is broken"
    );
    assert!(
        problems.is_empty(),
        "a caller-controlled SHA3 width is expressible again:\n{}",
        problems.join("\n")
    );

    println!(
        "  sha3 width shape: {found} public sha3-named fn(s) checked across \
         {} files",
        FILES.len()
    );
}

/// Every `unimplemented!()` in the crate is declared, and says why.
///
/// # What this is the mechanism for
///
/// The Miri session made `mochimo-crypto` compile without `ffi-oracle`, because Miri is an
/// interpreter and cannot execute linked C. **Compiling is not working.** A
/// third of the crate's surface panics in that configuration, and the danger of
/// a `unimplemented!()` is that it is invisible: the build is green, the tests
/// that would have caught it are gated off with the C they needed, and the gap
/// is discoverable only by reading the file it is in.
///
/// So the sites are enumerated here, fail-closed, with no third state between
/// *owed* and *excluded with an argument*.
///
/// # One half, enumerated
///
/// `error.rs`'s stubs are an allow-list. What would expand the domain without
/// expanding the check: an `unimplemented!()` in a module not named here. The
/// token count below is what closes that, and it is a count of the token
/// `unimplemented!(` in comment-stripped source — nothing subtler. The
/// derived half this check once carried -- the FFI backend's public surface
/// minus the native one's, equal to a stub module -- compared a seam that is
/// not compiled in this repository and is gone with it.
#[test]
fn unimplemented_sites_are_declared_with_a_reason() {
    // The derived half -- `ffi − native == unported` over the two backends'
    // public functions -- compared a seam that is not in this repository
    // against an empty stub module; both are gone. What is left is the
    // enumerated half.
    let declared: &[(&str, &str, Owing)] = DECLARED_UNIMPLEMENTED;

    // Closes the enumerated half: any `unimplemented!()` in a module nobody
    // declared moves this count and nothing else does.
    let mut tokens = 0usize;
    let mut files = 0usize;
    for (name, text) in crate_sources() {
        if !name.starts_with("crates/mochimo-crypto/src/") {
            continue;
        }
        files += 1;
        tokens += code_only(&text).matches("unimplemented!(").count();
    }
    assert!(
        files >= 10,
        "walked only {files} files under crates/mochimo-crypto/src/. The walk is \
         broken, and a token count over nothing is zero — which is also what a \
         crate with no stubs looks like."
    );
    assert_eq!(
        tokens,
        declared.len(),
        "counted {tokens} `unimplemented!(` tokens under \
         crates/mochimo-crypto/src/ but DECLARED_UNIMPLEMENTED has {} rows. An \
         undeclared stub is a hole in the native-only build that nothing \
         reports: the build is green, and the tests that would have caught it \
         are gated off with the C they needed.",
        declared.len()
    );
}

/// Whether a declared `unimplemented!()` is debt or a settled exclusion.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Owing {
    /// Someone can state what turns it green, so it belongs in the tooling.
    Owed,
    /// Nobody can, so it is knowledge rather than debt.
    Excluded,
}

/// `(module, function, owing)` for every `unimplemented!()` in the crate.
///
/// The reasons are at the sites; this is the census. Grouped by module because
/// the *kind* of gap differs by module and the debt marker reports them that way.
const DECLARED_UNIMPLEMENTED: &[(&str, &str, Owing)] = &[
    // The backend gap is EMPTY and there is no second backend to have one.
    // Nothing needs adding here by hand when the gap reopens. The set
    // difference asserted above computes it, and it will name the function.
    //
    // What did NOT come with them is a native transaction path. Emptying these
    // rows produced the accessor surface and nothing more; the path was filed
    // as its own red in the same commit so the obligation was not absorbed
    // into this one's green. That marker was
    // `no_native_transaction_path_exists`; `tx::wire` landed and it is
    // green under its post-discharge name,
    // `native_transaction_path_is_checked_on_layout_not_acceptance`
    //.
    //
    // Excluded, and the exclusion is recorded here beside the entries it is not
    // like, rather than by omission. These three return the
    // reference's own diagnostic spellings. A Rust restatement would compare our
    // naming to our naming, so there is no condition that turns a native version
    // green — which makes them knowledge rather than debt. A marker nobody can
    // discharge is a permanent red, and permanent reds train the reader to skim
    // past all of them.
    ("error", "ve2str", Owing::Excluded),
    ("error", "errno_name", Owing::Excluded),
    ("error", "errno_text", Owing::Excluded),
];

/// The native-only build compiles and cannot transact, encode Base58, or
/// convert a 32-bit integer.
///
/// # Why this is red and what it is not
///
/// It is **not** a complaint that the Miri session left work undone. Its scope was
/// "compiles without `ffi-oracle` so Miri can run", and that is a different
/// thing from "works without `ffi-oracle`". This marker is the difference,
/// carried where a run reports it rather than where someone has to go looking.
///
/// # What is left is the transaction surface, and nothing else
///
/// **The backend half cleared with the width change.** `crate::base58`, `crate::bytes` and
/// `crate::addr` all work natively; the empty stub module that once held the
/// computed difference `ffi − native == unported` went with the
/// foreign-function backend. The seven `tx` rows below were the whole
/// remainder.
///
/// They are shims over `types.h` macros, and their oracle is group D. **That
/// oracle is complete**: the entry is emitted at each of the fifteen sites
/// that record a verdict or a hash on bytes, and all 44 replay.
///
/// So what remains is the translation, which is what this marker was waiting to
/// be able to say. Each of the seven has a vector behind it: `TXDAT_TYPE`,
/// `TXDSA_TYPE` and `MDST_COUNT` in the three `D-acc-` vectors, the two address-half
/// pointers in `Ds8b`, the two length bounds in group E. **Do not close it by
/// writing a Rust signer** — that prohibition was never about the fixtures'
/// completeness and does not lift with it.
///
/// `TxEntry` is `#[cfg]`-absent here rather than stubbed, which is a different
/// admission from the seven: I7 says a `TXENTRY` may never be a Rust value, so
/// an `unimplemented!()` constructor would be a constructor for the thing the
/// invariant forbids.
///
/// # The shape of the claim, and its bound
///
/// Describing "the backend seven" as address-path-shaped work and "the
/// four Base58 entry points" as a pending decision, with `put32` as the
/// worked example on the grounds that `put16`'s little-endian verification is
/// an *inference* about the 32-bit pair rather than a measurement: all three
/// were discharged a session or more earlier:
///
/// * five of the seven were never missing behaviour — they were the C's calling
///   convention and its runtime `outlen` sitting in the backend seam, and
///   native already had those semantics under Rust-shaped names;
/// * `put32`'s byte order is anchored by the generator's own recorded bytes,
///   `identity.adrs_tail12` in `group_d_tx.json`, which the corpus replays.
///
/// This text is not a doc comment that aged. **It is the failure message a debt
/// marker prints on every run of the board**, so the most-read prose in the tree
/// was describing obligations that no longer existed. Kept as a note rather than
/// deleted because the drift audit counts instances, and a silently corrected
/// instance is one the count never sees.
///
/// # The dead code is deliberate
///
/// Some of `crate::bytes` and the transaction wrappers are unreachable in a
/// native-only build. That is acceptable, and it is written down here so nobody
/// later reads it as a defect and "fixes" it under time pressure: the
/// configuration exists for Miri, and `tests/miri.rs` drives
/// `backend::native::*` directly rather than through the public wrappers.
/// Nothing is waiting on these to become usable.
///
/// # What clears it, and what it does NOT assert
///
/// The `Owed` rows emptying — which happened when the seven `tx`
/// accessors were ported into `backend::native`. This test is green.
///
/// **It was called `native_only_build_cannot_transact_or_encode` until that
/// commit, and going green under that name would have been a lie.** Emptying
/// those rows produced the *accessor surface*: reading an options byte, taking
/// an address half, summing three struct sizes. It did not produce a
/// transaction path, and could not have — `TxEntry` is `#[cfg]`-absent by
/// design, because I7 forbids a `TXENTRY` ever being a Rust value and an
/// `unimplemented!()` constructor would be a constructor for what the invariant
/// forbids. A green named "cannot transact" reads as a capability
/// nobody built.
///
/// So it was renamed to what it actually asserts — that every `unimplemented!()`
/// left in the crate is `Owing::Excluded`, i.e. knowledge rather than debt —
/// and the transaction path was filed as its own red in the same commit rather
/// than absorbed into this green. That was decided before the work started, not
/// after it succeeded.
///
/// Renamed rather than deleted, on the discharged-marker rule and for its reason: the
/// argument above is the useful part and a test deleted on the day it passes
/// takes its reasoning with it.
#[test]
fn every_unimplemented_site_is_knowledge_not_debt() {
    let mut by_module: std::collections::BTreeMap<&str, Vec<&str>> =
        std::collections::BTreeMap::new();
    for (module, function, owing) in DECLARED_UNIMPLEMENTED {
        if *owing == Owing::Owed {
            by_module.entry(module).or_default().push(function);
        }
    }

    let owed: Vec<String> = by_module
        .iter()
        .map(|(module, fns)| format!("\x20 - {module}: {}", fns.join(", ")))
        .collect();
    let count: usize = by_module.values().map(Vec::len).sum();

    assert!(
        owed.is_empty(),
        "{count} public function(s) panic with `unimplemented!()` and are \
         declared OWED rather than excluded:\n{}\n\
         \n\
         This set was empty once the accessors were ported, so a non-empty one means a stub was added \
         or an existing one was reclassified. Neither is wrong on its face; \
         both are decisions. What is wrong is a stub that nobody classified, \
         which `unimplemented_sites_are_declared_with_a_reason` catches by \
         count.\n\
         \n\
         The seven `tx` accessors that used to be here are ported, and so \
         is the native transaction path (`tx::wire`, checked by \
         `native_transaction_path_is_checked_on_layout_not_acceptance`). \
         Neither was discharged by adding stubs here, and nothing else should \
         be either.\n\
         \n\
         error::ve2str, errno_name and errno_text panic in the C-free build and \
         are `Owing::Excluded`: no condition turns a Rust restatement of \
         upstream's own spellings green, so they are knowledge.",
        owed.join("\n")
    );
}

/// The native transaction path exists and is checked on layout, encoding and
/// the two offline validators — **not on acceptance**.
///
/// # What it asserts
///
/// **The proof test runs, passes, and reports** (execution census):
/// `txwire.rs::native_transaction_round_trip_needs_no_reference`, the native
/// round-trip walk over every accepted group D wire image with every recorded
/// fixture field asserted, in a binary gated on `native` alone -- which is
/// the mechanism behind "works in a build where the C is absent" (that file
/// runs under Miri too). The premise anchor on the reference's `types.h`, the
/// gate anchor on the FFI handle, and the census of the differential round
/// trip against the reference's parse are gone with their subjects.
///
/// # What the green establishes, and what it cannot
///
/// The codec agrees with the C on **layout and encoding** (71 named wire
/// images: 67 byte-identical both ways and 4 rejections the parser
/// reproduces), and the corpus behind it carries the two
/// offline validators' verdicts (`mdst_val`, `tx_val__wots`). **`tx_val` was
/// never run** — it needs an open ledger — so no wire image is a transaction
/// the C accepted end to end, and a serializer green here can still emit a
/// transaction a real node rejects for a ledger reason, a balance tally, or a
/// block-to-live range. That residue is stated at `tx::wire`'s module doc and
/// at the proof test; the place it will surface is testnet.
#[test]
fn native_transaction_path_is_checked_on_layout_not_acceptance() {
    let mut owed: Vec<String> = Vec::new();

    // Two anchors and one census row this guard carried are gone with their
    // subjects: the reference's `types.h` container, the `#[cfg]` gate over
    // the FFI handle in `tx.rs` (compiled out, and on the list to be deleted
    // -- and the differential round trip against
    // the reference's parse. What remains is the codec's own round trip in
    // the binary gated on `native` alone.
    const C_FREE_PROOF: &str = "native_transaction_round_trip_needs_no_reference";
    if let Err(why) = census::check(
        "native_transaction_path_is_checked_on_layout_not_acceptance",
        C_FREE_PROOF,
    ) {
        owed.push(format!(
            "\x20 - {C_FREE_PROOF} stopped holding: it is the mechanism behind \
             the claim that the transaction path works in a build where the C \
             is absent, so without it that sentence is prose.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "The native transaction path's arrangement came apart:\n{}\n\
         \n\
         WHAT THIS TEST HOLDS: tx::wire is the native construction path \
         (ordinary Rust types, serializer at the boundary), and \
         the proof test keeps the codec checked against group D -- 71 named \
         wire images, 67 byte-identical both ways and 4 rejections reproduced, \
         recorded fields asserted.\n\
         \n\
         WHAT A GREEN HERE DOES NOT SAY: tx_val needs an open ledger and never \
         ran, so nothing in the corpus is a transaction the C accepted end to \
         end. Checked on layout, encoding and two offline validators is not \
         known-to-work; the difference surfaces at testnet.\n\
         \n\
         This was no_native_transaction_path_exists until tx::wire cleared and \
         renamed it in the same commit.",
        owed.join("\n")
    );
}
/// A file under the repository root, read or panicking with its path.
fn read_crate_file(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The names of every **public** `fn` defined at item level, parsed from the AST.
///
/// Definitions, not resolvable paths: a re-export would resolve a name a file
/// does not define. That difference was what made the set difference in
/// `unimplemented_sites_are_declared_with_a_reason` measure anything while
/// there were two backends, and it is preserved on purpose rather than
/// papered over.
///
/// # Why this parses instead of matching a prefix
///
/// A `line.strip_prefix("pub fn ")` returns `None` for
/// `pub unsafe fn`, `pub const fn` and `pub async fn`. Measured: a
/// `pub unsafe fn` appended to `backend/native.rs` — **precisely the shape Miri
/// coverage exists to police** — left both
/// `memory_safety_is_established_only_for_the_native_paths_miri_walks` and
/// `unimplemented_sites_are_declared_with_a_reason` green, while the
/// unqualified spelling of the same function was caught. The `surface >= 30`
/// floor cannot see a single miss, because a name the parser never produced is
/// indistinguishable from a name that is not there.
///
/// Enumerating the qualifier permutations by hand — `pub unsafe fn`,
/// `pub const fn`, `pub async fn`, `pub const unsafe fn`, `pub extern "C" fn`,
/// `pub unsafe extern "C" fn` — reintroduces exactly the class that produced
/// the defect. `syn` already knows the grammar: [`syn::Signature`] carries the
/// qualifiers as fields, so **every ordering and combination is covered by not
/// looking at them at all.**
///
/// # `pub(crate)` is deliberately NOT collected
///
/// A set named *public* that contains things which are not is a set that has
/// stopped meaning anything, and widening it here would silently turn the
/// `ffi − native` difference in `unimplemented_sites_are_declared_with_a_reason`
/// into a difference over a different population.
///
/// That is not the same as deciding a `pub(crate) unsafe fn` should go
/// unnoticed — "cannot be covered by Miri" and "should not be noticed" are
/// different conclusions. `tests/miri.rs` is an external crate and cannot call
/// a `pub(crate)` item, so a `MIRI_DOMAIN` row for one would be dischargeable
/// only by writing "not applicable", which is a marker cleared by declaring it
/// irrelevant. The case is caught instead by
/// [`no_restricted_visibility_fn_in_the_backend`], which names its own subject.
///
/// Item level only — a `fn` inside an `impl` is not collected, matching what
/// the line-anchored version did. The three backend modules declare no inline
/// `mod` blocks, so "item level" and "top of the file" coincide there today.
///
/// **Measured across the parser change**: the prefix match and this both
/// yielded 34 names from `native.rs` (and 30 from the foreign-function
/// backend, 0 from the stub module, while those were here), so the domains
/// its consumers see were unchanged on that tree. The difference is entirely
/// prospective, which is why the injections below were run rather than the
/// equal counts being taken as evidence.
fn public_fn_names(code: &str) -> Vec<String> {
    let ast = syn::parse_file(code).unwrap_or_else(|e| {
        panic!(
            "syn could not parse a backend module: {e}\n\
             This parser feeds the Miri domain and the ffi/native set \
             difference; a file it cannot read would silently contribute an \
             empty name set, which reads as \"nothing to declare\"."
        )
    });
    ast.items
        .iter()
        .filter_map(|item| match item {
            // `Visibility::Public` is bare `pub` and nothing else --
            // `pub(crate)`, `pub(super)` and `pub(in path)` are
            // `Visibility::Restricted`. The qualifiers (`unsafe`, `const`,
            // `async`, `extern "C"`) live in `sig` and are simply not consulted,
            // which is what makes their orderings a non-issue.
            syn::Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                Some(f.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

/// No backend function hides behind a restricted visibility.
///
/// # What this is for, and why it is not part of `public_fn_names`
///
/// [`public_fn_names`] collects bare `pub` only, so the Miri domain and the
/// `ffi − native` difference keep meaning what their names say. A
/// `pub(crate) unsafe fn` pointer primitive in `backend/native.rs` would
/// therefore enter neither — and that is the right answer for those two checks
/// and the wrong answer for the tree, because a `pub(crate) unsafe fn` is
/// exactly the shape Miri coverage exists to police.
///
/// So the case gets a check that names it, rather than a domain quietly widened
/// to swallow it. If one appears, this goes red saying what it found; the Miri
/// domain stays silent, because it genuinely cannot walk what it cannot call
/// from an external test crate.
///
/// # THIS IS VACUOUSLY TRUE TODAY — read that before reading the green
///
/// The native backend contains **zero** restricted-visibility functions, and
/// so did the whole crate when this was written: all 107 item-level `fn`
/// declarations under `crates/*/src` were bare `pub fn`, measured. So this check has never
/// fired and has never had the opportunity to. A green here is a statement
/// about a case that has not occurred, not evidence that the case is handled —
/// a guard that inherits its blind spot, in marker form. Its polarity was demonstrated by injection
/// rather than inferred from the green.
#[test]
fn no_restricted_visibility_fn_in_the_backend() {
    let mut found: Vec<String> = Vec::new();
    let mut items = 0usize;
    // `backend/native.rs`, the one backend module.
    for file in ["backend/native.rs"] {
        let text = read_crate_file(&format!("crates/mochimo-crypto/src/{file}"));
        let ast = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("syn could not parse {file}: {e}"));
        for item in &ast.items {
            if let syn::Item::Fn(f) = item {
                items += 1;
                if let syn::Visibility::Restricted(r) = &f.vis {
                    use quote::ToTokens;
                    found.push(format!(
                        "\x20 - {file}::{} is `{} fn`",
                        f.sig.ident,
                        r.to_token_stream()
                    ));
                }
            }
        }
    }

    // Vacuity guard. An empty parse would satisfy the assertion below over
    // nothing, which is the failure mode this whole session is about.
    assert!(
        items >= 30,
        "parsed only {items} item-level functions out of the native backend \
         module; this tree's `backend/native.rs` holds 45 and this floor is two \
         thirds of that. The walk is broken and any \
         result from it is vacuous"
    );

    assert!(
        found.is_empty(),
        "these backend functions have a restricted visibility:\n{}\n\
         `public_fn_names` collects bare `pub` only, so these enter neither the \
         Miri domain nor the ffi/native set difference -- deliberately, since \
         tests/miri.rs is an external crate and cannot call them. That makes \
         them invisible to both, which is fine for an ordinary helper and NOT \
         fine for anything doing pointer work. Decide which this is: make it \
         `pub` and give it a MIRI_DOMAIN row, make it private, or add it here \
         with an argument.",
        found.join("\n")
    );

    println!(
        "  backend visibility: {items} item-level fns in the native backend, \
         0 restricted. VACUOUSLY TRUE -- the tree has never contained one; \
         see this test's documentation."
    );
}

// -------------------------------------------------------------------------
// Harness debt in the walk itself
// -------------------------------------------------------------------------

/// Every `.rs` under this crate's `tests/`, as `(path, text)`, sorted by path.
///
/// This is *the* walk: `test_sources()` is this joined. The file boundaries are
/// kept because the caller below reports damage by location, and "somewhere in
/// 280KB" would not be actionable.
///
/// **Sorted, and that is the point.** `read_dir` order is not sorted and is not
/// guaranteed stable across filesystems, so an unsorted concatenation gives the
/// checks that slice this corpus a domain that varies per machine on one commit
/// (a corpus that varies is a different subject). Measured on this tree: the
/// stray comment opener in `compile_fail.rs` destroyed 19,015 bytes in
/// `read_dir` order and 628 in sorted order -- same defect, different victim,
/// chosen by the filesystem. Sorting does not repair the stripper and was never meant to; it
/// makes the damage the same everywhere, so a measurement of it means something.
fn test_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// `code_only` must not mistake a construct in its inputs for a comment.
///
/// # What this replaced
///
/// `code_only` once treated a slash-star pair inside a string literal as
/// a block-comment opener, and its own doc comment judged that acceptable
/// because "the failure mode of a naive strip on a string literal containing a
/// slash-star is a false *pass*, which the per-check vacuity assertions catch".
/// Both halves were wrong.
///
/// Not a false pass: adding *one* literal to this file once moved the
/// hole's boundary and turned `crosscheck_fields_stay_asserted` and
/// `group_e_constants_stay_anchored` red, with messages about independence and
/// group E constants that pointed nowhere near the cause -- a check broken by an
/// edit to a file it does not read. Not caught by a vacuity assertion either:
/// the corpus was not empty, only silently shorter than its sources.
///
/// Measured on the concatenated `tests/` corpus:
///
/// | corpus, in bytes | length |
/// | --- | --- |
/// | raw concatenation | 288,630 |
/// | old stripper, `read_dir` order | 156,993 |
/// | old stripper, sorted order | 169,161 |
/// | repaired stripper, sorted order | 170,303 |
///
/// 13,310 bytes of code were destroyed. The single largest hole ran 19,015
/// bytes from the compile-fail runner+3321 to this file+1861, swallowing every
/// file the concatenation placed between them. In sorted order the same opener
/// instead ran unterminated to EOF and took 628 -- same defect, different
/// victim, chosen by the filesystem.
///
/// # What this asserts now
///
/// Two things, over every file `code_only` is given.
///
/// **Stripping distributes over concatenation.** `code_only(a + b)` must equal
/// `code_only(a) + code_only(b)`. That equation is exactly what a cross-file
/// hole breaks, and it needs no threshold to say so: an opener whose closer is
/// in the next file makes the two sides differ. It is the property the two
/// corpus-slicing checks actually depend on, stated directly rather than
/// approximated by a length floor.
///
/// **A second reader agrees with `code_only` about every raw string.** The
/// stripper reads `"..."`, char literals and raw strings; the scan below is a
/// second reader of the raw-string grammar and reports any literal the two
/// bound differently. That this finds nothing today is a fact about today's
/// inputs (which hold no raw string at all), which is why it is asserted here
/// instead of assumed in `code_only`'s comment.
///
/// # This test's green is narrow
///
/// It says the stripper is not damaging its inputs. It says **nothing** about
/// whether the checks that read the stripped corpus are correct -- those were
/// re-verified separately, each with its own fault injection against
/// the repaired corpus, because a check can go green from the corpus growing
/// while it was searching for the wrong thing all along. Do not read this
/// test's green as covering them.
#[test]
fn code_only_understands_every_construct_its_inputs_contain() {
    // Both tokens are built from chars rather than written. Writing either as a
    // literal here would put it in the corpus this test scans, and the check
    // would then be reporting on its own source.
    let opener: String = ['/', '*'].iter().collect();
    let closer: String = ['*', '/'].iter().collect();
    let line_comment: String = ['/', '/'].iter().collect();

    // ---------------------------------------------------------------------
    // The domain: derived from the call sites, not typed from
    // memory. Every `code_only` argument in this file resolves to a file in
    // one of these two sets. (Three more sets -- a bindgen build script, two
    // C shims and a TypeScript wallet -- were inputs when those sources were
    // vendored; they and the two quoting rules that read them are gone.)
    // ---------------------------------------------------------------------
    let root = repo_root();
    let mut inputs: Vec<(String, String)> = Vec::new();

    // 1. tests/**.rs -- the concatenated corpus. Kept as separate files here
    //    because the distributivity check below needs the boundaries.
    let corpus_files = test_source_files();

    // The input must be RAW, and once nothing said so because nothing
    // could get it wrong: `test_sources()` was raw too, so there was only one
    // path. The strip made `test_sources()` strip -- correctly, to close the
    // commented-out-test evasion -- which created a second path and made
    // `test_source_files()` the one that must NOT.
    //
    // Measured at the time: routing this walk through `code_only` as well left
    // this test GREEN. It would then have been measuring the stripper against
    // its own output, which is the exact vacuity the whole file exists to
    // prevent, and no mechanism objected. So the premise is asserted rather
    // than commented.
    //
    // Doc-comment openers are the signal: a raw tests/ corpus has thousands and
    // a stripped one has none. A `///` surviving inside a string literal is
    // possible in principle, which is why this is a floor in the hundreds
    // rather than a test for a single occurrence.
    let doc_openers: usize = corpus_files
        .iter()
        .map(|(_, t)| t.lines().filter(|l| l.trim_start().starts_with("///")).count())
        .sum();
    assert!(
        doc_openers >= 200,
        "the tests/ corpus reached this check with only {doc_openers} doc-comment \
         openers. It is supposed to arrive RAW -- `test_source_files()` must not \
         strip, because this is the check that measures the stripper, and a \
         stripper measured against its own output cannot fail. Something has \
         routed this walk through `code_only`."
    );

    inputs.extend(corpus_files.iter().cloned());

    // 2. crates/*/src/**.rs. `crate_sources()` already strips, so this walks
    //    for the raw text; secret.rs is a member of this set and needs no
    //    separate entry.
    let mut stack = vec![root.join("crates")];
    let mut crate_src = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // Only descend into a member's src/, and into target/ never.
                let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                if name == "target" || (d == root.join("crates") && name.starts_with('.')) {
                    continue;
                }
                if p.parent() == Some(root.join("crates").as_path()) {
                    stack.push(p.join("src"));
                } else {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p.strip_prefix(&root).unwrap_or(&p).to_string_lossy().into_owned();
                inputs.push((rel, std::fs::read_to_string(&p).unwrap_or_default()));
                crate_src += 1;
            }
        }
    }

    // Vacuity floors, one per set, so a walk that silently found nothing says
    // which walk.
    assert!(
        corpus_files.len() >= 5,
        "the tests/ walk found {} file(s); the distributivity check below needs \
         at least two files to have a boundary to cross",
        corpus_files.len()
    );
    assert!(
        crate_src >= 10,
        "the crates/*/src walk found {crate_src} .rs file(s); code_only is \
         called on this set from two sites and this test would be scanning \
         almost none of it"
    );

    // ---------------------------------------------------------------------
    // Property 1: code_only distributes over concatenation.
    // ---------------------------------------------------------------------
    let mut joined = String::new();
    let mut piecewise = String::new();
    for (_, text) in &corpus_files {
        joined.push_str(text);
        joined.push('\n');
        piecewise.push_str(&code_only(text));
        piecewise.push('\n');
    }
    let at_once = code_only(&joined);
    if at_once != piecewise {
        // Report where they diverge, not that they do. "Two 170KB strings
        // differ" is the message that once sent a session looking in the wrong file.
        let split = at_once
            .char_indices()
            .zip(piecewise.char_indices())
            .find(|((_, a), (_, b))| a != b)
            .map_or(at_once.len().min(piecewise.len()), |((i, _), _)| i);
        let mut which = String::from("<before the first file>");
        let mut acc = 0usize;
        for (name, text) in &corpus_files {
            let stripped = code_only(text).len() + 1;
            if split < acc + stripped {
                which = format!("{name} (+{} stripped chars in)", split - acc);
                break;
            }
            acc += stripped;
        }
        panic!(
            "code_only does not distribute over concatenation: stripping the \
             joined corpus gives {} chars, stripping each file and joining \
             gives {}. They first differ at {which}.\n\
             That difference is a comment opened in one file and closed in \
             another -- the corpus the slicing checks read is not the corpus \
             its files contain. Fix code_only, do not relax this.",
            at_once.len(),
            piecewise.len()
        );
    }

    // ---------------------------------------------------------------------
    // Property 2: a second reader, deliberately not a replay of code_only,
    // agrees with it about the extent of every raw string in the inputs.
    //
    // The assertion is agreement: whatever this reader thinks a raw string's
    // extent is, that exact text must survive stripping. It fires precisely
    // when a mis-parse causes DELETION, which is the damaging case; a
    // mis-parse that deletes nothing leaves the output text identical and is
    // harmless by construction. This reader implements the same grammar as
    // `raw_string_len` and is written separately rather than calling it, so a
    // defect has to occur twice to stay invisible. That is weaker than true
    // independence and is said plainly: what pins the *grammar* is the
    // constructed unit tests above, whose expected values come from the
    // language and not from either reader. This half pins the two readers to
    // each other over the real corpus. (The half that scanned constructs
    // code_only could NOT parse -- TypeScript template literals with a nested
    // backtick -- went with the TypeScript inputs.)
    // ---------------------------------------------------------------------
    let mut findings: Vec<String> = Vec::new();
    let mut agree_raw = 0usize;
    for (name, text) in &inputs {
        let stripped = code_only(text);
        let b = text.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            // Comments and the constructs code_only *does* handle: skip.
            if b[i..].starts_with(opener.as_bytes()) {
                match text[i + 2..].find(closer.as_str()) {
                    Some(rel) => i += 2 + rel + 2,
                    None => break,
                }
                continue;
            }
            if b[i..].starts_with(line_comment.as_bytes()) {
                match text[i..].find('\n') {
                    Some(rel) => i += rel,
                    None => break,
                }
                continue;
            }
            if b[i] == b'"' {
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                i = (j + 1).min(b.len());
                continue;
            }
            // A bare `'` in Rust is a lifetime and is deliberately not
            // examined: it is one token wide, the stripper emits it and walks
            // on, and a comment after it is a real comment. There is nothing
            // for a token to hide inside.
            if let Some(end) = raw_extent(b, i) {
                let inner = &text[i..end.min(text.len())];
                if stripped.contains(inner) {
                    agree_raw += 1;
                } else {
                    let line = text[..i].matches('\n').count() + 1;
                    findings.push(format!(
                        "\x20 - {name}:{line} holds a raw string that code_only did not emit \
                         verbatim. The two readers disagree about where it ends, so either \
                         `raw_string_len` or this scan has the delimiter rule wrong -- and \
                         the bytes between the two answers were deleted from the corpus \
                         every check downstream reads."
                    ));
                }
                i = end.max(i + 1);
                continue;
            }
            if b[i] == b'\'' {
                if let Some(n) = char_literal_len(b, i) {
                    i += n;
                    continue;
                }
            }
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }

    assert!(
        findings.is_empty(),
        "code_only is pointed at {} files, and {} raw string(s) in them are \
         parsed to a different extent than this reader gives them:\n{}\n\
         A disagreement about extent means bytes were deleted from the corpus \
         every downstream check reads. Do not add an exception here -- the \
         previous version of this hazard was handled by a comment saying it \
         was acceptable, and it was not.",
        inputs.len(),
        findings.len(),
        findings.join("\n")
    );

    // Reported, not merely asserted. Both of this test's properties are about
    // internal consistency, and a corpus uniformly 13,310 bytes short is
    // perfectly self-consistent, so it passes over one. The
    // number is what separates "green" from "green for the right reason", so it
    // is printed where `--nocapture` shows it rather than left to be re-derived.
    println!(
        "  code_only: {} inputs, tests/ corpus {} chars stripped from {} raw",
        inputs.len(),
        at_once.len(),
        joined.len()
    );
    // The population, printed because zero and "the scan never ran" look
    // identical from a green tick. On this tree it is 39, so the agreement arm
    // above is comparing two readers over real input rather than over an empty
    // set. The constructed unit tests above remain the enforcement, because
    // the escape-rule defect is reached by a spelling the corpus does not
    // contain. A floor over a population the check does not examine is worse
    // than no floor, so this is reported rather than asserted.
    println!("  code_only: agreement checked on {agree_raw} raw string(s)");
}

/// Group RX is an oracle with **no reference side**, and must not be read as
/// either of the other two kinds.
///
/// # The claim it makes, and why it needs its own test
///
/// `group_c_crosscheck.json` says: the C computed these values in
/// `group_c_addr.json`, a second implementation computed the ones beside them,
/// and the two can disagree. `group_f_derivation.json` says: one implementation,
/// no second opinion, believe nothing about correctness.
///
/// Group RX says a third thing. The vendored `ripemd160_final` overflows a
/// one-block stack buffer for every input length with `len % 64 >= 56`
///, so for one length in every 64 there is no reference answer and
/// cannot be one — calling the oracle is what crashes. What the file records is
/// `@noble/hashes`, so that RustCrypto's `ripemd` can be checked against
/// something that is not itself.
///
/// That is **two independent implementations of a published algorithm, neither
/// of which is the specification for the other** — a stronger relationship than
/// group C's, where the C *is* the specification. And it is simultaneously
/// evidence about nothing Mochimo-specific whatsoever. Both halves of that
/// sentence are easy to drop, and dropping either one is a misreading that
/// would spread: the first makes the group look weaker than it is, the second
/// makes it look like a second opinion about Mochimo, which it is not.
///
/// # Disclosure status
///
/// The defect that makes this group necessary was unfixed when the corpus was
/// generated. The record of its disclosure status lived in the errata document
/// of a repository this one does not carry; the fixture's `disclosure`
/// field points there and this site states nothing.
#[test]
fn group_rx_is_an_oracle_with_no_reference_side() {
    let dir = repo_root().join("fixtures");
    let path = dir.join("group_rx_ripemd.json");
    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{} is unreadable: {e}", path.display())
        }))
        .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));

    let mut problems: Vec<String> = Vec::new();
    let oracle = root
        .get("oracle")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("group_rx_ripemd.json carries no oracle block"));

    let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
    let text = |k: &str| {
        oracle
            .get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    if oracle.get("class").and_then(serde_json::Value::as_str)
        != Some(EXECUTED_CROSSCHECK_NO_REFERENCE)
    {
        problems.push(format!(
            "\x20 - oracle.class is {:?}, not {EXECUTED_CROSSCHECK_NO_REFERENCE:?}. \
             group_f_is_specification_not_crosscheck routes this file here by \
             that exact string; a different one lands it in the \
             specification-capture arm, where every claim it makes is false.",
            oracle.get("class")
        ));
    }
    // The three flags. `reference_side_exists: false` is the one that separates
    // this class from `executed-crosscheck`, and flipping it to true is how the
    // file would start claiming the C agrees with it about inputs the C cannot
    // be given.
    for (k, want) in [
        ("is_independent_oracle", true),
        ("second_implementation_exists", true),
        ("reference_side_exists", false),
    ] {
        if flag(k) != Some(want) {
            problems.push(format!(
                "\x20 - oracle.{k} is {:?}, not {want}",
                oracle.get(k)
            ));
        }
    }
    // The arguments, which are what make the flags durable. `why_not_group_cx`
    // is required specifically: the tempting move is to fold these vectors into
    // CX, and the reason not to has to be written where whoever is tempted will
    // read it.
    for (k, min) in [("why", 200usize), ("why_not_group_cx", 200), ("domain", 150)] {
        let n = text(k).len();
        if n < min {
            problems.push(format!(
                "\x20 - oracle.{k} is {n} chars, under {min}. The flags above are \
                 only as durable as the argument written beside them."
            ));
        }
    }
    // The fixture's `disclosure` and `errata` fields point at the entry that
    // recorded the defect's disclosure status. That document is
    // not in this repository, and the check that every site pointed at it
    // rather than restating it went with the sites; the two fields are read
    // here so the walk stays fail-closed over the block's shape, and nothing
    // more is claimed about them.
    for k in ["disclosure", "errata"] {
        assert!(
            oracle.get(k).is_some(),
            "group_rx_ripemd.json's oracle block carries no `{k}`; the block's shape moved"
        );
    }

    // No reference side means exactly that: nothing in the file may cite the C
    // as having produced a value. `derived_from` must be null for the same
    // reason -- a crosscheck derived from a C fixture is CX, not this.
    if root.get("derived_from") != Some(&serde_json::Value::Null) {
        problems.push(format!(
            "\x20 - derived_from is {:?}, not null. A group derived from a C \
             fixture has a reference side by construction.",
            root.get("derived_from")
        ));
    }

    let vectors = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("group_rx_ripemd.json has no vectors array"));
    let mut checked = 0usize;
    for v in vectors {
        let Some(obj) = v.as_object() else { continue };
        let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
        checked += 1;

        if obj.get("reference_can_compute").and_then(serde_json::Value::as_bool) != Some(false) {
            problems.push(format!(
                "\x20 - vector {id}: reference_can_compute is not false. Every \
                 vector in this group is here BECAUSE the reference cannot \
                 answer; one that says otherwise belongs in group C, where it \
                 would be checked against two implementations instead of one."
            ));
        }
        if obj
            .get("reference_cannot_compute_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .len()
            < 80
        {
            problems.push(format!(
                "\x20 - vector {id}: reference_cannot_compute_reason is missing or \
                 too short. 'The reference cannot answer' is the strongest \
                 claim in the file and the easiest to assert without grounds."
            ));
        }
        // The class, recomputed here rather than read off the vector. A vector
        // whose length has drifted out of the faulting class would be checked
        // against one implementation while two were available.
        let len = obj.get("in_len").and_then(serde_json::Value::as_u64).unwrap_or(0) as usize;
        if len % 64 < 56 {
            problems.push(format!(
                "\x20 - vector {id} is {len} bytes, residue {}, which is OUTSIDE \
                 the faulting class. The reference can compute this one.",
                len % 64
            ));
        }
        let source = obj.get("source").and_then(serde_json::Value::as_str).unwrap_or("");
        if !source.contains("@noble/hashes") {
            problems.push(format!(
                "\x20 - vector {id}: source is {source:?}, which does not name \
                 @noble/hashes. It is the only implementation behind this group; \
                 if the values came from somewhere else the pin block is wrong."
            ));
        }
        if source.contains("reference/mochimo-core") {
            problems.push(format!(
                "\x20 - vector {id}: source names reference/mochimo-core, which \
                 cannot have produced it -- the call aborts."
            ));
        }
    }

    // The pin. A version-less record of one implementation's output is not
    // reproducible, and this group has no second source to fall back on.
    let pin = root.get("pin").and_then(|v| v.as_object());
    if pin
        .and_then(|p| p.get("noble_hashes_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        problems.push(
            "\x20 - pin.noble_hashes_version is missing. Every value in this file \
             is one library's output; without its version the file records an \
             answer without recording who gave it."
                .to_string(),
        );
    }

    // Vacuity floor. Placed before the problems assertion deliberately: an
    // empty or unreadable vectors array makes every per-vector check above run
    // zero times, and `problems.is_empty()` would then be a true statement
    // about nothing.
    assert!(
        checked >= 24,
        "group RX holds {checked} vector(s), fewer than the 24 faulting-class \
         lengths in 0..=200. The group shrank, and a shrunk oracle for a class \
         the reference cannot answer is worse than a missing one: the marker \
         that used to demand it is gone."
    );

    assert!(
        problems.is_empty(),
        "group RX is not the kind of oracle it says it is:\n{}\n\
         This is the only group in the corpus with no reference side. Its \
         claims are (1) two independent implementations of a published \
         algorithm, neither being the other's specification, and (2) no \
         evidence about Mochimo whatsoever. Both are easy to drop and dropping \
         either spreads: the first makes the group look weaker than it is, the \
         second makes it look like a second opinion about Mochimo, which it is \
         not.",
        problems.join("\n")
    );

    println!("  group RX: {checked} vectors, no reference side, @noble/hashes only");
}

// ===========================================================================
// The pin blocks of the TypeScript- and Mesh-sourced groups
// ===========================================================================

/// Every `*_commit` a fixture's `pin` block records is the commit the
/// documents state for that subject, or is declared undocumented and then
/// held consistent across the files that carry it.
///
/// # What nothing checked before the pin check
///
/// The `reference`-block check counts the fixtures that carry a `pin` block
/// instead and never read a pin block's values. `mochimo_wallet_commit`,
/// `mochimo_wots_commit` and `mochiwallet_commit` were recorded by three
/// generators and compared to nothing, so a fixture regenerated from a moved
/// tree would have passed. When the submodules were here the comparison was
/// to their checkouts; here it is to the two documents, which is the record
/// that remains.
///
/// # The domain is derived
///
/// Every key ending in `_commit` inside every `pin` object under
/// `fixtures/*.json`. A key neither stated by a document nor declared in
/// [`UNDOCUMENTED_PIN_KEYS`] stops the run naming the key, and a declared row
/// no fixture carries is a stale permission and stops the run too. The count
/// of values compared is stated, not derived.
#[test]
fn pin_block_commits_match_the_commits_the_documents_state() {
    let root = repo_root();
    let stated = stated_commits();
    let dir = root.join("fixtures");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    let mut problems: Vec<String> = Vec::new();
    let mut values_checked = 0usize;
    let mut documented = 0usize;
    let mut pinned_files = 0usize;
    let mut keys_seen: BTreeSet<String> = BTreeSet::new();
    let mut undocumented_seen: BTreeMap<String, (String, String)> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));
        let Some(pin) = json.get("pin").and_then(|p| p.as_object()) else { continue };
        pinned_files += 1;
        let mut commits = 0usize;
        for (key, value) in pin {
            if !key.ends_with("_commit") {
                continue;
            }
            commits += 1;
            values_checked += 1;
            keys_seen.insert(key.clone());
            let value = value.as_str().unwrap_or("");
            if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                problems.push(format!("\x20 - {name}: pin.{key} is {value:?}, not a 40-hex object id"));
            }
            if let Some(want) = stated.get(key.as_str()) {
                documented += 1;
                if value != want {
                    problems.push(format!(
                        "\x20 - {name}: pin.{key} is {value}, but the documents state {want}. The \
                         fixture was generated from a different tree than the one the documents \
                         describe -- regenerate, and read the diff."
                    ));
                }
            } else if UNDOCUMENTED_PIN_KEYS.iter().any(|(k, _)| k == key) {
                match undocumented_seen.get(key) {
                    None => {
                        undocumented_seen.insert(key.clone(), (value.to_owned(), name.to_owned()));
                    }
                    Some((first, first_file)) if first != value => problems.push(format!(
                        "\x20 - {name}: pin.{key} is {value}, but {first_file} records {first}"
                    )),
                    Some(_) => {}
                }
            } else {
                problems.push(format!(
                    "\x20 - {name}: pin.{key} is stated by no document and declared by no row; \
                     add it to one rather than leaving a recorded commit compared to nothing"
                ));
            }
        }
        if commits == 0 {
            problems.push(format!(
                "\x20 - {name}: a `pin` block with no `*_commit` key records versions against no tree"
            ));
        }
    }

    for (key, _) in UNDOCUMENTED_PIN_KEYS {
        // The reference-block keys are carried by `reference` blocks, which
        // the sibling check walks; here only the pin-block keys are owed.
        if key.ends_with("_commit") && !keys_seen.contains(*key) {
            problems.push(format!(
                "\x20 - the undocumented-key table declares {key} and no fixture records it; a \
                 row nothing matches is a permission nobody is using"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "fixture pin blocks disagree with the documents or with each other:\n{}",
        problems.join("\n")
    );
    // Stated, not derived: F 3 (wallet, wots, mochiwallet), CX 2 (wots,
    // mochiwallet), RX 1 (wots), M 3 (client, wots, mochiwallet), N 2 (mesh,
    // go_mcminterface), AKX 2 and CK 2 (wots, mochiwallet) -- fifteen, over
    // seven pinned files, thirteen of them stated by a document.
    assert_eq!(
        values_checked, 15,
        "{values_checked} pin-block commit(s) were compared across {pinned_files} pinned file(s); the \
         corpus records fifteen (F 3, CX 2, RX 1, M 3, N 2, AKX 2, CK 2). Fewer means the walk stopped \
         finding them; more means a fixture gained one and this number is owed a deliberate move."
    );
    assert_eq!(documented, 13, "{documented} of the fifteen were stated by a document; expected 13");
    println!(
        "  pin-block commits: {values_checked} across {pinned_files} file(s), {documented} agree with \
         the documents, the rest consistent across files"
    );
}

/// The one Reader permission the mesh client added to the I1 route scan --
/// `SignedTransaction::attach` returns a signature-bearing value -- is backed
/// by an executed refusing check, not by its allow-list entry alone: a
/// Reader entry says only "takes no key material, reaches no signer", and
/// nothing in it says the reader verifies what it assembles.
///
/// The route scan itself cannot census (it is censused, by the I1 marker),
/// so the demand lives here. Floor 5: the five components a mismatched
/// signature can differ in -- position, public key, signature bytes, public
/// seed, source hash -- stated in the target's own output.
#[test]
fn mesh_reader_permission_is_backed_by_a_refusing_check() {
    const GUARD: &str = "mesh_reader_permission_is_backed_by_a_refusing_check";
    const TARGET: &str = "attach_refuses_every_mismatched_component";
    if let Err(why) = census::check(GUARD, TARGET) {
        panic!(
            "the Reader permission for mesh/spend.rs::SignedTransaction::attach in the I1 route scan is \
             backed by nothing that runs: {TARGET} must be in tests/spend.rs, run, pass and print \
             `attach refusals:` with at least 5.\n{why}"
        );
    }
    println!("  mesh reader permission: {TARGET} censused, attach's five refusals executed");
}

/// Every print-macro invocation in `code`, as (byte offset, macro name).
///
/// Located at an identifier boundary, so `eprintln!` is reported as
/// `eprintln!` and not as the `println!` it contains -- the misattribution
/// the substring loop in `the_cli_cannot_reach_around_the_wallet` has
/// (a known misattribution; left there, out of this arm's scope) and this scan does not
/// inherit. `print!` cannot match inside `println!` either: the `!` has to
/// follow the name directly.
fn print_sites(code: &str) -> Vec<(usize, &'static str)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for name in ["println", "print", "eprintln", "eprint"] {
        let needle = format!("{name}!");
        let mut from = 0usize;
        while let Some(i) = code[from..].find(&needle) {
            let at = from + i;
            let boundary = at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
            if boundary {
                out.push((at, name));
            }
            from = at + needle.len();
        }
    }
    out.sort_unstable();
    out
}

/// The body of an `impl` block, by brace matching from its header.
///
/// Crude on purpose: the alternative is a second `syn` walk for one arm, and
/// the failure mode of this one is visible -- an unmatched header returns the
/// empty string and the caller's floor fires.
fn impl_block(code: &str, header: &str) -> String {
    let Some(start) = code.find(header) else {
        return String::new();
    };
    let rest = &code[start..];
    let Some(open) = rest.find('{') else {
        return String::new();
    };
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[open..open + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// The CLI cannot reach around the wallet, and this is what says so.
///
/// # What it closes
///
/// Reconciliation recorded, as an injection green, that handing out `&mut Keystore`
/// would let a caller `persist_advance` and `sign_spend` around the gate, and
/// that **no check could see it**: `Wallet` exposes no such method, but nothing
/// stops a *consumer* from opening its own store, and the route scan cannot
/// flag a function that returns no signature-bearing type. The CLI is the first
/// consumer this project ships, so it is the first time that hole has a
/// subject — and a subject makes it checkable.
///
/// # The rule, stated exactly
///
/// It is **not** *the CLI never touches a mutable store*: `restore` must
/// [`Keystore::add`], which the `Wallet` does not expose (reported
/// rather than resolved by widening the gated type), and `reconcile`
/// must move an index through the acknowledgement gate before a `Wallet` can
/// exist. The rule is:
///
/// * **no CLI file** names `into_parts`, `store_mut`, `persist_advance`,
///   `persist_advance_to`, `sign_spend`, `resign_reserved`, or a raw signer
///   port; and
/// * the store-writing names are each permitted in exactly the pre-gate
///   module that owns them: `add` in `create` and `restore`, `Keystore::create`
///   in `create`, `advance_after_operator_review` -- the one route from a
///   report to a moved index -- in `reconcile`; and
/// * **every pre-gate module** (`create`, `address`, `discover`, `restore`,
///   `reconcile`) names no `Wallet` at all.
///
/// So no command holds a `Wallet` and a mutable store at once, the commands
/// that hold a mutable store are the pre-gate ones, and none of them signs.
/// (This once said *exactly one command holds a mutable store*, which had
/// been false since `create` got its own; and `persist_advance_to` was
/// permitted in `restore`, which called it in a second commit after `add` --
/// both corrected by the refutation pass.)
///
/// # Why the needles carry their punctuation
///
/// `persist_advance` is a prefix of `persist_advance_to`, so a bare substring
/// would flag restore's legitimate call as the forbidden one. Every needle is
/// the method-call spelling — `.name(` — which is what a caller actually
/// writes, and the positive controls below assert each needle matches
/// somewhere it should rather than being a string that matches nothing.
#[test]
fn the_cli_cannot_reach_around_the_wallet() {
    let files: Vec<(String, String)> = crate_source_files()
        .into_iter()
        .filter(|(p, _)| {
            p.contains("mochimo-crypto/src/cli/") || p.ends_with("src/bin/mcm-wallet.rs")
        })
        .collect();
    assert!(
        files.len() >= 4,
        "the CLI walk found {} file(s); it should find src/cli/{{mod,args,restore}}.rs and \
         src/bin/mcm-wallet.rs. A vacuous walk passes every arm below.",
        files.len()
    );
    // The floor above is satisfied by `src/cli/` alone -- five files -- so
    // without this the binary's three arms below (the impl print ban, the
    // census demand, the main-only ban) are asserted over nothing if the
    // walk misses `mcm-wallet.rs`. Found by a refutation panel, missed by
    // its nine reviewers and by every session before it.
    assert_eq!(
        files.iter().filter(|(p, _)| p.ends_with("src/bin/mcm-wallet.rs")).count(),
        1,
        "the CLI walk did not reach src/bin/mcm-wallet.rs; every arm scoped to the binary \
         below is then a verdict over nothing."
    );

    /// Forbidden in every CLI file, with why.
    ///
    /// **`store_mut` is deliberately not in this list**, and the reason is the
    /// check grading itself. It was, until the positive control below reported
    /// that `.store_mut(` matches nothing anywhere in the tree -- because the
    /// method does not exist. Forbidding a name nobody can write establishes
    /// nothing, so the property *there is no `store_mut`* moved to its own arm
    /// over `wallet.rs`, where it is a statement about the gated type rather
    /// than about the CLI. The direction nobody tests, applied to this
    /// test by its own control on the first run.
    const FORBIDDEN: [(&str, &str); 6] = [
        (".into_parts(", "takes the keystore back out of the gated type"),
        (".persist_advance(", "reserves an index with no plan behind it"),
        (
            ".persist_advance_to(",
            "moves an index with no acknowledgement behind it; the CLI's one route to a moved \
             index is `advance_after_operator_review`, in `reconcile`",
        ),
        (".sign_spend(", "signs without going through the wallet"),
        (".resign_reserved(", "the raw re-signer, below `resign_pending`"),
        ("wots_sign", "a raw signer port"),
    ];
    /// Names that mutate the store, and the modules permitted to write each.
    ///
    /// **Per name, not per module**. The list was one module until the
    /// pre-gate set grew from `restore` alone to `create`, `address` and
    /// `restore`, and a single allow-listed module would then have permitted
    /// `create`'s `add` to appear in `restore` and vice versa. Keying on the
    /// name says exactly which module may write which, so widening the set
    /// does not widen what any member of it may do.
    ///
    /// **`advance_after_operator_review(` has no leading dot on purpose**: it
    /// is a free function in `recon`, so its call spelling is
    /// `recon::advance_after_operator_review(`, and the bare needle matches
    /// that as well as the `Wallet` method's `.advance_after_operator_review(`
    /// -- either spelling in any CLI module but `reconcile` is the defect.
    /// `.persist_advance_to(` left this table for FORBIDDEN: `restore`
    /// builds its account at the found index and commits once through `add`,
    /// so no CLI file moves an index except through the acknowledgement.
    const STORE_WRITERS: [(&str, &[&str]); 3] = [
        (".add(", &["src/cli/create.rs", "src/cli/restore.rs"]),
        ("advance_after_operator_review(", &["src/cli/reconcile.rs"]),
        ("Keystore::create", &["src/cli/create.rs"]),
    ];

    /// The modules that run **before** a `Wallet` exists. Each owes the same
    /// arm: name no `Wallet` and no signer. That is what makes "outside the
    /// gate" a checked property rather than a description -- a pre-gate module
    /// that constructed a wallet would be holding both a wallet and a mutable
    /// store, which is the state this scan exists to forbid.
    ///
    /// **Membership criterion, stated because the acknowledged path admitted a member that does
    /// reconciliation** (the refutation pass): a pre-gate module runs before a
    /// `Wallet` exists, names no `Wallet` and no signer, and its only store
    /// writes are through the names STORE_WRITERS permits it -- for
    /// `reconcile`, one function that takes an `OperatorAcknowledgement`
    /// built from a `Divergence`. `create` and `address` need no reconciled
    /// state; `restore` constructs one; `reconcile` repairs one, and could not
    /// do so behind a constructor that refuses on the state it repairs;
    /// `discover` asks the node about tags the store does not hold, which is
    /// the one question a gate over the store's own accounts cannot answer.
    const PRE_GATE: [&str; 5] = [
        "src/cli/create.rs",
        "src/cli/address.rs",
        "src/cli/discover.rs",
        "src/cli/restore.rs",
        "src/cli/reconcile.rs",
    ];

    let all = crate_source_files();
    let all_named = |suffix: &str| -> String {
        all.iter()
            .find(|(p, _)| p.ends_with(suffix))
            .map(|(_, t)| code_only(t))
            .unwrap_or_default()
    };

    let mut pre_gate_seen = 0usize;
    for (path, text) in &files {
        let code = code_only(text);

        for (needle, why) in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{path} names `{needle}` -- {why}. The CLI's structure is what keeps the \
                 keystore behind the wallet (once an injection green); if this call is \
                 genuinely needed, that is a finding about the gate's shape and belongs in \
                 the errata before it belongs in the code."
            );
        }
        for (needle, permitted) in STORE_WRITERS {
            if !permitted.iter().any(|m| path.ends_with(m)) {
                assert!(
                    !code.contains(needle),
                    "{path} names `{needle}`, which mutates the store. Only {permitted:?} may, \
                     and only because those run before the wallet exists and sign nothing."
                );
            }
        }
        // Everything the operator sees in `create` must go through the
        // `Terminal` seam. A bare print reaches stdout and is invisible
        // to the test that asserts no phrase was shown without a terminal, so
        // the absence of prints is what makes that assertion mean what it says.
        if path.ends_with("src/cli/create.rs") {
            for construct in ["println!", "print!", "eprintln!", "eprint!"] {
                assert!(
                    !code.contains(construct),
                    "{path} contains `{construct}`. The phrase must reach the operator only \
                     through `Terminal::show`, or `create_without_a_terminal_writes_nothing_\
                     and_shows_no_phrase` is blind to whatever the print emits."
                );
            }
        }
        // **The binary's `Terminal` implementation may not print either**
        //, and that arm is scoped to the impl rather than to the file
        // because `main` legitimately prints the report.
        //
        // The create path acquired `/dev/tty` so the phrase could not reach *"whatever
        // captured stdout"*, and then `Tty::show` was `println!`, which sends
        // it to exactly that. `mcm-wallet ... create > seed.txt` therefore
        // wrote the twenty-four words into a plaintext file while the
        // confirmation prompt went to stderr -- so the operator was asked to
        // read back words from a screen that had never shown them, and the
        // argument for echoing the confirmation (*the phrase is three lines
        // above*) was an argument about a screen the phrase might never have
        // reached. The property is that the display goes to the acquired
        // descriptor; the check is that nothing in the impl can reach a
        // process-wide stream instead.
        if path.ends_with("src/bin/mcm-wallet.rs") {
            let block = impl_block(&code, "impl create_cmd::Terminal for Tty");
            assert!(
                block.len() > 200,
                "{path}: the `Terminal for Tty` impl was not found, so its print ban is \
                 asserted over {} character(s) of nothing.",
                block.len()
            );
            for construct in ["println!", "print!", "eprintln!", "eprint!"] {
                assert!(
                    !block.contains(construct),
                    "{path}: `impl Terminal for Tty` contains `{construct}`. Everything this \
                     impl shows the operator must go to the terminal it acquired -- a \
                     process-wide stream can be redirected, and the phrase then lands in a \
                     file while the question that asks about it does not."
                );
            }
            // **What enforces the property is not this ban**.
            //
            // A "positive control" of `block.contains("self.file")` would
            // claim to ensure *the impl really does write to the acquired
            // descriptor, or the ban above is satisfied by an impl that shows
            // nothing at all*. It does not: `self.file` can be named, opened read-only, and
            // every write to it failed with `EBADF` and was discarded. Naming
            // a descriptor is a text property; writing to it is a runtime one,
            // and a source scan cannot tell them apart. The control was
            // a needle the check did not control, exactly: the thing that appeared to enforce
            // the property was not what did, and it was green throughout.
            //
            // So the control is gone and the enforcing mechanism is named:
            // `tests/cli.rs`'s pty harness builds the shipped binary, runs it
            // under a pseudo-terminal and asserts the prompts, the phrase and
            // the echo behaviour on the screen -- and this census demand
            // requires that harness to have executed and reported. The ban
            // above is kept as the cheap early signal it always was: it holds
            // that nothing in the impl *can* reach a process-wide stream,
            // which the harness holds at runtime by redirecting both streams
            // inside the pty and finding the phrase on neither.
            const PTY: &str = "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store";
            if let Err(why) = census::check("the_cli_cannot_reach_around_the_wallet", PTY) {
                panic!(
                    "{path}: the print ban over `impl Terminal for Tty` is a text property and \
                     the thing that establishes the impl actually shows the operator anything \
                     is the pty harness -- which is not running: {PTY} must be in tests/cli.rs, \
                     run, pass and print `tty create:` with at least 6.\n{why}"
                );
            }
            println!("  tty display: {PTY} censused, the shipped binary answered its prompts on a pty");

            // **The domain is the file, not one impl**. The
            // ban above is scoped to `impl Terminal for Tty` because its author
            // wrote it beside the impl it had just fixed. The free
            // `read_secret_line` that the eight store-opening commands prompt
            // through sat one function outside that scope, writing its prompt
            // with `eprint!`, so `balance 2>file` asks for a password on no
            // screen while an impl-scoped arm stays green -- the scan's domain
            // an impl header, the defect the same class in the next function
            // down (a check does not weaken loudly; it narrows). So: the four print macros may occur only inside `fn
            // main`, which prints the report and the usage and nothing else,
            // so no prompt anywhere in the binary can reach a process-wide
            // stream. Sites are located at identifier boundaries so the
            // message names the macro that is actually there.
            //
            // What establishes the prompt reaches the terminal is still a
            // runtime measurement --
            // `pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr`
            // redirects stderr inside a pty and finds the prompt on the screen
            // and not in the file. This arm is the cheap early signal.
            // Arm order, stated: a print inside `impl Terminal for Tty` trips
            // the impl ban above first, whose message names the macro by
            // substring (and so misattributes `eprintln!`, a known misattribution); this
            // arm names the one that is there. Both are red on such a site.
            let main_at = code.find("fn main()").unwrap_or(0);
            let main_block = impl_block(&code, "fn main()");
            assert!(
                main_block.len() > 200,
                "{path}: `fn main()` was not found, so the print ban over the rest of the binary \
                 is asserted against {} character(s) of nothing.",
                main_block.len()
            );
            // The bound in the other direction: `impl_block` brace-matches
            // with no string awareness, so an unmatched `{` inside a string
            // in `main` would run its block past the close and swallow the
            // rest of the file, leaving `outside` empty while green. The next
            // function's header must not be inside the block.
            assert!(
                !main_block.contains("fn run_from_argv"),
                "{path}: `fn main()`'s block ran into `fn run_from_argv`, so the main-only \
                 ban is scoped over more than main and its verdict is vacuous."
            );
            // Three spellings of a process-wide write that are not `name!`
            // macros. They carry no positive control anywhere in
            // `crates/*/src` -- the fix is what emptied them (the old
            // `read_secret_line` flushed `std::io::stderr()`) -- so their
            // absence is asserted knowing that nothing demonstrates the
            // needles match; `dbg!` is the third because it writes to stderr
            // too.
            for needle in ["io::stderr(", "io::stdout(", "dbg!"] {
                assert!(
                    !code.contains(needle),
                    "{path}: `{needle}` reaches a process-wide stream around the macro ban; \
                     a prompt written this way is redirectable exactly as `eprint!` was."
                );
            }
            let main_open = main_at + code[main_at..].find('{').unwrap_or(0);
            let main_range = main_open..main_open + main_block.len();
            let sites = print_sites(&code);
            let inside = sites.iter().filter(|(at, _)| main_range.contains(at)).count();
            assert!(
                inside >= 2,
                "{path}: `fn main` prints from {inside} site(s); it renders the usage and the \
                 report, so fewer than two means this scan is not seeing the sites it is \
                 scoped by, and its verdict over the rest of the file is over nothing."
            );
            let outside: Vec<String> = sites
                .iter()
                .filter(|(at, _)| !main_range.contains(at))
                .map(|(at, name)| format!("`{name}!` at byte offset {at}"))
                .collect();
            assert!(
                outside.is_empty(),
                "{path}: a print macro outside `fn main`: {}. Every prompt in this binary goes \
                 to the terminal it acquired -- a process-wide stream can be redirected, and \
                 `balance 2>file` then asks for a password on no screen.",
                outside.join(", ")
            );
            println!("  print sites: {inside} inside fn main, {} outside", outside.len());
            // What establishes the eight commands' prompt actually reaches the
            // terminal is the second pty test, demanded here for the same
            // reason the first is: the create finding listed that prompt under "what
            // it cannot see", so the existing row's target cannot stand in
            // for it, and a scan alone is a text property.
            const PTY_PASSWORD: &str =
                "pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr";
            if let Err(why) = census::check("the_cli_cannot_reach_around_the_wallet", PTY_PASSWORD) {
                panic!(
                    "{path}: the main-only print ban is a text property and the thing that \
                     establishes the shared password prompt reaches the terminal is the pty \
                     harness -- which is not running: {PTY_PASSWORD} must be in tests/cli.rs, \
                     run, pass and print `tty password:` with at least 4.\n{why}"
                );
            }
            println!("  tty password: {PTY_PASSWORD} censused, the shared prompt reached a pty with stderr redirected");
        }
        if PRE_GATE.iter().any(|m| path.ends_with(m)) {
            pre_gate_seen += 1;
            assert!(
                !code.contains("Wallet"),
                "{path} names `Wallet`, and it is a pre-gate module. Holding both a wallet and \
                 a mutable store is the state this check exists to forbid."
            );
        }
    }
    assert_eq!(
        pre_gate_seen,
        PRE_GATE.len(),
        "the walk saw {pre_gate_seen} of {} pre-gate module(s); a module missing from the walk \
         has its no-Wallet arm asserted over nothing.",
        PRE_GATE.len()
    );

    // The other half of the constraint, and it is about the gated type rather
    // than about the CLI: there is no `store_mut` to call. Controlled by the
    // read-only accessor, which must be there -- otherwise this arm would pass
    // over a `wallet.rs` that had lost both.
    let wallet = all_named("mochimo-crypto/src/wallet.rs");
    assert!(
        !wallet.contains("fn store_mut"),
        "`Wallet::store_mut` exists. The CLI containment scan is written on the premise that          the only way to a mutable store is `Keystore::open`, which restore alone calls; a          `store_mut` hands one out from inside a reconciled wallet and defeats it."
    );
    assert!(
        wallet.contains("fn store("),
        "`Wallet::store` is gone, so the arm above would pass over a wallet with no store          accessor at all."
    );

    // Positive controls: every needle must match somewhere, or it is a string
    // that forbids nothing (the direction nobody tests).
    let find = |needle: &str| -> bool {
        all.iter()
            .any(|(p, t)| !p.contains("/cli/") && !p.ends_with("mcm-wallet.rs") && code_only(t).contains(needle))
    };
    for (needle, _) in FORBIDDEN {
        assert!(
            find(needle),
            "the needle `{needle}` matches nothing outside the CLI, so its absence inside the \
             CLI establishes nothing."
        );
    }
    for (needle, permitted) in STORE_WRITERS {
        let used = files.iter().any(|(p, t)| {
            permitted.iter().any(|m| p.ends_with(m)) && code_only(t).contains(needle)
        });
        assert!(
            used,
            "`{needle}` appears in none of {permitted:?}, so the places it is allowed do not \
             use it and its allow-list arm is vacuous."
        );
    }

    println!(
        "CLI containment: {} file(s) scanned, {} forbidden name(s), {} store-writing name(s) \
         over {} pre-gate module(s), plus the binary's Terminal impl",
        files.len(),
        FORBIDDEN.len(),
        STORE_WRITERS.len(),
        PRE_GATE.len()
    );
}

/// **The wallet has exactly one route to Argon2, and it is the one RFC 9106's
/// vector is replayed through**.
///
/// `format::tests::derive_key_agrees_with_the_anchored_argon2id_at_cheap_parameters`
/// compares the wallet's entry point to `crypt::argon2id_v13` numerically, and
/// a faithful re-inline of the constructor into `derive_key` -- the same
/// algorithm, version and roles, written a second time -- leaves it green
/// (a fault-injection row measured it). This is the structural claim that test cannot
/// make: across every `.rs` under `crates/`, comment-stripped, the Argon2
/// context is constructed exactly once, in `keystore/crypt.rs`, by
/// `new_with_secret`, which is the call the anchor drives. A second
/// construction anywhere -- `derive_key` growing its own, a future
/// `open_with` deriving differently, a `derive_key_v2` -- reds here by file,
/// whether or not it computes the same bytes today.
///
/// # Bound, stated
///
/// The needles are the crate's own type-path spellings, `Argon2::new(` and
/// `Argon2::new_with_secret(`, terminated on the paren so neither is a prefix
/// of the other. A caller that aliased the type (`use argon2::Argon2 as A;`)
/// would escape them -- a needle whose spelling the check
/// does not fully control -- so the alias form is forbidden by the same scan.
/// Test modules are inside the walk on purpose: `format.rs`'s tests call
/// `crypt::argon2id_v13`, never a constructor, and a test-only second route
/// would be exactly the kind this exists to name.
#[test]
fn the_wallet_has_one_route_to_argon2_and_it_is_the_anchored_one() {
    const CRYPT: &str = "crates/mochimo-crypto/src/keystore/crypt.rs";
    // Constructed, never written literally: this file is under `crates/`
    // and inside its own walk, and `code_only` strips comments but not
    // string literals, so a needle spelled out here is a site the scan then
    // reports -- in the code, and equally in an assertion message that
    // quotes one. The text explaining a needle is the likeliest place for
    // the needle to sit.
    let plain_needle = format!("Argon2::{}(", "new");
    let secret_needle = format!("Argon2::{}(", "new_with_secret");
    let alias_needle = format!("Argon2 {} ", "as");
    let sources = all_crate_rust_sources();
    assert!(
        sources.len() >= 40,
        "the source walk saw {} file(s), far below the tree's size; this is the walk failing, \
         not the crate having one route",
        sources.len()
    );
    let mut plain: Vec<(String, usize)> = Vec::new();
    let mut with_secret: Vec<(String, usize)> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    for (path, code) in &sources {
        let n = code.matches(plain_needle.as_str()).count();
        if n > 0 {
            plain.push((path.clone(), n));
        }
        let m = code.matches(secret_needle.as_str()).count();
        if m > 0 {
            with_secret.push((path.clone(), m));
        }
        if code.contains(alias_needle.as_str()) {
            aliases.push(path.clone());
        }
    }
    assert!(
        aliases.is_empty(),
        "{alias_needle:?} appears in {aliases:?}: an alias for the Argon2 type would let a \
         second constructor call escape the two needles below. Spell the type path."
    );
    assert!(
        plain.is_empty(),
        "{plain_needle} is called in {plain:?}: a second route to Argon2 exists beside \
         crypt::argon2id_v13. RFC 9106's vector is replayed through the one construction in \
         keystore/crypt.rs and says nothing about this one, whatever bytes it computes today \
         ."
    );
    assert_eq!(
        with_secret,
        vec![(CRYPT.to_string(), 1)],
        "the Argon2 context must be constructed exactly once, by `new_with_secret` in {CRYPT}; \
         found {with_secret:?}. More than one is a second route to Argon2 the RFC 9106 anchor \
         does not reach; none means the anchored path was removed or respelled."
    );
    println!("  argon2 route: one construction, {CRYPT}, the one the RFC 9106 anchor drives");
}

// ---------------------------------------------------------------------------
// The narrative under `src/`, `tests/`, `ui/` and `examples/` cites nothing
// that is not here.
//
// Three absence checks over the COMMENT text and the STRING LITERALS of every
// `.rs` under `crates/*/src`, this crate's `tests/`, its `ui/` cases (the
// compile-fail partition's inputs and the downstream probe) and its
// `examples/`: no entry of the old repository's errata document cited by
// number, no citation of a document that lives only there, and no session
// label or fault-matrix row name of its history. Fixtures are never walked
// (they cite that document freely and are never edited) and neither are the
// pinned `.stderr` files under `ui/`, which are compiler output.
// Each check floors the number of files walked and the number of comment and
// string lines examined, never the number of bytes read, so an empty or
// comment-stripped walk cannot pass; and every needle a matcher is exercised
// on is CONSTRUCTED from fragments that never spell it, so the checks cannot
// see themselves. The prose here names no needle either.
// ---------------------------------------------------------------------------

/// What one unit of text is: a comment line or a string literal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TextKind {
    Comment,
    Str,
}

/// One line of comment or of string-literal contents, with its file and
/// 1-based line number.
///
/// `span` numbers the lexical unit the line came out of -- one string
/// literal, one block comment, one `//` line -- and every line of the same
/// one carries the same number. It exists because a literal continued across
/// source lines arrives here as several `TextUnit`s, and a reader that
/// treated each of them as a whole literal would put a boundary inside one
/// sentence. [`joined_text_by_file`] is what needs to tell the difference.
struct TextUnit {
    file: String,
    line: usize,
    kind: TextKind,
    text: String,
    span: usize,
}

/// Every `.rs` under this crate's `ui/` and `examples/`, as `(path, text)`,
/// sorted by path: the compile-fail cases, the pass cases, the downstream
/// probe's two sources and the hand-run Mesh probe. A `target/` directory
/// under `ui/downstream` is trybuild's build tree and is skipped; the pinned
/// `.stderr` files are not `.rs` and are never read. These files are inputs
/// to `tests/compile_fail.rs` rather than tests, which is why
/// `test_source_files()` does not carry them (its module doc says so); the
/// narrative walk below carries them because a comment there can cite the
/// old repository as easily as one under `src/`, and twenty of the
/// twenty-four did.
fn ui_and_example_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack = vec![crate_dir.join("ui"), crate_dir.join("examples")];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// Every comment line and every line of every string literal under
/// `crates/*/src`, this crate's `tests/`, its `ui/` cases and its
/// `examples/`, in file order, plus the number of files walked.
///
/// The lexer mirrors `strip_comments`: `"..."` strings, char literals and
/// every raw-string spelling are read through the same helpers, so a comment
/// opener inside a string is not a comment and a string inside a comment is
/// not a string. A block comment or a multi-line string contributes one unit
/// per line it spans. Line comments keep their opener; string units carry
/// their contents without the delimiters.
fn crate_text_units() -> (usize, Vec<TextUnit>) {
    let mut out: Vec<TextUnit> = Vec::new();
    let mut files = 0usize;
    // Counted over the whole walk rather than per file, so two units can never
    // share a number without having come out of the same literal.
    let mut span = 0usize;
    let mut sources = crate_source_files();
    sources.extend(test_source_files());
    sources.extend(ui_and_example_source_files());
    sources.sort();
    for (name, text) in sources {
        files += 1;
        let b = text.as_bytes();
        let mut i = 0usize;
        let mut line = 1usize;
        let advance = |i: &mut usize, line: &mut usize, to: usize| {
            *line += text[*i..to].matches('\n').count();
            *i = to;
        };
        let push_lines = |out: &mut Vec<TextUnit>, kind: TextKind, first_line: usize, body: &str, span: usize| {
            for (k, l) in body.split('\n').enumerate() {
                out.push(TextUnit { file: name.clone(), line: first_line + k, kind, text: l.to_string(), span });
            }
        };
        while i < b.len() {
            // One number per lexical unit, so the lines of one literal or one
            // block comment stay identifiable as parts of a whole.
            span += 1;
            if b[i..].starts_with(b"/*") {
                let rel = text[i + 2..]
                    .find("*/")
                    .unwrap_or_else(|| panic!("{name}: block comment opened at byte {i} and never closed"));
                let end = i + 2 + rel + 2;
                push_lines(&mut out, TextKind::Comment, line, &text[i..end], span);
                advance(&mut i, &mut line, end);
            } else if b[i..].starts_with(b"//") {
                let end = text[i..].find('\n').map_or(b.len(), |rel| i + rel);
                out.push(TextUnit { file: name.clone(), line, kind: TextKind::Comment, text: text[i..end].to_string(), span });
                advance(&mut i, &mut line, end);
            } else if (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                && matches!(b[i], b'r' | b'b' | b'c')
                && matches!(raw_string_len(b, i), Some(RawString::Terminated(_)))
            {
                let Some(RawString::Terminated(n)) = raw_string_len(b, i) else { unreachable!() };
                // Contents: after the opening quote, before the closing quote
                // and its hashes.
                let open = text[i..i + n].find('"').map_or(0, |q| q + 1);
                let hashes = text[i + open - 1..i + n].matches('#').count() / 2;
                let close = n - 1 - hashes;
                if open < close {
                    push_lines(&mut out, TextKind::Str, line, &text[i + open..i + close], span);
                }
                let to = i + n;
                advance(&mut i, &mut line, to);
            } else if b[i] == b'"' {
                let mut j = i + 1;
                loop {
                    assert!(j < b.len(), "{name}: string opened at byte {i} and never closed");
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                push_lines(&mut out, TextKind::Str, line, &text[i + 1..j], span);
                let to = j + 1;
                advance(&mut i, &mut line, to);
            } else if b[i] == b'\'' {
                let to = i + char_literal_len(b, i).unwrap_or(1);
                advance(&mut i, &mut line, to);
            } else {
                let to = i + text[i..].chars().next().map_or(1, char::len_utf8);
                advance(&mut i, &mut line, to);
            }
        }
    }
    (files, out)
}

/// The floors the four walks share, derived from the measurement the evidence
/// lines print: **84 files, 19,365 comment lines in 2,990 runs and 14,648
/// string lines**. The three volume floors sit at roughly two thirds of their
/// measurement -- well above what a walk that dropped a directory, a kind, or
/// the strip would report, and far enough below it that ordinary prose churn
/// does not reach them.
///
/// **That measurement is provenance for the numbers below and has to be
/// re-taken whenever they move.** A floor is only as good as the figure it
/// was set from: left describing a tree that no longer exists, it says
/// nothing about how much headroom is left, and the next reader cannot tell a
/// floor with a third of the tree under it from one the tree has grown past.
/// The runs floor is the fourth, and it sits at its own site because only one
/// of the four walks forms runs; it follows the same rule.
///
/// # The files floor is structural, and two thirds is the wrong rule for it
///
/// The other three bound a QUANTITY: a walk that stopped seeing comments
/// reports a fraction of them, and two thirds is comfortably above any
/// fraction and comfortably below the whole. The files floor bounds a
/// STRUCTURE -- the walk covers four roots -- and a root is not a fraction of
/// a count. What it has to exceed is the largest total a walk that lost one
/// root can still report, which is a number about the roots' relative sizes
/// and not about the tree's total.
///
/// Measured, per root: `src/` 38, `tests/` 22, `ui/` 23, `examples/` 1, for
/// 84. A walk that lost `src/` reports 46, one that lost `tests/` reports 62,
/// one that lost `ui/` reports 61. The floor is **70**: above all three, and
/// fourteen below the measurement, so ordinary file churn does not red it
/// while any of those three losses does.
///
/// **`examples/` holds one file and is below this floor's resolution.** A
/// walk that lost it reports 83, which no floor can distinguish from the
/// deletion of one example -- so that root's coverage is not what this
/// assertion establishes, and the synthetic corpora in the four checks are.
/// Stated because a floor whose reach is assumed rather than derived stops
/// covering what its own sentence describes as soon as the roots change size,
/// and nothing reports that while every root is still present. `src/` and
/// `tests/` hold 60 between them; a floor at 60 is a floor two roots can
/// satisfy alone.
fn assert_text_walk_floors(what: &str, files: usize, units: &[TextUnit]) -> (usize, usize) {
    let comment_lines = units.iter().filter(|u| u.kind == TextKind::Comment).count();
    let string_lines = units.iter().filter(|u| u.kind == TextKind::Str).count();
    assert!(
        files >= 70,
        "{what}: walked {files} file(s). The four roots hold 84, and 70 is above the 62 a walk \
         that lost `tests/` would report -- the largest of the three root losses a count can \
         see. Either a root is missing from the walk or the tree has shrunk by fourteen files."
    );
    assert!(
        comment_lines >= 12_900,
        "{what}: examined {comment_lines} comment line(s). The four roots carry 19,365, and this \
         floor is two thirds of that, so the walk is not seeing comments"
    );
    assert!(
        string_lines >= 9_750,
        "{what}: examined {string_lines} string line(s). The four roots carry 14,648, and this \
         floor is two thirds of that, so the walk is not seeing string literals"
    );
    (comment_lines, string_lines)
}

/// The class of development-history marker a declared site carries.
///
/// One enumeration and one table rather than three, because the thing tracked
/// is one thing -- prose about how the code came to be, in a repository that
/// ships without that history -- and what a maintainer wants is to read the
/// remaining size of it in one place and watch one total fall.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkerClass {
    /// A session label, found by [`phase_tag_len`].
    SessionLabel,
    /// A citation of the board's open-item list by number, found by
    /// [`board_item_hit`].
    BoardItem,
    /// A citation of the old repository's errata document by number, found by
    /// [`errata_number_hit`].
    ErrataNumber,
    /// A row of [`DECLARED_UNRESOLVED_SRC_NAMES`] that permits a name no
    /// longer defined anywhere, cited only by history prose under `src/`.
    /// The subject of such a row is the name, and its count is the number of
    /// `src/` files that cite it.
    DeclaredName,
    /// A passage of prose about the code's own development, naming no
    /// marker at all. Found by [`narrative_hits`] against
    /// [`NARRATIVE_PHRASES`]; the subject of such a row is the file.
    Narrative,
}

impl MarkerClass {
    /// What the class is called in a failure message and an evidence line.
    fn label(self) -> &'static str {
        match self {
            MarkerClass::SessionLabel => "session label",
            MarkerClass::BoardItem => "open-item citation",
            MarkerClass::ErrataNumber => "errata citation",
            MarkerClass::DeclaredName => "declared dead name",
            MarkerClass::Narrative => "self-narrative passage",
        }
    }
}


/// Every site under `crates/` that carries a development-history marker
/// today, declared per subject with the count it holds and the sweep that
/// removes it.
///
/// # Why a baseline exists at all
///
/// The three text bans below were written before their matchers could see
/// everything they ban, and the holes were shaped like the markers that
/// remain: no arm read a session label, nothing read an open-item citation,
/// and an emphasised errata number fell through the separator set. The bans
/// were green, and green for the wrong reason -- the worst state for a guard,
/// because it reads as evidence.
///
/// Repairing the matchers and deleting the prose are different pieces of
/// work, and they cannot land together: the prose is thousands of sentences
/// across the tree and the matchers are one edit here. Landing the repair
/// alone with no baseline turns the suite red at every site at once, in files
/// nobody is editing yet, for as long as the cleanup takes -- and a wall of
/// red that everybody learns to run past is worth less than the broken
/// matcher was. Landing the cleanup first means shipping bans that provably
/// cannot see what they ban.
///
/// So the matchers run live, against everything, and this table says what
/// they are allowed to find while the prose is still here. It is the same
/// arrangement as [`NOT_THIS_WALLETS_TO_PIN`]: the exclusion is the check's
/// own data, it carries the reason the failure message prints, and guards
/// refuse a row that permits nothing and a row that lies.
///
/// # It can only shrink, and that is the whole mechanism
///
/// Two guards, and the second is the one that makes the cleanup
/// self-ratcheting:
///
/// * **More than the row declares is a new violation.** The failure names the
///   sites and the sweep that owns the subject. A new marker is not
///   declarable -- the remedy is to write the sentence without it, which is
///   what every sweep is doing to the ones already here.
/// * **Fewer than the row declares is a stale row.** A sweep that removes
///   four of a file's markers and leaves the row at the old count has left a
///   permit behind for four markers that could come back unnoticed. The
///   failure says to lower the row, or to delete it when the count reaches
///   zero. This is why no sweep can half-finish quietly: the table is red
///   until it matches the tree, in both directions.
///
/// The total prints in each check's evidence line, so shrinkage is visible
/// run to run without reading this table.
///
/// # What a row is
///
/// `(class, subject, count, sweep)`. The subject is a path under `crates/`
/// for the three text classes and a name for [`MarkerClass::DeclaredName`].
/// A subject appears at most once per class; a duplicate is refused below,
/// since the second row of a pair silently raises the first one's ceiling.
///
/// # It is empty, and that is the end state rather than a starting one
///
/// Every class reached zero. A row is what permits a site, so with no rows
/// each of the four checks is now an absence check over the whole tree, and
/// **a green says nothing about whether the matcher behind it still works.**
/// That is what the self-tests are for: each of those checks exercises its
/// matcher on text it constructs before it reads the tree, so a green there
/// means the matcher ran and fired, and then found nothing. Read them as the
/// live half. This table's own property from here is that it stays empty --
/// a row appearing in it is a site somebody chose to permit.
const DECLARED_HISTORY_MARKER_SITES: &[(MarkerClass, &str, usize, &str)] = &[];

/// The rows declared for one class, with the duplicate refused.
fn baseline_rows(class: MarkerClass) -> Vec<(&'static str, usize, &'static str)> {
    let rows: Vec<(&str, usize, &str)> = DECLARED_HISTORY_MARKER_SITES
        .iter()
        .filter(|(c, ..)| *c == class)
        .map(|(_, subject, count, sweep)| (*subject, *count, *sweep))
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (subject, ..) in &rows {
        assert!(
            seen.insert(subject),
            "DECLARED_HISTORY_MARKER_SITES carries two {} rows for `{subject}`. Two rows for one \
             subject add their ceilings together, so the second one raises the first's permit \
             without saying so. Merge them.",
            class.label()
        );
    }
    rows
}

/// The baseline compared against what a matcher found, in both directions.
///
/// `found` maps a subject to one description per site, in report order.
/// Returns the sites no row covers and the rows the tree no longer supports,
/// each as a block of message lines, plus the total the rows declare.
fn baseline_verdict(class: MarkerClass, found: &BTreeMap<&str, Vec<String>>) -> (Vec<String>, Vec<String>, usize) {
    let rows = baseline_rows(class);
    let what = class.label();
    let mut undeclared: Vec<String> = Vec::new();
    for (subject, sites) in found {
        match rows.iter().find(|(s, ..)| s == subject) {
            Some((_, declared, sweep)) if sites.len() > *declared => undeclared.push(format!(
                "\x20 - {subject}: {} {what}(s), and the baseline declares {declared}, owned by \
                 {sweep}. {} site(s) beyond that count are new.\n{}",
                sites.len(),
                sites.len() - declared,
                sites.join("\n")
            )),
            None => undeclared.push(format!(
                "\x20 - {subject}: {} {what}(s), and the baseline declares none for it.\n{}",
                sites.len(),
                sites.join("\n")
            )),
            Some(_) => {}
        }
    }
    let mut stale: Vec<String> = Vec::new();
    for (subject, declared, sweep) in &rows {
        let actual = found.get(subject).map_or(0, Vec::len);
        if actual < *declared {
            stale.push(format!(
                "\x20 - {subject}: the row declares {declared} {what}(s) and the tree now has \
                 {actual}. {} Owned by {sweep}.",
                if actual == 0 {
                    "Delete the row.".to_string()
                } else {
                    format!("Lower the row to {actual}.")
                }
            ));
        }
    }
    (undeclared, stale, rows.iter().map(|(_, n, _)| n).sum())
}

/// The two assertions every baselined check makes, in the order that reports
/// the table's own staleness first.
///
/// A stale row is a defect in this check's data and must not hide behind a red
/// about the tree -- the same ordering [`DECLARED_UNRESOLVED_SRC_NAMES`] uses,
/// and for the same reason. Returns the declared total for the evidence line.
fn assert_against_baseline(class: MarkerClass, found: &BTreeMap<&str, Vec<String>>) -> usize {
    let (undeclared, stale, declared_total) = baseline_verdict(class, found);
    let what = class.label();
    assert!(
        stale.is_empty(),
        "DECLARED_HISTORY_MARKER_SITES declares more {what}(s) than the tree carries:\n{}\n\n\
         The baseline only shrinks, and a row left at its old count is a permit for markers \
         that are gone -- exactly the room a marker needs to come back unnoticed. Lower each \
         row to what its subject holds now, or delete the row when nothing is left.",
        stale.join("\n")
    );
    assert!(
        undeclared.is_empty(),
        "{what}(s) under crates/ that DECLARED_HISTORY_MARKER_SITES does not declare:\n{}\n\n\
         This repository ships without its development history, so a marker naming a session, \
         a board item or an entry of a document that is not here points at nothing a reader \
         can follow. The baseline is the count that existed when the matchers were repaired \
         and it only shrinks: write the sentence without the marker. Raising a row is not the \
         remedy -- if the count genuinely belongs, that is a decision argued here, not a number \
         edited.",
        undeclared.join("\n")
    );
    declared_total
}

/// How many bytes of filler may sit between a citation's word and its number
/// before the two stop being one sentence.
///
/// This is a backstop and not the discriminator. The loop it bounds stops at
/// the first byte that is neither a separator nor one of the permitted words,
/// so the only way to spend the budget at all is on filler; the number only
/// decides how much filler is still one citation.
///
/// It is 64 because a string literal continued across source lines spends
/// most of it on indentation the compiler put there. The gap such a citation
/// writes is a space, a backslash, a newline and the whole indent of the
/// following line -- 37 columns at the deepest continuation under `crates/`,
/// so 40 bytes of pure wrapping before the number is reached. At 32 the two
/// citations spelled that way were invisible to the ban while every byte
/// between the word and the number was filler, which is the shape this budget
/// is supposed to catch rather than the shape it is supposed to reject.
const CITATION_GAP: usize = 64;

/// The word the matchers look for, built from fragments so it never appears
/// whole in this file's text.
fn errata_word() -> String {
    ["err", "ata"].concat()
}

/// Whether `text` names an entry of the old repository's errata document by
/// number: the document's name, in any case and in its singular spelling too,
/// then -- across at most [`CITATION_GAP`] bytes of whitespace, comment
/// openers (`/`, `!`, `#`), the backslash that continues a string literal,
/// markup that decorates a number rather than separating it from its word
/// (`*`, `_`, `(`, `[`), `§`, `:` and the words `entry`, `entries`, `no.` and
/// `number` -- a decimal digit. Spans a line break, so a citation wrapped
/// across two comment lines or two halves of one string literal is one hit.
/// Returns the byte offset of the word.
///
/// The markup characters and the backslash are in that set for one reason:
/// a citation is a citation however it is typed. Without the markup a bolded
/// number read as a non-citation; without the backslash a citation that
/// happened to fall at the end of a source line did, and the two spelled that
/// way sat in shipped `src/` while the ban reported none. That is the failure
/// mode a text ban has -- it goes green on the spelling it was written
/// against and says nothing about the rest -- and each spelling it cannot see
/// is a place the class comes back to.
///
/// What it must not swallow is the generic mention. `entry` is a permitted
/// word so that *a decision with an errata entry* stays legal prose, wrapped
/// or not; what makes a citation is the digit, and the self-test asserts both
/// directions over the wrapped spelling as well as the flat one.
fn errata_number_hit(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let stem = errata_word();
    let stem = &stem[..stem.len() - 1]; // the shared stem of both spellings
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(stem) {
        let at = from + rel;
        from = at + stem.len();
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let mut j = at + stem.len();
        if lower[j..].starts_with('a') {
            j += 1;
        } else if lower[j..].starts_with("um") {
            j += 2;
        } else {
            continue;
        }
        if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            continue;
        }
        let window_end = b.len().min(j + CITATION_GAP);
        let mut k = j;
        while k < window_end {
            let rest = &lower[k..window_end];
            if let Some(w) = ["entries", "entry", "number", "no."].iter().find(|w| rest.starts_with(*w)) {
                k += w.len();
            } else if rest.starts_with('§') {
                k += '§'.len_utf8();
            } else if matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b':' | b'*' | b'_' | b'(' | b'[' | b'\\') {
                k += 1;
            } else {
                break;
            }
        }
        if k < b.len() && b[k].is_ascii_digit() && k > j {
            return Some(at);
        }
    }
    None
}

/// The word the board's open-item citations name, built from fragments so it
/// never appears whole in this file's text.
fn board_item_word() -> String {
    ["Known", "-open"].concat()
}

/// Whether `text` cites an entry of the board's open-item list by number: the
/// list's name, in any case, then -- across at most [`CITATION_GAP`] bytes of
/// whitespace, comment openers (`/`, `!`, `#`), the backslash that continues
/// a string literal, markup (`*`, `_`, `(`, `[`), `:` and the words `item`,
/// `items` and `no.` -- a decimal digit. Spans a line break, so a citation
/// wrapped across two comment lines or two halves of one string literal is
/// one hit. Returns the byte offset of the word.
///
/// The same window technique as [`errata_number_hit`], against the same
/// failure: the two citations that wrap in this tree put the name at the end
/// of one comment line and the number at the start of the next, and a
/// line-at-a-time matcher reads both halves as innocent.
///
/// The backslash and the shared budget carry no site here -- every open-item
/// citation in this tree is flat, and the two spellings this arm cannot see
/// are the two the errata arm could not see either. They are matched to that
/// arm deliberately: two matchers for two names of the same thing, differing
/// in what counts as a gap, is a hole that opens the moment somebody wraps a
/// line.
fn board_item_hit(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let word = board_item_word().to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(&word) {
        let at = from + rel;
        from = at + word.len();
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let j = at + word.len();
        if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            continue;
        }
        let window_end = b.len().min(j + CITATION_GAP);
        let mut k = j;
        while k < window_end {
            let rest = &lower[k..window_end];
            if let Some(w) = ["items", "item", "no."].iter().find(|w| rest.starts_with(*w)) {
                k += w.len();
            } else if matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b':' | b'*' | b'_' | b'(' | b'[' | b'\\') {
                k += 1;
            } else {
                break;
            }
        }
        if k < b.len() && b[k].is_ascii_digit() && k > j {
            return Some(at);
        }
    }
    None
}

/// One file's share of the walk: its path, its units joined into one string,
/// the offset each unit starts at paired with its index, and the units
/// themselves.
type JoinedFile<'a> = (&'a str, String, Vec<(usize, usize)>, Vec<&'a TextUnit>);

/// The alternatives that may stand at one position of a phrase.
type Seg = &'static [&'static str];
/// One phrasing: segments in order, with filler permitted between them.
type Shape = &'static [Seg];

/// The sentinel alternative that matches a run of decimal digits.
const DIGITS: &str = "<digits>";

/// One class of prose about the code's own development.
struct NarrativeRow {
    /// What the row is called in a failure message. Rows are referred to by
    /// index and by this name, never by quoting what they match: a document
    /// that spells a phrase out is a site the check then reports, which is
    /// the same trap [`DOCUMENTS_NOT_IN_THIS_REPOSITORY`] avoids by building
    /// its needles rather than writing them.
    name: &'static str,
    /// Alternative phrasings. A row matches if any one of them does.
    shapes: &'static [Shape],
    /// Words that, standing immediately after a match, mean the match is not
    /// narrative after all.
    not_followed_by: Seg,
}

/// The spelled cardinals row 4 counts in, beside a run of digits.
const CARDINALS: Seg = &[
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
    "twenty", DIGITS,
];

/// Prose about the code's own development, as phrases rather than as markers.
///
/// # What this is for, and why the three older bans cannot do it
///
/// Those bans match a *token* -- a session label, a citation of a list or of
/// a document by number. A sentence can narrate this project's development
/// without carrying one of those, and most of them do. The subject matter is
/// the same and the reason for removing it is the same: a reader of a
/// shipping wallet cannot act on what the code looked like before, and the
/// repository does not carry the history that would make such a sentence
/// checkable.
///
/// # How a row is written, and why each one is narrow
///
/// Every row here was measured over the tree before it was admitted, and
/// several obvious candidates were measured and refused. The rule that
/// decided each is precision, not recall: a row that fires on live prose
/// teaches a maintainer to read reds as noise, and a ban read as noise is
/// worth less than no ban.
///
/// Refused, with what the measurement said. A bare negation of currency: 111
/// hits, under a third of them narrative. A bare adverb of singularity: 222
/// hits, because one-time signing is this crate's central invariant and the
/// word is everywhere legitimately. A bare comparative of preference: 685
/// hits and not one narrative -- it is the house idiom for stating a
/// decision. A bare past-tense verb of speech: 46 hits, 24 of them the node
/// or an endpoint answering. A definite article before an adjective of age:
/// the old address, the old inode and the old format are live nouns here.
/// Colour words for a test's state: a test that *is* green is a live claim
/// about a live test.
///
/// Where a row needs a closed set -- rows 2 and 3 -- the set is measured
/// rather than guessed, and two verbs were dropped from row 3 after
/// measurement because they are the purpose construction and not the
/// narrative one: a value *used to sign* and a key *used to spend* are what
/// the words do here, not what the code did before.
///
/// # The count is hits, not sentences
///
/// A row's count is the number of places a phrase matches, and one passage
/// commonly produces several. **It may be lowered only by deleting prose.**
/// Merging two narrated sentences into one, or restating a matched phrase as
/// a synonym this table does not carry, lowers the number without
/// discharging anything -- and the class has form for that: the same
/// retraction about a never-funded account stands in four places and the
/// same one about a stolen store in four more, so collapsing copies is
/// available and is not the remedy.
///
/// # Two stated bounds
///
/// **This check reads comments and not string literals.** That is what makes
/// row 5 safe at all -- `src/mnemonic/english.rs` carries the BIP-39
/// wordlist, whose entries include the words rows 5, 4 and 1 match, in a
/// file that must ship byte for byte -- and it is what keeps three live
/// assertion messages out of reach. The cost is declared: four narrative
/// passages live in string literals and this check cannot see them, at
/// `tests/invariants.rs` lines 2145, 5486 and 10381 and `tests/cli.rs` line
/// 5684. Widening the scope to reach them would put the wordlist back in.
///
/// **A red can therefore be answered by moving a sentence into an assertion
/// message.** Nothing here detects that, and naming it is the only guard
/// there is.
const NARRATIVE_PHRASES: &[NarrativeRow] = &[
    NarrativeRow { name: "a duration of the past", shapes: &[&[&["for"], &["a", "some"], &["time", "while"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "a piece of prose in the past tense",
        shapes: &[&[
            &["this", "the"],
            &["comment", "note", "paragraph", "section", "header", "bullet", "sentence", "test", "arm"],
            &[
                "said", "asserted", "claimed", "stated", "read", "called", "recorded", "demanded",
                "promised", "was", "were", "did", "held", "outlived", "passed", "prescribed",
                "went", "argued", "carried", "became", "documented", "closed", "measured",
                "returned",
            ],
        ]],
        not_followed_by: &[],
    },
    NarrativeRow {
        name: "a former behaviour",
        shapes: &[&[
            &["used"],
            &["to"],
            &[
                "assert", "be", "claim", "come", "compute", "defeat", "defer", "live", "read",
                "receive", "rely", "say", "sit", "stand", "treat", "demand", "name", "call",
                "hold", "carry", "mean", "report", "print", "exist", "run", "pin", "spell",
                "point", "list", "cover", "walk",
            ],
        ]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "a count of work periods", shapes: &[&[CARDINALS, &["sessions"]]], not_followed_by: &[] },
    NarrativeRow { name: "an earlier version of the text", shapes: &[&[&["draft", "drafts"]]], not_followed_by: &[] },
    NarrativeRow { name: "the first exercise against a live chain", shapes: &[&[&["first"], &["live"], &["run"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "the work period this text was written in",
        shapes: &[&[&["before", "until"], &["this"], &["session"]], &[&["this"], &["session's"]]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "a state in the past", shapes: &[&[&["was", "were"], &["once"]]], not_followed_by: &[] },
    NarrativeRow { name: "an initial state", shapes: &[&[&["at"], &["first"]]], not_followed_by: &["spend", "spends"] },
    NarrativeRow { name: "the state preceding a repair", shapes: &[&[&["before"], &["the"], &["fix", "repair"]]], not_followed_by: &[] },
    NarrativeRow { name: "a former location of the text", shapes: &[&[&["stood", "lived", "sat", "hung"], &["here", "there"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "a review ritual",
        shapes: &[&[&["design"], &["panel"]], &[&["adversarial"], &["pass", "passes"]], &[&["first"], &["sketched"]]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "an acknowledged correction", shapes: &[&[&["corrected"], &["since"]]], not_followed_by: &[] },
];

/// Whether `c` continues a word for the purpose of a phrase boundary.
///
/// Digits and letters only. `_` is deliberately absent, because it is handled
/// as filler below and the two roles cannot both be served by one predicate.
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Whether byte `k` may sit between two segments of a phrase.
///
/// Whitespace and the comment openers, because a phrase that wraps across two
/// comment lines is one phrase -- `TextUnit::text` keeps the `//` prefix, so
/// the text between the two halves reads as a line break and an opener. `*`
/// and `_` because a phrase is a phrase when it is emphasised, and emphasis
/// here is markdown.
///
/// `_` carries the one condition: it is markup at the edge of a word and part
/// of a name when it joins two. Without that, `for_a_time` reads as the
/// phrase row 1 matches, and snake_case names are quoted throughout these
/// comments.
fn is_phrase_filler(b: &[u8], k: usize) -> bool {
    match b[k] {
        b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b'*' => true,
        b'_' => !(k > 0 && b[k - 1].is_ascii_alphanumeric() && k + 1 < b.len() && b[k + 1].is_ascii_alphanumeric()),
        _ => false,
    }
}

/// The end offset of the longest alternative of `seg` matching at `at`.
fn segment_match(b: &[u8], at: usize, seg: Seg) -> Option<usize> {
    let mut best: Option<usize> = None;
    for alt in seg {
        let end = if *alt == DIGITS {
            let mut j = at;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j == at {
                continue;
            }
            j
        } else {
            if !b[at..].starts_with(alt.as_bytes()) {
                continue;
            }
            at + alt.len()
        };
        if end < b.len() && is_word_byte(b[end]) {
            continue;
        }
        best = Some(best.map_or(end, |x: usize| x.max(end)));
    }
    best
}

/// The end offset of `shape` matching at `at`, filler permitted between
/// segments but required -- two segments running together are one word.
fn shape_match(b: &[u8], at: usize, shape: Shape) -> Option<usize> {
    let mut pos = at;
    for (k, seg) in shape.iter().enumerate() {
        if k > 0 {
            let from = pos;
            let limit = b.len().min(pos + CITATION_GAP);
            while pos < limit && is_phrase_filler(b, pos) {
                pos += 1;
            }
            if pos == from {
                return None;
            }
        }
        pos = segment_match(b, pos, seg)?;
    }
    Some(pos)
}

/// Every `(row index, byte offset)` a row of [`NARRATIVE_PHRASES`] matches in
/// `text`, lower-cased first so a sentence-initial phrase is a hit.
///
/// The scan advances one byte at a time rather than by a needle's length:
/// the rows have no common length, a fixed advance long enough for one row
/// steps over a second row's hit on the same line, and one short enough
/// finds the same hit again.
fn narrative_hits(text: &str) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut out = Vec::new();
    for i in 0..b.len() {
        if i > 0 && is_word_byte(b[i - 1]) {
            continue;
        }
        for (r, row) in NARRATIVE_PHRASES.iter().enumerate() {
            let Some(end) = row.shapes.iter().find_map(|s| shape_match(b, i, s)) else {
                continue;
            };
            if !row.not_followed_by.is_empty() {
                let mut k = end;
                let limit = b.len().min(end + CITATION_GAP);
                while k < limit && is_phrase_filler(b, k) {
                    k += 1;
                }
                if segment_match(b, k, row.not_followed_by).is_some() {
                    continue;
                }
            }
            out.push((r, i));
        }
    }
    out
}

/// The canonical text of one row: the first alternative of every segment of
/// its first shape, single-spaced. Built from the table so a self-test vector
/// cannot drift from the row it is supposed to exercise.
fn narrative_vector(row: &NarrativeRow) -> String {
    row.shapes[0]
        .iter()
        .map(|seg| if seg[0] == DIGITS { "7" } else { seg[0] })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Each file's text units joined in order, with the offset every unit starts
/// at, so a matcher whose window spans a line break sees the file's text as
/// one string and a hit can still be reported at the unit it starts in.
///
/// Comment lines are joined with their line breaks, so a citation wrapped
/// across two of them is one citation. String units are fenced by NUL bytes,
/// which no matcher's window crosses, so a word at the end of one literal and
/// a digit at the start of the next are not a citation.
///
/// The fence goes around the **literal**, not around each of its lines, and
/// that is the whole of [`TextUnit::span`]'s purpose. A literal continued
/// across source lines arrives as one unit per line; fencing each of them put
/// a NUL in the middle of a single sentence, and a citation that happened to
/// wrap at the right column was hidden from every matcher by the same
/// mechanism that is supposed to stop two unrelated literals running
/// together. Two citations in shipped `src/` sat behind it. Opening the fence
/// at the first line of a span and closing it at the last keeps the guarantee
/// -- distinct literals stay distinct, because distinct literals have
/// distinct spans -- and stops it from cutting one literal in half.
///
/// Shared by the two window matchers rather than written twice. The joining
/// is the part that decides what a hit is, and two copies of it would be two
/// definitions of a citation that could drift apart without either check
/// going red.
/// One unit of text a check's collection path can be handed, built by a test
/// rather than read out of the tree.
///
/// [`crate_text_units`] is the only other producer of these, and it reads the
/// tree. Every text ban's baseline is empty, so each of them passes by finding
/// nothing there -- which means the tree can no longer distinguish a
/// collection path that works from one that has stopped seeing a kind, lost a
/// line in the join, or mislaid the offset that says which unit a hit sits in.
/// Units built here are what does.
fn synthetic_unit(line: usize, kind: TextKind, span: usize, text: &str) -> TextUnit {
    TextUnit { file: "<constructed>".to_string(), line, kind, text: text.to_string(), span }
}

/// Consecutive comment units of one file, on consecutive lines, as runs.
///
/// The unit of the row-name needle is the run and not the line: a
/// parenthesised row name two lines below the word *matrix* is inside the
/// sentence that cites the matrix. Grouping is therefore part of what that
/// needle means, and it is a function so that a test can hand it units and
/// see what it does with them -- inline in the check, the only thing that
/// could exercise it was the tree.
fn comment_runs(units: &[TextUnit]) -> Vec<&[TextUnit]> {
    let mut out: Vec<&[TextUnit]> = Vec::new();
    let mut i = 0usize;
    while i < units.len() {
        if units[i].kind != TextKind::Comment {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < units.len()
            && units[j].kind == TextKind::Comment
            && units[j].file == units[i].file
            && units[j].line == units[j - 1].line + 1
        {
            j += 1;
        }
        out.push(&units[i..j]);
        i = j;
    }
    out
}

fn joined_text_by_file(units: &[TextUnit]) -> Vec<JoinedFile<'_>> {
    let mut by_file: BTreeMap<&str, Vec<&TextUnit>> = BTreeMap::new();
    for u in units {
        by_file.entry(u.file.as_str()).or_default().push(u);
    }
    by_file
        .into_iter()
        .map(|(file, us)| {
            let mut joined = String::new();
            let mut starts: Vec<(usize, usize)> = Vec::new(); // (offset, unit index)
            for (idx, u) in us.iter().enumerate() {
                let opens = idx == 0 || us[idx - 1].span != u.span;
                let closes = idx + 1 == us.len() || us[idx + 1].span != u.span;
                starts.push((joined.len(), idx));
                if u.kind == TextKind::Str && opens {
                    joined.push('\u{0}');
                }
                joined.push_str(&u.text);
                if u.kind == TextKind::Str && closes {
                    joined.push('\u{0}');
                }
                joined.push('\n');
            }
            (file, joined, starts, us)
        })
        .collect()
}

/// Every hit `matcher` finds in the joined text of each file, as the unit the
/// hit starts in. `advance` is what to add to a hit's offset before searching
/// on, so a matcher that returns the offset of a word it then looks past does
/// not re-find the same word.
fn window_hits(units: &[TextUnit], matcher: fn(&str) -> Option<usize>, advance: usize) -> Vec<(&str, &TextUnit)> {
    let mut out: Vec<(&str, &TextUnit)> = Vec::new();
    for (file, joined, starts, us) in joined_text_by_file(units) {
        let mut from = 0usize;
        while let Some(rel) = matcher(&joined[from..]) {
            let at = from + rel;
            let idx = starts.iter().rev().find(|(o, _)| *o <= at).map_or(0, |(_, i)| *i);
            out.push((file, us[idx]));
            from = at + advance;
        }
    }
    out
}

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// cites an entry of the old repository's errata document by number.
///
/// That document is not here, so such a citation is a pointer into nothing.
/// A sentence
/// that stood on its own lost the number, a sentence that needed the entry
/// now carries the reason, and a sentence whose reason is in the
/// specification or in `AGENT.md` points there by section. Operator pages
/// and assertion messages are string literals and are walked too, since a
/// page that cites the document sends an operator to a file that is not in
/// this repository.
#[test]
fn no_comment_or_string_under_the_crate_cites_an_errata_entry_by_number() {
    // The matcher, both directions, on constructed needles.
    let er = errata_word();
    let cap = { let mut s = er.clone(); s.replace_range(0..1, "E"); s };
    let um = format!("{}um", &er[..er.len() - 1]);
    for hit in [
        format!("see {er} 213 §5"),
        format!("{cap} 182."),
        format!("({er}\n/// 213 §5)"),
        format!("{er} entry 51"),
        format!("{um} #4"),
        // Decorated numbers. The bolded form is the one this file's own doc
        // comments carried while the separator set could not see it.
        format!("{cap} **146** records"),
        format!("{er} (146)"),
        format!("{er} [146]"),
        format!("{er} _146_"),
        // Continued across two source lines. The gap is a space, a backslash,
        // a newline and the next line's indent -- 37 columns at the deepest
        // continuation in this tree, which is what [`CITATION_GAP`] is sized
        // for and what the old 32 could not reach.
        format!("{er} \\\n                                     213)."),
        format!("{er} \\\n             213 §3's declared-absent state"),
    ] {
        assert!(errata_number_hit(&hit).is_some(), "the matcher missed {hit:?}");
    }
    for miss in [
        format!("{er}-style discipline"),
        // Markup with no number behind it: widening the separator set must
        // not turn emphasis itself into a citation.
        format!("{er} **the whole document**"),
        format!("the {er} number to a page that carried four"),
        format!("the old repository's {er} entry, not these lines"),
        format!("an {er} document, 20,799 lines"),
        format!("in{er} 5"),
        format!("\u{0}{er}\u{0}\n213"),
        // The generic mention, wrapped. `entry` is a permitted word and no
        // digit follows it, so widening the gap and admitting the backslash
        // must leave this legal -- it is a sentence about the class, not a
        // pointer into the document, and this file writes one.
        format!("a decision with an {er} \\\n                 entry, not a moved line."),
    ] {
        assert!(errata_number_hit(&miss).is_none(), "the matcher fired on {miss:?}");
    }

    // --- the same needles, through the collection path ---
    //
    // Everything above calls `errata_number_hit` on a `String`. What decides
    // what this check finds in the tree is `window_hits`: the per-file join,
    // the NUL fence that goes around each string literal, and the mapping
    // from a byte offset back to the unit it sits in. None of that is
    // exercised by calling the matcher directly, and with the baseline empty
    // the tree cannot exercise it either -- zero is what a working path and a
    // severed one both report.
    //
    // **The property is not the narrative check's equality.** That check
    // filters the walk to one kind, so an inverted filter is its failure and
    // an equality against the walk's own comment count is what catches one.
    // This ban filters nothing: it reads comments and string literals alike.
    // What can break instead is the join, the fence, or the attribution, so
    // the property is that a citation in a unit of EITHER kind is found and
    // reported at that unit -- asserted as the exact set of lines, because a
    // count alone cannot tell a hit reported at the wrong line from a right
    // one.
    let corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, &format!("/// see {er} 213")),
        synthetic_unit(20, TextKind::Str, 2, &format!("{cap} 182, in a literal")),
        // Two adjacent literals, the first ending in the word and the second
        // opening with a number. What makes that not a citation is the fence
        // between two spans, which lives in the join and not in the matcher.
        synthetic_unit(30, TextKind::Str, 3, &format!("a bare {er}")),
        synthetic_unit(31, TextKind::Str, 4, "213 is a count"),
    ];
    let seen: Vec<usize> = window_hits(&corpus, errata_number_hit, errata_word().len() - 1)
        .iter()
        .map(|(_, u)| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the collection path reported citations at {seen:?} rather than at the comment on line \
         10 and the literal on line 20. Missing 10 or 20 means a kind is not reaching the join; \
         an extra 30 means the fence between two literals is gone and a word ending one runs \
         into a number opening the next; a line that is neither means the offset-to-unit \
         mapping is wrong and every hit this check reports names the wrong place."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("errata citations", files, &units);
    // The advance is the stem's length: the matcher returns the offset of the
    // word and then looks past it, so searching on from the word itself would
    // find the same one again.
    let mut found: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, u) in window_hits(&units, errata_number_hit, errata_word().len() - 1) {
        found
            .entry(file)
            .or_default()
            .push(format!("\x20     {file}:{} ({:?}): {}", u.line, u.kind, u.text.trim()));
    }
    let declared = assert_against_baseline(MarkerClass::ErrataNumber, &found);
    println!(
        "  errata citations: {files} files walked, {comment_lines} comment lines and {string_lines} \
         string lines examined, {} numbered citation(s) in {} file(s), all declared in \
         DECLARED_HISTORY_MARKER_SITES against a baseline of {declared}",
        found.values().map(Vec::len).sum::<usize>(),
        found.len()
    );
}

/// The documents the old repository carried and this one does not. A comment
/// or a page that cites one is a pointer into nothing; the fact it pointed
/// at is in `docs/specification.md` or `AGENT.md` or at the site.
const DOCUMENTS_NOT_IN_THIS_REPOSITORY: [&str; 5] =
    ["errata", "handoff", "port-inventory", "invariants", "protocol-survey"];

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// cites one of the five documents named in `DOCUMENTS_NOT_IN_THIS_REPOSITORY` by its old path.
///
/// The needles are built as `docs/<name>.md` from that table at run time, so
/// this file never spells one. The premise is checked too: if one of the five
/// is ever added to this repository, citing it is no longer a pointer into
/// nothing and this check should be re-scoped, not appeased.
#[test]
fn no_comment_or_string_under_the_crate_cites_a_document_that_is_not_in_this_repository() {
    let root = repo_root();
    let needles: Vec<String> = DOCUMENTS_NOT_IN_THIS_REPOSITORY.iter().map(|d| format!("docs/{d}.md")).collect();
    for n in &needles {
        assert!(
            !root.join(n).exists(),
            "{n} exists in this repository; this check's premise (that citing it is a \
             pointer into nothing) no longer holds -- re-scope it rather than appease it"
        );
    }
    // The matcher, both directions, on constructed needles.
    let hit = format!("see {}", needles[0]);
    assert!(needles.iter().any(|n| hit.contains(n.as_str())), "the matcher missed {hit:?}");
    let miss = "see docs/specification.md, section I3";
    assert!(!needles.iter().any(|n| miss.contains(n.as_str())), "the matcher fired on {miss:?}");

    // --- the same needles, through the collection path ---
    //
    // This scan has no join and no window: it asks every unit whether its
    // text contains one of the five paths. So the thing that can break is
    // narrower than for the two window checks, and so is the property -- that
    // the scan reads a unit of either kind, and that a document this
    // repository does carry is not a hit.
    //
    // It is worth asserting anyway, because "reads every unit" is exactly
    // what a `filter` added later would quietly narrow, and with the tree at
    // zero citations nothing else would notice.
    let corpus = [
        synthetic_unit(10, TextKind::Comment, 1, &format!("/// see {}", needles[0])),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {}", needles[1])),
        synthetic_unit(30, TextKind::Comment, 3, "/// see docs/specification.md, section I3"),
    ];
    let seen: Vec<usize> = corpus
        .iter()
        .filter(|u| needles.iter().any(|n| u.text.contains(n.as_str())))
        .map(|u| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the collection path reported citations at {seen:?} rather than at the comment on line \
         10 and the literal on line 20. A missing 10 or 20 means one of the two kinds is no \
         longer read; a 30 means the scan matches a document that is in this repository, which \
         is the one thing its premise forbids."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("dead-document citations", files, &units);
    let problems: Vec<String> = units
        .iter()
        .filter(|u| needles.iter().any(|n| u.text.contains(n.as_str())))
        .map(|u| format!("\x20 - {}:{} ({:?}): {}", u.file, u.line, u.kind, u.text.trim()))
        .collect();
    assert!(
        problems.is_empty(),
        "comment(s) or string(s) under the crate cite a document that is not in this repository:\n{}",
        problems.join("\n")
    );
    println!(
        "  dead-document citations: {files} files walked, {comment_lines} comment lines and \
         {string_lines} string lines examined, 0 citations of the {} absent documents",
        needles.len()
    );
}

/// The byte length of a session label starting at `i`, if one starts there:
/// the old repository's phase labels -- a `W`, `1`, dash and digits; a `P`
/// with one or two digits and an optional dash-number; an `H`, `L` or `V`
/// with one digit; a `Q`, digit, dash and lower-case letter -- and this
/// repository's own session labels, an `S` with one or two digits; each with
/// an optional lower-case suffix and delimited by non-word characters on both
/// sides.
///
/// # The `S` arm takes a bare label, and the reason is measured
///
/// `S` is an ordinary letter, so this is the arm that could fire on prose,
/// and the alternative was to demand a neighbouring word -- `closed at`,
/// `measured at`, `since`. Two measurements decide it for the bare form.
///
/// The tree carries its session labels in shapes no such qualifier reaches: a
/// label glued to a hyphenated adjective, a parenthesised label standing as a
/// whole clause, a label as the object of a verb the qualifier list does not
/// hold. A qualified matcher would ban the citations that read like sentences
/// and permit the ones that read like tags, which is backwards -- the tags
/// are the harder half to find by eye and the half a reader most needs gone.
///
/// And the letter followed immediately by a digit is not otherwise vocabulary
/// here: measured over the four walked roots, every occurrence is a session
/// label -- 138 of them across 24 files -- with no bucket
/// name, signal name or standard number among
/// them. The delimiters carry the rest -- a letter
/// before the `S` rejects `AES256`, a word character after the digits rejects
/// an identifier that merely begins that way, and a third digit rejects the
/// match as it does for `P`.
fn phase_tag_len(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let digits = |from: usize, max: usize| -> usize { b[from..].iter().take(max).take_while(|c| c.is_ascii_digit()).count() };
    let mut j;
    match b.get(i) {
        Some(b'W') if b.get(i + 1) == Some(&b'1') && b.get(i + 2) == Some(&b'-') => {
            let n = digits(i + 3, 3);
            if n == 0 {
                return None;
            }
            j = i + 3 + n;
        }
        Some(b'P') => {
            let n = digits(i + 1, 2);
            if n == 0 {
                return None;
            }
            j = i + 1 + n;
            if b.get(j) == Some(&b'-') {
                let m = digits(j + 1, 2);
                if m == 0 {
                    return None;
                }
                j += 1 + m;
            }
        }
        // This repository's own session labels. One or two digits, as `P`
        // takes: the sequence reached the high teens, and a third digit
        // rejects the match below rather than truncating it.
        Some(b'S') => {
            let n = digits(i + 1, 2);
            if n == 0 {
                return None;
            }
            j = i + 1 + n;
        }
        Some(b'H') | Some(b'L') | Some(b'V') if b.get(i + 1).is_some_and(u8::is_ascii_digit) => j = i + 2,
        Some(b'Q')
            if b.get(i + 1).is_some_and(u8::is_ascii_digit)
                && b.get(i + 2) == Some(&b'-')
                && b.get(i + 3).is_some_and(u8::is_ascii_lowercase) =>
        {
            j = i + 4
        }
        _ => return None,
    }
    if b.get(j).is_some_and(u8::is_ascii_lowercase) && !b.get(j + 1).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        j += 1;
    }
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    Some(j - i)
}

/// Every session label in `s`, as slices.
fn phase_tags_in(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    (0..b.len()).filter_map(|i| phase_tag_len(b, i).map(|n| &s[i..i + n])).collect()
}

/// The byte length of an old fault-matrix row name starting at `i`: an `R`
/// with one to three digits and an optional `b`, or an `E` with one digit,
/// delimited by non-word characters on both sides.
fn row_name_len(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let j = match b.get(i) {
        Some(b'R') => {
            let n = b[i + 1..].iter().take(3).take_while(|c| c.is_ascii_digit()).count();
            if n == 0 {
                return None;
            }
            let mut j = i + 1 + n;
            if b.get(j) == Some(&b'b') {
                j += 1;
            }
            j
        }
        Some(b'E') if b.get(i + 1).is_some_and(u8::is_ascii_digit) => i + 2,
        _ => return None,
    };
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    Some(j - i)
}

/// Whether `text` carries `word` as a whole word, in any case.
fn has_word(text: &str, word: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(word) {
        let at = from + rel;
        let end = at + word.len();
        let left_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        let right_ok = end >= b.len() || !(b[end].is_ascii_alphanumeric() || b[end] == b'_');
        if left_ok && right_ok {
            return true;
        }
        from = end;
    }
    false
}

/// The row names in a run of comment lines that also speaks of a matrix or
/// a row -- the qualifier that keeps a bare `R`-plus-digits elsewhere (a
/// register, a revision, a table cell) from being a hit. The run is the unit,
/// not the line: a parenthesised row name two lines below the word "matrix"
/// is inside the sentence that cites the matrix.
fn row_names_in_run(lines: &[&str]) -> Vec<String> {
    if !lines.iter().any(|l| has_word(l, "matrix") || has_word(l, "row")) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for l in lines {
        let b = l.as_bytes();
        for i in 0..b.len() {
            if let Some(n) = row_name_len(b, i) {
                out.push(l[i..i + n].to_string());
            }
        }
    }
    out
}

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// carries a session label or cites the board's open-item list by number
/// beyond what [`DECLARED_HISTORY_MARKER_SITES`] declares, and no comment run
/// that speaks of a fault matrix or a row names one of its rows.
///
/// The labels name sessions of a history that is not here. The matcher covers the brief's forms, the bare `P`
/// labels, the `L`, `Q` and `V` labels, this repository's own `S` labels, and
/// the lower-case suffixes a word-boundary regex over the brief's forms would
/// miss.
///
/// # Three findings, and only one of them is a hard zero
///
/// * **Session labels** are baselined. The `S` arm was missing when this
///   check was written, so the labels it now finds have been passing it all
///   along; they leave with the prose, sweep by sweep, and until then the
///   count each file holds is declared.
/// * **Open-item citations** are baselined for the same reason: nothing
///   matched them before, and the list they cite is going.
/// * **Fault-matrix row names** stay a hard zero, because the tree holds
///   none. The needle is qualified by the words `matrix` or `row` in the same
///   comment run, so an `R` with a digit that is a register, a revision or a
///   table cell is not a false positive (this repository's own fault tables
///   live in `AGENT.md` and in commit messages, which are not walked); and it
///   is applied to comments only, since no string literal in the tree names a
///   row.
///
/// The open-item scan reads each file's joined text rather than each unit's,
/// because two of the citations in the tree wrap: the name ends one comment
/// line and the number opens the next. Session labels need no such joining --
/// a label is one token and cannot be split by a line break without ceasing
/// to be one.
#[test]
fn no_comment_or_string_under_the_crate_carries_a_phase_tag_or_a_row_name() {
    // The matchers, both directions, on constructed needles.
    let tagged = [
        format!("({}1-3)", "W"),
        format!("since {}13", "P"),
        format!("{}1, total", "H"),
        format!("{}3-2 narrowed", "P"),
        format!("until {}1-14b;", "W"),
        format!("({}6b).", "P"),
        format!("{}3 submitted", "L"),
        format!("{}2-c pinned", "Q"),
        format!("as {}1 did", "V"),
    ];
    // This repository's own labels, built from fragments like the rest: a
    // needle spelled whole here would be a site this check then reports.
    let s = "S";
    let own = [
        format!("closed at {s}6)"),
        format!("({s}10)."),
        format!("the {s}11-gated tests"),
        format!("since {s}15 the ceiling is"),
        format!("re-derived at {s}9:"),
    ];
    for hit in tagged.iter().chain(own.iter()) {
        assert!(!phase_tags_in(hit).is_empty(), "the tag matcher missed {hit:?}");
    }
    // `AES256` and `HS256` are the shape the `S` arm could plausibly fire on
    // and does not: a letter precedes the `S`, so the left delimiter refuses
    // it before the digits are read.
    let mut missed: Vec<String> = ["SHA3-224", "P2P", "RFC 9106", "MP13", "P13_OFF", "TXHDR", "V1_SNAPSHOT", "Q6", "IPv6", "E0603", "AES256", "HS256"]
        .iter()
        .map(|m| (*m).to_string())
        .collect();
    missed.push(format!("{s}6_LIMIT"));
    missed.push(format!("{s}123 is three digits"));
    missed.push(format!("_{s}6"));
    for miss in &missed {
        assert!(phase_tags_in(miss).is_empty(), "the tag matcher fired on {miss:?}");
    }
    // The open-item matcher, both directions. The second hit is the wrapped
    // form; the last miss is the NUL fence that keeps two adjacent string
    // literals from reading as one citation.
    let ko = board_item_word();
    for hit in [
        format!("(AGENT.md, {ko} 22, closed"),
        format!("({ko}\n/// 31)."),
        format!("{ko} item 7"),
        // Continued across two source lines, the spelling the errata arm was
        // blind to. No site in this tree writes it; the arm carries it so the
        // two matchers cannot disagree about what a gap is.
        format!("{ko} \\\n                                     44)."),
    ] {
        assert!(board_item_hit(&hit).is_some(), "the open-item matcher missed {hit:?}");
    }
    for miss in [
        format!("{ko} items, all of them"),
        format!("the {ko} list"),
        format!("un{ko} 3"),
        format!("\u{0}{ko}\u{0}\n22"),
    ] {
        assert!(board_item_hit(&miss).is_none(), "the open-item matcher fired on {miss:?}");
    }
    let r = "R";
    let e = "E";
    let run_hit = [format!("// the matrix's {r}17 removes the check"), "// and this one still refuses".to_string()];
    let run_hit: Vec<&str> = run_hit.iter().map(String::as_str).collect();
    assert_eq!(row_names_in_run(&run_hit), vec![format!("{r}17")], "the row-name matcher missed a qualified run");
    let run_hit2 = ["// (matrix rows)".to_string(), format!("// the {e}5 injection found it, and ({r}10b) too")];
    let run_hit2: Vec<&str> = run_hit2.iter().map(String::as_str).collect();
    assert_eq!(row_names_in_run(&run_hit2), vec![format!("{e}5"), format!("{r}10b")]);
    let run_miss = [format!("// {r}1 in a comment with neither word beside it"), format!("// {e}0603 is a compiler error code")];
    let run_miss: Vec<&str> = run_miss.iter().map(String::as_str).collect();
    assert!(row_names_in_run(&run_miss).is_empty(), "the row-name matcher fired without its qualifier");
    let run_miss2 = [format!("// a row of {e}0603 errors")];
    let run_miss2: Vec<&str> = run_miss2.iter().map(String::as_str).collect();
    assert!(row_names_in_run(&run_miss2).is_empty(), "the row-name matcher fired on a five-digit code");

    // --- the same needles, through the three collection paths ---
    //
    // This check has three, and they fail differently, so each gets its own
    // corpus. None of them is exercised by the assertions above, which hand a
    // `String` to a matcher; and with the baseline empty the tree reports
    // zero whether the paths work or not.
    //
    // (1) Labels are read per unit, over both kinds. The property is that a
    //     unit of either kind reaches `phase_tags_in`.
    let label_corpus = [
        synthetic_unit(10, TextKind::Comment, 1, &format!("// closed at {s}6")),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {s}11")),
        synthetic_unit(30, TextKind::Comment, 3, "// AES256 is not a label"),
    ];
    let seen: Vec<usize> = label_corpus
        .iter()
        .filter(|u| !phase_tags_in(&u.text).is_empty())
        .map(|u| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the label scan reported {seen:?} rather than the comment on line 10 and the literal on \
         line 20; a missing one of those is a kind this check has stopped reading."
    );

    // (2) Row names are read per RUN, and the run is what carries the
    //     qualifier: the word `matrix` on one line licenses a name on the
    //     next. That only holds if consecutive comment units of one file
    //     group together, which is `comment_runs`' whole job and which
    //     nothing but the tree could exercise while it lived inline.
    let run_corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, "// the matrix below"),
        synthetic_unit(11, TextKind::Comment, 2, &format!("// names {r}17")),
        synthetic_unit(12, TextKind::Str, 3, "a literal between the runs"),
        synthetic_unit(13, TextKind::Comment, 4, "// the matrix below"),
        synthetic_unit(99, TextKind::Comment, 5, &format!("// names {r}18")),
    ];
    let grouped = comment_runs(&run_corpus);
    let shapes: Vec<(usize, usize)> = grouped.iter().map(|r| (r[0].line, r.len())).collect();
    assert_eq!(
        shapes,
        vec![(10, 2), (13, 1), (99, 1)],
        "`comment_runs` grouped {shapes:?}. Two consecutive comment lines of one file are one \
         run; a string literal between them ends a run; and a gap in the line numbers ends one \
         too. Grouping too little hides a name from the qualifier a line above it, and grouping \
         too much lends a qualifier to a name three hundred lines away."
    );
    let across: Vec<String> = row_names_in_run(&grouped[0].iter().map(|u| u.text.as_str()).collect::<Vec<_>>());
    assert_eq!(
        across,
        vec![format!("{r}17")],
        "the qualifier on the first line of a run did not reach the name on its second: {across:?}"
    );

    // (3) Open-item citations go through the join, where one wrapped across
    //     two comment lines is a single hit. The property is that the join
    //     makes it one -- a per-line scan finds neither half.
    let item_corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, &format!("// (AGENT.md, {ko}")),
        synthetic_unit(11, TextKind::Comment, 1, "//  22, closed)."),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {ko} 9")),
    ];
    let seen: Vec<usize> = window_hits(&item_corpus, board_item_hit, board_item_word().len())
        .iter()
        .map(|(_, u)| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the open-item collection path reported {seen:?} rather than the wrapped citation at \
         line 10 and the literal at line 20. A missing 10 means the join is not putting two \
         comment lines of one span together and every wrapped citation is invisible; a missing \
         20 means string literals are not reaching it."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("phase tags", files, &units);
    let mut problems: Vec<String> = Vec::new();
    let mut labels: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for u in &units {
        let tags = phase_tags_in(&u.text);
        if !tags.is_empty() {
            labels
                .entry(u.file.as_str())
                .or_default()
                .push(format!("\x20     {}:{} ({:?}): {tags:?} in {}", u.file, u.line, u.kind, u.text.trim()));
        }
    }
    // Comment runs, through the same grouping the corpus above exercises.
    let grouped_runs = comment_runs(&units);
    let runs = grouped_runs.len();
    for run in &grouped_runs {
        let lines: Vec<&str> = run.iter().map(|u| u.text.as_str()).collect();
        let names = row_names_in_run(&lines);
        if !names.is_empty() {
            problems.push(format!(
                "\x20 - {}:{}-{}: fault-matrix row name(s) {names:?} in a comment run that speaks of a matrix or a row",
                run[0].file,
                run[0].line,
                run[run.len() - 1].line
            ));
        }
    }
    assert!(
        runs >= 1_990,
        "the walk formed {runs} comment run(s). The four roots form 2,990, and this floor is two \
         thirds of that -- a walk that lost a root, or one that stopped joining consecutive \
         comment lines into a run, reports well under it"
    );
    // The open-item citations, over each file's joined text so the two that
    // wrap across a comment line are one hit each rather than none. The
    // advance past a hit is the name's own length.
    let mut items: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, u) in window_hits(&units, board_item_hit, board_item_word().len()) {
        items
            .entry(file)
            .or_default()
            .push(format!("\x20     {file}:{} ({:?}): {}", u.line, u.kind, u.text.trim()));
    }
    // Row names first and unconditionally: that half of this check is a hard
    // zero, and a red about the baseline must not bury it.
    assert!(
        problems.is_empty(),
        "comment run(s) under the crate name a fault-matrix row of the old repository:\n{}",
        problems.join("\n")
    );
    let declared_labels = assert_against_baseline(MarkerClass::SessionLabel, &labels);
    let declared_items = assert_against_baseline(MarkerClass::BoardItem, &items);
    println!(
        "  phase tags: {files} files walked, {comment_lines} comment lines ({runs} runs) and {string_lines} \
         string lines examined, 0 row names, {} session label(s) in {} file(s) against a baseline of \
         {declared_labels}, {} open-item citation(s) in {} file(s) against a baseline of {declared_items}",
        labels.values().map(Vec::len).sum::<usize>(),
        labels.len(),
        items.values().map(Vec::len).sum::<usize>(),
        items.len()
    );
}

/// No comment under `src/`, `tests/`, `ui/` or `examples/` narrates this
/// project's own development beyond what
/// [`DECLARED_HISTORY_MARKER_SITES`] declares.
///
/// [`NARRATIVE_PHRASES`] carries the classes and the argument for each. What
/// this test adds is the part an absence check cannot get from its subject:
/// evidence that it ran.
///
/// # Why that evidence is the point of this test
///
/// The three bans beside it are absence checks, and they are green today
/// partly because one site is still declared -- a red is one edit away, so a
/// broken matcher would be found. This one is aimed at a class that goes to
/// zero. On the day it does, a green stops distinguishing "the matcher ran
/// over the tree and found nothing" from "the matcher matched nothing
/// because a phrase is misspelled, or the filter is inverted, or the walk
/// lost a root". Every one of those is silent.
///
/// So the matcher is exercised on text this test builds before it is pointed
/// at the tree: a corpus of comment units constructed from the table itself,
/// on which every row must fire, and a control paragraph on which none may.
/// A green here reads as *the matcher ran, fired on constructed text, and
/// found nothing else* -- which is a different sentence from *nothing ran*.
#[test]
fn no_comment_under_the_crate_narrates_its_own_development() {
    // --- the table is its own vector source ---
    //
    // Thirteen classes were measured before any was admitted. A row removed
    // to silence a red takes its whole class with it and nothing else would
    // notice, so the floor is asserted and every vector below is derived
    // from the table rather than typed beside it.
    assert!(
        NARRATIVE_PHRASES.len() >= 13,
        "NARRATIVE_PHRASES carries {} row(s). Thirteen classes were measured over this tree \
         before any was admitted, and a row deleted to answer a red takes its class out of the \
         ban with it. Removing one is a decision argued at the table, not an edit.",
        NARRATIVE_PHRASES.len()
    );
    let vectors: Vec<String> = NARRATIVE_PHRASES.iter().map(narrative_vector).collect();
    assert_eq!(
        vectors.len(),
        NARRATIVE_PHRASES.len(),
        "a row exists that no vector exercises; the vectors are built from the table so that \
         cannot happen quietly"
    );

    // --- each row fires on its own canonical text, and on no other row's ---
    //
    // The second half is what keeps a widened row from swallowing a
    // neighbour: a row that matched another row's vector would hide that
    // row's disappearance behind its own hits.
    for (r, v) in vectors.iter().enumerate() {
        let hits = narrative_hits(v);
        assert_eq!(
            hits.len(),
            1,
            "row {r} ({}) matches its own canonical text {} time(s), not once. A row that \
             matches its vector twice double-counts every site it finds; one that matches it \
             not at all is spelled wrong and will report nothing for its whole class.",
            NARRATIVE_PHRASES[r].name,
            hits.len()
        );
        assert_eq!(
            hits[0].0, r,
            "row {r} ({})'s canonical text is matched by row {} ({}) instead. Two rows that \
             overlap report one passage twice and let one of them go to zero unnoticed.",
            NARRATIVE_PHRASES[r].name, hits[0].0, NARRATIVE_PHRASES[hits[0].0].name
        );
    }

    // --- the spellings a line-at-a-time, case-sensitive matcher would miss ---
    //
    // A phrase wrapped across two comment lines reads as the first half, a
    // line break, a comment opener and the second half, because the walk
    // keeps the opener. A phrase opening a sentence is capitalised, and one
    // of the sites in this tree is capitalised throughout. A phrase inside
    // markdown emphasis is still the phrase.
    for (r, v) in vectors.iter().enumerate() {
        let mut spellings = vec![
            format!("// {}", v.to_uppercase()),
            format!("// {}{}", v[..1].to_uppercase(), &v[1..]),
            format!("// **{v}**"),
        ];
        if let Some(sp) = v.find(' ') {
            spellings.push(format!("// {}\n    /// {}", &v[..sp], &v[sp + 1..]));
        }
        for s in &spellings {
            assert!(
                narrative_hits(s).iter().any(|(row, _)| *row == r),
                "row {r} ({}) does not match {s:?}. A matcher blind to one of these spellings \
                 goes green on the one it was written against and silent on the rest.",
                NARRATIVE_PHRASES[r].name
            );
        }
    }

    // --- and a control that must stay clean ---
    const CONTROL: &str = "// The index advances before the signature is released, and the \n\
                           // receipt is minted only after the advanced index is durable. A \n\
                           // second signature at one position is refused rather than \n\
                           // reported, because the key is a one-time key and the store is \n\
                           // the only thing that knows it has been used.";
    let control = narrative_hits(CONTROL);
    assert!(
        control.is_empty(),
        "the control paragraph carries no prose about this project's development and {} row(s) \
         fired on it: {:?}. A row this loose reports live sentences, and a maintainer who reads \
         one red as noise reads the next one that way too.",
        control.len(),
        control.iter().map(|(r, _)| NARRATIVE_PHRASES[*r].name).collect::<Vec<_>>()
    );

    // --- the synthetic corpus, through the collection path itself ---
    //
    // Not the matcher alone: units of the kind the walk produces, joined the
    // way the walk joins them, so a filter that admitted the wrong kind or a
    // join that lost a line is caught here rather than reported as a clean
    // tree.
    let synthetic: Vec<TextUnit> = vectors
        .iter()
        .enumerate()
        .map(|(r, v)| TextUnit {
            file: "<constructed>".to_string(),
            line: r + 1,
            kind: TextKind::Comment,
            text: format!("/// {v}"),
            span: r,
        })
        .collect();
    let joined: String = synthetic
        .iter()
        .filter(|u| u.kind == TextKind::Comment)
        .map(|u| u.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let fired: BTreeSet<usize> = narrative_hits(&joined).into_iter().map(|(r, _)| r).collect();
    let silent: Vec<&str> = NARRATIVE_PHRASES
        .iter()
        .enumerate()
        .filter(|(r, _)| !fired.contains(r))
        .map(|(_, row)| row.name)
        .collect();
    assert!(
        silent.is_empty(),
        "these row(s) found nothing in a corpus built out of their own text: {silent:?}. This is \
         the check that a green means the matcher ran, and it is the whole reason this test does \
         not simply walk the tree and report zero."
    );

    // --- now the tree ---
    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("self-narrative", files, &units);
    let mut by_file: BTreeMap<&str, Vec<&TextUnit>> = BTreeMap::new();
    for u in units.iter().filter(|u| u.kind == TextKind::Comment) {
        by_file.entry(u.file.as_str()).or_default().push(u);
    }
    let walked: usize = by_file.values().map(Vec::len).sum();
    // What this check reads, floored against what the walk counted. A floor
    // alone is not enough here: the tree carries more string lines than the
    // 11,000 comment lines the shared floor demands, so a filter inverted to
    // keep strings instead would clear that floor and change every row's
    // subject without failing anything. Equality is the property -- this
    // check reads every comment the walk found and nothing else.
    assert_eq!(
        walked, comment_lines,
        "the comment-only filter kept {walked} unit(s) where the walk counted {comment_lines} \
         comment line(s). A filter that admits a string literal puts the BIP-39 wordlist inside \
         row 5's reach; one that drops comments silently shrinks every row's corpus."
    );

    let mut found: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, us) in &by_file {
        let mut joined = String::new();
        let mut starts: Vec<(usize, usize)> = Vec::new();
        for (idx, u) in us.iter().enumerate() {
            starts.push((joined.len(), idx));
            joined.push_str(&u.text);
            joined.push('\n');
        }
        for (r, at) in narrative_hits(&joined) {
            let idx = starts.iter().rev().find(|(o, _)| *o <= at).map_or(0, |(_, i)| *i);
            let u = us[idx];
            found
                .entry(file)
                .or_default()
                .push(format!("\x20     {file}:{} [{}]: {}", u.line, NARRATIVE_PHRASES[r].name, u.text.trim()));
        }
    }
    let declared = assert_against_baseline(MarkerClass::Narrative, &found);

    println!(
        "  self-narrative: {files} files walked, {walked} comment lines of {comment_lines} \
         examined ({string_lines} string lines skipped), {} row(s) exercised on constructed \
         text, {} passage(s) in {} file(s) against a baseline of {declared}",
        NARRATIVE_PHRASES.len(),
        found.values().map(Vec::len).sum::<usize>(),
        found.len()
    );
}

