# Forking this wallet into a graphical one

Three repositories, in a line. This document says what each is for, what has
to be true before each fork is cut, and -- where a claim here was measured
rather than reasoned about -- what was measured and what the measurement does
not cover.

| | what it is | platform |
| --- | --- | --- |
| **Rep-0** | this repository: the command-line wallet | Unix. Linux and macOS, as `RELEASE.md` requires |
| **Rep-1** | a command-line wallet that also runs on Windows | Linux, macOS **and** Windows |
| **Rep-2** | a graphical wallet | all three |

**Rep-1 keeps Unix and adds Windows.** It is not a Windows port in the sense of
a Windows-only tree: Rep-2 descends from the tri-platform result, and a Rep-1
that dropped Linux and macOS would leave Rep-2 merging them back from Rep-0
forever.

---

## The organizing principle

Every structural change made downstream instead of here becomes permanent
friction on every later fix, because every Rep-0 fix has to cross two fork
points to reach the graphical wallet. **Phase 0's job is to shape the seams so
both deltas are thin**, and the measure of whether it succeeded is the size of
the Rep-0-to-Rep-1 diff, not the size of Phase 0 itself.

Phase 0 changes no behaviour. Every item in it is justified on this
repository's own terms, and where an item's larger beneficiary is downstream
that is said at the item rather than left to be inferred.

---

## Phase 0 -- work in Rep-0

### P0-1 -- concentrate the Unix surface **(done, 2026-09-20)**

`src/keystore/perms.rs` now holds every mode bit this crate sets or reads. It
was six call sites across `keystore/mod.rs` and `keystore/medium.rs` behind
three separate `std::os::unix::fs` imports; it is one module behind one import,
and the module's own doc carries the argument.

The reason is in `lib.rs`'s platform statement: it claims the crate needs a
permission model of a particular shape, and while the sites it described were
scattered that claim was prose checked against nothing. It now has one module
to be read against.

Measured rather than asserted: `cargo build --workspace`, `cargo test
--workspace --no-fail-fast` (385 tests, 17 targets), all four clippy rows at
`-D warnings`, and `cargo doc` are green at the commit that introduced it. The
error `op` strings at every moved site are unchanged, which is what keeps the
extraction invisible to `tests/keystore.rs`.

**What it is not.** It is not a portability layer. There is no second
implementation behind it, no `cfg` and no trait, and a non-unix build still
fails at `lib.rs`'s `compile_error!` and again at `keystore`'s.

### P0-2 -- cooperative cancellation, and the signal gap **(both walks done, 2026-09-20)**

**The gap, which is a defect of this wallet on Unix today.** Nothing in this
tree addresses signals -- not the source, not the documents, not `Cargo.toml`.
A `restore` walks up to `recon::RECOVERY_CEILING` key positions with `master:
&Secret<SEED_LEN>` live across the whole walk, and `SIGINT` terminates the
process without unwinding, so **no destructor runs and the seed is not
overwritten.** That is the argument the root `Cargo.toml` makes against
`panic = "abort"`, reaching a signal that argument does not mention.

**The mechanism.** `recon::Cancel` is asked once per position; a cancel is
`Error::Cancelled`, deliberately not the `Ok(None)` an exhausted bound
returns, because those two say opposite things. Both long walks take it now --
the restore scan and the divergence diagnostic -- under one rule: **a caller
that may say how far a walk goes may also say whether it keeps going**, so the
parameter travels wherever `&ScanScope` does and nowhere else. `README.md`
records the half that is still open.

**What remains is not a walk, and it is P0-3's.** Nothing installs a signal
handler and the binary passes `Cancel::NEVER`, so at the command line the gap
stays open. A wallet that catches a signal is a wallet with a new path through
its own shutdown, and that path owes the fault injection every other path here
owes -- it is a change to what the command layer *does* rather than to what
`recon` *offers*, which is why it now sits in the item below.

### P0-3 -- separate the decision from its rendering **(done, 2026-09-20)**

`cli/mod.rs` ended every command by building a `Report` -- a `String` and an
exit code -- so a command's decision and the sentence announcing it were one
statement, ninety-six times over.

`cli::decide` returns `Decided`, which is what a command established in the
types the layers below already use; `cli::render` turns one into a `Report`.
`cli::run` is `render(decide(..))` and nothing else, so **`tests/cli.rs` was
not touched by the split** -- its seven thousand lines are held to the new
layer without knowing it exists, which makes every one of them an assertion
that the words have not moved.

All sixteen commands are through it. The escape hatch that carried the
unconverted ones during the work is gone from the enum rather than left
standing, and two checks keep it that way:

* `the_decision_layer_carries_no_prose` refuses any `String` under
  `cli/outcome.rs`. One such field and a dependent can no longer tell which
  variants it may act on and which it may only print.
* `render::outcome` matches `Outcome` exhaustively, so a variant added with no
  rendering is a compile error rather than a blank page.

**One thing followed rather than being aimed at:** the decision layer does not
name `Code`. Whether a command exits 0 or 3 is a question about how a program
reports, and a dependent that is not a command line ignores the answer.

#### What the invariant suite caught, because it is worth recording

The route scan refused the split twice before it accepted it, and both were
real.

**A variant named `Transaction`.** The scan resolves signature-bearing types
**by name** across the crate, and `tx::wire::Transaction` is bearing, so
naming an `Outcome` variant `Transaction` made `Outcome` bearing -- and with
it every `cmd_*` returning one, and `reconcile::Reviewed`, which has a field
of that type name. `args.rs` records this exact hazard for `Command` and names
its variant `LookupTransaction` for it; the outcome is `LookedUpTransaction`
for the same reason.

**`run` stopped naming `Wallet`.** Its Entrypoint permission rests on the gate
being on its path, which the scan checked by looking for `Wallet` in the body
-- exact while dispatch and wallet were one function. The clause is widened
rather than waived, and only as far as the property already reaches: name
`Wallet`, **or** name another allow-listed Entrypoint, whose own permission is
checked by the same assertions on its own row.

#### The signal handler: decided, and declined

Folded in from P0-2 and answered rather than left open. `std` has no signal
interface, so a handler needs `libc` -- the first dependency here for
something that is neither a primitive, a codec nor a check -- and a signal
handler is `unsafe`, which would be the only `unsafe` under `src/`. What it
buys is the scrub on a wait an operator chose to abandon, whose length they
themselves bounded.

The caller `Cancel` is really for has an event loop and a button and watches a
flag with no handler at all, so the mechanism serves it today. The argument is
at `Cancel`'s own doc and the gap is in `README.md`'s limits.

### P0-4 -- decide the trust store **(decided, 2026-09-20: `webpki-roots`)**

Rep-0 keeps the bundled Mozilla store. The argument is written where the
provider is chosen, in `crates/mochimo-crypto/Cargo.toml` beside the
`mesh-https` feature, because a default is not a decision -- the rule the root
manifest already applies to the release profile.

Two reasons and one cost, in short:

* **The parser stays in safe Rust.** `lib.rs`'s head rests this feature's
  trusted computing base on where the `unsafe` is *not*: `rustls-webpki` reads
  the X.509 and the ASN.1, which is the hostile input on this path. Handing
  verification to CryptoAPI or Security.framework moves that parser into C on
  two of the three platforms a fork targets.
* **The same roots everywhere, so a failure reproduces.** `RELEASE.md` asks
  for a green board on more than one platform at one commit, and that
  comparison holds only if the trust anchors are held still across it. A store
  read from the host makes a handshake failure a property of the machine
  rather than of the commit, and no row of the board would notice.
* **The cost:** the roots are frozen at build time, and nothing on this path
  asks about revocation. What bounds it is that TLS here keeps the node's
  answers *the named node's rather than the network's* -- it is not what makes
  them true. A lying node is not a case this feature addresses, and `--node`
  has no default precisely because the operator chooses whom to believe.

**Rep-2 should weigh this again and will probably answer differently.** An
installed application outlives its roots, meets corporate middleboxes, and has
a user who expects the machine's own trust decisions to be honoured.
`rustls-native-certs` is the form that costs no verifier -- it supplies roots
and leaves rustls to verify -- and it owes a written rule for the store that
enumerates nothing. `rustls-platform-verifier` is the form that does cost the
verifier, and the first reason above is the argument against it.

**A correction to how this item was first written.** It said the decision was
cheaper made once than three times. That is right about the *reasoning* and
wrong about the *answer*: a command-line operator and a desktop user want
different things, and one answer would be chosen for whichever of them came to
mind. What this item produces is the reasoning, written down, and Rep-0's
answer -- so that a fork diverges deliberately rather than by drift.

### P0-5 -- fork hygiene **(done, 2026-09-20)**

The fork point is the tag `fork-point-1`. Everything below is what a fork is
for and against.

#### What Rep-1 may change

**Four files, and the release apparatus.** The four are what
`the_unix_surface_is_confined_to_the_files_a_port_would_touch` enumerates,
and the check is what keeps that list honest rather than remembered:

| file | what a port does to it |
| --- | --- |
| `keystore/perms.rs` | adds the `cfg(windows)` arm beside the mode bits |
| `keystore/medium.rs` | the durability primitives -- `fsync_dir` above all |
| `bin/mcm-wallet.rs` | the console device and the platform generator |
| `lib.rs`, `keystore/mod.rs` | the two `compile_error!` gates become a per-platform statement |

`medium.rs` is in the table and not in the check, because its sites are
`std::fs` calls that compile everywhere and behave differently -- which is
exactly why R1-3 is the item to fear. A check cannot find those by name.

The release apparatus -- `board`, `RELEASE.md`, `deny.toml`, CI -- is Rep-1's
to widen, because what it is widening is the platform list.

#### Permanent deltas outside those files

Written here as they are made, under the exception below: each only makes
sense with Windows in the tree, so Rep-0 would refuse it on its own terms.

| file | the delta | why it cannot be a Rep-0 change |
| --- | --- | --- |
| `keystore/perms/windows.rs` | the Windows permission model, a new file, and the slot files' creation and opening under it, shared for reading alone | it is the Windows arm; a separate file so `perms.rs` stays the Unix arm and upstream edits to it merge without meeting Windows code |
| `keystore/slots.rs` | the Windows layout's frame, and the rule by which `open` takes the newer of two slots -- a new file, compiled on Windows and under `cfg(test)` on every platform | the layout exists because Win32 documents no way to commit a rename, which is Windows' alone; a file of its own so the rule is tested on every board and none of it is Windows code in `medium.rs` or `keystore/mod.rs` |
| `error.rs` | `UnsafeAcl` and `HeldOpen`, both `cfg(windows)` | the evidence a Windows refusal carries has no Unix shape, and `UnsafePermissions`' `mode` would have to be invented to carry it |
| `crates/mochimo-crypto/Cargo.toml` | `windows-sys`, a `cfg(windows)` dependency | the declarations the two Windows arms call |
| `README.md`, `docs/specification.md` | the platform statements, the slot layout, and the Windows limits an operator must know -- a store that is two files and moves one way, and a store another program holds refused at `open` | they describe a Windows build Rep-0 does not have |
| `tests/invariants.rs` | two rows in `unsafe_is_confined_to_declared_files` -- the permission model, and the binary's console, held to its `cfg(windows)` `console` module -- and `from_raw_os_error` in the declared unresolved names | neither the Win32 security API nor the console mode has a `std` wrapper, so both are foreign calls or nothing |
| `tests/invariants.rs` | three rows in `DECLARED_PANIC_SITES` for `keystore/slots.rs`'s tests, and the Windows order pin's name among the declared unresolved names | the census counts every file under `crates/*/src`, and that file is this tree's; the pin is Windows' |
| `tests/invariants.rs` | the I3 and I2 proofs are `cfg(unix)`, each beside a Windows form under the same name that stops the slot layout's two steps and tears the write by sector; the I3 census row's comment says what meets its floor there | the Unix proofs walk the rename's four steps, which Windows no longer takes, and the census asks for the proofs by name on every platform |
| `tests/invariants.rs` | `the_unix_surface_is_confined_to_the_files_a_port_would_touch` lists the files the port touched, per needle, where upstream lists the four a port would | it is the record of the port; the test keeps its upstream name so that upstream edits to it still merge |
| `tests/invariants.rs` | its five source walks name files with `/` on every platform | on Windows a relative path joins with `\`, and forty-odd name literals would stop matching |
| `tests/invariants.rs` | the census's three demands on `pty::` tests, and the run-list witness that names one, are answered where the harness is not built by `census::not_built_here`, which asserts that `tests/cli.rs` still declares the harness behind exactly `cfg(all(unix, not(miri)))` with the test in it; the guard then reports the gap in place of evidence | the harness is `script(1)`, which Windows does not have, so the demand cannot be met there; it is replaced by a check of the declared absence rather than dropped, and on Unix nothing changes |
| `tests/keystore.rs` | the three mode-bit tests are `cfg(unix)`; three `cfg(windows)` tests measure the access-list refusal, the protected creation and a held slot refused at `open`. The four-step sequence and the poisoned handle are `cfg(unix)` beside Windows forms, the lock test's live holder is staged without a store on Windows, the at-rest scan covers both slot files, and one arm reads its store under its own password | mode bits do not exist on Windows, a Windows store is two slots written in place, and the Windows claims need tests that run there |
| `tests/support/keystore_harness.rs` | `snapshot_bytes` and `write_snapshot` have Windows arms -- the image `open` would take, and a store in the rename layout holding the bytes given -- beside `snapshot_bytes_under` and `slot_bytes` | a Windows store is two files, and the tests that compare, parse or damage a snapshot mean its image; `tests/cli.rs` goes on reading them unchanged |
| `tests/compile_fail.rs`, `ui/fail/medium_slot_steps_are_not_reorderable.rs` | the medium's order pin is registered per platform, and the slot steps have a pin of their own | each platform's `Medium` has only its own steps, so each pin names methods the other does not have |
| `tests/cli.rs` | one attribute: the `pty` module is `cfg(all(unix, not(miri)))` | its harness is `script(1)`; no assertion changes, which is what the rule about this file protects |
| `tests/mesh_http.rs` | the refused-connection test has its own five-second connect timeout in place of the shared 500 ms | Windows retries a connect a port refused before reporting it, and on a Windows runner the shared timeout ran out first; Linux and macOS refuse at once, so on Rep-0's platforms the change is inert |
| `.gitattributes` | every text file checked out with LF, and no `.bin` file converted in either direction | Git for Windows checks out CRLF by default, and the source scans, the JSON fixtures and the trybuild expectations are read byte for byte; two `.bin` fixtures are printable text to git's detection, so the binary files are named rather than detected |
| `AGENT.md` | the board runs under Git Bash on Windows; the `pty::` count and the board figures are per platform; a workflow runs the board, and the MSRV check beside it, on all three platforms when asked | the board is defined there, and its platform list is what widened |

#### What Rep-1 may not change

**Anything else.** A change Rep-1 wants outside that set is a Rep-0 change:
make it in Rep-0, let it flow down. That is not a courtesy to upstream, it is
the only thing that keeps the merge cheap -- a structural edit made downstream
conflicts with every later Rep-0 commit that touches the same region, forever.

The one exception is a change Rep-0 would refuse on its own terms, which in
practice means anything that only makes sense with Windows in the tree. That
goes in Rep-1 and is written into the table above as a permanent delta, so the
list of things the two trees disagree about stays knowable.

#### How Rep-0 changes flow down

Rep-0 is upstream and never merges from anywhere. Rep-1 merges from Rep-0;
Rep-2 merges from Rep-0 and takes Rep-1's Windows delta as its own merge when
it is ready. Nothing merges upward.

**The measure of whether this is working is the size of the diff at each
boundary**, and it is worth taking that measurement rather than assuming it:
`git diff fork-point-1..HEAD -- crates/` on Rep-1 should touch the four files
above and little else. If it is touching the command layer or `recon`, the
policy has already been broken and the next merge is where it will be felt.

#### What holds the thinness, besides this document

Three checks, and they are the reason Phase 0 was worth doing in this order:

* `the_unix_surface_is_confined_to_the_files_a_port_would_touch` -- a fifth
  file naming the Unix API is a fifth place a port has to find.
* `the_decision_layer_carries_no_prose` -- the command layer's split survives
  only while a page cannot travel through the type that says it is a decision.
* `no_wallet_visible_fn_hands_out_a_wots_signature` -- I1, which a fork
  inherits whole and which its delegation clause now lets a dispatch satisfy
  one call away.

None of them knows about forking. That is the point: they hold properties the
fork depends on, which is stronger than a document asking for the same thing.

#### What this does not cover

This file is not checked. `documented_counts_match_the_artifacts` reads
`AGENT.md` and the crate manifest and would catch a figure drifting there; it
does not read this, and nothing else does either. A table above that stops
matching the tree turns nothing red, and the check named beside it is what
would.

## Fork point 1 -- Rep-0 to Rep-1 **(cut, 2026-09-22)**

**The delta to expect after Phase 0: two `cfg` arms and a durability
statement.** If it is larger than that, P0-1 did not do its job and the
difference should be understood before the fork is cut rather than after.

`phase-0` fast-forwarded into Rep-0's `main`, so `fork-point-1` still names
the same commit, and `./board check` on that tree was green: 393 passed, 0
failed, 0 ignored, over seventeen result lines. Rep-0's `main` and the tag are
on GitHub as `patricksmithlaravel/mcm-rust-cli-wallet`.

**Rep-1 is `patricksmithlaravel/mcm-rust-cli-windows`, and it is downstream by
its history rather than by a badge.** It is not a GitHub fork: GitHub does not
fork a repository into the account that already owns it -- asked through the
API on 2026-09-22, it returned the source repository unchanged and created
nothing. What makes it downstream is what a fork's badge would only have
advertised: every commit up to `fork-point-1` is Rep-0's, Rep-1's `main`
starts there, and a working clone fetches Rep-0 as `upstream`, with pushing
to it disabled, because Rep-0 never merges from anywhere:

    git remote add upstream https://github.com/patricksmithlaravel/mcm-rust-cli-wallet.git
    git remote set-url --push upstream 'DISABLED: Rep-0 never merges from anywhere'

A Rep-0 change flows down as `git fetch upstream` and a merge of
`upstream/main`, and nothing flows back.

### The delta, measured

`git diff fork-point-1..HEAD --stat -- crates/` at the end of Phase 1: eleven
files, 1,405 lines added and 100 removed. **It touches neither the command
layer nor `recon`**, which is the policy's own test of whether it held.

The expectation above was low, and the difference is understood rather than
waved at. Three things made it larger, none of which P0-1 could have taken
upstream:

* **The permission arm is foreign calls.** `std` neither reads a security
  descriptor nor creates a file under one, so the access-list check and the
  owner-only creation are 288 lines of code over `windows-sys`, in a file of
  their own -- and the first `unsafe` under `src/` since the C backend left.
* **The console could not be a `File` over the console's handle.** `ReadFile`
  on a console returns the input code page's bytes, which would make a
  password different bytes on Windows than on Linux. The wide calls are
  foreign too, and they are most of the binary's 180 added lines of code.
* **The test tree assumed Unix in three places**: the mode-bit tests, the
  pseudo-terminal harness, and path separators in the invariant suite's walks.

What matters for merge cost is how much *upstream* code moved, and that is
small: 25 lines of Unix-compiled code were removed or replaced -- ten prompt
messages now naming their device through one constant, the two gates and
their messages, the rename's error mapping, and one field type. Everything
else is additive: `cfg(windows)` arms, one new file, three new tests, and
prose. By a count of added lines in `crates/`, more than half of what Phase 1
wrote is argument rather than code, which is this tree's standard and not an
accident of it.

## Phase 1 -- work in Rep-1

### What was measured

`cargo check --workspace --target x86_64-pc-windows-msvc`, run against this
tree, reports **eight errors**. Two are the deliberate `compile_error!` gates
(`lib.rs`, `keystore/mod.rs`). The other six are **mode bits and nothing else**
-- the sites P0-1 has since gathered into `keystore::perms`.

Patching only those six, the same command reports **no errors and no
warnings**. WOTS+, the address path, the transaction wire form, BIP39 and
derivation, the Mesh codec, the spend builder, reconciliation, `Wallet` and the
whole command layer compile for Windows unchanged.

**What that measurement does not cover.** It is a `cargo check`. It compiles
and it type-checks; it runs nothing, links nothing, and says nothing about
behaviour. Three of the items below are behavioural and the check is blind to
every one of them.

**Re-measured at the fork, 2026-09-22: seven errors, not eight.** The two
gates, and five in `keystore/perms.rs` -- one import and four `mode` calls --
because P0-1 folded three imports into one. At the end of Phase 1, with the
gates gone and nothing neutralised, `cargo check --workspace --all-targets
--target x86_64-pc-windows-msvc` reports no errors and no warnings, and
`cargo clippy --workspace --all-targets -- -D warnings` and `cargo doc` for
that target are clean too. The shipped binary was checked against
`mesh-http` in a scratch copy with `required-features` dropped, because
`ring` cannot cross-compile; a type error planted in a `cfg(windows)` item
fails that command, which is the evidence the arm was compiled and not
skipped. All of it is still a check.

### Two corrections to the platform statement Rep-0 makes

**`flock` was never an obstacle**, though the keystore's gate named it as one.
`std`'s `File::try_lock` is `LockFileEx` on Windows -- read in `std`'s Windows
`fs` source: `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY` over the
whole range, with `ERROR_LOCK_VIOLATION` mapped to `WouldBlock` -- and the
property the root manifest rests the lock design on survives: the system
releases a terminated process's locks, so a held lock means a live holder. One
residue is Microsoft's own: the release follows termination after a time that
depends on available system resources, so a lock can briefly outlive its
holder. That is a refusal, `Locked`, and so the fail-closed direction.

**The three-interface list omits the durability primitives**, and they are
where the work was. `lib.rs`'s gate named the permission model, the terminal
and the generator; the rename and the directory flush it did not name, and
R1-3 and R1-4 are both about them. The platform statement now has the three
interfaces in `lib.rs` and the storage primitives, per platform, in
`keystore`, and says so in each.

### R1-1 -- the gates **(done, 2026-09-22)**

Replace both `compile_error!`s with a per-platform statement. The Unix half of
what they say stays true and stays said.

Done last among the code items, because the gate was the only thing keeping
R1-3's failure unreachable. `lib.rs`'s head carries the statement as a table
with a Unix column and a Windows column and says the two are not established
to the same degree; each gate is now `cfg(not(any(unix, windows)))`. The
keystore's lock section records the correction about `flock` above, with the
one residue Microsoft documents: a lock can briefly outlive a terminated
holder, which is met as `Locked`.

### R1-2 -- the Windows permission model **(done, 2026-09-22; its tests green on a Windows runner, 2026-09-24)**

A second arm in `keystore::perms`: a DACL check where the mode check is, and
restricted creation where the mode-carrying creation is.

In `keystore/perms/windows.rs`. Creation hands a protected, owner-only
descriptor to `CreateFileW` and `CreateDirectoryW`; the check refuses a
directory anyone but the user, `SYSTEM` or Administrators can write to, and
one another user owns. The refusal is a new `cfg(windows)` variant,
`Error::UnsafeAcl`, rather than `UnsafePermissions` carrying an invented mode.
**This plan did not foresee that the arm is `unsafe`**, which
`unsafe_is_confined_to_declared_files` refused until it was given a row with
the argument its comment asks for.

**Reviewed and accepted, 2026-09-24.** All twenty-four `unsafe` blocks --
eighteen here and six in the binary's console -- were read against
Microsoft's documented contract for each call, and every SAFETY condition
holds. Three blocks here rested on more than they needed to and were narrowed
in `5cfed2e`: two descriptors taken into ownership before their call was known
to have succeeded, a SID pointer derived through a reference narrower than
the SID, and a raw pointer into a descriptor that no lifetime tied to it. The
allow-list's console row is held to its module by the commit that records
this. Of the twenty-four, these eighteen are what the Windows board goes
through, and it has run them both as they stood before `5cfed2e` and as that
commit narrowed them -- run 36073146927, at `7e45af7`, green. The console's
six have not run at all.

`windows-sys` is **already in `Cargo.lock`** (two versions, through the
transport's graph), and `deny.toml` leaves `targets` unset deliberately so the
licence walk already reaches it. A direct dependency on it adds no crate and no
licence to this workspace's policy.

Note what `perms.rs` records about the public surface: `Error::UnsafePermissions`
carries `mode: u32` and renders it as octal. A second implementation either
reports a Unix mode it did not measure or changes a public variant.

### R1-3 -- `fsync_dir`, which is the one that matters **(done, 2026-09-22; closed on Windows by the slot layout, 2026-09-25, run green on a Windows runner)**

`medium.rs`'s fourth durable step opens the directory and `sync_all`s it. On
Windows that **compiles and fails at runtime**: `File::open` on a directory is
refused there, so every commit fails at its last step. It is the only item in
this document that the compile gate is actively hiding, and it is the reason
the gate should not simply be deleted.

There is no directory `fsync` on NTFS to substitute. **I3's crash proof does
not transfer**, and the honest form is a per-platform durability claim that
says so, in the idiom the rest of this tree uses for what it cannot establish.

The Windows step performs no I/O. Two candidate substitutes are weighed and
refused at the site, and the hazard is written as one: a power cut before
NTFS flushes its log can bring back the previous snapshot, and with it the
chance to sign a reserved position twice. The README tells a Windows operator
what to do after a power cut.

**Decided, 2026-09-24: stated for the merge, closed before a release.**
Phase 1 goes into Rep-1's `main` with the hazard stated as above, and
`RELEASE.md` carries closing it as a gate, so no tag is cut while it stands.
Two routes close it. One is the measurement the site names: a power-cut test
on NTFS under each refused candidate, on a Windows machine or a VM that can be
powered off hard, which no hosted runner can do. The other removes the
dependence instead of measuring it: on Windows, write each new version into
one of two files that already exist -- alternating slots with a sequence
number, flushed in place with `FlushFileBuffers`, which is documented -- so no
directory entry is left to lose. The second is designed below, approved,
and built; it changes how the store is written on Windows, and the design is
the crash argument it owes.

**Closed on Windows, 2026-09-25, by the second route.** The slot layout is
built -- the reading rule in `2c35e02`, the write path in `764e7be` -- and
its first run on a Windows runner is green; the section below and R1-6 have
the run. On Windows the store no longer depends on the directory entry a
rename writes. What its power-loss claim rests on instead is the flush of a
slot written in place, which Microsoft documents, and a device that honours
it, which nothing can document: the footing an `fsync` gives the Unix path.
The paragraphs above state the hazard as it stood before; `RELEASE.md`'s gate
now says what a person checks at a tag.

#### Route A, designed: two slots written in place **(approved, 2026-09-24; built, and run green on a Windows runner, 2026-09-25)**

The second route above, carried as far as a design can be judged without
code; what of it is built, and what has run, is said at the section's foot.
Every claim it makes about Windows is read from Microsoft's documentation or
`std`'s source, and says which.

**What it would establish.** Once `Durable` is minted on Windows, no power
cut or operating-system crash can make a later `open` return a state older
than the one that commit wrote -- the claim the Unix path makes with its
directory flush. It gets there by taking every directory entry off a commit's
path: once a store's two files exist, a commit writes one of them in place
and flushes it, and nothing is created, renamed or deleted. The one call it
rests on is `FlushFileBuffers`, in the two uses Microsoft documents for it:
putting a file's written data on the device, and storing a file's metadata,
for which the documentation's own example is a file just created. The rest
is this tree's code, and the part a power cut exercises -- what `open` makes
of a slot left torn -- can be tested by fault injection.

**The layout.** Two slot files beside the lock: `accounts.mks`, slot 0, and
`accounts.mks.1`, slot 1. Each holds one frame and nothing after it:

    magic[8] = "MCMKSLOT" | frame_version u16 = 1 | payload_len u32
    | payload[payload_len]   version 1: one image in `format`'s layout,
                             unchanged, or nothing for the vacant frame
    | check[32]              SHA3-256 over every byte before it

A slot's file length is `46 + payload_len`, and a slot whose length disagrees
with its frame is torn. Only the payload is versioned: the magic, the version,
the length and the check keep their places in every frame version, so an older
build can still verify a later frame's check and refuse it, where a later
version free to move the check would have that build call the slot torn and
take the older one beside it. The image is what `format::encode` seals today
-- header, ciphertext and tag -- so **`format.rs` does not change**, and every
rule it enforces holds inside a slot. Slot 0 keeps the snapshot's name, so
`open` still reports `Missing` from one name, and a build that reads only the
plain image -- Rep-0's, and this tree's own on Unix -- refuses a slot at its
magic, as `Corrupt` at `magic` (or, for a store at the account cap, at its
length), instead of reading a stale snapshot, and refuses to `create` over it.

**The sequence number is the image's generation, and it stays encrypted.**
Format version 3 moved `generation` into the ciphertext so that a stolen file
does not say how often it was written. A plaintext counter in the frame would
undo that, and one short enough to say nothing would be too short to order
two slots, so the frame carries none: `open` orders the slots by decrypting
both. The key is derived once, from an intact frame's header when there is
one, because every generation of a store is sealed under one salt; two intact
slots whose headers disagree on the salt or the KDF parameters are refused,
since this writer never makes that pair.

**The check is keyless, on purpose.** The tag refuses a torn image too, but
only once a key exists, and it cannot say whether an image was torn or
altered -- by design, as `WrongPassword`'s doc argues. The check sorts the
slots before any key is derived. A frame whose check fails is torn, which is
what a crash leaves, and it is never a refusal while the other slot holds an
image. A frame whose check passes and whose tag then fails is sealed under
another key or altered -- no crash makes one -- and it is refused as
`WrongPassword`, as a damaged snapshot is today; one whose parse fails is
refused with the parser's own error. SHA3-256 is already the crate's own, for
the nonce, so the check adds no dependency.

**Open.** As today up to the lock and the stale temp. Then both slots are
read, and each is one of: *absent* (slot 1 only), *vacant*, *torn*, an
*intact* frame, or -- slot 0 only -- a *plain* image, which is what every
store is until its first Windows commit. Intact frames holding an image are
candidates. A plain slot 0 is read exactly as today while slot 1 holds no
intact frame; beside one, it is a candidate if it decrypts and parses, and
otherwise it is the torn remainder of an overwrite -- a plain image is
overwritten only after slot 1 holds a flushed frame -- and not a refusal.
`open` takes the candidate with the higher generation as the newest, and
names the other slot, whatever it holds, as the next commit's target. It
refuses a store with no candidate, two candidates at one generation, and a
frame in slot 0 with no slot 1 beside it, which only a deletion leaves: a
silent step back to the older image is otherwise how a deleted file would
show.

It holds both slots open for the handle's life, sharing read access only.
While a handle lives no other process can then write, rename or delete a
slot, which is the one way a flushed write could stop being the file the next
`open` reads; and a program already holding a slot without sharing write --
the scanner R1-4 names -- is refused by name at `open`, before anything is
reserved, rather than at a commit that then poisons the handle. `open` still
writes nothing.

**Commit.** Two steps, each consuming the token the one before it produced,
as the four do on Unix: `write_slot` writes the frame into the target at
offset 0 and sets the file's length to the frame's, and `flush_slot` is
`FlushFileBuffers` on the target, which is what `std`'s `sync_all` calls on
Windows, read in its Windows `fs` source. Then `Durable`. Two rules frame
them. The target is never the slot holding the newest image. And a handle's
first commit begins by flushing the newest slot as it found it, so that a
slot is overwritten only while the other is known to be on the device: after
a flush that failed, a later process can read a newer slot out of the cache
although it never reached the disk, and overwriting the older slot then would
leave a power cut nothing to go back to.

**A crash at every step.** On this path a kill and a power cut differ in one
respect: a power cut can also undo an unflushed write -- all of it, or any mix
of old and new sectors, at the old length or the new -- and an unflushed
creation. The other slot is not written, so it is not in play:

| the crash comes | the target holds | `open` takes | allowed because |
| --- | --- | --- | --- |
| before `write_slot` | what it held | the newest: pre | nothing new was written |
| once `write_slot` has begun, before `flush_slot` returns | the old image, the new, or a mix | the new image if the target is intact, else the newest: post or pre | no receipt exists for the new image, so taking it skips a position and never repeats one |
| after `flush_slot` returns | the new image, on the device | the new image: post | the documented flush |
| after `Durable` | the same | post | the next commit writes the other slot |

**Power loss.** What holds the third row is that a flush which returned is on
the device. Microsoft documents it from three sides: `FlushFileBuffers`
writes all of a file's buffered information to the device; the *File
Caching* page says file-system metadata is always cached and that flushing
the file is how its changes are stored; and the WDK documents a flush request
in its normal form as writing the file's data and metadata and then having
the storage flush its own cache, on NTFS, ReFS, FAT and exFAT -- the last two
of which the permission check already refuses a store on. What no document
can say is that a device honours the flush it is sent: storage that
acknowledges one it did not perform defeats this path as an `fsync` that lies
defeats the Unix one, and it is the same stated residue.

**Create, and the one directory entry each slot has.** Creating a slot writes
a directory entry, and it is stored the documented way: `CreateFile`'s
section on caching, in its paragraph on unbuffered handles, gives "creating
an empty file" as its example of metadata that may still be cached and
`FlushFileBuffers` as how to make sure it reaches the disk, and the *File
Caching* page says the same of all metadata. `create` writes slot 1 first --
the store's first image, in a file created under the protected list, then
flushed -- and only then `accounts.mks`, a vacant frame, flushed. So the
snapshot's name existing means an image is on the device, on Windows as on
Unix. A power cut inside `create` leaves at most an `accounts.mks.1` with no
`accounts.mks`: `open` calls that `Missing`, and on Windows `create` refuses
it by name rather than overwrite it, because it can also be the last copy of
a store whose `accounts.mks` was deleted by hand. Once a store has both slots,
no file is created again.

**Migration from the rename layout.** Two kinds of store reach this path
with a plain `accounts.mks`: one that a build of this tree made on Windows
before the change -- a development build, since no tag is cut while the gate
this closes stands -- and one copied from Linux or macOS. `open` reads it as
today. Its first commit is the one that differs: it writes the next image
into slot 1, creating it, and flushes it; then it overwrites `accounts.mks`
in place with a vacant frame and flushes that; and only then is `Durable`
minted. From that commit on, a build that reads only the plain image refuses
the store at its magic. A crash inside it leaves slot 1 absent, torn or
intact beside the plain image or its torn remainder, and the rules above take
the plain image until slot 1 is intact, and slot 1 from then on. The
version-3 crossing is separate and still happens at the first commit. The
residue: a crash between that commit's two flushes, followed by a build that
reads only the plain image opening the directory -- on Unix, or a Windows
build from before the change -- which would read the plain image and not the
newer slot.

**The lock and `Durable`.** The lock does not change: `keystore.lock` under
`LockFileEx`, taken before anything is read and held for the handle's life.
`Durable` is still constructed at one expression, the `Ok` arm of
`Keystore::commit`: `durable_witness_has_one_construction_site` counts
constructions in the source whatever their `cfg`, so the Windows steps return
into that arm rather than minting in one of their own. What it witnesses on
Windows becomes the Unix claim -- the image is on the device, in a slot the
next `open` takes over every older one. Poisoning does not change: any failed
step poisons the handle, and the next `open` reads both slots again.

**Unix does not change.** The rename path, its four steps and their
typestate, the proofs driven through them and the trybuild case pinning their
order stay as upstream has them, which keeps every Rep-0 change to them
merging. Rep-0 would refuse this path on its own terms, since Unix has the
directory flush it exists to do without. A store therefore moves from Unix to
Windows by copying its directory, and its first Windows commit migrates it;
one copied from Windows to Unix is refused there at the magic -- fail-closed,
and a limit the README would state, since moving a store that way needs a
conversion this design does not provide.

**Tests, through `Instrumented`.**

* *On every board.* The frame codec and `open`'s choice are pure functions of
  bytes and a key, so their tests run everywhere: every truncation and every
  single-byte change of a frame; an old frame and a new one mixed at 512-byte
  granularity, both ways round; and every pair of slot states -- absent,
  vacant, torn, plain, and intact one generation behind, level and ahead --
  asserting what `open` takes or refuses for each. That is the table above,
  enumerated rather than argued.
* *On the Windows runner.* `Instrumented` records the two steps with their
  arguments and stops after either, as it does now, and gains a torn
  injection: before returning its error it leaves the target holding a chosen
  mix of old and new bytes, at the old length or the new, or leaves no file
  where one was being created. The I3 proof's Windows arm drives every step
  and every mix over the commits it walks and finds every member fully pre or
  fully post, and post once `flush_slot` has returned; the I2 proof's finds no
  receipt escaping; `create` and the migrating commit are walked the same way.
  Both proofs keep their names, so the census asks for them on Windows as on
  Unix, and I3's floor of four is met by two steps over two commits before a
  single mix is counted.
* *By documentation alone*: that a flush which returned survives a power cut.
  No injection can model that, since it is the premise the injections are
  conditioned on; Route B's measurement is what would add evidence to it.

`tests/cli.rs` does not change. Its tests that run on Windows -- everything
outside the `pty` module -- compare `snapshot_bytes()` before and after a
command, ask whether `accounts.mks` exists, and in one case write a version-3
image and read the version word of the image its first write produced. The
harness's `snapshot_bytes()` gains a Windows arm returning the newest image,
and `write_snapshot()` one that leaves a store in the rename layout holding
exactly the bytes given -- which is what putting bytes back for the arms that
damage a file on purpose means once a store has two files.
Tests that assert the four-step sequence, among them
`medium_sequence_is_exactly_the_four_steps_with_their_arguments` and
`poisoned_handle_refuses_to_launder_a_rollback`, become Unix-only beside
Windows twins, and R1-4's held-snapshot test becomes a held-slot test,
refused at `open`.

**The delta.** `medium.rs` and `keystore/mod.rs` carry the path, and both are
Rep-1's to change. The frame and `open`'s choice are a new file, compiled on
Windows and under `cfg(test)` everywhere, so that its tests run on every board
and no platform compiles code it never calls: a permanent delta, with a row.
`error.rs`'s Windows variants change inside their row -- `ReplaceRefused`
names a rename that no longer happens, and its refusal moves to `open` -- and
so do the test rows: the proofs' Windows arms, the census floor's comment,
the harness's arms and the twins. `format.rs`, `recon.rs` and `src/cli/` do
not change, and nothing is asked of Rep-0. One question of shape is left to
the implementing commit, because it is about merge cost and not about
correctness: whether Windows' `Medium` is a trait of its own, which keeps
every step's name true and costs a per-platform registration of the order pin
in `tests/compile_fail.rs`, or the Unix trait with the slot steps added under
`cfg(windows)`, which leaves the pin alone and the four rename steps compiled
on Windows with nothing to call them. The first is recommended.

**Weighed, and refused.**

* `ReplaceFileW` with `REPLACEFILE_WRITE_THROUGH`: Microsoft documents that
  flag as not supported.
* `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`: weighed at `fsync_dir`
  already; the guarantee its page gives is stated for a move performed as a
  copy and a delete.
* Transactional NTFS: Microsoft recommends other means and says it may not be
  in future versions of Windows.
* Slots preallocated at `MAX_IMAGE_LEN`, so that no write changes a length:
  12,779,632 bytes a slot for a store that holds a handful of accounts, to
  save a metadata change the flush stores anyway.
* A plaintext frame counter: above.
* **Route B's second candidate, which reads better than its site says.** The
  *File Caching* page says flushing a file stores its metadata changes, and
  `CreateFile`'s caching section counts a rename among a file's metadata
  changes. Read together they say more for flushing the snapshot after the
  rename than `fsync_dir`'s refusal credits, and a temp whose handle is held
  through the rename could be flushed without the reopen's fresh chance of a
  sharing refusal. It is still an inference across two pages; it leaves
  unsaid whether the replaced target's entry is among the renamed file's
  metadata; and it keeps the reliance on the replacing move being atomic,
  which Win32 does not document. Route A needs none of that. It is a few lines
  against a new layout, though, and an improvement on a step that flushes
  nothing -- but it neither removes the dependence on the rename nor measures
  it, so by `RELEASE.md`'s own wording it does not close the gate alone. The
  same pages also make the tree's general sentence that Win32 documents no
  call committing a directory entry on NTFS -- in `RELEASE.md`, the
  specification and the keystore's crash section -- stronger than the
  documentation: it documents one for a file just created, which is what this
  design uses.

**Not established, here as on the path it replaces.** The store directory's
own entry in its parent is flushed by nothing, on Windows or on Unix, so a
power cut before the file system commits the directory's creation can take
the whole store with it, and any reservation made in it meanwhile. It is a
gap in both platforms' statements, and stating it is Rep-0's first. A device
that does not honour a flush. And all of the above is unbuilt.

**When it is built, every statement of the hazard changes with it**:
`medium.rs`'s module doc and `fsync_dir`'s Windows arm; the keystore's crash
section, its storage-gate comment and `Durable`'s doc; the README's platform
line and its two Windows limits; the specification's file table, its section
on how a file is replaced, and I3's limit; `RELEASE.md`'s gate and its
paragraph on the directory flush; and R1-3, R1-4 and the delta table here.

**What approval settled, 2026-09-24**: Route A as designed rather than Route
B's cheaper candidate first; the two names and the frame; that a store copied
from Windows to Unix is refused rather than converted; Windows' `Medium` as a
trait of its own; and the first-commit flush, which costs a committing command
one more flush.

**The reading rule is built first**, in `keystore/slots.rs`: the frame, how a
slot file is sorted before any key exists, and `take`, which is `open`'s
choice between the two. It is compiled under `cfg(test)` on every platform,
so the rule is tested on every board -- every cut and every one-bit change of
a frame, every sector-by-sector mix of an old frame and a new one at both
lengths, and each of forty-nine pairs of slot states against what `take` must
make of it -- before any Windows code calls it.

**The write path is built second**, in `764e7be`: Windows' `Medium` as a
trait of its own, with `write_slot`, `flush_slot` and `flush_standing`, and
its instrument's torn-write injection; `perms`' slot files, created under the
protected list and held sharing read alone; the keystore's Windows `open`
and commit; and `Error::HeldOpen` in `ReplaceRefused`'s place. What the
design above left to it: the order pin is registered per platform in
`tests/compile_fail.rs`, and the harness reads a store's image without a key
when one slot holds it and orders two through `keystore::newest_image`,
public on Windows alone, for the tests.

**Run on a Windows runner, 2026-09-25**: run 36095852071 at `764e7be`, green
in all six jobs, the first execution of the layout anywhere but this host's
unit tests. The I3 and I2 proofs ran in their slot-layout forms and passed,
their census guards with them: each commit stopped after each of its two
steps, and its write torn in every mix of its sectors at both lengths,
reopened fully pre or fully post -- post only once the write was whole -- and
no receipt escaped. A slot held by another program was refused at `open` as
`HeldOpen`, the medium's calls were the two steps with their arguments, and
the Windows order pin's expected output, normalised by hand from a compile
for that target, matched. What the run cannot say is what no hosted runner
can: a real power cut, an unelevated desktop, and a scanner, since real-time
protection is off on the image.

### R1-4 -- rename under a sharing violation **(done, 2026-09-22; measured on a Windows runner, 2026-09-24; no rename on Windows since the slot layout, and the refusal met at `open`)**

`fs::rename` over an existing file maps to a replacing move on Windows, which
fails while another process holds the target open without delete sharing --
scanners, indexers, backup agents. The commit fails cleanly and the store is
unchanged, so this is an availability problem and not a correctness one, but it
needs a named error rather than an anonymous `Io`.

`Error::ReplaceRefused { code }`, for `ERROR_ACCESS_DENIED` and
`ERROR_SHARING_VIOLATION`. One thing learned in `std`'s source: its Windows
`rename` retries a refused move with POSIX rename semantics, and returns the
first error if the retry fails too. **Measured on a Windows runner** --
Windows Server 2025, build 26100 -- the retry does not replace a snapshot
another process holds open sharing read only:
`a_snapshot_held_open_without_delete_sharing_refuses_the_commit_by_name` is
green there, so the commit is refused as `ReplaceRefused`, the snapshot is
unchanged and the handle is poisoned. That is one build of one Windows, and a
holder that shares delete is not measured.

**With the slot layout, 2026-09-24, Windows renames nothing**, so no commit
can meet this refusal. `open` holds both slot files for writing, shared for
reading alone, and a program already holding one without sharing write is
refused there as `Error::HeldOpen` -- before anything is read or reserved, so
there is no handle to poison -- while a program that comes later cannot open
a held slot for writing at all. `ReplaceRefused` is gone with the rename, and
the held-snapshot test with it; the held-slot test replaces both.

### R1-5 -- the binary **(done, 2026-09-22; built on a Windows runner; run at a Windows console by a person, 2026-09-25)**

`/dev/tty`, `stty` and `/dev/urandom` are the binary's, not the library's --
the library takes entropy as a parameter and `cli::create::Terminal` is already
the seam for the prompts. The Windows equivalents are the console device, the
console mode flags, and the platform generator.

`CONIN$` and `CONOUT$` by name, `ENABLE_ECHO_INPUT`, and `BCryptGenRandom`.
The `Terminal` impl is not copied: `Tty` holds a `Device`, which is a `File` on
Unix and a `Console` implementing `Read` and `Write` on Windows, so the prompt
ordering this binary's defects taught is written once and an upstream fix to
it reaches both platforms.

The shipped binary, TLS and all, builds natively on a Windows runner: the
`build: shipped` and `clippy: mesh-https` rows are green there, `ring`'s C
compiled by the image's MSVC. No board runs it, so on a runner the console,
its echo handling and `BCryptGenRandom` are established by nothing that
executes; one person's run at a console, below, is all that has.

The console module's six `unsafe` blocks were reviewed with the permission
arm's (R1-2) and needed no change. `unsafe_is_confined_to_declared_files`
holds them to that module: its row names `console`, and an `unsafe` anywhere
else in the binary, or the module losing its `cfg(windows)`, is red.

**A `Ctrl-Z` ends console input only when it begins a line** -- decided
2026-09-24 and made in `7ca154d`. `Console::read` took one that began any
read as the end, so with the 512-byte chunks `read_scrubbed_line` offers, a
`Ctrl-Z` typed as a line's 170th character cut the line there. `Console` now
tracks whether its next read begins a line, and nothing Rep-0 owns moved. The
changed module has compiled natively on a Windows runner, in the fifth run
below, and has run at a console in the run recorded next.

**Run at a Windows console, 2026-09-25.** A person other than the
maintainer ran the shipped binary, built from `e8d73aa`, at a Windows 11
24H2 console on an x86-64 machine, following a written runbook of setup and
eleven checks, and sent the results back as text. The runbook asked for an
unelevated session and the run was elevated, at High mandatory level;
Defender's state was not recorded; and the terminal for most checks was
recorded only as neither Windows Terminal nor the classic console. The
build, under Git for Windows 2.55.0.windows.5 and rustc 1.98.0, finished,
rustls 0.23.45 and `ring`'s C with it. Ten of the eleven checks came back as
the runbook described them:

- `create`: both password prompts took typing unseen, the phrase was shown,
  the three-word confirmation echoed, the store was written with exit 0, and
  the shell echoed normally afterwards. So the console mode was turned off,
  restored, and restored checked on the path that needs it, and
  `BCryptGenRandom` returned success for the phrase, the salt and the nonce
  seed.
- `address` opened that store, and a wrong password was refused with
  `WrongPassword`'s text and exit 2.
- `create --from-phrase` read a 215-character phrase over two `ReadConsoleW`
  calls and derived `ymDfL9C6eftjnVuhfHdhqjMp4KBfbu`, the destination macOS
  derives from it; its password, 169 characters and so 171 units with the
  CR LF, was read the same way and opened the store again.
- A `Ctrl-Z` beginning a line was refused as end of input, exit 2. A `Ctrl-Z`
  as the 170th character of a line, the first of its second read, was a
  character of the line: the 169 characters with it and an `x` did not
  decrypt the store, and the 169 alone did. That is `7ca154d`'s behaviour,
  measured.
- `blocks` and `balance` against `https://api.mochimo.org` completed TLS
  handshakes with rustls 0.23.45 -- the first handshake of this tree on
  Windows -- and `balance` refused the unfunded store on the node's `account
  not found`, as it must.
- Two stores sealed on macOS, one under a password with `ü`, `ß`, `ñ` and
  `ú` and one with two emoji outside the Basic Multilingual Plane, opened on
  Windows under the same passwords pasted at the console. The UTF-16 the
  console delivered was transcoded to the UTF-8 macOS sealed under,
  surrogate pairs whole.
- The classic console window, `conhost`, behaved as the other terminal did,
  for the `a` store and the Latin one.
- Git Bash reached a working prompt through `winpty`. Which of the runbook's
  three outcomes it met without `winpty`, and its `MSYS` value, were not
  recorded.

The eleventh was `Ctrl-C`, and it differed from what the console module
expected. From Microsoft's documentation the module had the default control
handler end the process at a prompt, running no destructor and leaving echo
off. From PowerShell, `Ctrl-C` at the `password:` prompt produced the
end-of-input refusal instead -- which here means a `ReadConsoleW` that
returned no characters -- and `echo hello` at the shell afterwards was
echoed. The guard restores the mode before that refusal prints, so the
restored console follows from the order the code already has. Whether the
handler ended the process after the refusal, which the unrecorded exit code
would say, and whether the read returns first every time, is not
established; the Command Prompt half of the check is not in the results.

What the run does not establish: the access-list check met the
Administrators group as the owner, as on the runner, because the session
was elevated, so an unelevated desktop is still unmeasured (R1-2). Nothing
held a store open, and whether a scanner was running is not known. It is
one run on one machine, returned as text, and nothing in the tree repeats
it.

### R1-6 -- the board **(done, 2026-09-22; green on all three platforms, 2026-09-24; its Windows `verify` assembled from parts, 2026-09-25)**

`./board` is a POSIX shell script. `RELEASE.md` asks for green on two platforms
at one commit; it becomes three.

**Record the coverage that does not come with it.** `tests/cli.rs`'s
pseudo-terminal harness drives the binary through `script(1)` and has no
Windows equivalent, so the binary's remainder -- argv, the prompts, the real
transport -- is exercised on two platforms and not on the third.

The script runs unchanged under Git for Windows' POSIX shell, and its head
says why there is no PowerShell copy. `RELEASE.md` asks for three green rows
at one commit and records the gap above, and what a green Windows board does
and does not say. For the board to be green on Windows at all, the test tree
had to compile there and its checkouts had to be byte-identical: the mode-bit
tests and the `pty` module are `cfg(unix)`, the invariant suite's walks name
files with `/`, and `.gitattributes` asks for LF. `cargo check --all-targets`
for the Windows target is clean.

**The runner.** `.github/workflows/board.yml` runs `./board check` on GitHub's
Linux, macOS and Windows runners at one commit, and in a job of its own
`RELEASE.md`'s check of the declared minimum compiler, when a person pushes a
branch whose name begins `board/`, on its own. It gates nothing and writes no
record; `RELEASE.md` says what it stands in for, and its own head argues the
rest -- the clone under the user's profile, no actions, `-latest` images,
`check` rather than `verify`, the minimum compiler as a job apart, and why
the branch is pushed alone. Its Linux and macOS jobs are coverage Rep-0 lacks
as much as this tree does. If Rep-0 takes a workflow of its own, it is made
there and flows down, and this file keeps only what Windows adds.

**Seven runs, 2026-09-24 and 25.** Each figure is summed from that job's own
seventeen result lines, read with `gh run view <run> --job <job> --log`:

| run | commit | Linux | macOS | Windows |
| --- | --- | --- | --- | --- |
| 35964912554 | `1ebbcaf` | green, 393 passed | green, 393 passed | seven rows green; `test` red, 371 passed and 4 failed |
| 35971159465 | `11da718` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36068611866 | `62fcca2` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36073146927 | `7e45af7` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36091463164 | `7ca154d` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36095852071 | `764e7be` | green, 400 passed | green, 400 passed | green, 382 passed |
| 36106141274 | `cb933ce` | green, 400 passed | seven rows green; `test` red, 399 passed and 1 failed; re-run green, 400 passed | green, 382 passed |

Nothing was ignored on any platform. Windows runs eighteen fewer: the
`pty::` tests its gate removes. The third run is of the tree after Rep-0's
`0c12e38` came down, so its Linux and macOS `pty::` tests drive the binary's
reads through `read_scrubbed_line`, and it is the first run of the workflow's
`msrv` job: on 1.89.0, read from the manifest's `"1.89"`, both of
`RELEASE.md`'s commands exit 0 on all three platforms, `ring`'s C compiled on
each. That is the per-platform MSRV check `RELEASE.md` asks for before a tag,
green at `62fcca2`. The fourth runs the permission arm as the review of its
`unsafe` narrowed it in `5cfed2e`, and the allow-list with the binary's row
held to its console module: both are green on Windows, and the `msrv` job is
green again on all three. The fifth runs the console that takes a `Ctrl-Z`
as the end of input only at a line's start, R1-5's decision: the Windows
`clippy: mesh-https` and `build: shipped` rows compiled the changed module
natively, and the `msrv` job is green on all three once more. The sixth runs
the slot layout, R1-3's close: seven more tests on every platform, the
reading rule's unit tests, which is why Linux and macOS pass 400 and Windows
382, and on Windows the layout's own forms of the I3 and I2 proofs and of the
keystore tests the rename layout's steps shaped; the `msrv` job is green on
all three again. The seventh runs Rep-0's `rustls` 0.23.45, merged down in
`be28279`: the Windows `clippy: mesh-https` and `build: shipped` rows
compiled it natively, and the `msrv` job compiled it on 1.89.0 on all three
and is green on each.

The seventh's one red was on macOS, in
`pty::submit_on_a_real_pty_ships_a_saved_artifact_and_opens_no_store`, and
before the binary ran: the test's own `Keystore::open`, which holds the
store's lock for the rest of the test, was refused as locked, a moment after
the in-process `send` that made the store had dropped its handle. Nothing
in the command layer outlives `cli::run` and every scratch directory is
unique, so the likely holder is another test thread's child caught mid-spawn,
whose descriptor table holds a copy of every descriptor the test process has
open, the lock's included, until its exec closes them; `flock` belongs to
the open file description, so a copy keeps the lock. That is inferred and
not measured. It is a race of the test process, which spawns children from
parallel threads, and not of the wallet, whose binary has no second thread
to take the lock while it spawns. The job's re-run at the same commit, on
the same image, passed 400 with that test green. The test is Rep-0's, in
`tests/cli.rs`, which this tree does not change, so the remedy is Rep-0's
to make.

The hosts were Linux 6.17 on x86_64, Darwin 25.6 on arm64 and Windows
10.0.26100 on x86_64. `macos26` was 20260907.0351.1 throughout; `ubuntu24`
moved from 20260907.300.1 to 20260920.314.1 after the first run; and within
each of the third and fourth runs the Windows board job had `win25-vs2026`
20260907.229.1 while the Windows `msrv` job had 20260922.246.2, where in the
fifth both had 20260907.229.1, in the sixth both had 20260922.246.2, and in
the seventh the board job had 20260907.229.1 and the `msrv` job
20260922.246.2 again -- the `-latest` trade the workflow's head makes,
recorded by the runs themselves.

The first run's four reds were two findings, both in the test tree and both
fixed at their sites: three invariant guards demanded `pty::` tests that
Windows does not build (`11da718`), and the refused-connection test's 500 ms
timeout lost a race with Windows' slower refusal (`bb67dc4`).

**What the Windows board established.** The library's and the command
layer's tests pass there, the invariant suite with them. The shipped binary
builds natively with `mesh-https`. The three `cfg(windows)` keystore tests
pass: a directory Everyone may modify is refused as `UnsafeAcl` naming
Everyone, a store made under such a parent inherits nothing from it, and a
snapshot held open sharing read only refuses the commit as `ReplaceRefused`,
which answers R1-4's question for this build. The proofs the keystore rests
its claim about a kill at a syscall boundary on pass there as on Unix. The
trybuild expectations match byte for byte, and the clone's working tree held
no CRLF file, which is the first measurement of `.gitattributes` on a Windows
checkout.

**What it did not.** The binary never runs there, so the console, its echo
handling and `BCryptGenRandom` are measured by nothing. The runner's account
is the built-in administrator at High mandatory level, and a directory
created there is owned by the Administrators group, so the access-list check
met that owner and never the user's own SID that an unelevated desktop would
give it. Defender's real-time protection is off on the image, so the holder
R1-4 names, a scanner, held nothing. Power loss is beyond any board. And
`verify` -- the Miri run and `cargo deny` -- has not run on Windows.

**On Linux** the eighteen `pty::` tests pass in all three runs through
util-linux `script(1)`, the form `tests/cli.rs` describes as written from the
manual and never run. That comment is Rep-0's, and correcting it is a Rep-0
change.

**`verify` on Windows, assembled (decided 2026-09-25).** `RELEASE.md`'s
Windows row takes `./board verify` in its three parts, and only `check` has
to run on Windows; the workflow's Windows job runs it. `cargo deny check`
judges the whole lockfile wherever it runs, because `deny.toml` leaves
`targets` unset and sets `all-features`. Miri interprets the target it is
given, so `cargo +nightly miri test -p mochimo-crypto --target
x86_64-pc-windows-msvc` is, from any host, the Miri row an x86_64 Windows
host's `verify` makes, and with MIRIFLAGS unset its isolation keeps the
host's entropy, environment and clocks out of what it interprets and
refuses its file system. The row's gate argues each part, and the
workflow's head says what its Windows job is to the row.

Measured from this macOS host at `76225ac`: `cargo +nightly miri setup
--target x86_64-pc-windows-msvc` built the sysroot in about eight seconds;
`cargo +nightly miri test -p mochimo-crypto --target x86_64-pc-windows-msvc
--no-run` compiled every test binary; the same command with `-- --list` in
place of `--no-run` names the same sixty tests, counted by their `: test`
lines, as it does for `aarch64-apple-darwin` -- forty-one of them the
library's, the slot layout's seven among those -- and `--test txwire`
passed its three for both targets, in about forty seconds each. The whole
run for the target has not been made; when it is, it belongs in a row of
`RELEASE.md`'s record at a tagged commit.

What those sixty reach is narrower than the name of the part. None of the
port's `unsafe` is under them: every test that reaches `perms/windows.rs`
does file I/O and is `not(miri)`, and the binary, which holds the console's,
is not built in the configuration Miri interprets. So what the Windows
target adds is Windows' `std` beneath the same tests, with the
`cfg(windows)` arms compiled in, and no Win32 call of the port's own.
`RELEASE.md` says so among what its gates do not reach, and the permission
arm's head and the allow-list's comment, which gave a Unix host as the
reason Miri walks none of that arm, now give the Windows target's reason
beside it.

`cargo deny check` was red at `76225ac`, and by the argument above on every
host: RUSTSEC-2026-0285, in `rustls` 0.23.43, which `ureq` brings in under
`mesh-https` -- TLS 1.3 handshake messages accepted across a change of
encryption level. The advisory's fix is 0.23.45, and `cargo update -p
rustls --dry-run` moved that one package and nothing else. Rep-0's lockfile
carried the same line, so the change was made there, as `4a3e420`, and came
down in `be28279`, whose change to this tree has the same `git patch-id
--stable` as Rep-0's commit. On the merge, `cargo deny check` reads
`advisories ok, bans ok, licenses ok, sources ok` on this macOS host, and
both of `RELEASE.md`'s MSRV commands exit 0 on 1.89.0. The seventh run
above compiled it on all three platforms, Windows included, and on 1.89.0
in the `msrv` job on each.

### R1-7 -- the surface check **(done, 2026-09-22)**

`the_unix_surface_is_confined_to_the_files_a_port_would_touch` keeps its name
and lists the files the port touched, one needle per kind of site, including
`cfg(unix)` and `cfg(windows)` -- the only way `medium.rs`, whose sites compile
everywhere and behave differently, becomes enumerable at all. A `cfg(windows)`
planted in `cli/address.rs` fails it and the failure names the file.

---

## Fork point 2 -- Rep-2

**Rep-2 forks from Rep-0, not from Rep-1**, as soon as Phase 0 lands, and takes
Rep-1's Windows delta as a merge when it is ready.

The reason is scheduling and nothing deeper: Phase 0 gives a graphical wallet
everything it needs, so forking from Rep-0 lets Phase 1 and Phase 2 run at the
same time instead of end to end. The merge is small for exactly the reason
Phase 0 exists.

It does not make Windows arrive sooner. It makes the Unix builds arrive sooner.

## Phase 2 -- work in Rep-2

### R2-1 -- where the graphical code lives

**Outside `crates/`.** Several checks in `tests/invariants.rs` walk
`crates/*/src` by glob -- the route scan, the panic census, the `Debug`-holder
scan, the zeroization scan, the name-citation scan. A crate under `crates/` is
adopted by all of them. A sibling workspace is not, and it follows the
precedent `crates/mochimo-crypto/ui/downstream` already sets. It also lets the
graphical workspace carry its own toolchain pin, which is what makes
`rust-toolchain.toml`'s pin -- held there by the `trybuild` expectations -- a
non-issue rather than a conflict.

### R2-2 -- the toolkit

Measured against this workspace's own `deny.toml` policy, on macOS/aarch64:

| | crates | new licences needed | trips `unmaintained = "all"` | webview |
| --- | --- | --- | --- | --- |
| egui/eframe | 166 | BSD-2-Clause, BSL-1.0, Zlib, **OFL-1.1 + Ubuntu-font-1.0** | 1 | no |
| iced | 150 | BSD-2-Clause, BSL-1.0, Zlib, CC0-1.0 | 2 | no |
| Tauri | 215 | Zlib, **MPL-2.0**, Apache-2.0 WITH LLVM-exception | 6 | **yes** |
| this wallet today | 55 | -- | 0 | -- |

No security advisories in any of them; the failures are maintenance status and
allow-list coverage. Windows backends will shift the counts.

**egui, with `default_fonts` off.** Turning it off drops
`epaint_default_fonts` and with it both font licences -- an `AND` of `OFL-1.1`
and the non-standard `Ubuntu-font-1.0` -- leaving the smallest licence delta of
the three. Immediate mode is also a direct fit for a worker thread that owns
the wallet and a frame that renders a snapshot of it.

**Against Tauri for a wallet:** a JavaScript runtime and an IPC bridge inside
the process that holds the master seed, safety-bearing refusal text rendered
through HTML, and the largest trusted computing base of the three -- of which
the webview is outside anything `cargo deny` can see.

### R2-3 -- the dependency debt stays quarantined

Any toolkit forces the first entries in `deny.toml`'s `ignore` list, which that
file describes as a decision that belongs in a commit message with a reason.
**Rep-0 and Rep-1 never take them.** They are taken in the graphical
workspace's own `deny.toml`, which is a second reason to put that workspace
outside `crates/`: the policy over the code that holds keys stays exactly as it
is today.

### R2-4 -- architecture

A worker thread owns the `Keystore` and the `Wallet`; the interface sends
commands and receives values. Nothing calls the library on the drawing thread:
the transport is synchronous, `Wallet::open` reconciles over the network, and
the KDF is 64 MiB over three passes at `Kdf::RECOMMENDED`. Progress and
cancellation come from P0-2.

### R2-5 -- the threat model changes, and must be restated

This wallet's memory argument is that it retains nothing between calls, because
a command is one process that exits. A graphical wallet holds the seed for
hours. No code follows from that by itself; a corrected paragraph does, and
writing it down is this tree's standard.

An idle timer that drops the `Keystore` drops the `Secret` and releases the
lock in one move, which is the cheapest thing that makes the restatement a
smaller one.

### R2-6 -- one writer, still

The lock is held for the handle's life. A running graphical wallet gives the
command line `Error::Locked`, and so does a second window. That is the correct
behaviour and it needs a sentence in the interface, not a workaround.

### R2-7 -- failing closed, in front of a person

I4 refuses an account whose stored index and the chain disagree, and refuses a
store in which nothing reconciled. `README.md` warns against deleting the store
and restoring the seed elsewhere, because those are the paths back to key
reuse.

**A graphical wallet turns that reflex into a button-shaped affordance**, and
the refusal text is the only thing standing against it. I4's message-quality
clause governs here exactly as it governs `Wallet::open`: a message that
satisfies the letter and produces a workaround is the failure the invariant
exists to prevent.

The states that need designing, and not one of them is a dialog with an OK
button: diverged; reserved and unsettled; a reservation that can no longer be
accepted; the emptied-account window; a spend between submission and
settlement.

This is the item with no estimate. It is also the item that decides whether the
result is worth shipping.

### R2-8 -- three residues, still owed

`cli/mod.rs` renders three things a graphical wallet inherits and must not
soften: submit is a socket write and not a verdict; `tx_val` has never run
offline; the retry artifact is losable. The third is the one place a graphical
wallet can do better than the command line -- the artifact can be a file the
operator saves rather than hex they must notice.

### R2-9 -- notices, generated

BSD-2-Clause requires its notice in binary distributions, and MIT and
Apache-2.0 run throughout the graph. Generate the aggregate in CI rather than
maintaining it, for the reason `board` gives about two copies not held to each
other. `BSL-1.0` and `Zlib` contribute nothing to it -- both exempt binary
distribution.

### R2-10 -- packaging

Installer, signed application bundle with notarisation, and a Linux package.
Certificates have lead time; notarisation especially. Start that before the
code is ready for it.

---

## Licence

*This section is an engineering reading of the licence, not advice, and the two
questions at the end are the ones worth putting to counsel.*

A graphical wallet is squarely inside the Field: the licence's own preface
names tools and wallets that work with the cryptocurrency. Section 3.3 permits
a Larger Work under terms of your choice provided the Covered Software's
obligations are met, which is the MPL lineage doing what it is for -- the
licence attaches to files, not to everything in a binary.

**The toolkit licences raise nothing.** BSD-2-Clause, BSL-1.0, Zlib, CC0-1.0,
MIT and Apache-2.0 are permissive: notice preservation and a warranty
disclaimer, no reciprocal clause, and nothing that reaches across into
`mochimo-crypto` or dictates the combined work's licence. GPL is the licence
that would fail here, and it fails on the field-of-use restriction being a
further restriction it forbids -- which is why a GPL-licensed toolkit is out
and these are not.

**The one real interaction is with the licence itself.** The grant-back at
3.2(a)(ii)(1) fires only if the executable is sublicensed under *different*
terms. Distribute Rep-2's executable under this licence -- the first option the
same clause offers -- and it never triggers. The source-availability obligation
is owed either way.

Over permissive dependencies the grant-back would be a no-op in any case, since
those rights are already available upstream. Over `MPL-2.0` dependencies it is
not, which is a fourth reason the toolkit table above matters.

No trademark rights are granted, so Rep-2 cannot be branded as an official
product of the cryptocurrency it serves.

**For counsel, two questions:**

1. Is `mochimo-crypto` *Original Software* or *Covered Software* under section
   1? It is a reimplementation this workspace's own `Cargo.toml` describes as a
   derivative work. The answer decides whether 3.2(a), which carries the
   grant-back, or 3.2(b), which does not, governs distributing an executable.
2. Does distributing under this licence rather than sublicensing leave
   3.2(a)(ii)(1) untriggered, as its text reads?

---

## What this document does not establish

It is a plan. Nothing in it is verified by anything that runs, and no check
reads it -- if an item here stops matching the tree, nothing goes red. The
figures in it were measured on one host on one day and are quoted with the
command that produced them so they can be taken again; take them again rather
than carrying them forward.

The estimates are absent on purpose for R2-7 and approximate everywhere else.
