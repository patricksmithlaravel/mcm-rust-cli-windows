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
| `keystore/perms/windows.rs` | the Windows permission model, a new file | it is the Windows arm; a separate file so `perms.rs` stays the Unix arm and upstream edits to it merge without meeting Windows code |
| `error.rs` | `UnsafeAcl` and `ReplaceRefused`, both `cfg(windows)` | the evidence a Windows refusal carries has no Unix shape, and `UnsafePermissions`' `mode` would have to be invented to carry it |
| `crates/mochimo-crypto/Cargo.toml` | `windows-sys`, a `cfg(windows)` dependency | the declarations the two Windows arms call |
| `README.md`, `docs/specification.md` | the platform statements, and the Windows limits an operator must know -- no power-loss flush, a rename another program can refuse | they describe a Windows build Rep-0 does not have |
| `tests/invariants.rs` | two rows in `unsafe_is_confined_to_declared_files` -- the permission model, and the binary's console, held to its `cfg(windows)` `console` module -- and `from_raw_os_error` in the declared unresolved names | neither the Win32 security API nor the console mode has a `std` wrapper, so both are foreign calls or nothing |
| `tests/invariants.rs` | `the_unix_surface_is_confined_to_the_files_a_port_would_touch` lists the files the port touched, per needle, where upstream lists the four a port would | it is the record of the port; the test keeps its upstream name so that upstream edits to it still merge |
| `tests/invariants.rs` | its five source walks name files with `/` on every platform | on Windows a relative path joins with `\`, and forty-odd name literals would stop matching |
| `tests/invariants.rs` | the census's three demands on `pty::` tests, and the run-list witness that names one, are answered where the harness is not built by `census::not_built_here`, which asserts that `tests/cli.rs` still declares the harness behind exactly `cfg(all(unix, not(miri)))` with the test in it; the guard then reports the gap in place of evidence | the harness is `script(1)`, which Windows does not have, so the demand cannot be met there; it is replaced by a check of the declared absence rather than dropped, and on Unix nothing changes |
| `tests/keystore.rs` | the three mode-bit tests are `cfg(unix)`; three `cfg(windows)` tests measure the access-list refusal, the protected creation and the named rename refusal | mode bits do not exist on Windows, and the Windows claims need a test that runs there |
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

### R1-3 -- `fsync_dir`, which is the one that matters **(done, 2026-09-22; exercised on a Windows runner, 2026-09-24; power loss unmeasured, and a release gate)**

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
directory entry is left to lose. The second is unevaluated; it changes how
the store is written on Windows and would owe a crash argument of its own.

### R1-4 -- rename under a sharing violation **(done, 2026-09-22; measured on a Windows runner, 2026-09-24)**

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

### R1-5 -- the binary **(done, 2026-09-22; built on a Windows runner, never run there)**

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
compiled by the image's MSVC. Nothing runs it, so the console, its echo
handling and `BCryptGenRandom` are established by nothing that executes.

The console module's six `unsafe` blocks were reviewed with the permission
arm's (R1-2) and needed no change. `unsafe_is_confined_to_declared_files`
holds them to that module: its row names `console`, and an `unsafe` anywhere
else in the binary, or the module losing its `cfg(windows)`, is red.

### R1-6 -- the board **(done, 2026-09-22; green on all three platforms, 2026-09-24)**

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

**Four runs, 2026-09-24.** Each figure is summed from that job's own
seventeen result lines, read with `gh run view <run> --job <job> --log`:

| run | commit | Linux | macOS | Windows |
| --- | --- | --- | --- | --- |
| 35964912554 | `1ebbcaf` | green, 393 passed | green, 393 passed | seven rows green; `test` red, 371 passed and 4 failed |
| 35971159465 | `11da718` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36068611866 | `62fcca2` | green, 393 passed | green, 393 passed | green, 375 passed |
| 36073146927 | `7e45af7` | green, 393 passed | green, 393 passed | green, 375 passed |

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
green again on all three.

The hosts were Linux 6.17 on x86_64, Darwin 25.6 on arm64 and Windows
10.0.26100 on x86_64. `macos26` was 20260907.0351.1 throughout; `ubuntu24`
moved from 20260907.300.1 to 20260920.314.1 after the first run; and within
each of the third and fourth runs the Windows board job had `win25-vs2026`
20260907.229.1 while the Windows `msrv` job had 20260922.246.2 -- the
`-latest` trade the workflow's head makes, recorded by the runs themselves.

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
