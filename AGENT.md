# mcm-wallet

A Rust wallet for Mochimo v3: WOTS+ one-time signatures, 40-byte `tag || hash`
addresses, an encrypted keystore whose key index only ever moves forward, and
a client for the Mesh API. One crate, `crates/mochimo-crypto`, and one binary,
`mcm-wallet`. The crate and every test target are pure Rust; the shipped
binary is not -- `--features mesh-https` links `ring`'s C and assembly for
TLS, and both the board's last row and `tests/cli.rs`'s pty harness build it.

**How the wallet works is written down once, in `docs/specification.md`.** Read
it before changing anything that touches a wire format, a key, or the store.
The numbers in it are pinned by the fixture corpus under `fixtures/`, which is
the executable form of the same specification.

Where a comment cites `tx.c:NN`, `types.h:NN`, `wots.c:NN` or
`reference/.../file:NN`, it names the Mochimo C reference at the commit given
under *The fixture corpus* below -- or the `mochimo-wots` TypeScript at its
pin there. Those sources are public and are read there; nothing is vendored
here, and no part of building, testing or running this wallet reaches for
them. Every reason a comment needs is written at the site, in
`docs/specification.md` or in this file, and three checks in
`tests/invariants.rs` hold the comments and the string literals under `src/`,
`tests/`, `ui/` and `examples/` to that.

## Build and test

```sh
export PATH="$HOME/.cargo/bin:$PATH"       # cargo is not on the default PATH on this machine

cargo build --workspace
cargo test --workspace --no-fail-fast     # the board; see "The board" below
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace -- -D warnings                                              # what a dependent compiles
cargo clippy -p mochimo-crypto --features mesh-https --all-targets -- -D warnings    # the binary's graph
cargo clippy --manifest-path crates/mochimo-crypto/ui/downstream/Cargo.toml --bin pass -- -D warnings
cargo doc --workspace --no-deps                                                      # zero warnings; see the note below
cargo build --features mesh-https --bin mcm-wallet                                   # the shipped binary (TLS)
cargo +nightly miri test -p mochimo-crypto      # not part of the board; MIRIFLAGS unset; hours, not minutes
```

`./board check` runs the eight commands above in order, names any row that
failed and exits non-zero if one did; `./board verify` is that plus `cargo
deny check` and the Miri run, and is what `RELEASE.md` asks for before a tag.
The script transcribes this block and **nothing holds the two copies to each
other** -- a row edited here and not there leaves the script running the old
board and printing green for it. On Windows it runs unchanged under the POSIX
shell Git for Windows installs; `board`'s head says what else that host needs
and why there is no PowerShell copy. `.github/workflows/board.yml` runs
`./board check` on Linux, macOS and Windows when a person asks for it, and
gates nothing; `RELEASE.md` says what a run of it does and does not stand in
for.

`cargo fmt` is not a gate; do not reformat unrelated code.

`cargo doc` is the only command that reads doc links, so it is the only one that
sees a link to an item that was deleted. `lib.rs` denies
`rustdoc::broken_intra_doc_links` for that and allows
`rustdoc::private_intra_doc_links` with the argument written beside it: the
private links resolve, the deny is what makes them resolve, and unbracketing
them to satisfy rustdoc would turn the tree's only assertion that those names
exist into prose nothing checks. `cargo doc --document-private-items` is not a
gate and does not pass -- four links resolve in every configuration the gates
use and not in that one.

### Features

| feature | default | what |
| --- | --- | --- |
| `native` | yes | the whole crate: primitives, keystore, derivation, mesh codec, CLI |
| `mesh-http` | no | the HTTP transport (`ureq`, no TLS); on for every test target through the dev-dependency on the crate itself |
| `mesh-https` | no | TLS (rustls, `ring`); required by the `mcm-wallet` binary and the `mesh_probe` example |
| `raw-backend` | no | makes the primitive layer nameable; on for the test targets only, never for a dependent |

## The fixture corpus

`fixtures/` holds 5,364 vectors in 15 groups (`fixtures/manifest.toml`
lists them; `tests/kat.rs::manifest_and_disk_agree` and
`manifest_counts_match_the_files` hold the manifest to the directory in both
directions). Every value was produced by executing an implementation that is
not this crate -- the Mochimo C reference at commit
`bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4` (v3.1.0-beta), the `mochimo-wots`
TypeScript at `b583580bffcbe51dbcfd4e30aa711d0d2703b851`, the shipped browser
extension `mochimo-wallet` at `f4694cefd3fc4f15a9922db0bb2ca1c0f27ecb60` with
its lockfile from `mochiwallet` at `af20bfccdde1b0dd75ac1a98f7c83b82ccf359a2`,
or the live Mesh API at one block. Each file's header says which.

| group | file | subject | vectors | oracle |
| --- | --- | --- | --- | --- |
| A | `group_a_keygen.json` | WOTS+ key generation, curated | 11 | C |
| AK | `group_ak_keygen_bulk.json` | WOTS+ key generation, bulk (digests) | 1512 | C |
| AKX | `group_akx_keygen_bulk_crosscheck.json` | the AK keys recomputed by the TypeScript | 1000 | TypeScript, executed crosscheck |
| B | `group_b_sign.json` | WOTS+ signing and recovery, curated | 33 | C |
| BK | `group_bk_sign_bulk.json` | WOTS+ signing and recovery, bulk (digests) | 1128 | C |
| C | `group_c_addr.json` | addresses, Base58, CRC-16 (+ a 1000-entry tag corpus) | 29 | C |
| CX | `group_c_crosscheck.json` | group C recomputed by the TypeScript | 29 | TypeScript, executed crosscheck |
| CK | `group_ck_tag_crosscheck.json` | the 1000-entry tag corpus recomputed by the TypeScript | 1000 | TypeScript, executed crosscheck |
| D | `group_d_tx.json` | transaction layout, hashing, offline validation verdicts | 72 | C |
| E | `group_e_net.json` | network constants; framing is a recorded gap | 10 | C |
| F | `group_f_derivation.json` | the extension's seed derivation and BIP39 | 96 | TypeScript, specification capture |
| HS | `group_hs_hash_sweep.json` | sha256, sha3-512, ripemd160 at every length across two blocks | 390 | C |
| RX | `group_rx_ripemd.json` | RIPEMD-160 where the C cannot compute it | 26 | `@noble/hashes`, no reference side |
| M | `group_m_mesh_client.json` | the shipped mesh client under a recording double | 6 | TypeScript, specification capture |
| N | `group_n_mesh_live.json` | the Mesh API, live, at one block | 22 | api.mochimo.org |

**Three rules about the corpus.**

1. **A fixture is never edited.** Not a value, not a count, not a file list.
   An expectation moved to fit an observation certifies the observation. The
   only hand-written text under `fixtures/` is the `reason` prose in
   `manifest.toml`.
2. **It is frozen.** The corpus is replayed, never regenerated: nothing in
   this repository produces a vector, and no vector here is downstream of
   anything that can be re-run. A vector that looks wrong is therefore a
   finding about this crate, or about the reading of the reference behind it.
   It is settled against that reference at the commit pinned above, and
   answered in the code or in the specification -- never by moving the vector,
   which is rule 1.
3. **Bulk groups record digests; curated groups record bytes.** AK and BK
   carry sha256 of any value wider than 64 bytes and never a sidecar; every
   other group carries the bytes (`*.bin` sidecars over 64 bytes).
   `tests/kat.rs::artifact_policy_is_declared_by_the_generator_and_enforced_here`
   holds the split.

**How it is replayed.** `tests/kat.rs` dispatches every vector on its `source`
string to a handler, reads every field the vector carries (an unread field is
a failure, not a skip), and compares this crate's answer with the recorded
one. `tests/derive.rs` replays group F, `tests/mesh.rs` groups M and N,
`tests/txwire.rs` round-trips every group D wire image through the native
serializer. In this repository the group D handlers that called the C validators are compiled out; `reference_verdicts_native` round-trips every group D wire image through the native serializer, asserts the layout offsets the vector records, recomputes the two transaction digests, and marks the validator verdicts *not called* -- the crate has no transaction validator, and those recorded verdicts are what a node does. `derived_inputs_are_exactly_as_expected` holds the not-called set to exactly the five named vectors plus the group D vectors under the reference-only sources: 74 of 5,364.

**What the corpus points at that is not here.** Some of the prose a vector
carries names a document this repository does not hold: 1,564 such references
across nine of the fifteen files, seven of them a structured header field
rather than a sentence. They are part of the frozen record of what each
generating run observed. They are not claims this wallet makes, and nothing
replays them -- the dispatch is on `source` and what is asserted is values,
`note` being metadata and the header field not a vector field at all. They are
also not removable: a fixture is never edited, and rule 1 is what makes the
corpus worth anything. `manifest.toml` carries none, and the difference is
rule 1 rather than a different standard: its `reason` prose is hand-written, so
a reference there could be removed and was.

**Known-wrong prose in the corpus.** A fixture is never edited, so where a
vector's own note is inaccurate the correction is recorded here instead of
being made there. Group C's `C7`-`C10` cite `tx.c:268-270` where the composing
statements are at 269-271; `C-base58-degenerate`'s two prose halves name lines
144 and 145 for one fault; group F's `F-ascii-control` note calls a round trip
"not a simple high-bit drop" that its own recorded probe shows is exactly one;
`F-high-byte-seed`'s citation is off by one; group N's `N-network-options` note
says code 9 is never returned, and two Mesh handlers this wallet never calls
return it; `group_hs_hash_sweep.json` declares `artifacts: "whole"` explicitly
where the other whole-artifact groups rely on the default. Every one is prose
only: no value, count or file list is affected, and the replay reads none of it.

## Invariants

Each is a property the code holds today and a test that would go red if it
stopped. Details, and what each mechanism does and does not reach, are in the
specification.

- **I1 -- a key signs once per store.** The raw signer is crate-private. The
  two public routes to a signature are `Keystore::sign_spend`, which consumes
  an `AdvanceReceipt` minted only after the advanced index is durable, and
  `Keystore::resign_reserved`, which takes no receipt and no digest -- both
  come from the pending record, so it can only reproduce the signature already
  released. WOTS+ is deterministic, so those bytes are identical.
- **I2 -- the index is durable before the signature is released.**
- **I3 -- spend state moves atomically:** index, generation, pending record and
  the retained settled block change in one temp-write, fsync, rename, fsync.
- **I4 -- every account reconciles before that account acts.** `Wallet::open` is
  the only constructor; it partitions the store into the accounts the chain
  confirmed and the accounts it could not explain, refuses every operation on
  the second set by name, and refuses outright a store in which nothing
  reconciled.
- **I5 -- restore derives the index from the chain, never from zero.**
- **I6 -- key material never leaves the process readable:** zeroized on drop,
  redacted `Debug`, encrypted at rest under Argon2id + ChaCha20-Poly1305.
- **I7 -- no self-referential C transaction struct is ever a Rust value.** In
  this crate the transaction is `tx::wire::Transaction`, plain Rust with a
  serializer at the boundary; I7 is satisfied by construction.
- **I8 -- an imported account keeps a path back to its key material** and its
  first key is verified against the root.

### What holds this document to the code

`tests/invariants.rs::documented_counts_match_the_artifacts` reads this file
and `crates/mochimo-crypto/Cargo.toml` and refuses a figure that disagrees
with the artifact it describes: the vector totals against `fixtures/`, the
corpus table row by row, and -- the arm with no artifact behind it -- any
number written in front of the phrase `cfg` sites. There are none to count,
so a count appearing there would be a claim about a feature this crate does
not have.

That phrase is written out here deliberately, and this paragraph is its
anchor. The check refuses to pass if the phrase occurs nowhere in either
file, because a needle that matches nothing is a tripwire that has been
stepped over rather than one that holds; keeping the phrase in a sentence
*about the check* means no edit to the prose elsewhere can quietly retire the
arm. Leave the phrase in place when rewriting around it.

## The board

`cargo test --workspace --no-fail-fast` is **green**, and it is green *by
name*: every row that runs passes. Green on a row means the check that runs
passes; it does not mean every condition this project cares about has been
met. **Check by name, not by count.**

`invariants::group_e_constants_stay_anchored` is the census that demands every
group E constant be compared by a checker that runs. It carries a declared
exclusion for the 33rd, `sizeof_TX`, as the check's own data. That constant is
the size of the node's network packet container (65,664 bytes). This wallet
never builds or reads such a packet -- it speaks to the Mesh over HTTP, and
the node's own framing is the specification's open item -- and the two ways to
pin the number here, a literal transcribed from the fixture or an expression
transcribed from the reference's `types.h`, both compare the fixture to
itself. The packet size is not this wallet's to pin. The row names the
constant and carries that reason, the failure message prints it, and two
guards hold the row honest: a name the fixture does not carry is refused as a
permit for nothing, and a name the checker compares after all is refused as a
lie. `kat::group_e_constants_match_the_reference` compares the 32 it can.

Three conditions are deliberately **not** carried as rows: a live node for
group E's framing, a capture at submit time for Mesh authorship, and an
upstream header for `valid_op`. Each depends on something that lives outside
any repository, so a row for it would be red for reasons no commit can
address, and a permanently red row destroys the exit code as a signal -- a
suite that is expected to be red is a suite nobody reads. Their home is this
section and the specification's *Open items* table. That is the reason the
rule above is worth stating: the board's green does not reach them.

And **the total is summed, never carried.** Where this section writes one it
is the sum of that run's own result lines -- seventeen of them, one per
target -- added up from the run being reported. It is never a previous
figure with the latest deltas added to it. **No check reads the total**:
`documented_counts_match_the_artifacts` walks this file for vector counts and
`cfg` site counts and never for the board, and nothing else in the tree names
it, so a person adding the line up is the only check there will ever be.

The board on commit `5e0726b`, cargo's exit read from its own process: exit 0,
**385 passed** -- summed from its own seventeen result lines -- 0 failed, 0
ignored, 17 result lines, 5 m 05 s on a warm `target/`, read from `./board`'s
own total -- it brackets the run with `date`, so the figure is wall clock
around the run being reported rather than estimated from a previous one. **The commit is named
by its hash rather than pointed at, because a commit cannot contain its own
hash**: a sentence that says *this commit* is true when it is written and
false at the next one. A reader runs `git diff 5e0726b` and, if nothing
outside the documents moved, these figures are still theirs; if something did,
the remedy is to run the board and write down what it says, never to carry
these numbers forward. The figure to compare across runs is the per-target
one: lib 44, cli 111, compile_fail 1,
derive 10, invariants 68, kat 18, keystore 33, mesh 13, mesh_http 10, miri 2,
net 3, recon 29, signing 17, spend 19, txwire 3, wots_internals 4,
doc-tests 0. Those are a macOS run's figures; on Windows `cli` runs eighteen
fewer and `keystore` swaps three mode-bit tests for three access-list tests,
which `RELEASE.md` records beside the gate that asks for these figures.

Three things about running it. The `cli` target's eighteen `pty::` tests build
the shipped binary with `--features mesh-https` and drive it under BSD
`script(1)`; they need `cargo` on the path and a host whose `script` accepts
`-q /dev/null cmd args`, and the count is whatever `cargo test -q -p
mochimo-crypto --test cli -- --list | grep -c 'pty::'` prints. On Windows the
module is compiled out -- the harness has no Windows counterpart -- and
`RELEASE.md` says what that leaves unreached. The
`invariants` target's census spawns `cargo test --workspace --no-run` and the
sibling binaries, so it has to be run *by* `cargo test` and never by invoking
the test binary directly. And `kat.rs` replays all 5,364 vectors twice, 111 s
of the run above in a debug build -- over a third of it, and the reason the
board is minutes rather than seconds.

The shipped binary builds with `--features mesh-https`, and the four clippy
gates listed under *Build and test* exit 0.
