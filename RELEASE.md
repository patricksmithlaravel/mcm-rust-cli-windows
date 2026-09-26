# Release checklist

This is the manual replacement for automated verification: weaker than
automation, because it runs only when a person remembers to run it and reports
only what that person writes down, and stronger than memory, because the run
is named, the platform is recorded, and an unticked box is visible where an
unasked question is not.

Work down it before a tag. Nothing here is new verification -- every gate is
one the repository already has. What this document adds is that they were all
run, on every platform, at the commit being tagged.

## The gates

- [ ] The working tree is clean and the commit to be tagged is the one in hand.
      `git status --short` prints nothing.
- [ ] `./board verify` is **green on Linux**. Record the run below.
- [ ] `./board verify` is **green on macOS**. Record the run below.
- [ ] `./board verify` is **green on Windows**, in its three parts, each at
      the commit being tagged. Only the first has to run on Windows, so the
      three may come from three runs rather than one -- `./board verify`
      run whole on a Windows host is all three at once. Record them in one
      row below, each with where it ran:

      - `./board check`, green on Windows: from Git Bash as the board's
        head describes, or the workflow's Windows job (below).
      - `cargo deny check`, green on any host. `deny.toml` leaves `targets`
        unset and sets `all-features`, so the graph it judges is the whole
        lockfile's and not a host's; the `linux` or `macos` row's own run
        at this commit is this part too.
      - Miri for the Windows target, green on any host, with MIRIFLAGS
        unset as the board leaves it:

            cargo +nightly miri test -p mochimo-crypto --target x86_64-pc-windows-msvc

        On an x86_64 Windows host that is `./board verify`'s Miri row;
        anywhere else the target has to be named. Miri interprets the
        target it is given whatever the host -- its README calls this
        cross-interpretation -- and with MIRIFLAGS unset its isolation is
        on, which the README says replaces entropy, environment variables
        and clocks with deterministic fakes, and which refuses the file
        system. The same README says isolation is not a sandbox, and that
        a gap in it is a Miri bug.

      The third part reaches less than its name suggests: *What this
      checklist does not reach* says what.
- [ ] **The Windows power-loss hazard is closed, at the commit being
      tagged.** The hazard was a directory entry nothing could flush: a power
      cut before NTFS committed a rename could bring back the previous
      snapshot, and with it the chance to sign a reserved key position twice.
      The slot layout removes that dependence -- a Windows store is two files
      rewritten in place and flushed with `FlushFileBuffers` before a change
      is durable -- and `keystore/medium.rs`'s module doc says what it rests
      on instead. Tick this when the commit being tagged still writes that
      layout and its Windows board, part of the gate above, runs the layout's
      I3 and I2 proofs green: stops after each step, and writes torn by
      sector. `FORK.md`, under R1-3, has the design and the runs.
- [ ] The board's figures in `AGENT.md` match the run that just happened --
      the per-target counts and the wall time, re-derived from the run being
      reported. AGENT.md's own rule governs: the total is summed from that
      run's result lines, never carried forward from a previous one, and a
      figure that moved is re-read rather than adjusted. **The figures are
      per platform**: on Windows the `cli` target has eighteen fewer tests,
      because the `pty::` module is Unix-only, and `keystore` runs three
      access-list tests in place of three mode-bit tests and one fewer in
      all, `create`'s parent-flush test being Unix's alone. AGENT.md's figures
      are for the platform its board section names.
- [ ] `AGENT.md`'s board section names the commit being tagged.
- [ ] The version in `crates/mochimo-crypto/Cargo.toml` is the version being
      tagged.
- [ ] **The declared MSRV still builds.** `rust-toolchain.toml` pins the board
      to one compiler, so no board row ever compiles this tree on the
      `rust-version` the workspace declares. This is the only thing that
      checks it, and both must exit 0:

          cargo +1.89.0 check --workspace
          cargo +1.89.0 check -p mochimo-crypto --features mesh-https

      On every platform, and not once: the Windows arms compile only on
      Windows, so a Unix host's check says nothing about the MSRV there.
      The workflow's `msrv` job runs both commands on all three, reading the
      version from `Cargo.toml`; a green run of it is evidence for this box,
      and a person still ticks it.

      The version is written out twice here and once in `Cargo.toml`. If
      either moves, this line moves with it -- a version number in a checklist
      is a value that drifts, and nothing holds this one to the manifest.

`./board verify` is `./board check` -- the eight commands under *Build and
test* in `AGENT.md` -- followed by `cargo deny check` and the Miri run. It
takes hours, most of it Miri. `./board check` alone is the pre-commit gate and
takes minutes; it is not sufficient here.

## Why every platform, and not as a formality

The wallet claims Linux, macOS and Windows. The keystore's durability and
exclusion rest on syscalls whose behaviour is not the same on the three, and
the divergence is documented in the code rather than assumed away:

- **The directory fsync.** `keystore/medium.rs`'s `fsync_dir` carries the
  note that on Apple targets `std`'s `sync_all` is `fcntl(F_FULLFSYNC)` with
  no fallback, and that it was *measured* succeeding on a directory fd on
  APFS. That is a different syscall from the `fsync(2)` the same line makes on
  Linux, and the measurement behind it was taken on one platform. I3 -- spend
  state moves atomically through temp-write, fsync, rename, fsync -- rests on
  that step on both.
- **The lock.** `keystore.lock` is held with `File::try_lock` (`flock(2)`),
  and the module's own note records the residue: local filesystems only, with
  NFS lock emulation able to make it silently meaningless. Whether a given
  host's filesystem is one where the lock means what I1 needs it to mean is a
  property of that host, not of this source.
- **The mode bits.** `Keystore::create_with` makes the store directory with
  `DirBuilderExt::mode(0o700)`, and the lock file and every temp file a
  snapshot is written through are opened with `OpenOptionsExt::mode(0o600)`.
  `refuse_unsafe_dir` then stats that directory and **refuses to open the store
  at all** when `mode & 0o022` is set -- group- or other-writable. Whether that
  refusal fires is settled by the host's umask and by whatever the filesystem
  and any ACL layer above it do to a mode, which is a property of the platform
  and not of this source.

On Windows the same three are different in kind, not only in degree:

- **There is no rename.** Win32 documents no way to commit the directory
  entry a rename writes, so a Windows store is two slot files: a commit
  rewrites the one not holding the newest state and flushes it with
  `FlushFileBuffers`, which writes a file's data and metadata, before the
  change is taken as durable, and `open` takes the newer intact slot. A green
  Windows board establishes that layout under kills and under writes torn by
  sector; that a flush which returned survives a power cut is the
  documentation's claim and the device's, as an `fsync`'s is on Unix, and
  nothing on this checklist measures it.
- **The lock is `LockFileEx`.** The system releases a terminated process's
  locks, after a delay Microsoft documents as depending on system resources,
  so a lock can briefly outlive its holder -- met as `Locked`, and gone on a
  retry.
- **The permission model is access lists.** `keystore/perms/windows.rs`
  creates under a protected list granting the user alone and refuses a
  directory anyone but the user, `SYSTEM` or Administrators can write to. The
  three `cfg(windows)` tests in `tests/keystore.rs` are its only measurement,
  and they run only there. Run the Windows board from a checkout under the
  user's profile: a folder directly under `C:\` inherits `Authenticated
  Users` with modify rights, and the three tests in `tests/keystore.rs` that
  make their own store directory rather than letting the keystore make it are
  then refused as `UnsafeAcl` -- the check working, not the tests failing.

A green board on one platform is evidence about that platform. Running it on
another is not duplication; it is the only thing that makes that platform's
claim true.

## Hosts this repository does not have

The gates above ask for three platforms, and this tree is developed on one.
`.github/workflows/board.yml` runs `./board check` on GitHub's Linux, macOS
and Windows runners at one commit, and in a job of its own the MSRV check
above, when a person pushes a branch whose name begins `board/`, on its own
-- the workflow's head says why alone -- or, once the workflow is on the
default branch, dispatches it. `FORK.md` records its runs. It is a way to
reach a platform, and it changes nothing above:

- **It gates nothing.** No pull request waits on it and no check is required
  of one.
- **It runs `check`, not `verify`.** A green run is evidence about the board
  on that platform, and the record below is for `verify`. A green Windows
  job is the first of the three parts that platform's row is assembled
  from, and the gate says why the other two need no Windows host. Whether
  the Miri run finishes inside a hosted job's six hours has not been
  measured.
- **It writes nothing here.** The run's log is the transcript, GitHub deletes
  it when its retention period ends, and the record is what a person copies
  out of it before then.
- **A runner is not an operator's machine.** GitHub documents its Windows
  runners as administrators with User Account Control disabled, and a new
  directory there is owned by the Administrators group, so the access-list
  check meets that group as the owner where an unelevated desktop meets the
  user. Defender's real-time protection is off on the image, so no scanner
  holds the store. The workflow prints the token, the owner a new directory
  gets and the scanner's state beside the board.

The workflow's head carries the rest of its argument: why it clones under the
user's profile rather than into the runner's workspace, why it uses no
actions, and why its images are `-latest`.

## What this checklist does not reach

Stated here for the same reason `AGENT.md` states it of the board: a gate that
is believed to cover more than it does is worse than a gate known to be
narrow.

- The three conditions `AGENT.md` deliberately declines to carry as board rows
  -- a live node for group E's framing, a capture at submit time for Mesh
  authorship, and an upstream header for `valid_op` -- are not reached by any
  gate here either. They live outside any repository, and tagging does not
  change that.
- `cargo deny check` catches a policy violation introduced by a change. It
  cannot catch a new advisory filed against a dependency whose version did not
  move; `deny.toml`'s own comments say so at length.
- `./board check`'s `cargo doc` row does not fail on a warning -- rustdoc
  warns and exits 0. It does catch a broken intra-doc link, because `lib.rs`
  denies that lint. Read the row's output rather than trusting its status.
- A green board means every row that runs passes. `AGENT.md`'s rule holds
  here: check by name, not by count.
- **On Windows, nothing runs the binary.** `tests/cli.rs`'s pseudo-terminal
  harness drives the shipped binary through `script(1)` and has no Windows
  counterpart, so its `pty::` tests are compiled out there. The binary's
  remainder -- argv, the console prompts and their echo handling, the real
  transport -- is exercised on Linux and macOS and on nothing else. A green
  Windows board is a statement about the library and the command layer, which
  every other target reaches, and not about `CONIN$`, `CONOUT$` or
  `BCryptGenRandom`, which only a person at a Windows console has seen work.
- **Miri reaches none of the port's `unsafe`.** That `unsafe` is in
  `keystore/perms/windows.rs` and the binary's `console` module, where
  `unsafe_is_confined_to_declared_files` holds it. Every test that reaches
  the first does file I/O, which Miri's isolation refuses and which those
  targets are `not(miri)` for, and the binary is not built in the
  configuration Miri interprets. So the Windows row's Miri part runs the
  same tests as a macOS host's -- `-- --list` names the same ones for both
  targets -- over Windows' `std` and with the `cfg(windows)` arms compiled
  in, and not one Win32 call of the port's. The Windows board runs the
  permission model's blocks natively, where undefined behaviour need not
  show itself; what stands behind them is the condition each block states
  beside it.
- The TLS graph cannot be cross-compiled: `ring` compiles C for its target,
  so every platform's `mesh-https` rows run on that platform's own host.

## The record

The one thing this document does that memory cannot: it says which platform
the last verification actually ran on.

**Append a row; never edit one.** A record adjusted after the fact certifies
nothing -- the same reason the fixture corpus is never edited. If a run was
red, the row says red and a later row says green.

| date | commit | platform | OS / kernel | toolchain | `./board verify` | by |
| --- | --- | --- | --- | --- | --- | --- |
| _(no verification recorded yet)_ | | | | | | |

`platform` is `linux`, `macos` or `windows`. `toolchain` is the stable version the board
ran on and the nightly Miri ran on, since the `compile_fail` target pins
rustc's exact diagnostic wording and a toolchain bump can turn it red with no
change to the property it checks. The stable half should now equal the channel
in `rust-toolchain.toml`; recording it anyway is what would show that someone
had overridden the pin, which a row reading only "pinned" never could.

A `windows` row may be assembled, as its gate says. Its `OS / kernel` is
then the Windows host `./board check` ran on, and its `./board verify` cell
names each part and where it ran: the check by its host or its workflow
run, `cargo deny` by its host, and Miri by its host and target.

A tag needs one green `linux` row, one green `macos` row and one green
`windows` row at the commit being tagged. Rows at different commits are
partial verifications, however many of them there are.
