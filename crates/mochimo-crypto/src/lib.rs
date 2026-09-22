//! Safe Rust API for the Mochimo cryptographic primitives.
//!
//! Every operation here delegates to [`backend::native`] through the alias
//! [`backend::selected`]. That module is pure safe Rust -- no `unsafe`, no C,
//! no linked library -- and what holds it to the protocol is the fixture
//! corpus under `fixtures/`, replayed by `tests/kat.rs`. `docs/specification.md`
//! says what each group establishes and what it does not.
//!
//! # What `mesh-https` adds, since the claim above is about the backend alone
//!
//! That sentence is true of `backend::selected` and of nothing wider. The
//! shipped binary is built with `mesh-https` for TLS, and the feature puts a
//! second trusted computing base under the wallet: eight crates no test target
//! ever compiles -- `ring`, `rustls`, `rustls-webpki`, `rustls-pki-types`,
//! `webpki-roots`, `untrusted`, `once_cell` and `getrandom`. Against the
//! current lockfile they carry 348 `unsafe` occurrences between them (`ring`
//! 230, `getrandom` 59, `once_cell` 53, `rustls` 5, `rustls-pki-types` 1), and
//! `ring`'s build compiles 24 non-Rust objects, 13 from C and 11 from
//! assembly. Those are figures read off one lockfile rather than constants;
//! re-measure them rather than carrying them forward.
//!
//! **Where that `unsafe` is NOT is what makes the trade defensible.** The
//! layer that parses hostile input -- `rustls-webpki`, for X.509 and its
//! ASN.1, and `untrusted` beneath it -- has none of it and is pure Rust.
//! `ring`'s C is fixed-size constant-time arithmetic over values already
//! validated by that layer. TLS failures are historically parser failures, and
//! this arrangement puts the parser in safe Rust with the C behind it.
//!
//! **What no test establishes.** The board builds this binary and drives it --
//! `tests/cli.rs` runs it under a pseudo-terminal -- so everything above is
//! linked and loaded on every board run. But no test completes a handshake,
//! so nothing here exercises that stack against a peer.
//!
//! # The platforms, and the three interfaces each supplies
//!
//! This crate targets **Unix and Windows**, and is built and tested on Linux
//! and macOS. Three interfaces it needs have no portable stand-in, so each
//! platform supplies its own, and a build for any other target fails at
//! compile time rather than degrading:
//!
//! | interface | Unix | Windows |
//! | --- | --- | --- |
//! | the keystore's permission model, a check against another local user rather than a convenience | mode bits: the store is created `0600` and its directory `0700`, and a directory that is group- or world-writable is refused | access lists: created with a protected list granting this user alone, and a directory anyone but this user, `SYSTEM` or the Administrators group can write to is refused |
//! | where the password and the recovery phrase are read, so that neither can be piped or redirected | `/dev/tty`, by path, with echo turned off by `stty` | the console's own buffers, `CONIN$` and `CONOUT$`, by name, with echo turned off in the console mode |
//! | entropy | `/dev/urandom` | `BCryptGenRandom`, the system-preferred generator |
//!
//! The first is `keystore::perms` and its Windows arm; the other two are the
//! binary's, since the library takes entropy as a parameter and prompts
//! through `cli::create::Terminal`. `keystore` states the storage guarantees
//! it rests on, per platform, beside its own gate.
//!
//! **The two columns are not established to the same degree.** The Unix
//! column is what every board run measures. The Windows column compiles and
//! passes clippy for `x86_64-pc-windows-msvc`; the tests that would measure it
//! run on a Windows host, and `RELEASE.md` is where a run is recorded. The
//! BSDs have all three Unix interfaces and are untested.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![deny(unsafe_op_in_unsafe_fn)]
// A doc link that resolves to nothing renders as plain text and fails
// nothing, so a deleted item leaves every reference to it reading as a
// pointer while pointing at no item at all. `cargo doc` is the only command
// that sees this; `cargo test` and `cargo clippy` do not.
#![deny(rustdoc::broken_intra_doc_links)]
// A link from a public item's documentation to a PRIVATE one is a different
// thing, and it is allowed here deliberately rather than left to warn.
//
// The three groups it covers are `backend::{native, selected}`, which are
// crate-private in every build a wallet uses because that is I1's mechanism;
// `KeyMaterial` and its variants, the closed representation behind
// `AccountKind`; and the private items a public doc names because they are
// what the public item is explained BY -- `Keystore::commit`,
// `AdvanceReceipt::attesting`, `Keystore::key_at`, `crypt::nonce_for`,
// `read_new_password` and their kind. Every one of those is private because
// an invariant's mechanism requires it, so the remedy rustdoc implies --
// widen the item -- is refused at each site: it would trade a mechanism for a
// warning.
//
// The other remedy, dropping the brackets, is worse than the warning here.
// These links RESOLVE, and the deny above is what makes them resolve: it is
// the only thing in the tree asserting that `Keystore::commit` and
// `KeyMaterial::Imported` still exist under those names. Written as plain
// backticks they become prose nothing checks, which is exactly the class of
// dead pointer the deny exists to catch. So the links stay, the deny stays,
// and the warning about a reader who cannot follow them is allowed: this
// crate is `publish = false` and ships a binary, and the reader it documents
// for has the source open.
#![allow(rustdoc::private_intra_doc_links)]

#[cfg(not(feature = "native"))]
compile_error!(
    "no backend selected: mochimo-crypto requires the `native` feature. \
     Building with --no-default-features would silently produce a crate that \
     cannot compute anything."
);

// The crate-level platform statement is the table in the head of this file,
// per platform. What is left for a gate is every target that table does not
// name: the three interfaces have an implementation on Unix and one on
// Windows, and a third platform would be a third column nobody has written.
// `keystore` carries its own gate for the storage guarantees it rests on, so
// such a build is told about both.
#[cfg(not(any(unix, windows)))]
compile_error!(
    "mochimo-crypto targets Unix and Windows. Three interfaces it needs have no \
     portable stand-in, and each of those platforms supplies its own: the \
     keystore's permission model (Unix mode bits; Windows access lists), the \
     device the password and recovery phrase are read from so that neither can \
     be piped or redirected (the controlling terminal; the console), and the \
     entropy source (the kernel's generator; BCryptGenRandom). This target is \
     neither, and has none of the three here."
);

/// The backend seam is public **only under `raw-backend`**, the test tree's
/// surface. In every other build it is crate-private, so no dependent can
/// name a raw primitive -- the raw WOTS+ signer above all (I1). The
/// KATs route through `selected` on purpose; a wallet needs nothing from it.
#[cfg(feature = "raw-backend")]
pub mod backend;
/// Without the feature the backend carries the whole primitive surface --
/// every function the corpus replays, most of which the wallet never calls
/// -- so the dead-code lint is off for it in that build on purpose: the
/// surface is sized by `tests/kat.rs`, not by the wallet's call graph.
#[cfg(not(feature = "raw-backend"))]
#[allow(dead_code)]
pub(crate) mod backend;
mod error;

pub mod account;
pub mod addr;
pub mod base58;
pub mod bytes;
pub mod crc16;
#[cfg(feature = "native")]
pub mod derive;
#[cfg(feature = "native")]
pub mod keystore;
#[cfg(feature = "native")]
pub mod mesh;
#[cfg(feature = "native")]
pub mod mnemonic;
#[cfg(feature = "native")]
pub mod cli;
#[cfg(feature = "native")]
pub mod recon;
#[cfg(feature = "native")]
pub mod wallet;
pub mod net;
pub mod secret;
pub mod tx;
pub mod wots;

pub use error::{errno_name, errno_text, ve2str, Error, Result, TransportKind, Verdict};
pub use secret::Secret;

/// The protocol's constants, as Rust literals.
///
/// A literal retyped from a specification is a literal nobody checked, so
/// these are anchored against the corpus rather than against each other:
/// `tests/kat.rs::constants_match_the_reference` compares the WOTS+ and
/// address widths to the `constants` block group A's fixture `printf`'d from
/// the real macros, and `tests/kat.rs::group_e_constants_match_the_reference`
/// does the same for every network constant against group E's. A literal that
/// disagrees with what the C compiler saw fails there, by name, rather than
/// inside a 2144-byte diff.
pub mod consts {
    /// Declares each constant once, as a Rust literal.
    ///
    /// Emits `mod native` and the `pub use` of it.
    macro_rules! declare_consts {
        ($(
            $(#[doc = $doc:literal])*
            $name:ident : $ty:ty = $native:expr;
        )*) => {
            /// The Rust literals.
            pub mod native {
                $($(#[doc = $doc])* pub const $name: $ty = $native;)*
            }

            pub use native::*;
        };
    }

    declare_consts! {
        /// WOTS+ hash output and seed width.
        PARAMSN: usize = 32;
        /// Winternitz parameter.
        WOTSW: usize = 16;
        /// `log2(WOTSW)`.
        WOTSLOGW: usize = 4;
        /// Message chains: `(8 * PARAMSN / WOTSLOGW)`.
        ///
        /// The header's expression, not its value. A folded `64` would agree with
        /// itself if `PARAMSN` ever moved.
        WOTSLEN1: usize = 8 * PARAMSN / WOTSLOGW;
        /// Checksum chains.
        WOTSLEN2: usize = 3;
        /// `(WOTSLEN1 + WOTSLEN2)`.
        WOTSLEN: usize = WOTSLEN1 + WOTSLEN2;
        /// `(WOTSLEN * PARAMSN)`.
        WOTSSIGBYTES: usize = WOTSLEN * PARAMSN;
        /// Legacy full WOTS+ address length.
        WOTS_ADDR_LEN: usize = 2208;
        /// Full v3 address: a tag then a hash.
        ADDR_LEN: usize = 40;
        /// Address tag.
        ADDR_TAG_LEN: usize = 20;
        /// Address hash.
        ADDR_HASH_LEN: usize = 20;
        /// A destination's optional reference field.
        ADDR_REF_LEN: usize = 16;
        /// Where an address's tag half starts.
        ADDR_TAG_OFF: usize = 0;
        /// Where an address's hash half starts.
        ///
        /// Not `ADDR_TAG_LEN`. The two are equal and that is a fact about this
        /// protocol rather than a rule about addresses -- deriving one from the
        /// other assumes the halves abut, which is the shape corrected once
        /// before, when `put16`'s byte order was standing in for `put32`'s
        /// (`backend::native::put32`'s doc).
        ADDR_HASH_OFF: usize = 20;
        /// Digest length of the core hashes.
        HASHLEN: usize = 32;
        SHA256LEN: usize = 32;
        /// SHA3-224.
        SHA3LEN224: usize = 28;
        /// SHA3-256.
        SHA3LEN256: usize = 32;
        /// SHA3-384.
        SHA3LEN384: usize = 48;
        /// SHA3-512.
        SHA3LEN512: usize = 64;
        RIPEMDLEN160: usize = 20;
        CRC16LEN: usize = 2;
        /// The success status code.
        ///
        /// `c_int` because that is what the reference's validators return, and
        /// comparing a return code against a `usize` would need a cast at every
        /// call site.
        VEOK: core::ffi::c_int = 0;
        /// The one transaction-data type `tx__init` accepts.
        TXDAT_MDST: u8 = 0x00;
        /// The one signature-algorithm type `tx__init` accepts.
        TXDSA_WOTS: u8 = 0x00;
        /// The minimum transaction fee, in nanoMochimo. The 64-bit
        /// little-endian form the validators take is `MFEE64`; `u64` here
        /// because `tx_val` compares it against `tx_fee` and `mdst_val`
        /// accumulates one per destination into the floor `fee_total` must
        /// clear. Read by `mesh::spend`.
        MFEE: u64 = 500;
    }

    /// The four wire-struct sizes, as `types.h` asserts them.
    ///
    /// # Why these are expressions and not `size_of`
    ///
    /// `TXLEN_MIN` and `TXLEN_DSK_MIN` are sums of `sizeof`s, and the native
    /// backend has no C structs to take `sizeof` of. What it does have is the
    /// reference's own `STATIC_ASSERT`s, each of which states a struct's size as
    /// an arithmetic expression over constants already declared above:
    ///
    /// ```text
    /// sizeof(MDST)    == ADDR_REF_LEN + ADDR_TAG_LEN + 8
    /// sizeof(WOTSVAL) == WOTS_SIG_LEN + 32 + 32
    /// sizeof(TXHDR)   == 4 + (ADDR_LEN * 2) + (8 * 4)
    /// sizeof(TXTLR)   == 8 + HASHLEN
    /// ```
    ///
    /// Transcribing the *expression* rather than the value is the same choice
    /// [`WOTSLEN1`] makes — a folded literal would agree with itself if a
    /// constant underneath it moved.
    ///
    /// # What checks them
    ///
    /// `tests/kat.rs::reference_verdicts_native` and `tests/txwire.rs` hold
    /// each of these to the offsets `group_d_tx.json`'s layout table records,
    /// through the native serializer, on every replay.
    pub mod wire {
        use super::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SIG_LEN};
        pub const SIZEOF_TXHDR: usize = 4 + (ADDR_LEN * 2) + (8 * 4);
        pub const SIZEOF_MDST: usize = ADDR_REF_LEN + ADDR_TAG_LEN + 8;
        /// `WOTS_SIG_LEN` is this crate's [`SIG_LEN`].
        pub const SIZEOF_WOTSVAL: usize = SIG_LEN + 32 + 32;
        pub const SIZEOF_TXTLR: usize = 8 + HASHLEN;
    }

    /// WOTS+ seed, message digest, and public seed width.
    pub const SEED_LEN: usize = PARAMSN;
    /// A WOTS+ public key, and equally a WOTS+ signature.
    ///
    /// The reference calls these `WOTS_PK_LEN` / `WOTS_SIG_LEN` and files them
    /// under the "LEGACY" comment. They are not legacy: that
    /// comment spans both dead constants (the 12-byte legacy tag's, which this
    /// crate never bound) and load-bearing ones (the 2,208-byte `WOTSVAL`
    /// layout these two size, `STATIC_ASSERT`-pinned), so its scope is not
    /// evidence that a symbol is droppable — anything under it needs a
    /// call-site check before removal.
    pub const PK_LEN: usize = WOTSSIGBYTES;
    /// Ditto — the reference gives these separate names for the same value.
    pub const SIG_LEN: usize = WOTSSIGBYTES;

    /// The network surface: protocol version, framing marks, ports, and the
    /// operation codes.
    ///
    /// These are `u16`/`u8` rather than `usize` because every one of them is a
    /// wire value with a width the protocol fixes, not a length. `TXNETWORK`
    /// and `TXEOT` go onto the wire through `put16`; the opcodes occupy a
    /// single byte.
    ///
    /// Until this module existed, `fixtures/group_e_net.json` pinned all of
    /// these against nothing at all — the fixture and the survey agreed with
    /// each other and neither was compared to the C.
    /// `kat.rs::group_e_constants_match_the_reference` now checks every one
    /// against the `constants` block the reference printed into that fixture.
    pub mod net {
        declare_consts! {
            /// Protocol version number.
            PVERSION: u16 = 5;
            /// Capability bits for TX.
            CBITS: u16 = 0;
            /// Network TX protocol version.
            TXNETWORK: u16 = 1337;
            /// End-of-transmission id for packets.
            TXEOT: u16 = 0xabcd;
            /// Default TCP listening port.
            PORT1: u16 = 2095;
            /// Secondary port, primarily for testnet.
            PORT2: u16 = 2096;
            /// First valid operation code.
            FIRST_OP: u8 = 3;
            /// Last valid operation code.
            LAST_OP: u8 = 19;
            OP_NULL: u8 = 0;
            OP_HELLO: u8 = 1;
            OP_HELLO_ACK: u8 = 2;
            OP_TX: u8 = 3;
            OP_FOUND: u8 = 4;
            OP_GET_BLOCK: u8 = 5;
            OP_GET_IPL: u8 = 6;
            OP_SEND_FILE: u8 = 7;
            OP_SEND_IPL: u8 = 8;
            OP_BUSY: u8 = 9;
            OP_NACK: u8 = 10;
            OP_GET_TFILE: u8 = 11;
            OP_BALANCE: u8 = 12;
            OP_SEND_BAL: u8 = 13;
            OP_RESOLVE: u8 = 14;
            OP_GET_CBLOCK: u8 = 15;
            OP_MBLOCK: u8 = 16;
            OP_HASH: u8 = 17;
            OP_TF: u8 = 18;
            OP_IDENTIFY: u8 = 19;
        }

        /// Expands to `WORD16_C(0xFFFF)`, a macro chain the
        /// bindings generator did not evaluate, which is why this is a
        /// function rather than a `declare_consts!` row: the binding side was
        /// a shim *call*, and `kat.rs` paired the two by hand. The binding is
        /// gone; the function stays so the call sites and the fixture's
        /// `WORD16_MAX` row keep their shape.
        #[must_use]
        pub const fn word16_max() -> u16 {
            word16_max_native()
        }

        /// The native `WORD16_MAX`.
        ///
        /// The single definition of the literal: [`word16_max`] forwards here
        /// rather than repeating `0xFFFF`, so there is one place to be wrong.
        #[must_use]
        pub const fn word16_max_native() -> u16 {
            0xFFFF
        }
    }
}
