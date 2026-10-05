//! The Mesh API client: what the wallet asks the network and what it
//! sends it. Three reads and one write over the middleware in
//! the Mesh middleware (a recon source, never an oracle),
//! which delegates its wire work to its own interface library; both are
//! pinned, and every behaviour cited below was read at those pins and
//! captured live from `api.mochimo.org` into `fixtures/group_n_mesh_live.json`
//! (a specification capture of one server at one block).
//!
//! # What is verified here
//!
//! Request bodies are built from typed values ([`codec`]) and are byte-equal
//! to the bodies the capture sent, whose replies are the ones recorded, so
//! "the server accepted this exact request" is the recorded fact. Response
//! bodies are parsed by hand with every field's presence, type, width and
//! range checked before it becomes a Rust value; the address the ledger
//! returns must begin with the tag asked for. The chain's current address for
//! a tag must equal the address of the key this keystore would sign with next
//! before anything is reserved ([`spend::SpendPlan::new`]). Every parser is
//! total over truncations and byte flips of every captured body
//! (`tests/mesh.rs`): a malformed reply is an error, never a panic, because a
//! panic on network input is a denial of service.
//!
//! # What a 200 from `submit` means
//!
//! **The bytes left the process; nothing more.** `constructionSubmitHandler`
//! decodes the hex with
//! `TransactionFromHex`, hands it to `SubmitTransaction`, and that function
//! writes the bytes as `OP_TX` to
//! each of a set of picked nodes, one raw frame per socket, and returns
//! `nil` as soon as one of those writes completes **without reading a
//! reply** from any of them. Nothing is validated on the way ("Validate the signed
//! transaction - TODO LATER"). The `hash` in the reply is computed by the
//! middleware from the bytes it received with the nonce forced to zero, which
//! is why [`MeshClient::submit`] refuses a reply whose hash is not the id of
//! the bytes it sent — the acknowledgement is then about something else.
//! Not accepted, not validated, not in a block: a caller learns acceptance
//! only by observing the chain, and that observation is reconciliation's.
//!
//! # The `tx_val` residue, at this site
//!
//! `tx_val` runs on the node against an open ledger, and **no
//! image in the corpus has ever been through it**. What this
//! crate checks a transaction against offline is layout, `mdst_val` and
//! `tx_val__wots`; the ledger arms — exact balance equality, the block-to-live
//! window, the source/change relation as the ledger sees it — are outside
//! every fixture, and nothing in `cargo test` reaches them.
//!
//! **Two of the three have now run once, on a live node and not in this
//! suite.** One live run submitted a transaction this crate built and the chain carried
//! it in block 1078535: `send + change + fee` equalled the ledger
//! balance exactly, and `src_addr`/`chg_addr` carried one tag over two hash
//! halves — the relation the node enforces. One group D image is built to
//! carry that shape, `D17`, and its own vector records `tx_val` as not
//! evaluated on it for want of a ledger: the corpus pins a layout two
//! comparators approve of, and a node accepting the relation is what the live
//! run adds. The block-to-live window was **not**
//! exercised: `blk_to_live` was 0 and the node checks only non-zero values.
//! Acceptance there was inferred from the ledger moving, not read off a
//! verdict — `/construction/submit` returns before any reply.
//!
//! So a transaction these types build can still satisfy every check this crate
//! runs and be rejected on a ledger reason, for every shape that run did not have:
//! multiple destinations, a non-zero `MDST::ref`, a zero change, a live
//! block-to-live range. No marker in this tree has "the ledger arms are
//! exercised" as its clearing condition, and none could: that is knowledge
//! rather than debt. `docs/specification.md`'s *Open items* table records
//! the neighbouring one — authorship of a submitted transaction, which no
//! read-only capture can establish — and what would move either is fixture
//! data from a capture taken at submission time.
//!
//! # What this module does not do
//!
//! It does not reconcile (I4), does not settle (`persist_settled` is never
//! called from here), does not decide expiry, and does not re-sign. Each of
//! those is named where it is stopped at.

use core::fmt;

use crate::addr::{Address, Tag};
use crate::consts::HASHLEN;
use crate::error::{Error, Result};

pub mod codec;
pub mod hex;
#[cfg(feature = "mesh-http")]
pub mod http;
pub mod spend;

pub use spend::{SignedTransaction, SpendPlan};

/// The middleware's request-body cap: `http.MaxBytesReader(w, r.Body,
/// 30*1024)` in `maxRequestSizeMiddleware`.
/// Enforced here too, so an oversize body is a named refusal rather than a
/// dropped connection. A 256-destination signed image is 13,628 bytes —
/// 27,256 hex characters plus the envelope — and fits.
pub const MAX_REQUEST_BYTES: usize = 30 * 1024;
/// The response-body cap for everything but the two history endpoints.
///
/// `/call`, `/account/balance`, `/network/status` and `/construction/submit`
/// answer in a few hundred bytes: measured against the group N capture, the
/// widest of them is `/network/status` at 664 bytes, and the widest reply any
/// parser in this module reads outside history is `/network/options` at 964.
/// Eight kibibytes is eight times that and twelve times the widest the client
/// actually asks for.
///
/// It stays small on purpose. The cap bounds an allocation whose size a remote
/// server chooses, and on these endpoints there is nothing for extra room to
/// buy -- a reply that needs it is a reply this crate would refuse to parse
/// anyway.
pub const MAX_RECON_RESPONSE_BYTES: usize = 8 * 1024;
/// The response-body cap for `/block`, `/search/transactions`, `/mempool`
/// and `/mempool/transaction`.
///
/// These two scale with what they are reporting, so a single number sized from
/// the small endpoints is a bound the CLI can walk into. Measured against the
/// group N capture: a `/search/transactions` row is 1,221 bytes at its widest
/// and a `/block` transaction 1,020, each transaction rendering about 337 bytes
/// per operation.
///
/// 256 KiB holds:
///
/// * **214 search rows**, against the 100 that `--count`'s ceiling allows, so a
///   full page fits twice over. A cap under 122,100 bytes would make `--count
///   100` a value the parser accepts and the transport refuses.
/// * **256 block transactions** at the widest recorded one, where mainnet
///   blocks currently carry a handful.
///
/// What it does not hold is a block of transactions that each pay hundreds of
/// destinations: at 337 bytes an operation, one 256-destination transaction
/// renders around 87 KiB, so three of them in a block exceed this. That block
/// gets a named refusal rather than an unbounded allocation, which is the
/// trade a cap is.
///
/// The mempool's two replies scale the same way: one waiting transaction is
/// rendered as `/block` renders one, and the queue's list is about 75 bytes
/// an id, so this holds a list of some 3,400 ids, beyond which it is refused
/// by size as a block is.
pub const MAX_HISTORY_RESPONSE_BYTES: usize = 256 * 1024;

/// The response cap for `path`.
///
/// Unknown paths get the tight cap. A path this table does not name is not a
/// reason to allow a larger allocation, and the two the history cap exists for
/// are both named here.
#[must_use]
pub fn max_response_bytes(path: &str) -> usize {
    match path {
        "/block" | "/search/transactions" | "/mempool" | "/mempool/transaction" => MAX_HISTORY_RESPONSE_BYTES,
        _ => MAX_RECON_RESPONSE_BYTES,
    }
}

/// How bytes reach the middleware. `path` is the endpoint (`"/call"`), `body`
/// an already-serialised JSON request; the return is the body of a 200
/// response, at most [`max_response_bytes`] of it for that path. Not sealed: the test tree
/// fakes it with recorded bodies, and nothing in it touches key material.
pub trait Transport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// A block the middleware named: index and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    pub index: u64,
    pub hash: [u8; HASHLEN],
}

/// What `/call tag_resolve` returns: the ledger's current entry for a tag,
/// which is what makes I5's restore scan target-directed — the
/// full 40-byte address, tag half then current hash half, and the balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub address: Address,
    /// nanoMochimo.
    pub balance: u64,
}

/// What `/account/balance` returns: the balance and the block the middleware
/// had cached when it answered. The address is resolved and discarded by that
/// handler, which is why [`LedgerEntry`] comes from `/call` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAt {
    /// nanoMochimo.
    pub balance: u64,
    pub tip: ChainTip,
}

/// A transaction id: `TX_HASH_ID` with the nonce zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TxId(pub [u8; HASHLEN]);

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({})", hex::encode(&self.0))
    }
}

/// The client: one transport, thirteen operations -- four the wallet needs to
/// spend, seven read-only ones the explorer verbs use, and two that say which
/// network a node serves and how current its tip is.
#[derive(Debug)]
pub struct MeshClient<T: Transport> {
    transport: T,
}

impl<T: Transport> MeshClient<T> {
    pub fn new(transport: T) -> MeshClient<T> {
        MeshClient { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// `POST /network/status`: the current block.
    pub fn network_status(&self) -> Result<ChainTip> {
        let reply = self.transport.post("/network/status", &codec::request_network_status())?;
        codec::parse_network_status(&reply)
    }

    /// The same `POST /network/status`, read for a page that shows the
    /// node: the tip, when it was solved, the genesis block and the
    /// middleware's sync state ([`codec::parse_network_status_full`]). The
    /// sync state is the middleware's view of its own node, not of the
    /// network; see [`codec::SyncStatus`].
    pub fn network_status_full(&self) -> Result<codec::NetworkStatus> {
        let reply = self.transport.post("/network/status", &codec::request_network_status())?;
        codec::parse_network_status_full(&reply)
    }

    /// `POST /network/list`: every network the middleware serves.
    pub fn networks(&self) -> Result<Vec<codec::NetworkIdentifier>> {
        let reply = self.transport.post("/network/list", &codec::request_network_list())?;
        codec::parse_network_identifiers(&reply)
    }

    /// `POST /call tag_resolve`: the ledger's current entry for `tag`. An
    /// unknown tag is [`Error::Mesh`] with the middleware's code 4.
    pub fn resolve_tag(&self, tag: &Tag) -> Result<LedgerEntry> {
        let reply = self.transport.post("/call", &codec::request_tag_resolve(tag))?;
        codec::parse_tag_resolve(&reply, tag)
    }

    /// `POST /account/balance` for `tag`.
    pub fn balance(&self, tag: &Tag) -> Result<BalanceAt> {
        let reply = self.transport.post("/account/balance", &codec::request_account_balance(tag))?;
        codec::parse_account_balance(&reply)
    }

    /// `POST /block` by index: the block and every transaction in it.
    ///
    /// **Index 0 is the current block, not genesis** (`getBlock`,
    /// routes by number only when `Index != 0`).
    /// Callers that mean a named block refuse 0 before they get here.
    pub fn block_by_index(&self, index: u64) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_index(index))?;
        codec::parse_block(&reply)
    }

    /// `POST /block` by hash. The middleware reads a hash from its own
    /// archive folder, so a not-found here is about that deployment's
    /// archive rather than about the chain.
    pub fn block_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_hash(hash))?;
        codec::parse_block(&reply)
    }

    /// `POST /search/transactions` by transaction hash: the indexer's own
    /// rendering of one transaction, which differs from `/block`'s and is
    /// not reconciled with it (see [`codec::MeshTransaction::metadata`]).
    ///
    /// Served only where the deployment set `EnableIndexer`; where it did
    /// not, the handler answers an internal error rather than an empty page.
    pub fn search_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::SearchPage> {
        let reply = self.transport.post("/search/transactions", &codec::request_search_by_hash(hash))?;
        codec::parse_search(&reply)
    }

    /// `POST /search/transactions` by account tag, newest first,
    /// at most `limit` rows.
    ///
    /// `limit` must be in `1..=100`: outside that the handler ignores it and
    /// uses its own default of 10, so a caller
    /// that passed 250 would be answered with ten rows and no indication.
    /// The command line refuses the count before it reaches here.
    pub fn search_by_account(&self, tag: &Tag, limit: u64) -> Result<codec::SearchPage> {
        let reply = self
            .transport
            .post("/search/transactions", &codec::request_search_by_account(tag, limit))?;
        codec::parse_search(&reply)
    }

    /// [`Self::search_by_account`] from the `offset`-th newest row on: the
    /// rows below the newest `offset`, at most `limit` of them. A page's
    /// [`codec::SearchPage::next_offset`] is the `offset` of the page after
    /// it.
    ///
    /// `limit` is held to `1..=100` as above, and `offset` to
    /// `0..=i64::MAX`, the handler's `int64`: above that the request does
    /// not decode and the handler answers code 1. Rows arrive at the newest
    /// end, so a page asked for after others have landed repeats them and
    /// skips none.
    pub fn search_by_account_from(&self, tag: &Tag, limit: u64, offset: u64) -> Result<codec::SearchPage> {
        let reply = self.transport.post(
            "/search/transactions",
            &codec::request_search_by_account_from(tag, limit, offset),
        )?;
        codec::parse_search(&reply)
    }

    /// `POST /mempool`: the ids of every transaction the node's queue holds,
    /// in the queue's order.
    ///
    /// The middleware reads the queue from the node's own file beside it, so
    /// a deployment that does not run beside a node answers code 2, as an
    /// internal error. What it lists is the node's view of what is waiting,
    /// not the network's.
    pub fn mempool(&self) -> Result<Vec<[u8; HASHLEN]>> {
        let reply = self.transport.post("/mempool", &codec::request_mempool())?;
        codec::parse_mempool(&reply)
    }

    /// `POST /mempool/transaction`: one transaction from the node's queue,
    /// as `/block` renders one. An id the queue no longer holds is
    /// [`Error::Mesh`] with code 3, *Transaction not found*: it has been
    /// mined since the list was read, or dropped.
    pub fn mempool_transaction(&self, id: &[u8; HASHLEN]) -> Result<codec::MeshTransaction> {
        let reply = self.transport.post("/mempool/transaction", &codec::request_mempool_transaction(id))?;
        codec::parse_mempool_transaction(&reply)
    }

    /// `POST /construction/submit` with the whole wire image. `Ok` means the
    /// middleware wrote the bytes to a node's socket and echoed their id;
    /// see the module doc for what that does and does not establish. A reply
    /// naming any other id is [`Error::SubmitIdMismatch`].
    pub fn submit(&self, signed: &SignedTransaction) -> Result<TxId> {
        self.submit_wire(&signed.wire(), signed.id())
    }

    /// The same `POST /construction/submit` over a wire image the caller
    /// already holds -- the retry artifact `send` printed -- and the id the
    /// caller computed for it, which the echo must match. [`Self::submit`] is
    /// this over the signed transaction's own bytes and id. Nothing here
    /// judges the bytes, because nothing here can: the `submit` verb parses
    /// and re-serializes them before it calls this, and the node validates.
    pub fn submit_wire(&self, wire: &[u8], id: TxId) -> Result<TxId> {
        let body = codec::request_submit_wire(wire)?;
        let reply = self.transport.post("/construction/submit", &body)?;
        let echoed = codec::parse_submit(&reply)?;
        if echoed != id {
            return Err(Error::SubmitIdMismatch);
        }
        Ok(echoed)
    }
}
