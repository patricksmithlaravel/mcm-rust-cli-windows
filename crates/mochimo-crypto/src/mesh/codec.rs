//! The Mesh API's request bodies and response bodies, as bytes: pure
//! functions with no transport, so every one is a KAT against the bodies the
//! capture sent and the replies
//! `api.mochimo.org` returned (`fixtures/group_n_mesh_live.json`, a
//! specification capture — one server at one block, not an oracle).
//!
//! # Requests
//!
//! Built with `serde_json::json!` and serialised compact. `serde_json`'s map
//! is ordered, so keys come out sorted, which is what makes a request body
//! here byte-equal to `json.dumps(obj, sort_keys=True, separators=(',',':'))`
//! on the capture side. Every endpoint takes the same `network_identifier`,
//! `{blockchain: "mochimo", network: "mainnet"}`,
//! compared exactly by every handler (`ErrWrongNetwork` otherwise).
//!
//! # Responses
//!
//! Parsed by hand out of a `serde_json::Value`, never by derive, and each
//! parser reads exactly the fields the endpoint documents, checking presence,
//! type, width and range before a Rust value exists. The middleware's own
//! failures come back as **HTTP 200** carrying `{code, message, retriable}`
//! (`giveError`), so every parser first asks whether
//! the object is that shape and answers [`Error::Mesh`] if it is. Anything
//! else off the documented shape is [`Error::MeshResponse`] naming the field,
//! never the bytes.

use serde_json::{json, Map, Value};

use crate::addr::{Address, Tag};
use crate::consts::HASHLEN;
use crate::error::{Error, Result};

use super::hex;
use super::spend::SignedTransaction;
use super::{BalanceAt, ChainTip, LedgerEntry, TxId, MAX_HISTORY_RESPONSE_BYTES, MAX_RECON_RESPONSE_BYTES, MAX_REQUEST_BYTES};

/// `Constants.NetworkIdentifier.Blockchain`.
pub const NETWORK_BLOCKCHAIN: &str = "mochimo";
/// `Constants.NetworkIdentifier.Network`.
pub const NETWORK_NAME: &str = "mainnet";
/// The one `/call` method the middleware answers.
pub const TAG_RESOLVE_METHOD: &str = "tag_resolve";
/// `MCMCurrency`, `handlers.go`: the symbol and decimals every amount carries.
pub const CURRENCY_SYMBOL: &str = "MCM";
pub const CURRENCY_DECIMALS: u64 = 9;

fn network_identifier() -> Value {
    json!({ "blockchain": NETWORK_BLOCKCHAIN, "network": NETWORK_NAME })
}

fn body(value: &Value) -> Vec<u8> {
    // `Value::to_string` cannot fail for a value built from strings, numbers
    // and objects; `to_vec` on the same value is its bytes.
    value.to_string().into_bytes()
}

fn prefixed(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

// --- requests -------------------------------------------------------------

/// `POST /network/list` (`networkListHandler`): the one endpoint that takes
/// no `network_identifier`; the body names it anyway, harmlessly, so every
/// request this codec builds has the same envelope.
pub fn request_network_list() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /network/options` (`networkOptionsHandler`).
pub fn request_network_options() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /network/status` (`networkStatusHandler`).
pub fn request_network_status() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /call` with `method: "tag_resolve"` (`callHandler`): the tag as
/// `0x` + 40 hex, which the handler requires to the character
/// (`len == 2 + TXTAGLEN*2` and the prefix).
pub fn request_tag_resolve(tag: &Tag) -> Vec<u8> {
    body(&json!({
        "method": TAG_RESOLVE_METHOD,
        "network_identifier": network_identifier(),
        "parameters": { "tag": prefixed(tag) },
    }))
}

/// `POST /account/balance` (`accountBalanceHandler`) for a tag: the
/// 42-character form, which the
/// handler routes to the same tag resolution `/call` uses.
pub fn request_account_balance(tag: &Tag) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /construction/submit` (`constructionSubmitHandler`,
/// `construction_handler.go`): `signed_transaction` is the **bare** hex of
/// the whole wire image, trailer included — `TransactionFromHex` reads it
/// straight into the Go `TXENTRY` and `SubmitTransaction` re-serialises it
/// byte for byte. Refused before it is built if the body would exceed the
/// middleware's request cap, which a 256-destination image nearly reaches.
pub fn request_submit(signed: &SignedTransaction) -> Result<Vec<u8>> {
    request_submit_wire(&signed.wire())
}

/// [`request_submit`] over a wire image the caller already holds -- the
/// retry artifact `send` printed, handed back through the `submit` verb.
/// The same body: bare lowercase hex of the whole image, trailer included,
/// under the same request cap.
pub fn request_submit_wire(wire: &[u8]) -> Result<Vec<u8>> {
    let out = body(&json!({
        "network_identifier": network_identifier(),
        "signed_transaction": hex::encode(wire),
    }));
    if out.len() > MAX_REQUEST_BYTES {
        return Err(Error::PayloadTooLarge {
            what: "submit request body",
            max: MAX_REQUEST_BYTES,
            got: out.len(),
        });
    }
    Ok(out)
}

/// `POST /block` by index (`blockHandler`).
///
/// **Index 0 is not genesis.** `getBlock` routes to the
/// by-number query only when `Index != 0`; an identifier carrying 0 with no
/// hash falls through to the `else` arm, which fetches the **current**
/// block. Genesis is not reachable by number through this endpoint, so the
/// command line refuses `block 0` rather than print the tip under that name.
pub fn request_block_by_index(index: u64) -> Vec<u8> {
    body(&json!({
        "block_identifier": { "index": index },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /block` by hash (`getBlock`'s second arm).
/// The handler takes a hash of at most `32*2+2` characters and reads it from
/// the deployment's own archive folder, so a hash is served only for blocks
/// that deployment archived — a not-found is about the archive, not the
/// chain. No group N vector records this shape; the request is built from
/// the Go and the reply shape from `N-submit-block`.
pub fn request_block_by_hash(hash: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "block_identifier": { "hash": prefixed(hash) },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /search/transactions` by transaction hash
/// (`searchTransactionsHandler`).
pub fn request_search_by_hash(hash: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "network_identifier": network_identifier(),
        "transaction_identifier": { "hash": prefixed(hash) },
    }))
}

/// `POST /search/transactions` by account, newest first.
///
/// The address is the 20-byte **tag**: the indexer matches
/// `a.account_tag`, converting whatever hex it is handed to base58 of the
/// tag, which is the same form
/// [`request_tag_resolve`] builds.
///
/// `limit` is passed as given and the caller is responsible for the
/// endpoint's window: the handler takes the value **only** when
/// `0 < limit <= 100` and otherwise leaves its own default of 10,
/// so an out-of-range count would silently
/// return ten rows rather than be clamped. No `offset` is sent: the rows
/// come back `ORDER BY bm.block_height DESC, tm.id DESC`,
/// so offset 0 already names the newest. [`request_search_by_account_from`]
/// is the same request starting further down.
///
/// No group N vector records this shape either; it is built from the Go.
pub fn request_search_by_account(tag: &Tag, limit: u64) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "limit": limit,
        "network_identifier": network_identifier(),
    }))
}

/// [`request_search_by_account`] with an `offset`: the rows from the
/// `offset`-th newest on, skipping the `offset` newest.
///
/// The handler decodes `offset` into an `int64` and takes it when it is not
/// negative (`searchTransactionsHandler`), and the indexer applies it as SQL
/// `OFFSET` after the same newest-first ordering. A value above
/// `i64::MAX` does not decode, and the handler answers code 1, *Invalid
/// request*; the caller keeps to the range, as it does for `limit`.
///
/// The offset counts rows as they stand when the request is served. The
/// index grows at the newest end, so a later page asked for with the
/// `next_offset` an earlier one gave repeats the rows that arrived between
/// the two requests and skips none.
///
/// The key is sent even when it is 0, so the request says what it asked
/// for. No group N vector records this shape; it is built from the Go.
pub fn request_search_by_account_from(tag: &Tag, limit: u64, offset: u64) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "limit": limit,
        "network_identifier": network_identifier(),
        "offset": offset,
    }))
}

/// `POST /mempool` (`mempoolHandler`): every transaction id the node's
/// queue holds.
pub fn request_mempool() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /mempool/transaction` (`mempoolTransactionHandler`): one
/// transaction from the node's queue, by id. The handler compares the id it
/// is sent with `fmt.Sprintf("0x%x", id)` as strings, so it is sent as that
/// spells it: `0x` and 64 lower-case hex digits.
pub fn request_mempool_transaction(id: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "network_identifier": network_identifier(),
        "transaction_identifier": { "hash": prefixed(id) },
    }))
}

// --- responses ------------------------------------------------------------

/// A response body as an object, the error object already routed to
/// [`Error::Mesh`].
fn envelope(bytes: &[u8], cap: usize) -> Result<Map<String, Value>> {
    if bytes.len() > cap {
        return Err(Error::PayloadTooLarge {
            what: "response body",
            max: cap,
            got: bytes.len(),
        });
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::MeshResponse { what: "json" })?;
    let Value::Object(map) = value else {
        return Err(Error::MeshResponse { what: "object" });
    };
    // giveError's shape: {code, message, retriable}. No documented success
    // body carries a top-level `code`.
    if let Some(code) = map.get("code").and_then(Value::as_u64) {
        if map.get("message").and_then(Value::as_str).is_some() {
            let retriable = map.get("retriable").and_then(Value::as_bool).unwrap_or(false);
            return Err(Error::Mesh { code, retriable });
        }
    }
    Ok(map)
}

fn field<'a>(map: &'a Map<String, Value>, key: &str, what: &'static str) -> Result<&'a Value> {
    map.get(key).ok_or(Error::MeshResponse { what })
}

fn object<'a>(v: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    v.as_object().ok_or(Error::MeshResponse { what })
}

fn unsigned(v: &Value, what: &'static str) -> Result<u64> {
    // `as_u64` is `Some` only for a JSON integer that fits: a float, a
    // negative or a string is refused here rather than coerced.
    v.as_u64().ok_or(Error::MeshResponse { what })
}

fn string<'a>(v: &'a Value, what: &'static str) -> Result<&'a str> {
    v.as_str().ok_or(Error::MeshResponse { what })
}

/// A decimal string of one to twenty ASCII digits, as `/account/balance`
/// spells an amount (`fmt.Sprintf("%d", balance)`). Stricter than
/// `str::parse`, which accepts a leading `+`.
fn decimal(s: &str, what: &'static str) -> Result<u64> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error::MeshResponse { what });
    }
    s.parse::<u64>().map_err(|_| Error::MeshResponse { what })
}

fn tip(map: &Map<String, Value>, key: &str, what_index: &'static str, what_hash: &'static str) -> Result<ChainTip> {
    let block = object(field(map, key, what_index)?, what_index)?;
    let index = unsigned(field(block, "index", what_index)?, what_index)?;
    let hash = hex::decode_prefixed::<HASHLEN>(string(field(block, "hash", what_hash)?, what_hash)?, what_hash)?;
    Ok(ChainTip { index, hash })
}

/// `/network/list`: whether the middleware serves exactly the identifier this
/// codec sends. `Ok(true)` when `{mochimo, mainnet}` is among the
/// `network_identifiers`; `Ok(false)` when the list is well formed and it is
/// not.
pub fn parse_network_list(bytes: &[u8]) -> Result<bool> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let list = field(&map, "network_identifiers", "network_identifiers")?
        .as_array()
        .ok_or(Error::MeshResponse {
            what: "network_identifiers: array",
        })?;
    let mut serves = false;
    for entry in list {
        let entry = object(entry, "network_identifiers[]")?;
        let blockchain = string(field(entry, "blockchain", "network_identifiers[].blockchain")?, "network_identifiers[].blockchain")?;
        let network = string(field(entry, "network", "network_identifiers[].network")?, "network_identifiers[].network")?;
        if blockchain == NETWORK_BLOCKCHAIN && network == NETWORK_NAME {
            serves = true;
        }
    }
    Ok(serves)
}

/// A network the middleware serves, as `/network/list` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkIdentifier {
    pub blockchain: String,
    pub network: String,
}

/// The most networks [`parse_network_identifiers`] copies, and the longest
/// name it copies. `networkListHandler` lists the one identifier the
/// middleware serves; the bounds are applied before anything is copied, as
/// [`parse_network_options`] bounds its strings and its table.
pub const MAX_NETWORKS: usize = 64;
/// See [`MAX_NETWORKS`].
pub const MAX_NETWORK_NAME_BYTES: usize = 64;

/// `/network/list`: every network the middleware serves, in the reply's
/// order. [`parse_network_list`] answers whether `{mochimo, mainnet}` is
/// among them; this keeps the names, for a page that shows which network a
/// node is on.
pub fn parse_network_identifiers(bytes: &[u8]) -> Result<Vec<NetworkIdentifier>> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let list = field(&map, "network_identifiers", "network_identifiers")?
        .as_array()
        .ok_or(Error::MeshResponse {
            what: "network_identifiers: array",
        })?;
    if list.len() > MAX_NETWORKS {
        return Err(Error::MeshResponse { what: "network_identifiers: too many" });
    }
    let name = |entry: &Map<String, Value>, key: &str, what: &'static str| -> Result<String> {
        let s = string(field(entry, key, what)?, what)?;
        if s.len() > MAX_NETWORK_NAME_BYTES {
            return Err(Error::MeshResponse { what });
        }
        Ok(s.to_owned())
    };
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let entry = object(entry, "network_identifiers[]")?;
        out.push(NetworkIdentifier {
            blockchain: name(entry, "blockchain", "network_identifiers[].blockchain")?,
            network: name(entry, "network", "network_identifiers[].network")?,
        });
    }
    Ok(out)
}

/// What `/network/options` declares: the three version strings and the
/// error codes it advertises (`networkOptionsHandler` carries its own copy
/// of the table in `handlers.go`; the two are compared in the tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkOptions {
    pub rosetta_version: String,
    pub node_version: String,
    pub middleware_version: String,
    pub error_codes: Vec<u64>,
}

/// `/network/options`. Version strings are capped at 64 bytes each and the
/// error table at 64 entries before anything is copied.
pub fn parse_network_options(bytes: &[u8]) -> Result<NetworkOptions> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let version = object(field(&map, "version", "version")?, "version")?;
    let ver = |key: &str, what: &'static str| -> Result<String> {
        let s = string(field(version, key, what)?, what)?;
        if s.len() > 64 {
            return Err(Error::MeshResponse { what });
        }
        Ok(s.to_owned())
    };
    let rosetta_version = ver("rosetta_version", "version.rosetta_version")?;
    let node_version = ver("node_version", "version.node_version")?;
    let middleware_version = ver("middleware_version", "version.middleware_version")?;
    let allow = object(field(&map, "allow", "allow")?, "allow")?;
    let errors = field(allow, "errors", "allow.errors")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "allow.errors: array" })?;
    if errors.len() > 64 {
        return Err(Error::MeshResponse {
            what: "allow.errors: too many",
        });
    }
    let mut error_codes = Vec::with_capacity(errors.len());
    for e in errors {
        let e = object(e, "allow.errors[]")?;
        error_codes.push(unsigned(field(e, "code", "allow.errors[].code")?, "allow.errors[].code")?);
    }
    Ok(NetworkOptions {
        rosetta_version,
        node_version,
        middleware_version,
        error_codes,
    })
}

/// `/network/status`: the current block. The rest of the reply (genesis,
/// sync status, the middleware's certificate report) is not read here;
/// [`parse_network_status_full`] reads the parts a page shows.
pub fn parse_network_status(bytes: &[u8]) -> Result<ChainTip> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    tip(
        &map,
        "current_block_identifier",
        "current_block_identifier.index",
        "current_block_identifier.hash",
    )
}

/// `/network/status` beyond the tip: when the tip was solved, the genesis
/// block, and the middleware's own sync state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkStatus {
    /// `current_block_identifier`, as [`parse_network_status`] reads it.
    pub tip: ChainTip,
    /// `current_block_timestamp`: when the tip was solved, in milliseconds
    /// since the epoch (its trailer's `stime`). The middleware moves it only
    /// when its refresh sees a new tip (`RefreshSync`), so an old one says
    /// the tip has not moved, whether because the network has not or because
    /// the node, or the middleware's view of it, is behind.
    pub tip_timestamp_ms: i64,
    /// `genesis_block_identifier`: block 0 as the middleware read it from
    /// its node when it started.
    pub genesis: ChainTip,
    /// `sync_status`, or `None` when the reply carries none.
    pub sync: Option<SyncStatus>,
}

/// The middleware's own sync state: how its last refresh of its node's tip
/// went (`RefreshSync`, `bsync.go`).
///
/// It is about the middleware and its one node. **It does not say whether
/// the node is current with the network**: a node that has fallen behind
/// answers its old tip, and the middleware, having taken it, reports itself
/// synchronized. [`NetworkStatus::tip_timestamp_ms`] is what shows a tip
/// that has not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    /// `stage`, in the middleware's words: `synchronized` once a refresh
    /// has finished, `synchronizing` while one takes a new tip, or the step
    /// that failed (`latest block error`, `min fee error` and others).
    pub stage: String,
    /// `synced`: whether the last refresh finished.
    pub synced: bool,
}

/// The longest sync stage [`parse_network_status_full`] copies.
pub const MAX_SYNC_STAGE_BYTES: usize = 64;

/// `/network/status`, read for a page that shows the node: the tip, when it
/// was solved, the genesis block, and the middleware's sync state. The tip,
/// its timestamp and the genesis block are required, as Rosetta requires
/// them; `sync_status` is optional there and `None` here when it is absent.
/// The stage is capped before it is copied. `oldest_block_identifier` and
/// `https_status` are not read.
pub fn parse_network_status_full(bytes: &[u8]) -> Result<NetworkStatus> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let current = tip(
        &map,
        "current_block_identifier",
        "current_block_identifier.index",
        "current_block_identifier.hash",
    )?;
    let tip_timestamp_ms = field(&map, "current_block_timestamp", "current_block_timestamp")?
        .as_i64()
        .ok_or(Error::MeshResponse { what: "current_block_timestamp" })?;
    let genesis = tip(
        &map,
        "genesis_block_identifier",
        "genesis_block_identifier.index",
        "genesis_block_identifier.hash",
    )?;
    let sync = match map.get("sync_status") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = object(v, "sync_status")?;
            let stage = string(field(s, "stage", "sync_status.stage")?, "sync_status.stage")?;
            if stage.len() > MAX_SYNC_STAGE_BYTES {
                return Err(Error::MeshResponse { what: "sync_status.stage" });
            }
            let synced = field(s, "synced", "sync_status.synced")?
                .as_bool()
                .ok_or(Error::MeshResponse { what: "sync_status.synced" })?;
            Some(SyncStatus { stage: stage.to_owned(), synced })
        }
    };
    Ok(NetworkStatus { tip: current, tip_timestamp_ms, genesis, sync })
}

/// `/call tag_resolve`: `result.address` is the full 40-byte ledger address
/// (`fmt.Sprintf("0x%x", wotsAddr.Address)`) and `result.amount` the balance
/// as a JSON **number** — unlike `/account/balance`, which spells the same
/// figure as a string. `tag` is the tag the request carried: the address the
/// ledger returned must begin with it, or the reply answers a different
/// question than the one asked.
pub fn parse_tag_resolve(bytes: &[u8], tag: &Tag) -> Result<LedgerEntry> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let result = object(field(&map, "result", "result")?, "result")?;
    let address: Address =
        hex::decode_prefixed(string(field(result, "address", "result.address")?, "result.address")?, "result.address")?;
    if !address.starts_with(tag) {
        return Err(Error::MeshResponse {
            what: "result.address: does not begin with the tag resolved",
        });
    }
    let balance = unsigned(field(result, "amount", "result.amount: unsigned integer")?, "result.amount: unsigned integer")?;
    Ok(LedgerEntry { address, balance })
}

/// `/account/balance`: `balances[0].value` as a decimal string in nanoMCM,
/// with the currency checked to be the one the middleware declares, and the
/// block the middleware had cached when it answered.
pub fn parse_account_balance(bytes: &[u8]) -> Result<BalanceAt> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let tip = tip(&map, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let balances = field(&map, "balances", "balances")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "balances: array" })?;
    let first = object(
        balances.first().ok_or(Error::MeshResponse { what: "balances[0]" })?,
        "balances[0]",
    )?;
    let balance = decimal(
        string(field(first, "value", "balances[0].value")?, "balances[0].value")?,
        "balances[0].value: decimal",
    )?;
    let currency = object(field(first, "currency", "balances[0].currency")?, "balances[0].currency")?;
    if string(field(currency, "symbol", "balances[0].currency.symbol")?, "balances[0].currency.symbol")? != CURRENCY_SYMBOL
    {
        return Err(Error::MeshResponse {
            what: "balances[0].currency.symbol: not MCM",
        });
    }
    if unsigned(field(currency, "decimals", "balances[0].currency.decimals")?, "balances[0].currency.decimals")?
        != CURRENCY_DECIMALS
    {
        return Err(Error::MeshResponse {
            what: "balances[0].currency.decimals: not 9",
        });
    }
    Ok(BalanceAt { balance, tip })
}

/// `/construction/submit`: `transaction_identifier.hash`, bare hex (the
/// handler `hex.EncodeToString`s it with no prefix, unlike `/mempool`).
pub fn parse_submit(bytes: &[u8]) -> Result<TxId> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let ident = object(
        field(&map, "transaction_identifier", "transaction_identifier")?,
        "transaction_identifier",
    )?;
    let hash = hex::decode_exact::<HASHLEN>(
        string(field(ident, "hash", "transaction_identifier.hash")?, "transaction_identifier.hash")?,
        "transaction_identifier.hash",
    )?;
    Ok(TxId(hash))
}

// --- the explorer endpoints' replies ---------------------------------------

/// One Rosetta operation, as both `/block` and `/search/transactions` spell
/// it.
///
/// `amount.value` is a **decimal string on both endpoints** and may be
/// negative (a source debit), which is why it is read by
/// [`signed_decimal`] and kept as an `i128` rather than through the codec's
/// unsigned [`decimal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub index: u64,
    /// `REWARD`, `DESTINATION_TRANSFER`, `SOURCE_TRANSFER`, `FEE`. Kept as
    /// the string the endpoint sent: the set is the middleware's and a value
    /// this crate does not know is rendered, not refused.
    pub kind: String,
    pub address: String,
    pub amount: i128,
    /// `metadata.memo` where the endpoint carries one, empty otherwise.
    pub memo: String,
}

/// The operation type the middleware gives a mining reward.
pub const OP_REWARD: &str = "REWARD";
/// The operation type for value arriving at an address.
pub const OP_DESTINATION: &str = "DESTINATION_TRANSFER";
/// The operation type for value leaving a source address.
pub const OP_SOURCE: &str = "SOURCE_TRANSFER";
/// The operation type for the fee paid to the miner.
pub const OP_FEE: &str = "FEE";

/// One transaction as an explorer endpoint renders it.
///
/// `block` and `timestamp` are `Some` only on `/search/transactions`, which
/// carries a `block_identifier` and a `timestamp` per row;
/// inside a `/block` reply the block is the
/// enclosing one and the fields are absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshTransaction {
    pub hash: [u8; HASHLEN],
    pub block: Option<ChainTip>,
    pub timestamp_ms: Option<i64>,
    pub operations: Vec<Operation>,
    /// The `metadata` map rendered as `key = value` pairs in the endpoint's
    /// own spelling.
    ///
    /// **Not parsed into numbers, on purpose.** The same four keys come back
    /// as decimal strings from `/block` and as JSON numbers from
    /// `/search/transactions`, because both handlers put them in an untyped
    /// `map[string]interface{}` and the Go
    /// expression's type leaks into the JSON. Rendering them as they arrived
    /// is what lets a page say which endpoint it read without reconciling
    /// two computations that are both correct.
    pub metadata: Vec<(String, String)>,
}

/// A whole block, as `/block` renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshBlock {
    pub block: ChainTip,
    pub parent: ChainTip,
    pub timestamp_ms: i64,
    pub transactions: Vec<MeshTransaction>,
    /// The block's own figures, from its trailer; `None` when the reply
    /// carries no `block.metadata`, or carries it without one of the eight
    /// keys [`BlockMetadata`] reads.
    pub metadata: Option<BlockMetadata>,
}

/// A block's own figures, as `/block` sends them in `block.metadata`.
///
/// `getBlock` writes eight keys, every one read from the block's trailer
/// except the size: `block_size` (the block's length in bytes),
/// `difficulty`, `fee` (the trailer's `mfee`), `haiku`, `nonce`, `root`
/// (`mroot`), `stime` (in milliseconds) and `tx_count` (`tcount`). The
/// group N capture of a sealed block carries all eight, numbers as JSON
/// numbers and the two hashes as `0x` and 64 hex digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockMetadata {
    /// The block's length in bytes, as the node holds it.
    pub block_size: u64,
    /// The trailer's difficulty.
    pub difficulty: u32,
    /// The trailer's `mfee`, the least fee a transaction in it pays, in
    /// nanoMCM (`types.h:657`, "minimum transaction fee").
    pub fee: u64,
    /// The trailer's nonce expanded into words by the middleware. It is sent
    /// for every block, and it is the solve's haiku only for a normal one:
    /// the reference prints it for no other (`bup.c:98`).
    pub haiku: String,
    /// The trailer's nonce (`types.h:662`, "solving nonce of standard
    /// blocks").
    pub nonce: [u8; HASHLEN],
    /// The trailer's Merkle root over the block's contents (`mroot`).
    pub root: [u8; HASHLEN],
    /// When the block was solved, in milliseconds since the epoch: the
    /// trailer's `stime`, which `/block` also sends as the block's
    /// `timestamp`.
    pub stime_ms: i64,
    /// The trailer's transaction count, the miner's reward not among them:
    /// `/block` lists the reward as a transaction of its own.
    pub tx_count: u32,
}

/// What kind of block a block is, by the reference's own test.
///
/// `print_bup` names a block whose trailer counts no transactions
/// `Pseudo`, and then names a block whose number's low byte is zero
/// `Neogen`, which wins (`bup.c:88-89`). A pseudo-block carries no
/// transactions and no proof of work is checked for it (`bval.c:240`,
/// `:280`); a neogenesis block carries the ledger (`bval.c:33`) and comes
/// every 256th block; block 0 passes the same test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Transactions, solved by proof of work.
    Normal,
    /// No transactions.
    Pseudo,
    /// The ledger, at a block number whose low byte is zero.
    Neogenesis,
}

impl MeshBlock {
    /// The block's kind, by [`BlockKind`]'s test: from its number alone for
    /// a neogenesis block, and otherwise from the transaction count in
    /// [`Self::metadata`], so `None` when the node sent none.
    pub fn kind(&self) -> Option<BlockKind> {
        if self.block.index & 0xff == 0 {
            return Some(BlockKind::Neogenesis);
        }
        let metadata = self.metadata.as_ref()?;
        Some(if metadata.tx_count == 0 { BlockKind::Pseudo } else { BlockKind::Normal })
    }
}

/// A page of `/search/transactions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchPage {
    pub transactions: Vec<MeshTransaction>,
    pub total_count: u64,
    /// `next_offset`, set by the handler only when a full page came back and
    /// more rows exist.
    pub next_offset: Option<u64>,
}

/// The most rows this codec will copy out of one reply, whatever the reply
/// claims. The handler's own ceiling is 100 and a
/// block cannot carry more transactions than the chain allows; this is the
/// codec's own bound, applied before anything is allocated.
const MAX_ROWS: usize = 4096;

/// A decimal string that may carry a leading `-`, as an amount does on both
/// explorer endpoints. Stricter than `str::parse`: no `+`, no spaces, no
/// empty digit run, and a width that cannot overflow `i128`.
fn signed_decimal(s: &str, what: &'static str) -> Result<i128> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || digits.len() > 30 || !digits.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(Error::MeshResponse { what });
    }
    s.parse::<i128>().map_err(|_| Error::MeshResponse { what })
}

/// A `metadata` value in the endpoint's own spelling: a JSON string as
/// itself, a number as its digits, a bool and null by name. An object or an
/// array is refused rather than flattened -- no documented metadata key
/// carries one, and a page that printed `[object]` would be worse than a
/// named refusal.
fn metadata_text(v: &Value, what: &'static str) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_owned()),
        _ => Err(Error::MeshResponse { what }),
    }
}

fn parse_operations(v: &Value) -> Result<Vec<Operation>> {
    let list = v.as_array().ok_or(Error::MeshResponse { what: "operations: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "operations: too many" });
    }
    let mut out = Vec::with_capacity(list.len());
    for op in list {
        let op = object(op, "operations[]")?;
        let ident = object(field(op, "operation_identifier", "operations[].operation_identifier")?, "operations[].operation_identifier")?;
        let index = unsigned(field(ident, "index", "operations[].operation_identifier.index")?, "operations[].operation_identifier.index")?;
        let kind = string(field(op, "type", "operations[].type")?, "operations[].type")?.to_owned();
        let account = object(field(op, "account", "operations[].account")?, "operations[].account")?;
        let address = string(field(account, "address", "operations[].account.address")?, "operations[].account.address")?.to_owned();
        let amount = object(field(op, "amount", "operations[].amount")?, "operations[].amount")?;
        let amount = signed_decimal(
            string(field(amount, "value", "operations[].amount.value")?, "operations[].amount.value")?,
            "operations[].amount.value",
        )?;
        // `metadata` is absent on a REWARD. On /search it is present only
        // on a destination whose stored reference is not empty
        // (`SearchTransactions` sets `memo` from the transfer's reference
        // and nothing else), so an operation with none carries no key.
        let memo = match op.get("metadata").and_then(Value::as_object) {
            Some(m) => match m.get("memo") {
                Some(v) => string(v, "operations[].metadata.memo")?.to_owned(),
                None => String::new(),
            },
            None => String::new(),
        };
        out.push(Operation { index, kind, address, amount, memo });
    }
    Ok(out)
}

fn parse_metadata(map: &Map<String, Value>) -> Result<Vec<(String, String)>> {
    let Some(Value::Object(m)) = map.get("metadata") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        out.push((k.clone(), metadata_text(v, "metadata value")?));
    }
    // A map's iteration order is the serialiser's; sort so a page is stable.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn parse_transaction(map: &Map<String, Value>, with_block: bool) -> Result<MeshTransaction> {
    let ident = object(field(map, "transaction_identifier", "transaction_identifier")?, "transaction_identifier")?;
    let hash = hex::decode_prefixed::<HASHLEN>(
        string(field(ident, "hash", "transaction_identifier.hash")?, "transaction_identifier.hash")?,
        "transaction_identifier.hash",
    )?;
    let block = if with_block {
        Some(tip(map, "block_identifier", "block_identifier.index", "block_identifier.hash")?)
    } else {
        None
    };
    let timestamp_ms = if with_block {
        Some(
            field(map, "timestamp", "timestamp")?
                .as_i64()
                .ok_or(Error::MeshResponse { what: "timestamp" })?,
        )
    } else {
        None
    };
    Ok(MeshTransaction {
        hash,
        block,
        timestamp_ms,
        operations: parse_operations(field(map, "operations", "operations")?)?,
        metadata: parse_metadata(map)?,
    })
}

/// `/block`: the block, its parent, its timestamp, every transaction in it,
/// and its own figures ([`BlockMetadata`]).
pub fn parse_block(bytes: &[u8]) -> Result<MeshBlock> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let block = object(field(&map, "block", "block")?, "block")?;
    let identifier = tip(block, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let parent = tip(
        block,
        "parent_block_identifier",
        "parent_block_identifier.index",
        "parent_block_identifier.hash",
    )?;
    let timestamp_ms = field(block, "timestamp", "timestamp")?
        .as_i64()
        .ok_or(Error::MeshResponse { what: "timestamp" })?;
    let list = field(block, "transactions", "transactions")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "transactions: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transactions: too many" });
    }
    let mut transactions = Vec::with_capacity(list.len());
    for t in list {
        transactions.push(parse_transaction(object(t, "transactions[]")?, false)?);
    }
    let metadata = parse_block_metadata(block)?;
    Ok(MeshBlock { block: identifier, parent, timestamp_ms, transactions, metadata })
}

/// The eight keys `getBlock` writes into `block.metadata`.
const BLOCK_METADATA_KEYS: [&str; 8] =
    ["block_size", "difficulty", "fee", "haiku", "nonce", "root", "stime", "tx_count"];

/// The longest haiku this codec copies. The reference expands a nonce into
/// a 256-byte buffer (`bup.c:84`), and the bound is applied before anything
/// is copied, as every other string this codec keeps is bounded.
pub const MAX_HAIKU_BYTES: usize = 256;

/// `block.metadata`, read only when it carries all eight of
/// [`BLOCK_METADATA_KEYS`]: a deployment that writes fewer, or none, is read
/// as sending none, so its blocks still read. A key that is there with a
/// value of the wrong shape is refused naming it, as any other field is.
fn parse_block_metadata(block: &Map<String, Value>) -> Result<Option<BlockMetadata>> {
    let m = match block.get("metadata") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => object(v, "metadata")?,
    };
    if BLOCK_METADATA_KEYS.iter().any(|k| !m.contains_key(*k)) {
        return Ok(None);
    }
    let narrow = |key: &str, what: &'static str| -> Result<u32> {
        u32::try_from(unsigned(&m[key], what)?).map_err(|_| Error::MeshResponse { what })
    };
    let haiku = string(&m["haiku"], "metadata.haiku")?;
    if haiku.len() > MAX_HAIKU_BYTES {
        return Err(Error::MeshResponse { what: "metadata.haiku: too long" });
    }
    Ok(Some(BlockMetadata {
        block_size: unsigned(&m["block_size"], "metadata.block_size")?,
        difficulty: narrow("difficulty", "metadata.difficulty")?,
        fee: unsigned(&m["fee"], "metadata.fee")?,
        haiku: haiku.to_owned(),
        nonce: hex::decode_prefixed::<HASHLEN>(string(&m["nonce"], "metadata.nonce")?, "metadata.nonce")?,
        root: hex::decode_prefixed::<HASHLEN>(string(&m["root"], "metadata.root")?, "metadata.root")?,
        stime_ms: m["stime"].as_i64().ok_or(Error::MeshResponse { what: "metadata.stime" })?,
        tx_count: narrow("tx_count", "metadata.tx_count")?,
    }))
}

/// `/block/transaction`: the one transaction, without a block identifier of
/// its own.
pub fn parse_block_transaction(bytes: &[u8]) -> Result<MeshTransaction> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let t = object(field(&map, "transaction", "transaction")?, "transaction")?;
    parse_transaction(t, false)
}

/// `/mempool`: the ids of the transactions the node's queue holds, in the
/// queue's order.
///
/// The handler reads the node's queue file and lists every entry's id; for
/// an empty queue its list is Go's nil slice, which encodes as `null`, and
/// that is read as no transactions. A list longer than the codec's row
/// bound is refused before anything is copied.
pub fn parse_mempool(bytes: &[u8]) -> Result<Vec<[u8; HASHLEN]>> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let list = match field(&map, "transaction_identifiers", "transaction_identifiers")? {
        Value::Null => return Ok(Vec::new()),
        Value::Array(list) => list,
        _ => return Err(Error::MeshResponse { what: "transaction_identifiers: array" }),
    };
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transaction_identifiers: too many" });
    }
    let mut ids = Vec::with_capacity(list.len());
    for entry in list {
        let entry = object(entry, "transaction_identifiers[]")?;
        ids.push(hex::decode_prefixed::<HASHLEN>(
            string(field(entry, "hash", "transaction_identifiers[].hash")?, "transaction_identifiers[].hash")?,
            "transaction_identifiers[].hash",
        )?);
    }
    Ok(ids)
}

/// `/mempool/transaction`: one transaction from the node's queue, rendered
/// as `/block` renders one (`getTransactionsFromBlockBody`, its status
/// `PENDING`): the source debited net, no change operation, each
/// destination's reference. The reply is `/block/transaction`'s shape, and
/// is read as that is. An id the queue no longer holds -- mined since, or
/// dropped -- is answered code 3, *Transaction not found*.
pub fn parse_mempool_transaction(bytes: &[u8]) -> Result<MeshTransaction> {
    parse_block_transaction(bytes)
}

/// `/search/transactions`: the page, each row carrying its own block and
/// timestamp.
pub fn parse_search(bytes: &[u8]) -> Result<SearchPage> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let list = field(&map, "transactions", "transactions")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "transactions: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transactions: too many" });
    }
    let mut transactions = Vec::with_capacity(list.len());
    for t in list {
        transactions.push(parse_transaction(object(t, "transactions[]")?, true)?);
    }
    let total_count = unsigned(field(&map, "total_count", "total_count")?, "total_count")?;
    let next_offset = match map.get("next_offset") {
        None | Some(Value::Null) => None,
        Some(v) => Some(unsigned(v, "next_offset")?),
    };
    Ok(SearchPage { transactions, total_count, next_offset })
}
