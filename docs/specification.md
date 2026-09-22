# mcm-wallet — how the wallet works

`mcm-wallet` is a Rust wallet for Mochimo v3. Every signature it produces is a WOTS+ (Winternitz one-time) signature over SHA-256, 2,144 bytes wide, and a WOTS+ secret key signs at most once. An address is 40 bytes: a 20-byte **tag**, which is the account's permanent identity, followed by a 20-byte **hash** of the current key's public key — so a spend keeps the tag and moves the hash. Every account seed, tag, key and address is a pure function of one 32-byte master seed and one or two integers, with no randomness after the seed exists. The wallet's state lives in an encrypted keystore directory whose per-account key position only ever moves forward, and which is durable on disk before any signature is released. It reaches a chain through a Mesh API client with four operations, and it ships as a command-line program that creates a store, prints receiving addresses, reads balances, builds, signs and submits a spend, and reconciles the store against the chain.

Read every statement here as present tense: it describes the wallet as it ships, not work planned for it. Every numeric claim that a fixture pins names its group in parentheses — `(group D)` — and the groups are the JSON files under `fixtures/`, catalogued in the last section. That corpus is the executable specification: replaying a group and agreeing field for field is what conformance means. Some facts carry no group letter, and the text says so where they appear — the keystore file is wallet-local and no fixture group covers it, and a few properties (zeroization, crash atomicity, the C transaction handle) have no vector that could express them. The limits are part of the specification, not caveats appended to it: a transaction that passes every check this wallet can run offline can still be rejected by a node, and this document says where that boundary falls.

## Contents

1. [WOTS+ signatures](#wots-signatures)
2. [Addresses and tags](#addresses-and-tags)
3. [Transactions](#transactions)
4. [Seed derivation and mnemonic](#seed-derivation-and-mnemonic)
5. [The keystore file (format version 4)](#the-keystore-file-format-version-4)
6. [Reservation, signing and reconciliation](#reservation-signing-and-reconciliation)
7. [The Mesh API client and the command-line wallet](#the-mesh-api-client-and-the-command-line-wallet)
8. [Invariants](#invariants)
9. [Limits and known-open items](#limits-and-known-open-items)
10. [The fixture corpus as the specification](#the-fixture-corpus-as-the-specification)

---

## WOTS+ signatures

Every signature the wallet produces is a WOTS+ (Winternitz one-time) signature over SHA-256. The transaction's signature union has exactly one populated member, WOTS+, so there is no second scheme to select between.

### Parameters

| symbol | name in the code | value |
| --- | --- | --- |
| `n` | `PARAMSN` | 32 |
| `w` | `WOTSW` | 16 |
| `log2(w)` | `WOTSLOGW` | 4 |
| `len1` | `WOTSLEN1` | 64 |
| `len2` | `WOTSLEN2` | 3 |
| `len` | `WOTSLEN` | 67 |
| hash | — | SHA-256 |

`len1` is `8 * n / log2(w)`, `len` is `len1 + len2`, and the signature width is `len * n` = 2,144. SHA-256 is the only hash function inside the scheme: it is called in exactly two places, the pseudorandom function and the chain compression step, and nowhere else. Group A's `constants` block carries the six constants named above plus the 2,144-byte signature width.

### Sizes

| object | bytes | shape in the API |
| --- | --- | --- |
| secret seed | 32 | `Secret<32>` |
| public seed (`pub_seed`) | 32 | `[u8; 32]` |
| hash address (`adrs`) | 32 | `Adrs`, eight `u32` words |
| message digest signed | 32 | `[u8; 32]` |
| expanded private key | 2144 | `len * n`, 67 chain seeds of 32 bytes |
| public key | 2144 | `Box<[u8; 2144]>`, 67 chain ends of 32 bytes |
| signature | 2144 | `Box<[u8; 2144]>`, 67 chain elements of 32 bytes |
| full legacy address image | 2208 | public key ‖ public seed ‖ hash-address image |

A public key and a signature have the same width, and both are a bare concatenation of 67 32-byte blocks with no tag or length prefix, so nothing in the byte string distinguishes them. The 2,208-byte image is the concatenation `pk[0..2144] ‖ pub_seed[2144..2176] ‖ adrs[2176..2208]`, and its 64-byte tail (`pub_seed ‖ adrs` image) is what the wallet stores for an imported account, because the public key is a function of the secret plus those 64 bytes.

### The hash address

`adrs` is eight 32-bit words. They split into two disjoint roles:

| words | role | who writes them |
| --- | --- | --- |
| 0–4 | caller-supplied domain separation | the caller only; no WOTS+ operation ever writes them |
| 5 | chain index | set to `i` at the top of each of the 67 chain iterations |
| 6 | hash index | set to the chain position before each compression step |
| 7 | key/mask selector | set to 0, then to 1, inside every compression step |

Key generation, signing and recovery all take `&mut Adrs` and mutate words 5, 6 and 7 in place. Words 0–4 pass through unchanged; across 1,000 bulk signing vectors and 1,000 bulk keygen vectors — half of each set starting with non-zero words 0–4 — not one changes. Because words 5–7 are overwritten before they are ever hashed, their incoming values do not affect the output: group B's `B-adrs-invariance` vector signs the same message with words 5–7 zeroed and with them pre-set to `{66, 14, 1}` and records the two signatures equal.

The terminal state of the three trailing words is fixed for two of the three operations:

| operation | word 5 | word 6 | word 7 |
| --- | --- | --- | --- |
| key generation | 66 | 14 | 1 |
| public-key recovery | 66 | 14 | 1 |
| signing | 66 | one less than the step count of the last chain that ran at least one step | 1 |

Signing's word 6 is message-dependent and takes every value in `0..=14` across the 1,000 bulk signing vectors. Word 5 is 66 because the chain index is set unconditionally on the last iteration. Key generation and recovery end at word 6 = 14 because every chain ends at chain position 15, so the last compression step any chain performs is the one at position 14; at least one chain always runs, because an all-fifteen digit vector is unreachable — it would require a zero checksum, which forces the three checksum digits to zero. In recovery a chain whose digit is already 15 runs no steps at all, and the terminal word 6 is then left by an earlier chain, at the same value.

### Big-endian serialization versus the little-endian image

There are two byte pictures of one `Adrs`, and they are different.

* **Big-endian, 4 bytes per word, words in order.** This is the form the hashing consumes: it is what the pseudorandom function is fed when deriving the compression key and mask. For words `[1,2,3,4,5,66,14,1]` it is `00000001 00000002 00000003 00000004 00000005 00000042 0000000e 00000001`.
* **The little-endian image, 4 bytes per word.** This is the 32-byte form that goes on the wire, into the 2,208-byte legacy address image, and into a stored account record. The same words render as `01000000 02000000 03000000 04000000 05000000 42000000 0e000000 01000000`.

Nothing converts between them implicitly. Wire and storage code uses the little-endian image; the hash path uses the big-endian serialization.

### Primitives

**Big-endian integer write.** A value is written into a buffer of a given width, most significant byte first, truncating from the top if the buffer is narrower than the value. A zero-width buffer is rejected.

**`prf(in, key)`** — `SHA-256( pad ‖ key ‖ in )` over exactly 96 bytes, where `pad` is the 32-byte big-endian encoding of **3** (31 zero bytes then `0x03`), `key` is 32 bytes and `in` is 32 bytes. Output is 32 bytes. Group A pins it: `prf(0^32, 0^32) = 6945a6f1…bf80`.

**`expand_seed(inseed)`** — the WOTS+ private key. For `i` in `0..67`, chain seed `i` is `prf(ctr_i, inseed)` where `ctr_i` is the 32-byte big-endian encoding of `i` and the seed is the PRF **key**. The result is 67 × 32 = 2,144 bytes. The counter is the whole content of the function; without it all 67 chain seeds would be identical. Group A records the full 2,144 bytes for one seed; group AK records 128 more as digests.

**`thash_f(in, pub_seed, adrs)`** — the keyed, masked compression step, and the only place a chain element advances.

1. Set word 7 of `adrs` to 0; `key = prf(to_bytes(adrs), pub_seed)`.
2. Set word 7 of `adrs` to 1; `mask = prf(to_bytes(adrs), pub_seed)`.
3. Return `SHA-256( pad0 ‖ key ‖ (in XOR mask) )` over 96 bytes, where `pad0` is the 32-byte big-endian encoding of **0**.

The key and the mask are two different derivations of the same address, separated only by word 7. Word 7 is left at 1 on return, and the next call overwrites it, so the mutation is carried but harmless. Group A pins one call including the `adrs` transition `[0,0,0,0,0,3,7,0] → [0,0,0,0,0,3,7,1]`.

**`gen_chain(in, start, steps, pub_seed, adrs)`** — `steps` applications of `thash_f`, beginning at chain position `start`. Before each application, word 6 is set to the current position. The loop performs no step at position 16 or beyond, regardless of `steps`. With `steps == 0` the input is copied out unchanged, touching neither the hash nor `adrs`. Group AK records 128 chain walks over 84 distinct `(start, steps)` pairs with `start + steps <= 16`.

**`base_w(output, input)`** — reinterprets the input bytes as base-16 digits, **high nibble first**. Byte `0x8f` yields the digits `8` then `15`. Each digit is masked to `0..=15`; that mask is what keeps `15 - digit` from underflowing during recovery.

**Checksum.** Over the 64 message digits:

```
csum = Σ (15 - m[i])            for i in 0..64,   range 0..=960
csum = csum << 4                                  range 0..=15360
csum_bytes = big-endian 2 bytes of csum
checksum_digits = base_w(csum_bytes, 3 digits)
```

The shift is `8 - ((len2 * log2(w)) mod 8)` = `8 - (12 mod 8)` = 4, and the buffer is `ceil(len2 * log2(w) / 8)` = 2 bytes. Three digits need 12 bits and two bytes hold 16, so the shift pushes the significant bits to the top nibbles where `base_w` — reading high nibble first — finds them. The three digits are exactly the base-16 digits of `csum`, so they read as a monotone encoding of it.

**`chain_lengths(msg)`** — 67 digits: the 64 base-`w` digits of the 32-byte message, followed by the 3 checksum digits. Every digit is in `0..=15`. Group B pins five whole tables:

| message | first 64 digits | checksum digits |
| --- | --- | --- |
| `00…00` | all 0 | 3, 12, 0 |
| `ff…ff` | all 15 | 0, 0, 0 |
| `000102…1f` | `0,0,0,1,0,2,0,3,…` | 2, 12, 0 |
| `00…01` | all 0 except the last, which is 1 | 3, 11, 15 |
| `80` then 31 zero bytes | `8,0,0,…,0` | 3, 11, 8 |

The fourth row is the case worth reading twice: a checksum digit reaches 15, so the last chain runs 15 steps when signing and none at all when recovering.

### Key generation

```
pk = wots::pkgen(secret, pub_seed, &mut adrs)
```

Expand the secret to 67 chain seeds, then for each chain `i`: set word 5 to `i` and run the chain from position 0 for 15 steps. The 2,144-byte result is the concatenation of the 67 chain ends. Nothing here is data-dependent: the step count is the literal 15 for every chain and the expansion loop runs 67 times unconditionally, so the secret selects no branch and no count.

The expansion is in place: the same 2,144 bytes are the private key on entry to the chain loop and the public key on exit. That buffer is a scrubbed working buffer, and the public key is copied out of it.

Group A records seven whole key pairs, including all-zero, all-`0xff`, ordered and single-bit-set seeds; group AK records 1,000 more as SHA-256 digests of the public key plus the 40-byte address derived from it. A second, independently executed implementation reproduces all 1,000 of those — both the public key's digest and the derived address — with half of them under non-zero address words 0–4 (group AKX).

### Signing

```
sig = wots::sign(msg, secret, pub_seed, &mut adrs)     // crate-private
```

Compute `lengths = chain_lengths(msg)`, expand the secret to 67 chain seeds, then for each chain `i`: set word 5 to `i` and run the chain from position 0 for `lengths[i]` steps. The signature is the concatenation of the 67 stopping points, 2,144 bytes. Signing always uses the Rust signer, whose expansion goes into a scrubbed working buffer, whichever backend is otherwise selected.

`msg` is a 32-byte digest, not a message. The per-chain step count is the digit, so it is derived entirely from `msg`; the secret selects nothing.

A digit of 0 runs zero steps, which copies the chain's expanded private seed straight into the signature. That is the scheme working as designed, not a defect — it is exactly the mechanism that makes the key one-time.

Group B records 28 whole 2,144-byte signatures, among them one per base-`w` digit value `1..=14` under a single key; group BK records 1,000 more as digests.

### Public-key recovery

```
pk = wots::pk_from_sig(sig, msg, pub_seed, &mut adrs)
```

Compute `lengths = chain_lengths(msg)`, then for each chain `i`: set word 5 to `i` and run the chain from position `lengths[i]` for `15 - lengths[i]` steps, starting from the signature's `i`-th 32-byte block. Signing stops where recovery resumes, and `start + steps == 15` for every chain, which is what makes the two inverse.

**This always produces 2,144 bytes and never fails. It does not verify anything.** Verification is comparing the recovered key against a key you already trust, and that is the caller's job. In the wallet the comparison is made twice: once against the signing key's own public key when a signature is attached to a transaction, and once against the source address's hash half when an assembled transaction is checked.

Group B records five recover-from-signature vectors that reproduce the corresponding generated public key exactly, and three negatives that do not: a signature with its first byte's low bit flipped, one with its last byte's low bit flipped, and a correct signature against a message with one bit flipped. Group BK records the positive verdict for 1,000 signatures, plus the negative: with a single bit flipped at a recorded byte and bit position, recovery fails to reproduce the key in all 1,000 cases.

### The hash address on the wire

A signed transaction carries a 2,208-byte WOTS+ validation block: the 2,144-byte signature, then the 32-byte public seed, then the 32-byte `adrs` in its little-endian image.

The `adrs` written there is **the state recovery leaves behind**, not the state the key started from. Because recovery always terminates at words 5–7 = `{66, 14, 1}`, the last 12 bytes of that field are always the same literal:

```
offset 20..32:   42 00 00 00  0e 00 00 00  01 00 00 00
```

Both comparisons a node applies to this field (see [Transactions](#transactions)) are applied, so the field is a fixed point — a transaction whose `adrs` words 5–7 are anything else is rejected. Group D records the rejection: `Ds7` is byte-for-byte identical to the accepted `D1v` image apart from a single byte (`42` → `43` at offset 20 of the field) and is refused with "Invalid address scheme data"; `D1v` validates, as do the unrelated accepted images `Ds6-N1` and `Ds8b`.

Bytes 0..20 of the field are the caller's words 0–4, carried through untouched.

### Determinism

Key generation, signing and recovery are pure functions of their inputs. There is no randomness, no nonce and no timestamp anywhere in the scheme. The same `(msg, secret, pub_seed, adrs)` always produces the same 2,144 bytes.

This has one operational consequence the wallet depends on: a lost transaction artifact can be reproduced from the store's own reservation, byte for byte, without the key signing a second message. See [Reservation, signing and reconciliation](#reservation-signing-and-reconciliation).

### The one-time property

A WOTS+ signature publishes, for each of the 67 chains, the chain element at the position its digit names. Anyone holding it can advance any chain **forward**, so any digit vector that is greater than or equal to the signed one in every position is reachable from that signature alone. The checksum is what prevents a single signature from being universally forgeable: raising any message digit lowers `csum`, and since the three checksum digits are the base-16 digits of `csum`, at least one of them drops — and a lower digit is a position nobody can walk back to.

Two signatures under one key erode that: the released chain elements union, and the union can cover digit vectors neither signed message reached. **A WOTS+ secret key signs at most once, ever.**

The crate enforces this structurally rather than by convention:

* The raw signer is not part of the public API. `wots::pkgen` and `wots::pk_from_sig` are public; the raw signer is crate-private unconditionally, and the backend module that would otherwise expose an equivalent is crate-private in every build that does not enable the feature that publishes it. That feature is not in the default set and is enabled only by the crate's own test targets.
* The only public routes to a signature are `Keystore::sign_spend` and `Keystore::resign_reserved`.
* `sign_spend` consumes an `AdvanceReceipt` by value. A receipt is minted only after the advanced position is durable on disk, it names the store's live position, the digest must be the one the reservation recorded, and the receipt is spent whichever way the call returns. Obtaining a signature without the position having advanced is not representable.
* `resign_reserved` takes no receipt and no digest, advances nothing and writes nothing, and can only reproduce the signature for the reservation the store currently holds open.

Rolling a position backwards is refused: the advance is forward-only and a target at or below the stored position is an error. That is the correct refusal, and it means a signature from a spent key is the only route by which funds still sitting at that key's address can move — which is why `resign_reserved` exists.

### Present-tense limits

* `pk_from_sig` computes a key; it never returns a verdict. The WOTS+ layer has no verify primitive. A verdict exists one layer out, in the transaction path, where the recovered key is compared against the source address's hash half.
* Signing is not reachable from a dependent. The backend module that holds the raw signer is public only under the `raw-backend` feature, which the default feature set does not contain and which only the crate's own test targets turn on; a dependent compiled without it is refused both spellings of the raw signer at compile time. The only public routes to a signature are the two keystore routes described under Reservation, signing and reconciliation.
* The per-chain step count is a function of the signed message, and the timing of a signing operation varies with it. Every message the wallet signs is a transaction digest that is public in the transaction itself. Nothing in the crate checks that a future caller does not sign a secret-derived digest.
* The expanded private key returned by the standalone expansion routine is scrubbed when the caller drops it, and ownership is what decides when that is: the caller is the only party that knows when the key stops being secret, and nothing forces the drop to be prompt. The expansion inside signing and inside key generation writes into a scrubbed working buffer and returns no private key at all.
* Nothing in the crate scrubs the SHA-256 implementation's internal block buffer and state words. Secret material transits them.
* `gen_chain`'s clamp at chain position 16 is unreachable from key generation, signing and recovery, all of which pass `start + steps <= 15`. No fixture exercises it either: the widest bulk chain walk has `start + steps == 16`, where the clamp and the step bound coincide.
* A digit above 15 would underflow recovery's `15 - digit`. The only thing preventing it is the mask inside `base_w`.
* The one-signature property is enforced per keystore. Two stores over one seed each reach the same key position once, and nothing inside a single store observes that.
* `resign_reserved` reads only the open reservation. Once a reservation settles, the retained block is not a reservation this build will re-open.
* Signing and recovery have one oracle: the reference C, through the corpus. Only key generation carries an independently executed second implementation. The crate's own two-backend differential, which once compared the native primitives to the linked C on random inputs, is not in this repository.

---

## Addresses and tags

### The 40-byte address

An address is 40 bytes: a 20-byte **tag** followed by a 20-byte **hash**.

| offset | width | field |
| --- | --- | --- |
| 0 | 20 | tag |
| 20 | 20 | hash |

`addr::Address` is `[u8; 40]`; `addr::Tag` and `addr::AddrHash` are `[u8; 20]`. `addr::tag_of(&Address)` and `addr::hash_of(&Address)` borrow the two halves.

The tag width, the hash width and the two offsets are four separately declared constants (20, 20, 0, 20). The crate does not read all four consistently: the transaction accessors locate each half at its declared offset, but `addr::hash_of`, the native `addr_from_implicit` and the account-address builder all locate the hash half at the tag's *width* instead. Those three assume the halves abut with no gap — true of this protocol, but an inference rather than a reading of the declared offset.

### The address hash

`addr::hash_generate(input: &[u8]) -> [u8; 20]` is `RIPEMD-160(SHA3-512(input))` over the whole input. The outer hash is SHA3-512 as published, not Keccak-512; the inner hash consumes all 64 SHA3 bytes. The input may be any length.

Pinned values (group C, each reproduced by a second implementation in group CX):

| input | address hash |
| --- | --- |
| 0 bytes | `1a67d3141edc94fe4b11bbc5ab1a66608de77fb2` |
| `"abc"` (3 bytes) | `5312d20489980bdfd79e14cf67e6707248ed5aed` |
| 2144 zero bytes | `61951d88b4957b3393dc764070a507c79ab3f433` |
| 2144 bytes of `0x42` | `7fe0655e22061d36f253085bfe4e3ffe8079176d` |

SHA3-512 of the empty input is pinned separately, as `a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26`, so a broken composition and a broken hash report separately (group C).

The `addr` module also exposes the pieces: `sha3_224`, `sha3_256`, `sha3_384` and `sha3_512` (28-, 32-, 48- and 64-byte outputs; only the 512-bit width is on the address path), and `ripemd160`. `ripemd160` answers every input length, including the class the C implementation mishandles (`len % 64 >= 56`). There is one implementation and no length-dependent branch; what the length class selects is which fixture group covers the call, because the reference cannot be asked for a digest on it.

### Implicit addresses

`addr::from_implicit(tag: &Tag) -> Address` writes the same 20 bytes into **both** halves. An implicit address is one whose hash half is its tag.

`addr::from_wots(pk: &[u8; 2144]) -> Address` is `from_implicit(hash_generate(pk))`. It takes exactly 2,144 bytes — the WOTS+ public key — so both halves of its result are always equal (group C, group CX). Any other input length is not representable at the call site.

Hashing 2,208 bytes instead of 2,144 produces a different, wrong address. Group C carries this as a negative control on one key: the correct address is `80f2dbf13bf0a0bd5d1b8741ec1c5b5494a944a7` repeated, and the 2,208-byte mistake yields `3fa842916e8b409a9c00122f379224fb81a66fd5` repeated.

### The tag is the identity; the hash is the current key

Each account carries one 20-byte tag, fixed when the account is constructed and never written again — no rotation touches it.

The rotation position is a separate `u32`. Every write to it on a held account moves it strictly forward: the public step refuses to wrap and returns a range error at the ceiling, and the internal jump refuses any target that is not strictly ahead. A position is otherwise set only when an account is rebuilt from its record, and a record is plain public data — so the forward-only guarantee is about a held account, not about every `Account` value that can be constructed.

The address an account presents at position *n* is `tag ‖ hash(pk at n)`. At position 0 the two halves are equal, because the account tag **is** the address hash of the position-0 key. From position 1 on they differ, and the second half is no longer a tag anyone controls.

A spend keeps the tag and moves the hash. `Keystore::spend_addresses` returns, for one account:

| field | value |
| --- | --- |
| `tag` | the account tag |
| `position` | the position that will sign |
| `source` | `tag ‖ hash(pk at position)` |
| `change` | `tag ‖ hash(pk at position + 1)` |

Validation requires exactly that arrangement: a transaction whose source and change addresses have **equal hash halves** is rejected, and so is one whose **tag halves differ**.

On the wire the transaction header carries two full 40-byte addresses — `src_addr` at offset 4 and `chg_addr` at offset 44. A destination entry carries only the 20-byte tag: a destination is 44 bytes, being a 20-byte tag, a 16-byte reference and an 8-byte amount.

A ledger entry is keyed by the full 40-byte address and the ledger is kept sorted ascending over that full address, so a lookup compares the first *n* bytes (clamped to 40) and a 20-byte tag resolves by prefix. The Mesh requests this crate builds name an account as `0x` followed by the tag's 40 hex characters, and the `tag_resolve` call returns the full 40-byte ledger address.

One further use of a 20-byte address hash: an account's key stream is named by the address hash of the key at rotation 0. The value is carried in the account record. For a derived account it is recomputed from the master seed and compared every time a key is derived; for an imported account it is recomputed from the root and compared when the record is restored.

### The printable destination

A tag is given out as Base58 over a 22-byte payload:

| offset | width | content |
| --- | --- | --- |
| 0 | 20 | the tag |
| 20 | 2 | CRC-16 of those 20 bytes, low byte first |

`addr::tag_to_base58(&Tag) -> Result<String>` builds it; `addr::tag_from_base58(&str) -> Result<Tag, NotATag>` is the inverse.

The checksum is CRC-16/XMODEM: polynomial `0x1021`, initial value `0x0000`, no input or output reflection, no final XOR. Its check value over `"123456789"` is `0x31c3`, and over any run of zero bytes it is `0` (group E). The two bytes are written little-endian, so a CRC of `0x5833` appends `33 58`.

Worked example (group C):

| step | value |
| --- | --- |
| tag | `3f1fba7025c7d37470e7260117a72b7de9f5ca59` |
| CRC-16 | `0x5833` (22579) |
| checksum bytes | `33 58` |
| 22-byte payload | `3f1fba7025c7d37470e7260117a72b7de9f5ca593358` |
| Base58 | `J8gqYehTJhJWrfcUd766sUQ8THktNs` (30 characters) |

A 22-byte payload encodes to between 22 and 31 characters. `addr::TAG_BASE58_MIN_CHARS` is 22 and `addr::TAG_BASE58_MAX_CHARS` is 31; both ends are witnessed by fixtures — the all-zero tag gives exactly 22 `'1'` characters and the all-`ff` tag gives `2CUupRZfa1aCgvwLsbRzNpuQJuZy18W`, 31 characters. Over a 1,000-tag corpus the lengths run 29 to 31 (group C).

`tag_from_base58` applies four checks in order, and returns a `NotATag` naming which one failed:

| order | check | failure |
| --- | --- | --- |
| 1 | character count is 22..=31 | `Length { chars }` |
| 2 | the string is Base58 | `NotBase58(error)` |
| 3 | it decodes to exactly 22 bytes | `PayloadLen { got }` |
| 4 | the last two bytes equal the CRC-16 of the first twenty | `Checksum { found, computed }` |

The length window is applied before decoding, so an arbitrarily long paste is refused without running the decoder. The function is total over arbitrary input: every string returns either the tag or one of the four refusals, and no input reaches the decoder's faulting class.

The all-zero tag is the one destination the checksum cannot refuse: CRC-16 of twenty zero bytes is `0`, so `1111111111111111111111` decodes to twenty-two zero bytes whose checksum verifies and `tag_from_base58` returns `[0u8; 20]`. The codec accepts it because it is a codec; the command-line wallet refuses it as a destination, in either accepted form.

### The two destination forms the command line accepts

| form | shape | length | checksum |
| --- | --- | --- | --- |
| destination | Base58 over tag ‖ CRC-16 | 22–31 characters | yes |
| machine form | `0x` + 40 hex characters | 42 characters | no |

Input is trimmed before either form is tried. A **bare** 40 hex characters is refused with an instruction to write `0x` in front: the 40-byte ledger address prints as 80 hex characters, and its second half is also 40 hex characters — a tag nobody holds, which a bare-hex parser would accept. The two accepted forms cannot collide: the Base58 alphabet has no `0`, so no destination begins `0x`, and 31 characters is shorter than 40 either way.

A 40-byte address is printed as 80 hex characters and is never a destination. Which form each command prints is in [The Mesh API client and the command-line wallet](#the-mesh-api-client-and-the-command-line-wallet).

### The Base58 codec

The alphabet is `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. It excludes `0`, `O`, `I` and `l` — the four alphanumerics missing from it. Each leading zero byte encodes to one leading `'1'` character.

`base58::encode(&[u8]) -> Result<String>` and `base58::decode(&str) -> Result<Vec<u8>>`.

**The codec carries no checksum of its own.** Altering one character of a valid destination still decodes cleanly, to different bytes: `J8gqYehTJhJWrfcUd766sUQ8THktNA` decodes to `3f1fba7025c7d37470e7260117a72b7de9f5ca59332f`, whose last two bytes are not the CRC-16 of the first twenty (group C, group CX). The CRC-16 comparison in `tag_from_base58` is the only thing that catches a mistyped destination.

The input-dependent rejections, and there are no others:

| input | result |
| --- | --- |
| empty string | refused (both directions) |
| any byte with the high bit set | refused |
| any character outside the alphabet | refused |
| a valid Base58 string over 21 or 23 bytes | **accepted**; the 22-byte length rule lives in the caller |

`decode` is total: an all-`'1'` string of length *n* decodes to *n* zero bytes.

### The length probe

`base58::encode_probe_len(&[u8]) -> Result<usize>` and `base58::decode_probe_len(&str) -> Result<usize>` report the length the codec would produce without producing it. Both are safe on every input.

The reference implementation's length probes are one short for two input classes, and the corpus records the reference's values (group C); this crate's probes report the true length. The two classes:

| class | operation | the reference's probe | this crate's probe |
| --- | --- | --- | --- |
| non-empty all-zero input of *n* bytes | encode | *n* − 1 | *n*, the true length |
| all-`'1'` string of *n* characters | decode | *n* − 1 | *n*, the true length |
| everything else | both | the true length | the true length |

A 20-byte all-zero tag therefore carries a recorded probe of 19 beside a 20-character encoding, and a 22-character all-`'1'` string a recorded probe of 21 beside a 22-byte payload. `encode` and `decode` themselves return the whole value: the encoder sizes its buffer from the input length rather than from the probe, and the all-`'1'` decode class -- which faults in the reference -- is answered before the codec sees it.

### The 2,208-byte legacy WOTS+ address

| offset | width | field |
| --- | --- | --- |
| 0 | 2144 | WOTS+ public key |
| 2144 | 32 | WOTS+ public seed |
| 2176 | 32 | hash address, eight 32-bit words little-endian |
| 2196 | 12 | 12-byte legacy tag, overlaid on the last three of those words |

Where it still appears:

* **Key derivation.** Each key draws 2,208 bytes from its generator; see [Seed derivation and mnemonic](#seed-derivation-and-mnemonic).
* **`derive::WotsKey::legacy_address(&self, tag12: &[u8; 12]) -> Box<[u8; 2208]>`** assembles the four parts above. The overlay covers the three address words key generation rewrites anyway — the chain, hash and key-and-mask words — so the pre- and post-generation images agree on every byte it leaves.
* **`Account::import(root, first_address: &[u8; 2208])`** is the import path. It reads the 64-byte tail as the public seed and hash address, regenerates the public key from the root, and refuses the pair if the regenerated key is not the address's first 2,144 bytes. The account tag is then computed, never supplied.
* **Fixture sidecars.** Fourteen group F address files and one group C negative-control file are 2,208 bytes each.

Where it does **not** appear: the address path never takes it — `from_wots` accepts exactly 2,144 bytes, so the 2,208-byte form cannot reach it — and the keystore never stores it. A record carries 64 bytes (public seed ‖ hash-address image), from which the 2,144-byte public key is recomputed.

---

## Transactions

A transaction is one contiguous byte image in four parts: a 116-byte header, an array of N destinations of 44 bytes each, a 2,208-byte WOTS+ validation block, and a 40-byte trailer. N runs from 1 to 256. Every offset past the header moves with N, and the total length is

```
tx_sz = 116 + 44N + 2208 + 40 = 2364 + 44N
```

so a one-destination transaction is 2,408 bytes and a 256-destination transaction is 13,628 bytes, the largest the format can express (group D).

### The header

| field | offset | width | meaning |
| --- | --- | --- | --- |
| `options` | 0 | 4 | four independent bytes, below |
| `src_addr` | 4 | 40 | source address: 20-byte tag half then 20-byte hash half |
| `chg_addr` | 44 | 40 | change address, same shape |
| `send_total` | 84 | 8 | sum of the destination amounts |
| `change_total` | 92 | 8 | amount returned to `chg_addr` |
| `fee_total` | 100 | 8 | total fee |
| `blk_to_live` | 108 | 8 | expiry block number; 0 means never |

The four option bytes are four separate reads:

| byte | meaning |
| --- | --- |
| `options[0]` | transaction-data type. The only accepted value is `0x00`, multi-destination. |
| `options[1]` | signature-algorithm type. The only accepted value is `0x00`, WOTS+. |
| `options[2]` | destination count **minus one**. `0x00` means one destination, `0xff` means 256. There is no encoding for zero destinations. |
| `options[3]` | reserved. Any value parses, is carried through a parse/serialize round trip unchanged, and is read by no rule. |

Each type byte is checked before the offset that depends on it — the data type before the destination-array offset, the algorithm type before the trailer offset — so no offset is ever derived from an unvalidated byte. An unrecognised value in either is rejected outright, with nothing written (group D).

### A destination

| field | offset within the destination | width |
| --- | --- | --- |
| `tag` | 0 | 20 |
| `reference` | 20 | 16 |
| `amount` | 36 | 8 |

Destination *i* (0-based) begins at `116 + 44i`, so the last one begins at `116 + 44(N−1)`. The reference is a 16-byte text field, zero-filled where unused, with a grammar the validator enforces; the amount is an unsigned 64-bit integer. The wallet validates the reference offline by the node's own rule: `mdst_val__reference` at the pinned reference commit, transcribed state for state into `mesh::spend::reference_is_valid` and pinned at that function's stated examples and at the corpus's two recorded values (`D16-badref`) — all-NUL, or groups of uppercase letters or digits, each group one kind, neighbouring groups of different kinds, single dashes between groups and none at either end, NUL-terminated with every byte after the first NUL zero.

### The WOTS+ validation block

| field | offset | width |
| --- | --- | --- |
| `signature` | `116 + 44N` | 2144 |
| `pub_seed` | `2260 + 44N` | 32 |
| `adrs` | `2292 + 44N` | 32 |

`adrs` is the little-endian byte image of eight 32-bit words — the hash address that public-key recovery ends on. Its last 12 bytes must be exactly `42 00 00 00 0e 00 00 00 01 00 00 00`.

### The trailer

| field | offset | width |
| --- | --- | --- |
| `nonce` | `2324 + 44N` | 8 |
| `id` | `2332 + 44N` | 32 |

The trailer is the node's, not the wallet's: after a node validates a transaction it zeroes the nonce and overwrites `id` with the transaction's own id digest. Whatever trailer a wallet sends is replaced. The trailer is outside what a signature covers.

### Accepted lengths

There are two canonical images: without the trailer, `2324 + 44N` bytes, and with it, `2364 + 44N`. A parser accepts any length in the closed range `[2324 + 44N, 2364 + 44N]`; the 39 intermediate lengths are a truncated trailer, and the missing bytes read as zero. One byte below the range, one byte above it, and any buffer shorter than the 116-byte header are all rejected (group D).

The parse checks run in this order:

| order | condition | error |
| --- | --- | --- |
| 1 | fewer than 116 bytes | length error, `transaction wire header`, expected 116 |
| 2 | `options[0] != 0x00` | range error, `TXDAT type byte` |
| 3 | `options[1] != 0x00` | range error, `TXDSA type byte` |
| 4 | length outside the window | range error, `transaction wire length`, carrying both bounds |

The destination count is read from `options[2]` before the length window is computed, because the window depends on it.

### Integers

Every multi-byte integer on the wire is unsigned little-endian: the four 64-bit header fields, each destination amount, and the nonce. Group D pins byte order and field identity together, with four mutually distinct asymmetric values across the four header fields, so a serializer that swapped two fields or reversed a field's bytes fails.

### The two digests

One hash function, SHA-256, over two prefixes of the same image.

| digest | covers bytes | length |
| --- | --- | --- |
| message digest | `0 .. 116 + 44N` — options through the last destination | `116 + 44N` (the signed length) |
| id digest | `0 .. 2332 + 44N` — everything up to, not including, the trailer's `id` | `2332 + 44N` |

The message digest is what a WOTS+ signature is computed over. The id digest additionally covers the WOTS+ validation block and the nonce. Both are pinned per destination count, with the bytes the message digest hashes recorded on their own and the whole image the id digest is a prefix of recorded beside them (group D): flipping a byte in the trailer or in the validation block leaves the message digest unchanged, and flipping a byte in the last destination changes it.

Sealing a transaction sets `nonce = 0` and `id` = the id digest computed with that zero nonce — the pair a node writes itself. That id is the name the transaction goes by afterwards.

### What the signature commits to

Everything in the header and every destination byte: both type bytes, the destination-count byte, the reserved byte, both addresses in full — tag half and hash half — all four 64-bit totals, and each destination's tag, reference and amount.

**`blk_to_live` is inside the signature.** It is the last header field, it cannot be changed after signing without invalidating the signature, and it is recoverable from nothing but the signed bytes or a record of the value.

Outside the signature: the WOTS+ validation block and the trailer.

### Offline validation

Two of the protocol's checks run without a ledger. Only one of them is a function of the transaction bytes alone: the destination-array check also takes a minimum fee as an argument.

**Destination-array validation.** For each destination *j* in wire order:

| condition | error on failure |
| --- | --- |
| destination *j*'s 44-byte image is not less than destination *j−1*'s, compared byte-wise over all 44 bytes | `EMCM_TXMDSTSORT` |
| `amount` is non-zero | `EMCM_XTXDSTAMOUNT` |
| `tag` differs from the source address's tag | `EMCM_XTXTAGMATCH` |
| the running amount tally does not overflow 64 bits | `EMCM_MATH64_OVERFLOW` |
| the running fee floor does not overflow 64 bits | `EMCM_MFEES_OVERFLOW` |
| `reference` satisfies the grammar | `EMCM_XTXREF` |

Then, once:

| condition | error on failure |
| --- | --- |
| the amount tally equals `send_total` exactly | `EMCM_XTXTOTALS` |
| `fee_total` is at least `N ×` the minimum fee the check was handed | `EMCM_XTXFEES` |

The floor accumulates one copy of that minimum fee **per destination**, not one per transaction (group D). The protocol constant `MFEE` is 500, and it is the floor of the value a node may hand in — a node can raise its own figure but not lower it — so `500 × N` is what a wallet can compute offline, not what a given node will apply.

The ordering comparison is byte-wise over the whole destination — tag, then reference, then the amount's eight bytes least-significant first — so it is not a sort by tag and not a numeric sort by amount. Non-decreasing is the requirement, so byte-identical duplicate destinations are legal; two destinations sharing a tag are still ordered by the bytes that follow (group D).

The reference-field grammar, over the 16 bytes:

- only uppercase `A`–`Z`, digits `0`–`9`, dash, and NUL appear;
- the first NUL ends the text and every byte after it must be NUL;
- a group is a run of uppercase or a run of digits; a dash separates two groups, and two adjacent groups must be of different classes;
- the field must end inside a group or in NUL padding — a leading or trailing dash is invalid;
- all sixteen bytes zero is valid.

`AB-00-EF`, `123-CDE-789`, `ABC` and `123` are accepted; `AB-CD-EF`, `123-456-789`, `ABC-`, `-123` and `A\0B` are rejected (group D).

**WOTS+ signature validation.** Over the assembled image:

1. recover the 2,144-byte public key from the signature, the message digest, the public seed, and a working copy of `adrs` taken from the wire;
2. the `adrs` the recovery leaves behind must equal the `adrs` on the wire, and its last 12 bytes must be the required literal — otherwise `EMCM_TXADRS`;
3. `RIPEMD-160(SHA3-512(recovered public key))` must equal `src_addr` bytes 20..40, the hash half — otherwise `EMCM_TXWOTS`.

This check does not constrain the source address's **tag** half: an address whose tag half is arbitrary passes it (group D). Because all 40 bytes of `src_addr` sit inside the signed prefix, though, altering either half after signing changes the message digest, which changes the recovered key, which fails step 3 anyway.

The wallet runs this check over the image it assembles, and names which comparison failed — `address scheme` or `source address hash`. It does not restate the 12-byte literal separately: a genuine recovery always ends on that triple, so the equality comparison already excludes a wrong tail. The `adrs` it writes to the wire is taken from the recovery rather than restated.

The wallet does not run the destination-array validator. It applies the equivalent rules itself, as refusals while it lays a spend out; the reference's own destination-array check is reachable only through the C-backed transaction container, which the C-free build does not have.

### What only a node can decide

The full validator needs an open ledger and a current block number, and the wallet never runs it. Its rules, in the order the node applies them:

| rule | needs | error |
| --- | --- | --- |
| non-zero `blk_to_live` satisfies `bnum ≤ blk_to_live ≤ bnum + 256` | the current block number | `EMCM_TXBTL` |
| `src_addr` and `chg_addr` hash halves differ | only the bytes | `EMCM_TXCHG` |
| `src_addr` and `chg_addr` tag halves are equal | only the bytes | `EMCM_XTXTAGMISMATCH` |
| `fee_total ≥` the node's configured minimum fee | node configuration | `EMCM_TXFEE` |
| destination array valid | the bytes and that same minimum fee | as above |
| WOTS+ data valid | only the bytes | as above |
| `src_addr` is present in the ledger | the ledger | `EMCM_TXSRCLE` |
| `send_total + change_total + fee_total` does not overflow | — | `EMCM_TXOVERFLOW` |
| that sum equals the ledger balance **exactly** | the ledger | `EMCM_TXTOTAL` |

A `blk_to_live` of 0 never expires. A non-zero value expires for every block number greater than it: a node validating an arriving transaction compares against its own current block, the mempool revalidates against the next block, and a block validates against its own number, so block *B* is the last block that can carry `blk_to_live = B` and the transaction is dropped from the queue once the tip reaches that value. The same window refuses, on arrival, any value more than 256 blocks past the node's tip.

No transaction in the fixture corpus has been through this validator — it cannot be called without a chain. One vector records the two address-relation predicates as computed by the protocol's own comparators and states in its own field that the rule acting on them never ran (group D). A transaction that is correct by every offline check can still be rejected by a real node.

### The change address rule

`src_addr` and `chg_addr` must share their 20-byte tag half and differ in their 20-byte hash half. A v3 address is `tag ‖ hash`.

The wallet builds both from one account: the source is the account's current WOTS+ key, the change is the next one, and each address is the account tag followed by `RIPEMD-160(SHA3-512(that key's 2,144-byte public key))`. The tag relation therefore holds by construction, and the hash halves differ because the keys differ. **No function in the crate checks either half of the rule.** The node does.

### Building a spend

The wallet lays out every byte of the signed prefix itself, from the keystore's own addresses, the caller's destinations, the caller's fee and block-to-live, and one chain observation — the tag's ledger entry, carrying its address and balance. Nothing it signs is a transaction a server built.

The first refusal runs against the caller's list as given. The list is then sorted by each destination's 44-byte image, duplicates preserved, and the rest of the refusals run over the sorted list — which is also the order that reaches the wire, so the indexes they name are positions after the sort.

| # | condition | error |
| --- | --- | --- |
| 1 | the chain's address for the tag is not the address the store would sign with | `ChainAddressMismatch` |
| 2 | destination count outside `1..=256` | `Range` |
| 3 | a destination amount is zero | `ZeroAmount`, naming the index |
| 4 | a destination tag equals the source tag | `DestinationIsSource`, naming the index |
| 5 | the amount tally overflows 64 bits | `Overflow` |
| 6 | a destination reference the node's rule refuses | `InvalidReference`, naming the index |
| 7 | `fee_total < 500 × N` | `FeeBelowMinimum`, naming fee and minimum |
| 8 | `send_total + fee_total > balance` | `InsufficientBalance`, naming balance and needed |

`change_total` is then `balance − send_total − fee_total`, so `send + change + fee` equals the observed balance by construction. `blk_to_live` is whatever the caller passed. Each destination's reference field must satisfy the node's rule (refusal 6), so a reference the node would reject is refused before anything is reserved; the bytes are then emitted exactly as given.

Attaching a signature refuses unless the signature's key position is the position the plan was built for (`PositionMismatch`), the recovery reproduces the signing key's public key (`SignatureDoesNotRecover`, naming `public key`), and the assembled image passes the wallet's two WOTS+ comparisons. The `adrs` written to the wire is the post-recovery state. The transaction is then sealed, and `wire()` — the full image, trailer included — is final.

### Limits and gaps

- 1 to 256 destinations. The bound is enforced when the destination list is set, so serialization itself cannot fail.
- The largest image is 13,628 bytes; the smallest full image is 2,408 (2,368 without the trailer).
- The wallet enforces no block-to-live window, no source/change address relation, and no fee above the 500-per-destination protocol floor; the destination-reference grammar it does enforce, by transcription of the node's.
- Ledger equality is checked against a single balance observation. A payment landing between that observation and validation makes the totals disagree with the ledger and the node rejects the transaction. The change still goes to the wallet's own next key, so a wrong or stale balance costs a rejection, never funds.
- The signed bytes are the only place `blk_to_live` survives outside the keystore's own record of it.
- The command-line wallet sends one to 256 destinations — positional `<to> <amount>` pairs, or a file of them — each with a zero reference field unless one is named, a fee defaulting to `500 × N` and a block-to-live of 0, unless told otherwise.
- For submission the whole image travels as hex inside a JSON body capped at 30,720 bytes. A one-destination submission body is 4,907 bytes and a 256-destination one is 27,347, so every representable transaction fits.

---

## Seed derivation and mnemonic

A wallet holds one 32-byte master seed. Every account seed, account tag, WOTS+ key and address is a pure function of that seed and one or two integers: nothing on this path draws from a random source after the seed exists, so the same seed reproduces the same bytes on any machine. The derivation and the BIP39 code are pure Rust and need no C.

### The digest generator

All derivation output comes from one deterministic generator over SHA-512.

| field | width | initial value |
| --- | --- | --- |
| `seed` | 64 bytes | all zero |
| `state` | 64 bytes | all zero |
| `stateCounter` | integer | 1 |
| `seedCounter` | integer | 1 |

A counter is serialized to 8 bytes: the low 32 bits little-endian, then four zero bytes.

The three operations:

- **add seed material `m`**: `seed = SHA-512(m ‖ seed)`. The material goes first.
- **generate state**: take `c = counter_bytes(stateCounter)`, increment `stateCounter`, set `state = SHA-512(c ‖ state ‖ seed)`, then cycle the seed if the *incremented* counter is a multiple of 10.
- **cycle seed**: take `c = counter_bytes(seedCounter)`, increment `seedCounter`, set `seed = SHA-512(seed ‖ c)`. The counter goes last here — the opposite order from adding seed material.

Cycle count is 10, and the phase is one call earlier than the period suggests: because the counter starts at 1 and is read before the increment, the first cycle happens on the **9th** state generation, then on the 19th, 29th, and so on.

Drawing `n` bytes generates `ceil(n / 64)` states and copies the leading bytes of each; whatever the last state did not need is **discarded, not buffered**. Two draws of 32 bytes are therefore not one draw of 64: the second draw starts a fresh state, and the second half of the first state is never seen. A draw of 0 bytes generates no state.

A fresh generator with no seed material added yields, as its first 32 bytes, `e6036445aaf7ef918bd7e4d83a5eeb22a55f2ec68b9e6ddb32634554abb3f661` (group F).

### Two integer encodings, both on the live path

Two different integer-to-bytes conventions coexist in one scheme. Using either one for both produces valid-looking, wrong keys.

| use | width | order | value 1 | value 256 | value 16909060 |
| --- | --- | --- | --- | --- | --- |
| account / rotation index | 4 bytes | big-endian | `00000001` | `00000100` | `01020304` |
| generator counters | 8 bytes | low 32 bits little-endian, then four zero bytes | `0100000000000000` | `0001000000000000` | `0403020100000000` |

### `deriveSeed(seed, index)`

1. `material = SHA-512(seed ‖ index_bytes(index))`, 64 bytes.
2. Create a fresh generator and add `material` as seed material.
3. Draw 32 bytes. Those are the derived secret; one state has been consumed.

The generator is **not discarded**. It is returned alongside the secret and keeps running, and the key construction below draws from it exactly where `deriveSeed` left off. A port that starts a new generator for the key gets different public components from the same secret.

An account seed is `deriveSeed(master, account_index)`. A rotation key's secret is `deriveSeed(account_seed, rotation)`.

### The key construction

From a derived secret and the generator left behind:

1. Draw 2,208 bytes in **one** call — 35 states, the final 32 bytes of the 35th discarded.
2. Bytes `2144..2176` of that draw are the WOTS+ **public seed**.
3. Bytes `2176..2208` are the WOTS+ **hash address**, read as eight 32-bit words **little-endian**.
4. `wots_pkgen(secret, pub_seed, adrs)` produces the 2,144-byte public key. Generation writes hash-address words 5, 6 and 7 — and writes each of them before it reads them, so whatever those three words held on entry cannot change the key. Words 0 through 4 are left untouched, and the words the key was generated *from* are what a later signature re-runs.

The **implicit address** of that key is `RIPEMD-160(SHA3-512(pk))`, the same 20 bytes written into both halves of a 40-byte address. The key's tag is that 20-byte hash.

### The account's first key, and the account tag

An account's first key is the key construction applied to `deriveSeed(master, account_index)` — its secret **is the account seed itself**, and its public seed and hash address come from the master-level generator. `deriveAccountTag(master, account_index)` returns the tag half of that key's implicit address, which is the account's permanent 20-byte tag.

Rotation 0 is a different key. Its secret is `deriveSeed(account_seed, 0)`, not the account seed, and it has its own public components. The first key is not a rotation product.

Because the first key's public seed and hash address come from a generator seeded by the *master* seed, they are not recoverable from the account seed alone. An account restored from a root secret without them cannot reconstruct position 0; the crate therefore takes the whole 2,208-byte first address when building an imported account and rebuilds the first key from its 64-byte tail. Only the public seed and the first five hash-address words in that tail carry information — the last three words are overwritten by generation, which is why the tag those bytes actually hold does not disturb the reconstruction.

### The 2,208-byte legacy address

| offset | width | content |
| --- | --- | --- |
| 0 | 2144 | WOTS+ public key |
| 2144 | 32 | public seed |
| 2176 | 32 | hash address, little-endian image, as the generator produced it |
| 2196 | 12 | a 12-byte tag, written over the last 12 bytes after the key is generated |

Only the first 20 bytes of the hash-address field survive the overlay, and those are the five words generation never touches, so the surviving image is the same whether it is taken before or after generation. The 12-byte tag cannot reach the public key: it is applied after generation, and it lands on the three words generation overwrites before reading them. Account derivation writes a hardcoded 12-byte tag of `010101010101010101010101` there; the account's own 20-byte tag is never what goes there, and a port that writes different bytes into that field produces a different 2,208-byte address for the same seed.

### The 40-byte address

`deriveWotsSeedAndAddress(account_seed, rotation, tag)` yields the rotation key — its secret, its public seed and hash address — together with a 40-byte address:

```
address = tag (20 bytes) ‖ hash half of the key's implicit address (20 bytes)
```

The tag is supplied by the caller and is the account tag. It is not derived from the rotation key, and it does not enter the key. The first 20 bytes of the address are therefore constant across every rotation of one account; only the second 20 bytes move.

"Address" names two different things in this scheme — the 40-byte v3 address here and the 2,208-byte legacy address above — and neither is a prefix or suffix of the other (group F).

### Position numbering

Positions are unsigned and count from 0.

| position | key |
| --- | --- |
| 0 | the account's first key (secret = account seed) |
| `n ≥ 1` | rotation `n - 1` (secret = `deriveSeed(account_seed, n - 1)`) |

The external numbering used by the browser extension is one lower: its `-1` is position 0, its `n ≥ 0` is position `n + 1`. Converting from the external form refuses anything below `-1` or above `u32::MAX - 1`. Advancing a position past `u32::MAX` is refused rather than wrapped.

### Index widths and what is refused

Every index the derivation takes — account index and rotation — is a `u32`, serialized as 4 bytes big-endian. The generator's own counters are a separate quantity, counted in 64 bits and truncated to the low 32 when serialized. **Nothing in the derivation refuses an index.** The whole `u32` range derives a real secret, including `0xffffffff`, which is the value a negative index computes under the same shifts.

Two refusals that exist in the browser extension are unrepresentable here rather than checked at runtime: a negative rotation (the parameter is unsigned) and a tag of any length but 20 bytes (a tag is a fixed 20-byte array). The two are not refused the same way there. The negative index is refused only at the outer entry point — the inner `deriveSeed` accepts it and returns a secret, so the same argument is refused by one function and accepted by another (group F). The 20-byte tag width, by contrast, is checked at the outer entry point and again inside the wallet construction it calls.

### Master seed from a mnemonic

```
master_seed = PBKDF2-HMAC-SHA512(
    password = phrase bytes,
    salt     = "mnemonic" ‖ passphrase,
    rounds   = 2048,
    dkLen    = 64
)[0..32]
```

The BIP39 library normalizes the phrase before stretching it; for the ASCII input this path accepts, normalization is the identity, so the two agree byte for byte.

The master seed is the **first 32 bytes** of the 64-byte BIP39 seed. The mnemonic's entropy is a separate value and is not the master seed. A restore that used the full 64 bytes, the second 32 bytes, or the entropy derives accounts nobody holds.

The phrase is validated before it is stretched, so a phrase with a bad checksum is refused rather than turned into a seed.

The BIP39 passphrase is a distinct parameter and the wallet always passes the empty string — a non-empty passphrase changes the master seed, therefore the accounts, therefore what a recovery phrase restores in any other client. **The store password is never passed here.** The password encrypts one file on one disk; the phrase is the wallet's identity and travels between clients.

### Entropy, phrase and word counts

Encoding: the checksum is the first `entropy_len / 4` bits of `SHA-256(entropy)`; the entropy bits followed by the checksum bits are read in 11-bit groups, each group an index into the 2,048-word English wordlist.

| entropy | checksum bits | words |
| --- | --- | --- |
| 16 bytes | 4 | 12 |
| 20 bytes | 5 | 15 |
| 24 bytes | 6 | 18 |
| 28 bytes | 7 | 21 |
| 32 bytes | 8 | 24 |

`entropy → phrase → entropy` is exact in both directions for all five widths. The English wordlist is the only one supported: 2,048 words, sorted. Phrase input must be ASCII and single-space separated; non-ASCII input is refused rather than normalized. A generated phrase draws 32 bytes of entropy and is therefore 24 words.

The refusals, each with a fixed message rendered under a `bip39: ` prefix:

| condition | message |
| --- | --- |
| entropy width not in the table | `entropy is not 16, 20, 24, 28 or 32 bytes` |
| phrase contains a non-ASCII byte | `phrase is not ASCII` |
| word count not in {12, 15, 18, 21, 24} | `word count is not 12, 15, 18, 21 or 24` |
| a word is absent from the list | `a word is not in the English wordlist` |
| checksum bits do not match | `checksum mismatch` |
| passphrase contains a non-ASCII byte | `passphrase is not ASCII` |

A phrase is held zeroized in memory and its debug rendering is redacted, as are the generator's state and seed, every derived secret, and a key's public seed and hash address.

### Exporting a phrase is not the inverse of restoring from one

The export is the **browser extension's**, not this wallet's. Its `toPhrase` has two branches: over the entropy it stored beside the seed when a phrase produced that seed, and — for a seed that was **constructed directly**, with no mnemonic behind it and so no entropy to store — over the seed's own 32 bytes *as entropy*. Restoring from a phrase made by that second branch runs PBKDF2 over the words and keeps the first 32 bytes. Those are different values, so the round trip does not return the seed:

| step | value |
| --- | --- |
| constructed seed | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| phrase exported from it | `doctor anxiety move mass federal casual cancel citizen ensure give fatal pact agree powder essence melt film river bind regret remind concert just welcome` |
| seed restored from that phrase | `3ba5cf5dc97eaa0d771760749791e929e7f93b4f4d0249eeaf1152c957c9966e` |
| entropy restored from that phrase | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |

The *entropy* round trips; the *seed* does not (group F).

**This wallet has no export, and keeps nothing a phrase could be rebuilt from.** The store holds the 32-byte master seed and the per-account records tabulated in [The keystore file](#the-keystore-file-format-version-4); there is no entropy field in the body header or in a record, and `create` uses the entropy it draws only to make the words, derives the seed from the phrase itself, and passes the entropy on to nothing — it lives in a `ZeroizeOnDrop` value that is overwritten when the command returns. No verb exports a phrase — the fifteen in [The command line](#the-command-line) are the whole surface, and none of them reads a phrase out. `mnemonic::phrase_from_seed_as_entropy` is on the library surface, because `F-create-not-inverse` pins that it and `master_seed_from_phrase` are not inverses, and the only caller anywhere in this repository is the harness that replays that vector. So the branch above cannot be reached from a store at all: **the twenty-four words are the operator's own copy, and the store cannot reproduce them**, which is what `create` tells the operator at the moment it shows them.

### Pinned values (group F)

Master seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`:

| quantity | value |
| --- | --- |
| account 0 seed | `664edd3d3bf1a0e29c9398ddc16114abc6d6b432b1e5e4de267c7e2ae53f580b` |
| account 0 tag | `05ff0f69d4c1cd682ed3341c0b7773054b58800f` |
| account 1 seed | `ea8be9b5bd021bb82866121d117c168c9907d117a9241fd0bbaa3fa7c34400e5` |
| account 0, rotation 0 secret | `368ebded85547079380595026a72bd849125c1afcf102dc909bfd1e82146384f` |
| account 0, rotation 0 address (40 bytes) | `05ff0f69d4c1cd682ed3341c0b7773054b58800f2587878ad34d29cf2e4be48386aec3a0c2a7ea8c` |

Phrase `abandon` ×23 followed by `art`, empty passphrase:

| quantity | value |
| --- | --- |
| master seed | `408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70` |
| account 0 seed | `46af59ebd9706bda6e14652cd0c7057a04ef6f7ceefd2c5d30d2831a15dad23d` |
| account 0 tag | `626fc4a4bca6b3c39b2502d4bc117a89cb942012` |
| account 1 seed | `dc917b567b860afbb36d0ccd87d04cac4663522450eec8137fe2dd04d0ff93b1` |
| account 1 tag | `4d9b31e47874668e45895a1b93388e5aa9b6fbe9` |

Group F also carries the 2,208-byte legacy addresses of those first keys as separate binary files.

### Limit: which scheme guards existing funds

Five key-derivation schemes exist across the reference clients, and they are not five implementations of one function — they consume and produce different things, so no two of them can agree or disagree.

| scheme | what it is |
| --- | --- |
| `rndbytes` | the C node's wallet binary: a SHA-256 counter stream over a 64-byte seed concatenated with the binary's global password, both incremented per block |
| `tx_bot_get_secret` / `tx_bot_get_wots` | the C node's transaction bot: SHA-256 over an 8-byte index and an origin secret, except at index zero, which copies the origin secret verbatim |
| `WOTSWallet.componentsGenerator` | three SHA-256 hashes of the seed re-read as ASCII, with three suffixes |
| digest generator over SHA-512 | the scheme specified above |
| `TransactionBuilder.createWallets` | the mesh API client: SHA-256 over the seed string concatenated with the index rendered as decimal text, and again with the index plus one; its own comment says it is for testing |

**Only the fourth is captured as a derivation.** Group F records the browser extension's own executed output: one implementation, no second opinion anywhere. The third appears in the corpus only as a control demonstrating that it is never reached. Agreement with the fourth establishes that this crate reproduces that extension's pinned source exactly; it establishes nothing about which scheme any particular user's existing funds sit under, and no fixture in this corpus can settle that. Which one the deployed extension uses is answerable only by the people who shipped it.

The operational limit follows directly: **a restore reaches funds only if they were created under the digest-generator scheme.** A phrase from the browser extension restores the same accounts here and the same addresses. A wallet created by any of the other four clients does not: it derives a valid, well-formed wallet whose accounts are empty, which is indistinguishable from a wallet that is genuinely empty. Nothing detects it, because a phrase carries no mark of the scheme it was written under. `create --from-phrase` therefore shows `cli::create::SCHEME_WARNING` before it reads the password or the phrase — early enough to stop before typing twenty-four words — and the text describes the silence rather than promising an error, because there is no error to see. It is a warning and not a refusal: there is nothing to refuse on, and a phrase this program wrote is the common case. `restore` carries no such warning; it acts on a store whose seed is already committed.

The `componentsGenerator` scheme is present but dead on this path: it re-reads seed bytes as ASCII, masking every byte to its low seven bits, which corrupts every byte at or above `0x80`. Every live construction site supplies its own generator instead — two of them through the wallet constructor and one calling the address generator directly — so none of them reaches it. It is deliberately not reproduced here.

---

## The keystore file (format version 4)

A keystore is a directory holding three files:

| file | what it is |
| --- | --- |
| `accounts.mks` | the snapshot: the whole wallet state as one image |
| `accounts.mks.tmp` | the staging file a commit writes before renaming it over the snapshot. It exists for the length of a commit, and outlives one only when a commit was interrupted; `open` unlinks a leftover before reading, and every commit unlinks one before creating its own, so a leftover is never adopted and its mode is never inherited |
| `keystore.lock` | a file nothing ever writes to, held with `flock(2)` for the life of an open handle |

The snapshot is one whole-state image, not a log: every write re-encodes every account. All integers in it are little-endian and every field is fixed-width, so the image length is a closed formula of the account count and the parser bounds every read before it happens.

No fixture group covers this file. The fixture corpus pins protocol bytes; the keystore is wallet-local. What pins the keystore is a set of captured images (below) and the two published vectors the primitives are replayed against.

### Image layout

| region | offset | length | encrypted |
| --- | --- | --- | --- |
| plaintext header | 0 | 51 | no — and it is the AEAD's additional authenticated data |
| ciphertext | 51 | `45 + 195 * count` | yes |
| AEAD tag | `51 + 45 + 195 * count` | 16 | n/a |

The AEAD is ChaCha20-Poly1305, which is a stream cipher with a detached tag, so the ciphertext is exactly as long as the plaintext it covers. The tag is Poly1305 over the ciphertext with all 51 header bytes as associated data.

### The plaintext header (51 bytes)

| field | offset | width | value |
| --- | --- | --- | --- |
| `magic` | 0 | 8 | ASCII `MCMKSTOR` |
| `version` | 8 | 2 | u16, `4` for what this build writes |
| `kdf_id` | 10 | 1 | u8, `1` = Argon2id version 0x13 |
| `m_cost_kib` | 11 | 4 | u32, Argon2 memory cost in KiB |
| `t_cost` | 15 | 4 | u32, Argon2 passes |
| `p_cost` | 19 | 4 | u32, Argon2 lanes |
| `salt` | 23 | 16 | the KDF salt for this store |
| `nonce` | 39 | 12 | the ChaCha20 nonce for this image |

The header is plaintext because a reader needs the KDF's identity, its three cost parameters, the salt and the nonce before it can derive the key or decrypt anything, and needs the magic and the version word before it can decide whether to try. It is authenticated because it is all the AAD: an image whose `m_cost` is rewritten down to 8 KiB derives a different key and fails the tag.

`generation` and `count` are not header fields. They are inside the ciphertext, so a stolen file does not say how many accounts a wallet holds or how many times it has been written.

### Argon2id parameters

The KDF is Argon2id, version 0x13, with an empty secret and no associated data, deriving a 32-byte key from the password and the header's salt. The algorithm and version are fixed in the build; the three cost parameters live in each file's header, so raising them changes new stores and leaves existing ones opening.

| parameter point | `m_cost_kib` | `t_cost` | `p_cost` | where it is used |
| --- | --- | --- | --- | --- |
| shipped default for a new store | 65536 | 3 | 1 | every store the binary creates |
| cheap point | 8 | 1 | 1 | test stores only |

`p_cost` is 1: the Argon2 dependency is built without its threading support, so more lanes cost the defender the same wall clock and hand a multi-core attacker the parallelism.

`m_cost_kib` read from a file is bounded before anything allocates, because it is an instruction to allocate that many KiB. The ceiling is 1,048,576 KiB (1 GiB); above it the open fails with a range error naming `keystore kdf m_cost`, before the key is derived and before the AEAD runs, and the minimum that error reports is 8, Argon2's own floor, which the second gate enforces. Parameters inside that ceiling but which Argon2 itself rejects fail as a range error naming the parameter Argon2 refused — `keystore kdf m_cost` below 8 KiB, `keystore kdf t_cost` below 1 pass, `keystore kdf p_cost` outside 1 to 16,777,215 lanes — with that parameter's value and bounds; a refusal Argon2 makes for any other reason names `keystore kdf parameters`. There is no lower bound of the format's own: a small-but-legal `m_cost` opens, and an `m_cost` Argon2 will not accept is refused by Argon2 and reported as memory.

The key is derived once per open and held for the handle's life.

### The nonce

The nonce is not stored entropy and not a counter. A caller supplies a 32-byte nonce seed once per open; each commit's nonce is the first 12 bytes of `SHA3-256(nonce_seed ‖ generation_le_u64)`. Within one open the generation strictly increases, so the input never repeats. Two copies of one directory opened by two processes that each draw fresh entropy get different seeds, so equal generations do not produce equal nonces; that separation is the caller's to supply, and a caller passing a constant seed — which is what makes the byte-level pins possible — gets the same nonce for the same generation in both copies.

There is no RNG in the crate. The salt and the nonce seed are parameters: the binary reads them from `/dev/urandom`, and a caller that supplies constants gets a byte-identical image for identical state.

The salt does not change across rewrites of a store, so every generation of one store is sealed under the same key and only the nonce moves.

### AEAD failure is one error

A wrong password, a flipped bit anywhere in the ciphertext or tag, a forged salt or nonce, and an in-bounds forged cost parameter all arrive as the same tag mismatch and all leave as `WrongPassword`. Nothing distinguishes them, because an error that did would be a decryption oracle. The consequence is an operator's: a bit-rotted store is reported as a possibly-wrong password.

Two damaged shapes do not reach the tag and are named instead: a file too short to frame — fewer than 16 trailing bytes, or a ciphertext under 45 bytes — is corrupt at the region it ran out in, and an `m_cost` above the ceiling is a range error. A truncation that still frames is a tag mismatch like the rest.

The tag is not rollback protection. An older snapshot of the same store copied back verifies under the same password, because the salt is in the header and does not move across rewrites.

### The plaintext image

The decrypted body is a 45-byte body header followed by `count` records.

| field | offset in body | width | notes |
| --- | --- | --- | --- |
| `generation` | 0 | 8 | u64, the commit counter |
| `count` | 8 | 4 | u32, the number of records |
| `master_present` | 12 | 1 | 0 or 1 |
| `master` | 13 | 32 | the master seed; enforced all-zero when `master_present == 0` |

Records begin at body offset 45 (image offset 96), are 195 bytes each, and are sorted by tag strictly ascending with no duplicates.

### The record (195 bytes)

| field | offset in record | width | meaning |
| --- | --- | --- | --- |
| `tag` | 0 | 20 | the account identifier, and the sort key |
| `kind` | 20 | 1 | 0 derived, 1 imported |
| `body` | 21 | 32 | derived: `account_index` u32 then 28 enforced-zero bytes. imported: the 32-byte root |
| `first` | 53 | 64 | imported: the first key's public components, `pub_seed[32] ‖ adrs_le_image[32]`. derived: 64 enforced-zero bytes |
| `stream` | 117 | 20 | the key-stream identity: the address hash of the rotation-0 public key. Both kinds |
| `wots_index` | 137 | 4 | u32, the next unused key position |
| `pending` | 141 | 1 | the state byte: 0 none, 1 reserved, 2 settled-and-retained |
| `spent_index` | 142 | 4 | u32, the reserved or settled position |
| `digest` | 146 | 32 | the message that key signed or is reserved to sign |
| `figures` | 178 | 1 | 0 not recorded, 1 recorded |
| `reserved_balance` | 179 | 8 | u64 nanoMochimo: the ledger balance the spend plan was built against |
| `blk_to_live` | 187 | 8 | u64: the spend's block-to-live; zero never expires |

The first 178 bytes are format version 3's record, byte for byte and in version 3's order. Version 4 appends the 17-byte figures block: the flag and the two u64.

`first[64]` exists so an imported account can sign at position 0 without the seed being re-entered: the 64 bytes are the tail of a 2,208-byte shipped address, and they plus the root reproduce the account's tag.

`stream[20]` is the identity that makes duplicate key streams detectable across the two kinds. Adding an account whose key-stream identity equals a stored one is refused — for an imported account that identity is recomputed from its root, and for a derived one from the master seed the store holds; only a derived account added to a store holding no master carries its stored value unchecked, until `sign_spend` re-derives it.

Nothing in the block is secret. The digest is the message being signed, the position is public state, and the two figures are plan inputs.

### The state byte and the figures flag

`pending` has three values and a record is in exactly one state:

| value | state | meaning |
| --- | --- | --- |
| 0 | none | no block; every field from `spent_index` to `blk_to_live` is zero |
| 1 | reserved | a key is reserved for `digest` at `spent_index` and no further advance is permitted until the spend settles |
| 2 | settled, retained | the reservation settled; the block is kept until the position moves again |

A record can never hold an open and a settled block at once: there is one state byte, so the pair has no image, and the encoder refuses to build one.

`figures == 1` means the two u64 are the reservation's real figures. `figures == 0` means *not recorded*, and both u64 are then zero. A record written by this build with a block occupied records its figures; `figures == 0` on an occupied block is what a reservation migrated from a version-3 store looks like, and it is carried forward on re-seal rather than being filled with an invented value. `figures == 1` with `reserved_balance == 0` is representable and is not refused by the format.

Nothing on the signing path reads the figures. Re-signing a reserved key takes only `spent_index` and `digest` from the record.

### Sizes

```
image_len(count) = 51 + 45 + 195 * count + 16
                 = 112 + 195 * count
```

| quantity | value |
| --- | --- |
| header | 51 |
| body header | 45 |
| record | 195 |
| tag | 16 |
| `MIN_IMAGE_LEN` — an empty store's image | 112 |
| maximum accounts | 65,536 |
| cap image — `image_len(65536)` | 12,779,632 |
| one derived account | 307 |
| two accounts | 502 |

A version-3 image is `112 + 178 * count`, so an image holding one record is 290 bytes there. `MIN_IMAGE_LEN` is the same 112 for both, because it carries no record term. It is the value the header read reports as the minimum of its length range; it is not a floor the parser enforces, and an image shorter than 112 bytes is refused as corrupt by the framing checks rather than as out of range.

An image longer than 12,779,632 bytes is refused as a range error before anything else. The snapshot's length is also checked against that ceiling from its `stat` before the file is read; that earlier check reports the same error name with the same range, 112 to 12,779,632.

### What the parser refuses, in order

Header stage, before any key is derived:

1. total length above 12,779,632 — range error naming `keystore image length`.
2. fewer than 16 bytes for the tag — corrupt at `tag`.
3. `magic` not `MCMKSTOR` — corrupt at `magic`, offset 0.
4. `version` not 4 and not 3 — unsupported version, carrying the version read, the version written, and, for a version-1 or version-2 file, that file's first account.
5. `kdf_id` not 1 — unsupported version, carrying the id read and the id supported, naming no account.
6. `m_cost_kib` above the ceiling, or parameters Argon2 rejects — range error naming the field.
7. ciphertext shorter than 45 bytes — corrupt at `ciphertext shorter than a body header`, offset 51.

Decryption stage: the key is derived from the password and the header's salt, and the tag is verified over the ciphertext with the header as AAD. Failure is `WrongPassword` and no record byte is read.

Body stage, over authenticated bytes. Offsets in these refusals are measured from the start of the decrypted body.

1. `master_present == 0` with any non-zero `master` byte — corrupt at `master seed present flag is 0 with non-zero bytes`.
2. `master_present` not 0 or 1 — corrupt at `master seed present flag is not 0 or 1`.
3. `count` above 65,536 — range error naming `keystore account count`.
4. body length not equal to `45 + record_width * count`, where the record width is 195 for a version-4 image and 178 for a version-3 one — corrupt at `image length disagrees with count`.

Then, per record, in this order:

5. a tag not strictly greater than the previous record's — corrupt at `records not strictly ascending by tag`. This is what refuses duplicates and unsorted files alike.
6. `figures` flag 0 with a non-zero `reserved_balance` or `blk_to_live` — corrupt at `figures not zero while figures == 0`.
7. `figures` flag not 0 or 1 — corrupt at `figures flag`.
8. `pending == 0` with a non-zero `spent_index`, a non-zero `digest`, or a non-zero `figures` flag — corrupt at `pending fields not zero while pending == 0`.
9. `pending == 1`, or `pending == 2` in a version-4 record, with `spent_index + 1 != wots_index` — corrupt at `pending index does not precede wots_index by one`. The relation holds in both occupied states.
10. any other `pending` byte, and `pending == 2` in a version-3 record — corrupt at `pending flag`.
11. `kind` not 0 or 1 — corrupt at `kind`.
12. a derived record whose `body` padding is not 28 zero bytes — corrupt at `derived body padding not zero`.
13. a derived record whose `first` field is not 64 zero bytes — corrupt at `derived first-key field not zero`.
14. an imported record whose root does not reproduce the stored tag — corrupt at `imported record: the root does not reproduce the stored tag`.
15. an imported record whose root does not reproduce the stored key-stream identity — corrupt at `imported record: the root does not reproduce the stored key-stream identity`.

The figures rules run before the state-byte rules, so a record with no block and a `figures` byte of 2 is refused as a bad figures flag rather than as a dirty state-0 record. Rules 12 to 15 are the two kinds' own, so exactly one kind's checks run per record.

Finally, any byte left after `count` records — corrupt at `trailing bytes`. The body-length equality already fixes the body's length, so this is a belt rather than a reachable refusal.

Every corrupt refusal carries an offset and never a byte of the file. The parser indexes nothing; every read is a bounded take that fails with the offset it stopped at, so a truncated or malformed image refuses rather than panicking.

The encoder refuses the same two representable inconsistencies on the way out — records not strictly ascending, and an occupied block whose `spent_index + 1` is not `wots_index` — under the same wording the parser uses, plus one refusal that is the encoder's alone: a record carrying both an open and a settled block. It also refuses more than 65,536 records as a range error.

### Canonical encoding

One state has exactly one image. The padding is enforced zero, an absent master is 32 enforced-zero bytes, an unoccupied block is 53 enforced-zero bytes across `spent_index`, `digest`, `figures` and the two u64, tag order is enforced, and the widths are fixed. Given the same state, the same KDF parameters, the same salt and the same nonce seed, the encoder produces byte-identical files.

### Version 3 stores

A version-3 snapshot opens. Its plaintext header has the same eight fields at the same offsets, so one key derivation and one AEAD path serve both versions; only the record width differs, 178 instead of 195. A version-3 record ends at the digest, and its reservation's figures are read as *not recorded* rather than as zeros.

`open` never rewrites the snapshot. The handle remembers which version it read; the first commit under that handle — an account added, a position advanced, a spend reserved, a settle recorded, a master adopted, whichever comes first — seals version 4 under the next generation, so that image's nonce is fresh by construction. Until that write the file on disk is untouched and still version 3. After it, the handle reports that it crossed from 3, and the command that made the write says so on its page.

The crossing is one way: a build older than this one no longer opens the re-sealed file, and the advice it gives is the advice it has for any version it cannot read — re-add the accounts into a fresh directory, which for an open reservation costs that key a second signature. This build, meeting a version word above the one it writes, says instead that a newer build wrote the store, to open it with a build at least that new, and not to rewrite it or re-add its accounts elsewhere.

A version-3 record's state byte has the domain 0 and 1. State 2 in a version-3 image is refused as an unknown state.

### Versions 1 and 2

Version 1 (94-byte records) and version 2 (178-byte records) are refused. Both sit under a 22-byte plaintext header and end in a 32-byte hash trailer. Neither is upgraded in place, and the refusal says why and what to do instead: re-add the accounts into a fresh directory, from the master seed and from each imported account's root and first address.

The refusal is not damage and does not cost an Argon2 derivation: the version word is dispatched before the key is derived.

The refusal also names the refused file's first account when it can. For a version-1 or version-2 image holding at least one record and whose length is exactly `22 + count * width + 32` for that version's record width, bytes 22..42 are the first record's tag and byte 42 its kind, both unencrypted. The message prints the tag in hex with its kind and the procedure for comparing it against the store in hand — run `address 0x<tag>` there; an answer means both stores derive the same account, so a spend from each is one key signing twice. When the length test does not fit, no account is named and the message says so.

### The lock file

`keystore.lock` is created once with mode 0600 and never unlinked. It is held with `flock(2)` for the handle's life: the crate writes no `Drop` of its own, and the lock is released when the handle's file descriptor closes — when the handle is dropped, and when the process dies, `SIGKILL` included — so a held lock always means a live holder, and deleting the file is never the remedy.

The file's existence means nothing. A lock file with no snapshot beside it is inert, and `create` walks through it. Only a live `flock` holder refuses, as `Locked`. Two opens in one process conflict, because `flock` is per open-file-description.

Every refusal `open` makes after its missing-snapshot check leaves the lock file behind, because the read has to happen under the lock to be authoritative and taking the lock creates the file.

The lock is meaningful on local filesystems only. NFS lock emulation can make it silently meaningless, and the crate cannot detect that.

On Windows the same call is `LockFileEx`, exclusive and failing immediately, and the property above survives: the system releases a terminated process's locks, and a second open in one process is refused. Microsoft documents that the release follows termination after a time that depends on available system resources, so a lock can briefly outlive its holder; that is met as `Locked` and is gone on a retry. Whether an SMB share honours the lock between machines is not established.

### What `open` and `create` refuse

`open` refuses a group- or other-writable directory (`UnsafePermissions`, carrying the mode; on Windows, a directory anyone but this user, `SYSTEM` or the Administrators group can write to, or that another user owns — `UnsafeAcl`, carrying the trustee and the rights), a directory with no snapshot (`Missing` — an absent file is not an empty store), a live lock holder (`Locked`), and a snapshot that grows between its `stat` and its read (corrupt at `snapshot grew while being read`). A stale `accounts.mks.tmp` is unlinked after the lock is taken and is never adopted, even when it would parse: two files must never both be authorities.

`create` makes the directory with mode 0700 if it is absent (on Windows, under a protected access list granting this user alone, inherited by what is created inside it), refuses a group- or other-writable directory, refuses a directory that already holds a snapshot (`Exists`), refuses a live lock holder, and asks the existence question again under the lock before sealing anything. It does not unlink a stale `accounts.mks.tmp` itself; its first commit does, as every commit does.

### How a file is replaced

Every write is four steps in this order: write the whole image to `accounts.mks.tmp` (a leftover unlinked first, then the file created new with mode 0600 — a mode passed at open applies only to a file being created, which is why the leftover is not truncated), `fsync` that file, rename it over `accounts.mks`, `fsync` the directory. The snapshot inherits the temp's mode through the rename, and that mode is always the fresh file's. Each step's return value is the next step's argument, so the order is a type constraint rather than a convention.

If any step fails, the handle is poisoned: every later call that reads or writes the store's state fails, and the fix is to drop it and reopen from disk. Nothing is retried.

On Unix this relies on POSIX rename atomicity, directory `fsync` and `flock`. Two limits are stated rather than detected: it does not survive an `fsync` that lies, and rename atomicity is not detectable from the standard library on FAT, exFAT or FUSE.

On Windows the temp is created under a protected access list granting this user alone, and the snapshot keeps that list through the rename. The rename is `MoveFileExW` replacing the target, relied on to be atomic on NTFS as the rename is on the Unix filesystems above, which Win32 does not document either. **The fourth step flushes nothing on Windows**: Win32 documents no call that commits a directory entry on NTFS, so the step performs no I/O and the power-loss half of I3 has no mechanism behind it there. A power cut or an operating-system crash before NTFS flushes its log can bring back the previous snapshot; if the lost commit reserved a key whose spend has not settled, the next spend can sign the same position, and reconciliation catches that only once the first spend is on the chain. `keystore::medium::Disk::fsync_dir`'s Windows arm weighs the two candidate substitutes and says why each is refused. A rename refused because another process holds the snapshot or the temp open without delete sharing is `ReplaceRefused`; it changes nothing, and the handle is poisoned as after any failed step.

The build refuses to compile for any target that is neither Unix nor Windows.

### The captured images

Five real files are kept and read by the test suite. They are recordings of what this crate's encoders wrote, not oracle data, and they are never re-captured.

| file | size | parameters | role |
| --- | --- | --- | --- |
| `keystore_v1_snapshot.bin` | 242 | — | a version-1 file: refused |
| `keystore_v2_snapshot.bin` | 410 | — | a version-2 file: refused, and the source of the first-account naming |
| `keystore_v3_snapshot.bin` | 290 | 65536/3/1 | the version-3 read path, one derived account |
| `keystore_v3_reserved_snapshot.bin` | 290 | 8/1/1 | a version-3 file with a reservation open: the not-recorded figures arm |
| `keystore_v4_snapshot.bin` | 307 | 65536/3/1 | the version-4 image this build must reproduce byte for byte |

The two published vectors the primitives are replayed against are RFC 9106 §5.3 for Argon2id and RFC 8439 §2.8.2 for ChaCha20-Poly1305, and the RFC texts are carried in the tree so the replayed literals have their provenance on disk.

---

## Reservation, signing and reconciliation

An account spends by reserving the key it is about to use, signing exactly one digest with it, and then resolving that reservation against the chain. The reservation is durable state inside the account's keystore record; the signature itself is never stored. Reconciliation compares the store's record with what a Mesh node says about the same tag, and refuses rather than guesses when they disagree.

### The reservation block in a record

Each account record is 195 bytes. The last 58 bytes are the position and the reservation block:

| offset | width | field | encoding |
| --- | --- | --- | --- |
| 137..141 | 4 | `wots_index` — the position the account signs with next | u32 little-endian |
| 141..142 | 1 | state byte | 0, 1 or 2 |
| 142..146 | 4 | `spent_index` — the reserved position | u32 little-endian |
| 146..178 | 32 | `digest` — the message the key is reserved for | raw bytes |
| 178..179 | 1 | figures flag | 0 or 1 |
| 179..187 | 8 | `reserved_balance` — nanoMochimo | u64 little-endian |
| 187..195 | 8 | `blk_to_live` | u64 little-endian |

A version-3 record is 178 bytes and ends at the digest. A reservation read out of one has its figures declared absent rather than read as zero; re-encoding it under version 4 writes figures flag 0 with both values zero, so an absent pair is produced both by the version-3 read and by a version-4 record whose flag is 0.

### The three states

| state byte | name | in memory | what the record holds |
| --- | --- | --- | --- |
| 0 | nothing reserved | `pending: None`, `settled: None` | `spent_index`, `digest`, figures flag and both figures are all zero |
| 1 | reserved | `pending: Some(p)`, `settled: None` | the reserved position, the digest it is reserved for, and the figures when recorded |
| 2 | settled block retained | `pending: None`, `settled: Some(p)` | the same three things, for a reservation that has already settled |

`Pending` is `{ spent_index: WotsIndex, digest: [u8; 32], figures: Option<Figures> }`. `Figures` is `{ reserved_balance: u64, blk_to_live: u64 }` — the ledger balance the spend plan was built against, and the plan's block-to-live, where 0 means never expires.

**State 1 is two chain states, and the record cannot tell them apart.** The reservation says a key signed; whether what it signed has landed is the chain's answer, not the store's, and reconciliation reads it as `SpendOutstanding` (the chain still at the reserved key) or `SpendLanded` (the chain at the change key). `settle` acts on the second and `resign` exists for the first. Until 2026-09-15 `resign` did not distinguish them: it rebuilt the plan through `SpendPlan::new`, whose opening guard compares the chain's address with the source it is laying out against, and for `resign` that source is the reserved key — so a reservation that had landed refused with `ChainAddressMismatch`, whose page names I4's three causes and none of them was the state. It now asks the same classifier `settle` acts on and refuses `ReservationLanded { spent_index, settled_index }`, naming `settle`. The guard in `SpendPlan::new` is unchanged, because the planner's rules are the node's and this is not one of them.

**What that observation does and does not establish.** A change address follows the *position*, not the transaction: the chain standing at the reservation's change key is equally what a different spend from the same reserved key looks like, and this chain holds one ledger entry per tag, so no query separates them. `SpendLanded` is therefore one observation reported as one observation. `Wallet::settle_if_landed`'s doc argues why one is the right depth to act on; `resign`'s refusal says on its page what it did not see.

The parser applies every rule below, the figures rules first and then the state-byte rules. The encoder applies two of them: the relation, under the same refusal text, and its own both-blocks refusal. The rest are unrepresentable in the encoder's input, which builds the block from a sum type rather than from bytes.

| rule | refusal text |
| --- | --- |
| figures flag 0 requires both figure values zero | `figures not zero while figures == 0` |
| figures flag is 0 or 1 | `figures flag` |
| state 0 requires `spent_index`, `digest` and the figures flag all zero | `pending fields not zero while pending == 0` |
| states 1 and 2 require `spent_index + 1 == wots_index` | `pending index does not precede wots_index by one` |
| the state byte is 0, 1 or 2; state 2 only in a version-4 record | `pending flag` |
| a record never holds an open and a settled block together | `both an open and a settled reservation in one record` |

The last rule is the encoder's alone: no state byte encodes both blocks, so the parser has no counterpart for it.

### Transitions

| from | to | function | effect |
| --- | --- | --- | --- |
| 0 or 2 | 1 | `Keystore::persist_advance(&Tag, &[u8; 32], Figures)` | `wots_index` becomes stored + 1; the block becomes state 1 at the stored position with the supplied digest and figures. A retained settled block is overwritten. Refuses `PendingUnresolved { spent_index }` when a reservation is already open |
| 1 | 2 | `Keystore::persist_settled(&Tag)` | the position does not move; the block moves from `pending` to `settled`. Refuses `NothingPending` in state 0 and state 2 |
| 0 or 2 | 0 | `Keystore::persist_advance_to(&Tag, WotsIndex)` | `wots_index` becomes the target; both blocks are cleared. Refuses `PendingUnresolved` in state 1, and `Range { what: "wots index for tag", min: stored + 1, max: u32::MAX }` for a target not strictly ahead |

All three also refuse `NoSuchAccount` for a tag the store does not hold, and `persist_advance` refuses `Range` rather than wrapping when the stored position is already at the ceiling.

Every transition is one whole-snapshot rewrite through the four-step commit described in [The keystore file](#the-keystore-file-format-version-4). In-memory state is applied only after those four steps return `Ok`, and a failure at any of them poisons the handle: every later call that reads or writes store state returns `Error::Poisoned`.

`persist_advance` and `persist_advance_to` return an `AdvanceReceipt`. `persist_settled` returns `()`. Slots the write does not name keep both of their own blocks.

### What each state permits

| operation | state 0 | state 1 | state 2 |
| --- | --- | --- | --- |
| `persist_advance` | yes | `PendingUnresolved` | yes — overwrites the retained block |
| `persist_advance_to` | yes | `PendingUnresolved` | yes — clears the retained block |
| `persist_settled` | `NothingPending` | yes | `NothingPending` |
| `spend_addresses` | yes | `PendingUnresolved` | yes |
| `address_at` | yes | yes | yes |
| `sign_spend` | `NoReservation` | yes | `NoReservation` |
| `resign_reserved` | `NothingPending` | yes | `NothingPending` |

`address_at` deliberately does not refuse an open reservation: reconciliation asks for the addresses at `spent_index` and `spent_index + 1` precisely while a spend is in flight.

Outside the snapshot writer, which carries every slot's two blocks forward into each new image, and the view the store hands out, the retained settled block is read in exactly one place: the divergence report's reverted-settle clause.

### The two routes to a signature

Both return a `SpendSignature`:

| field | type | meaning |
| --- | --- | --- |
| `spent_index` | `WotsIndex` | the position that signed |
| `signature` | `Box<[u8; 2144]>` | the WOTS+ signature over the digest |
| `pub_seed` | `[u8; 32]` | the signing key's public seed |
| `adrs` | `Adrs` | the hash address the signature started from |
| `public_key` | `Box<[u8; 2144]>` | the signing key's public key |

`Debug` on `SpendSignature` prints the position and the key's address hash, not the bytes.

#### `Keystore::sign_spend`

```rust
pub fn sign_spend(&mut self, digest: &[u8; 32], receipt: AdvanceReceipt, access: KeyAccess<'_>)
    -> Result<SpendSignature>
```

There is no tag parameter: the account is `receipt.tag()`. The receipt is taken by value and has no `Clone`, so one receipt buys at most one call, and an `Err` spends it as surely as an `Ok`.

`AdvanceReceipt` has private fields and no public constructor: minting it is crate-private and demands a `Durable` witness. The witness is constructed at exactly one expression — the `Ok` arm of the commit, after all four durable steps — and the receipt is minted at exactly one expression, in the helper that commits and then applies the same state in memory. So a receipt exists only for a position that is on disk.

The checks run in this order:

1. the receipt names an account this store holds — `NoSuchAccount`
2. the store's position equals `receipt.index()` — `StaleReceipt { attested, stored }`
3. a reservation is open — `NoReservation`
4. `pending.spent_index + 1 == receipt.index()` — `NoReservation`
5. `pending.digest == *digest` — `DigestMismatch`
6. the access shape matches the account kind — `KeyAccessMismatch { kind }`
7. for a derived account: the master seed reproduces the account's tag — `DerivedTagNotReproduced { account_index }`; the derived seed is not also a stored imported root — `KeyStreamSharedWithImportedAccount`; the derived seed reproduces the record's 20-byte key-stream identity — `StreamIdNotReproduced`

`Keystore::check_spend(&self, digest, &receipt, &access)` runs all of it on a borrowed receipt and derives then drops the key, so a passphrase can be confirmed without spending the receipt.

`sign_spend` persists nothing and touches no file.

#### `Keystore::resign_reserved`

```rust
pub fn resign_reserved(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendSignature>
```

`&self`, no receipt, no digest parameter. The digest and the position both come from the record's open reservation, so signing over anything but the reserved digest is unrepresentable rather than refused. It reads `pending` only, never the retained settled block.

WOTS+ signing is a pure function of the message, the secret seed, the public seed and the starting hash address (group B), so this reproduces the bytes `sign_spend` already released, byte for byte: one signature produced twice, not two signatures under one key.

It exists because the position never rolls back, which makes a signature from the reserved key the only way the balance at that key's address can move.

#### Why a position never rolls back

- `persist_advance` computes the next position as stored + 1 and accepts no caller-supplied value.
- `persist_advance_to` refuses any target not strictly ahead of the stored position, and the in-memory `advance_to` applied after the commit refuses the same.
- `WotsIndex` has no public constructor from `u32`; `advanced()` returns `Error::Range` on overflow rather than wrapping.
- Records are keyed by tag in a `BTreeMap` in memory and are written and read in strictly ascending tag order, refused in both directions otherwise, so a record is addressed by tag and never by position.
- A handle that saw a commit error refuses every later call, because memory and disk are then unknown relative to each other.

#### The ReSigner property

A source scan classifies every wallet-visible function that can hand out signature-bearing data. The classes are `Signer`, `Reader`, `Composer`, `ReSigner` and `Entrypoint`, and each carries a mechanically checked condition:

| class | member | checked condition |
| --- | --- | --- |
| `Signer` | `Keystore::sign_spend` | allow-listed |
| `ReSigner` | `Keystore::resign_reserved` | takes **no** parameter whose type renders as `[u8;32]` or `[u8;HASHLEN]`, and its body names `pending` |
| `Composer` | `Wallet::reserve_and_sign`, `Wallet::resign_pending` | the body names `sign_spend` or `resign_reserved`, and names no raw signer port |
| `Entrypoint` | `cli::run` | the body names `Wallet`, and names neither the gated signers nor a raw signer port |
| `Reader` | transaction assembly, decoding and wire attachment | the body does not reach the signer, and it takes no key-material parameter |

A "re-signer" that accepted a digest fails the class and the scan fails with it. The raw signer itself is crate-private and the backend module is public only under a non-default feature.

#### The wallet's two spend paths

`Wallet::reserve_and_sign(&plan, access)` calls `persist_advance(&plan.tag(), &plan.digest(), plan.figures())` and then `sign_spend(&plan.digest(), receipt, access)`, and assembles the wire image. The returned bytes are the retry artifact and the wallet does not keep them.

`Wallet::resign_pending(tag, access, dsts, fee_total, blk_to_live)` rebuilds the plan from the parameters the caller remembers, over the addresses at `pending.spent_index` and the stored position and over a freshly read ledger entry for the tag, refuses `DigestMismatch` unless the rebuilt digest equals the reserved one, and only then calls `resign_reserved`.

It has three refusals: `NothingPending` with no reservation open, `ReservationLanded` when the chain has already moved to the reservation's change key, and `DigestMismatch` when the rebuilt plan is not the reserved one. The middle one is reached only through `SpendPlan::new`'s chain-address guard: when that guard refuses, the account is put to `reconcile_account_with` under a scope that walks **nothing** — the comparison that decides *landed* does not use the scope, and the walk exists only for a divergence's report, which this path does not render and whose page it keeps unchanged for every answer but `SpendLanded`.

The reserved digest is the SHA-256 over the unsigned transaction image up to the WOTS+ validation block (group D).

### Reconciliation

Reconciliation is per account. It makes these reads, in this order:

| read | source | failure |
| --- | --- | --- |
| the account view — kind, `wots_index`, `pending`, `settled` | the store | `CannotReconcile { cause }`; an unknown tag is `CannotReconcile { cause: NoSuchAccount }` |
| `POST /call` with method `tag_resolve` → `LedgerEntry { address: [u8; 40], balance: u64 }` (group N) | the Mesh node | Mesh code 4 is `TagUnresolved`; anything else is `ChainUnreachable { cause }` |
| the 20-byte key-stream identity | the store | `CannotReconcile { cause }` |
| the address at one or more positions, derived through the same code path `sign_spend` uses | the store plus the caller's key access | `CannotReconcile { cause }` |
| `POST /network/status` → `ChainTip { index: u64, hash }` (group N) | the Mesh node | recorded as an unchecked expiry, never as a refusal |

The node's `tag_resolve` answer is the ledger's current 40-byte address for the tag — the tag half followed by the current hash half — and its balance in nanoMochimo. Code 4 means the node did not resolve the tag, and it is given for a tag the ledger has no entry for, for a tag the ledger holds at zero balance, and for a lookup that failed; the class name and its report say all three and prefer none.

#### The comparison

With no reservation open, the chain's address must equal the address at `wots_index`. With a reservation open, it must equal the address at `spent_index` (not landed) or the address at `wots_index`, the change key (landed).

| outcome | variant | fields |
| --- | --- | --- |
| agreement, nothing reserved | `AccountStatus::InSync` | `index`, `address`, `balance` |
| reservation open, chain at the spent key | `AccountStatus::SpendOutstanding` | `spent_index`, `balance`, `reservation` |
| reservation open, chain at the change key | `AccountStatus::SpendLanded` | `spent_index`, `settled_index`, `balance` |

#### The divergence classes

| variant | when | fields |
| --- | --- | --- |
| `IndexMismatch` | no reservation, and the chain holds an address the store does not expect | `tag`, `local`, `local_address`, `chain_address`, `balance`, `stream`, `found`, `reverted_settle` |
| `ReservationUnexplained` | a reservation is open and the chain holds neither of its two keys | `tag`, `spent_index`, `chain_address`, `balance`, `stream`, `found` |
| `TagUnresolved` | the node answered code 4 | `tag`, `local` |
| `ChainUnreachable` | any other node failure | `tag`, `cause` |
| `NoMasterForDerivedAccount` | a derived account with no master seed supplied | `tag` |
| `CannotReconcile` | a store error, an unparsed response, a key that would not derive | `tag`, `cause` |

Each renders an operator report naming what diverged and one action. The two comparison failures also name both positions or why there is no second one, the size of the gap, the balance at stake and the key-stream identity; the four that could not compare anything name the tag, and the local position or the underlying cause where there is one. Where a bounded walk cannot separate causes, the report names every cause that fits and prefers none.

`Error::ReconciliationRefused { what }` carries a short fixed kind: `index mismatch`, `reservation unexplained`, `tag unresolved by the node`, `chain unreachable`, `no master for a derived account`, `reconciliation could not run`.

#### Locating the chain's address

When the comparison fails, a target-directed walk derives addresses and stops on the one that equals the chain's:

| variant | meaning |
| --- | --- |
| `ChainPosition::Ahead { index, gap }` | the chain's address is this seed's key at a position ahead of the local position |
| `ChainPosition::Behind { index, gap }` | it is this seed's key at a position behind the local position |
| `ChainPosition::Unlocated { local, scope, failed_at }` | no position the walk reached reproduces it; `failed_at` is set when a derivation error stopped the walk early |

The scope is `{ ceiling: u32, window: Option<u32> }`. The diagnostic scope is ceiling **10,000** with window 20: it walks `local - 20 ..= local + 20` first, clamped, with the high edge capped at `u32::MAX - 1`, then `0..10000` skipping positions the window already covered. The restore scope is ceiling 10,000 with no window. A caller can set the ceiling for one invocation; raising it only widens the search and never becomes the answer.

**The ceiling and the window are separate bounds, and they do not coincide.** BIP-44's 20 is a gap limit over unused addresses; the ceiling bounds how many spends an account has already made before a phrase alone cannot recover it, which is a quantity BIP-44 does not have, so one number serving both would share a value and nothing else. 10,000 is taken from the only other implementation of this protocol — the shipped browser extension walks `0..10000` over the same key positions in `MasterSeed.deriveWotsIndexFromWotsAddrHash` — and those are the users whose funds a phrase restored here has to reach. The window stays 20: it bounds the size of a *disagreement*, which is the shape BIP-44's number does fit.

**The diagnostic's ceiling follows the recovery ceiling, and that is a change on the startup path.** It was decided rather than inherited: pinning the diagnostic at 20 would leave `Wallet::open` reporting `Unlocated` — whose text names a foreign seed and a foreign chain among its three causes — for an account this wallet's own `restore` had just placed at position 5,000, and would leave I4's two-instance case, where another wallet on the same seed has spent hundreds of keys, described as three causes with the true one missing rather than as `Ahead { gap }`. What it costs is confined to the failing path: an account that reconciles runs no walk at all, a disagreement inside ±20 is found in at most 41 derivations wherever the account sits, and only a divergence **larger than the window** now pays — up to a full exhaustion, about 16 seconds of derivation in a release build, per diverged account, on a startup that is going to refuse either way.

Per-position usage is not observable on this chain — the ledger holds one entry per tag and a lookup answers only "is this the tag's current address" — so the walk stops on a match and never scans for absence.

#### The dead-reservation rule

For `SpendOutstanding` only, the record's figures are compared with the entry and the tip:

| `Reservation` | when |
| --- | --- |
| `Unrecorded` | the record carries no figures; no tip is read |
| `Recorded(Diagnosis)` | the figures are present |

`Diagnosis` is `{ figures, balance_moved, balance_now, expiry }`, where `balance_moved` is `entry.balance != figures.reserved_balance`.

| `Expiry` | when |
| --- | --- |
| `NoExpiry` | `blk_to_live == 0`; no tip is read |
| `Reached { tip }` | the tip was read and `tip >= blk_to_live` |
| `Below { tip }` | the tip was read and `tip < blk_to_live` |
| `Unreadable { cause }` | `blk_to_live != 0` and `/network/status` could not be read |

`Diagnosis::is_dead()` is `balance_moved || matches!(expiry, Expiry::Reached { .. })`. An unreadable tip is neither dead nor asserted live: it is reported as unchecked. A dead reservation is still an `Ok` status — the wallet opens on it — and the diagnosis is what the pages render: the reserved balance against the balance now, the block-to-live against the tip, and, when dead, that the only other way the balance at that key can move is a second, different signature under it.

The tip is read only when a reservation is open, the chain still holds the spent key, the figures are recorded, and the block-to-live is non-zero. No other account costs a second chain call.

#### Settling

`Wallet::settle_if_landed(tag, access)` re-reconciles and then:

| status | result |
| --- | --- |
| `SpendLanded` | calls `persist_settled`, returns `Settlement::Settled { spent_index, index }` |
| `SpendOutstanding` | returns `Settlement::StillOutstanding { spent_index, reservation }`, carrying the diagnosis |
| `InSync` | returns `Settlement::NothingPending { index }` |
| any divergence | returns `Error::ReconciliationRefused { what }` |

Settling takes one observation and no confirmation depth. Settling too early costs one skipped key and creates no reuse; settling too late freezes the account, because no further advance is permitted while a reservation is open.

#### The reverted-settle report

`IndexMismatch::reverted_settle` is `Some(block)` when, and only when, `found` is `ChainPosition::Behind { index }` and the record's retained settled block has `spent_index == index`. It is `None` for an `Ahead`, an `Unlocated`, a `Behind` at any other position, and a record with no retained block.

The `Behind` report then adds, to the causes it already names, that this store recorded a settle at that position and this node's answer does not show it, that two things produce that — a reorg that reverted the settling block, or a settle taken against a node that does not share this chain or had not seen it — and that it cannot tell them apart. It prints the settled position, the digest, and either both figures or that they were not recorded. It states both halves of what is true of the bytes: a copy of the artifact held outside the store can still be re-submitted while the source balance has not moved and a non-zero block-to-live has not passed, and this build has no command that turns the retained block back into those bytes, because both re-signers read the open reservation and this state leaves it clear.

#### Advancing past a divergence

`Divergence::advance_target()` is `Some(index)` only for an `IndexMismatch` whose `found` is `Ahead`, and it is the found position itself, not one past it. `OperatorAcknowledgement::of(&divergence)` is the only constructor and returns `None` for every divergence advancing is not a remedy for.

`advance_after_operator_review(store, client, tag, access, ack, scope)` refuses `AcknowledgementDoesNotMatch` when the acknowledgement's tag is not the tag, re-reconciles under the same scope, refuses `NothingToReconcile` when the account now reconciles, refuses `AcknowledgementDoesNotMatch` when the live divergence's target is not the acknowledged one, and otherwise calls `persist_advance_to`. The store's own refusal of a target not strictly ahead stands behind all of it.

#### The wallet gate

`Wallet::open(store, client, master)` is the only constructor. It reconciles every account in the store, collects every failure rather than stopping at the first, and **partitions**: the wallet it returns carries the accounts the chain confirmed with their status, and the accounts it could not explain with their `Divergence`. Every operation on an account in the second set is refused by name and renders that account's whole report. `StartupRefusal { diverged: Vec<Divergence>, accounts: usize }` is returned when **no** account reconciled, which is a store offering no action at all; a store holding no accounts opens. A derived account needs the master seed and an imported account needs nothing beyond its stored root; a derived account with no master is a refusal, not a skip. A wallet that exists is a wallet with at least one reconciled account, and every account it will act on is one of them — the diverged half travels with it, refused by name and printed on every page.

A never-funded account is refused: the node's code 4 cannot separate never funded from emptied, from a failed lookup, from the wrong chain, and from the wrong seed, so nothing acts on it. Sibling accounts are unaffected, and a store whose only account is in this state does not open. Those five are readings an operator has to rule out, not five answers the endpoint has: it has the three states [The emptied-account window](#the-emptied-account-window) enumerates, and never funded, the wrong chain and the wrong seed are three ways into the first of them.

---

## The Mesh API client and the command-line wallet

### What the client talks to

The wallet reaches a chain through one abstraction: a transport with a single operation, `post(path, body) -> bytes`. Everything above it — request construction, response parsing, the spend layout — is pure and testable without a socket. The shipped transport is HTTP/HTTPS over `ureq` against a base URL.

`MeshClient` has eight operations: four the wallet needs in order to spend, and four read-only ones the explorer verbs use. There is no server-assisted construction path: the wallet never calls `/construction/preprocess`, `/construction/metadata`, `/construction/payloads` or `/construction/combine`, and no code path can reach them — the six endpoint strings in the table below are the only ones in the crate. (The corpus records a different, third-party client that delegates construction through all five construction endpoints and submits the bytes the server returned from `combine`, byte for byte, with its own signature nowhere in them. Nothing in this crate does that.)

| operation | endpoint | request body (keys sorted, compact) | what is read from the reply |
| --- | --- | --- | --- |
| `network_status` | `POST /network/status` | `{"network_identifier":{"blockchain":"mochimo","network":"mainnet"}}` | `current_block_identifier.index` (u64) and `.hash` (`0x` + 64 hex) |
| `resolve_tag` | `POST /call` | `{"method":"tag_resolve","network_identifier":{…},"parameters":{"tag":"0x<40 hex>"}}` | `result.address` (`0x` + 80 hex, the 40-byte ledger address) and `result.amount` (JSON **number**, nanoMochimo) |
| `balance` | `POST /account/balance` | `{"account_identifier":{"address":"0x<40 hex>"},"network_identifier":{…}}` | `block_identifier.index`/`.hash`, and `balances[0].value` (decimal **string**) with `balances[0].currency` checked to be `MCM`/`9` |
| `submit` | `POST /construction/submit` | `{"network_identifier":{…},"signed_transaction":"<bare lowercase hex of the whole wire image, trailer included>"}` | `transaction_identifier.hash` (**bare** hex, no `0x`) |
| `block_by_index`, `block_by_hash` | `POST /block` | `{"block_identifier":{"index":N}}` or `{"block_identifier":{"hash":"0x<64 hex>"}}`, with the network identifier | `block.block_identifier`, `.parent_block_identifier`, `.timestamp` (ms), and every `transactions[]` with its `operations[]` |
| `search_by_hash` | `POST /search/transactions` | `{"network_identifier":{…},"transaction_identifier":{"hash":"0x<64 hex>"}}` | `transactions[]` each with `block_identifier`, `timestamp`, `operations[]` and `metadata`; `total_count`; `next_offset` when present |
| `search_by_account` | `POST /search/transactions` | `{"account_identifier":{"address":"0x<40 hex>"},"limit":N,"network_identifier":{…}}` | the same page |

**`/block` and `/search/transactions` render the same transaction two ways, and the wallet keeps both.** `/block` re-parses the wire on every request: the source is debited its **net** amount — what it sent plus the fee — and the change is not an operation at all. `/search/transactions` replays rows the indexer wrote when the block was first seen: the source is debited its **gross** balance and the change comes back as its own `DESTINATION_TRANSFER`. For the one transaction the corpus captured through both, that is `-10,000,500` against `-50,000,000`, and the difference is exactly the `39,999,500` change. The four `metadata` values differ in JSON type by the same split — decimal strings from `/block`, numbers from `/search` — because both handlers put them in an untyped `map[string]interface{}` and the Go expression's type leaks into the JSON. (`amount.value` is a decimal string on both.) They disagree about the **timestamp** as well: for one transaction observed live on 2026-09-15 they were four seconds apart — `/block` reports the block's own timestamp and `/search/transactions` the moment the indexer wrote the row. Nothing in the crate compares the two, and neither is wrong. Both renderings are correct. No parser reconciles them: `MeshTransaction::metadata` keeps each value in the spelling its endpoint used, and every page names the endpoint it read.

`/search/transactions` is served only where the deployment enabled its indexer, which is not the default; where it did not, the handler answers an internal error rather than an empty page. Its rows come back newest first, so no `offset` is sent, and it takes a `limit` only inside `1..=100` — outside that window it silently uses its own default of ten, which is why the command line refuses a count it would ignore. A `/block` request carrying index 0 is served as the **current** block, not as genesis, which is why the command line refuses `block 0`.

Two further endpoints, `POST /network/list` and `POST /network/options`, have codec functions with no client method above them. `parse_network_options` caps each of the three version strings at 64 bytes and the advertised error table at 64 entries before copying anything.

Every request carries the same `network_identifier`, `{"blockchain":"mochimo","network":"mainnet"}` — including `/network/list`, which the middleware does not require it on. Bodies are serialised compactly with sorted keys, so a request body is byte-identical to `json.dumps(obj, sort_keys=True, separators=(',',':'))` over the same object; the live-capture group asserts that what the codec builds is byte-equal to the request body the capture actually sent, and the reply recorded beside it is the one that server returned.

Seven of the eight operations are reachable from a command. `resolve_tag` supplies every balance and every ledger address the wallet uses. `network_status` is read in two places: diagnosing an open reservation whose recorded block-to-live is non-zero, and finding the tip for `blocks`. The four explorer reads are reached from the four read-only verbs and from nothing else. `submit` is reached from `send` and `resign`, and, over bytes the operator already holds, from the `submit` verb through `submit_wire` -- the same endpoint, the same body, the same reply check. **`/account/balance` has no caller anywhere in the wallet** — it exists on the client, and only the fixture replay and a hand-run probe exercise it.

### What a reply is allowed to be

The middleware answers its own failures with **HTTP 200** carrying `{"code":N,"message":"…","retriable":bool}`. Every parser therefore inspects for that shape first and turns it into a Mesh error carrying the code and the retriable flag. In the live capture every single recorded response — success and failure alike — is HTTP 200. The codes the server advertises:

| code | message | retriable |
| --- | --- | --- |
| 1 | Invalid request | false |
| 2 | Internal general error | true |
| 3 | Transaction not found | true |
| 4 | Account not found | true |
| 5 | Wrong network identifier | false |
| 6 | Block not found | true |
| 7 | Wrong curve type | false |
| 8 | Invalid account format | false |

The middleware declares a ninth code, *Service unavailable*, that this table omits; it is returned only by endpoints this wallet never calls.

Parsing is hand-written field by field, never by deserialising into a struct. Presence, JSON type, width and range are checked before a Rust value exists; anything off the documented shape is an error naming the field, never the bytes. Amounts spelled as strings must be 1 to 20 ASCII digits (a leading `+` is refused, where `str::parse` would accept it). `result.address` from `/call` **must begin with the tag that was asked for**, or the reply is refused as answering a different question. `submit` refuses any reply whose hash is not the id of the bytes just sent.

Every parser is total over the recorded response bodies and over their truncations and byte flips: a malformed reply is an error, never a panic.

### Transport limits

| property | value |
| --- | --- |
| request body cap | 30,720 bytes (30 KiB), the middleware's own; refused before any socket opens |
| response body cap | per endpoint: 262,144 bytes (256 KiB) for `/block` and `/search/transactions`, 8,192 bytes (8 KiB) for every other path; a longer body is refused, not truncated |
| connect timeout | 10 seconds, the shipped constructor's default |
| whole-request timeout | 30 seconds, the shipped constructor's default |
| redirects | **off** — maximum 0; a 3xx is never followed |
| headers this client sets | `Content-Type: application/json`, `Accept: application/json`, `User-Agent: mochimo-crypto/<crate version>` — the crate name and version, both read from the package |
| non-200 status | reported as an HTTP-status error **with the body unread** |

The base URL must be `http://host[:port]` or `https://host[:port]` and nothing else: no path, query, fragment, userinfo or space. One trailing slash is stripped. `https://` requires the `mesh-https` transport feature and is refused at construction, not at the first request, when that feature is off. A body of 30,721 bytes is refused without opening a connection.

Failures are classified without their messages: resolve, connect, timeout, TLS, protocol, redirect, an I/O kind, or other.

### Building a spend

The wallet builds the transaction locally from its own keystore addresses, the caller's destinations and one chain observation. No byte of what is signed comes from a server except the balance.

```
a    = wallet.spend_addresses(tag, access)   source = key at position i, change = key at position i+1
e    = client.resolve_tag(tag)               e.address must equal a.source
plan = SpendPlan::new(a, e, dsts, fee, btl)  every refusal below, before any key is reserved
r    = store.persist_advance(tag, plan.digest(), plan.figures())    the reservation commit
sig  = store.sign_spend(plan.digest(), r, access)
tx   = SignedTransaction::attach(plan, sig)  recovery-checked, re-validated, sealed
id   = client.submit(tx)                     a socket write, not a verdict
```

`spend_addresses` comes first, so an account that already has an unresolved reservation is refused before anything is asked of the chain.

`SpendPlan::new` applies the refusals listed in [Transactions](#transactions), in that order. Between the first refusal and the second it sorts the destinations by their 44-byte wire image, duplicates kept — the same key the node's sort check uses — so the list the remaining rules see, and the list that goes on the wire, is already in validator order.

The **fee is a total supplied by the caller**, never computed. The floor is 500 nanoMochimo per destination; the command line defaults `--fee` to `500 × N`, which is exactly the floor for the destinations it was given, and so 500 for one. (The middleware's own construction-metadata endpoint, which this wallet never calls, independently advertises a suggested fee of 500.)

The **change is the remainder**, and `send + change + fee == balance` holds by construction against the observed balance — which is exactly the equality the node demands against the ledger. A zero change is legal. The change goes to `chg_addr = tag ‖ hash(public key at position i+1)` — this wallet's own next key, under the same account tag.

The **block-to-live is entirely the caller's**. Nothing in the build path reads the tip to choose it; the command line defaults it to 0. Zero means never expires and is the only value the node does not check. A non-zero value is checked against a two-sided window: the node refuses it if it is below the node's own block number, and refuses it if it is more than 256 blocks past it; once accepted, the transaction expires for every block number greater than the value. The value is a signed field, so it cannot be changed after signing, and it is recorded in the keystore alongside the reservation.

The **bytes that are signed** are the first `116 + 44 × N` bytes of the image — the header and the destination array, everything before the WOTS+ validation block — hashed with SHA-256. That digest is what the reservation records and what the key signs.

| offset | width | field |
| --- | --- | --- |
| 0 | 1 | `options[0]`, data type — always `0x00` |
| 1 | 1 | `options[1]`, signature algorithm — always `0x00` |
| 2 | 1 | `options[2]` = destination count − 1 (zero-based, so 0..=255 means 1..=256) |
| 3 | 1 | `options[3]`, reserved — 0 on everything this wallet emits |
| 4 | 40 | `src_addr`: tag (20) ‖ hash (20) |
| 44 | 40 | `chg_addr`: tag (20) ‖ hash (20) |
| 84 | 8 | `send_total`, little-endian |
| 92 | 8 | `change_total`, little-endian |
| 100 | 8 | `fee_total`, little-endian |
| 108 | 8 | `blk_to_live`, little-endian |
| 116 | 44 × N | destinations: `tag`(20) ‖ `reference`(16) ‖ `amount`(8, little-endian) each |
| 116 + 44N | 2144 | WOTS+ signature |
| … + 2144 | 32 | public seed |
| … + 32 | 32 | hash address (`adrs`), 8 little-endian u32 words |
| 116 + 44N + 2208 | 8 | trailer nonce, little-endian — always 0 as sent |
| … + 8 | 32 | trailer id |

For the one-destination spend the command line builds: the signed prefix is **160 bytes**, the full image is **2,408 bytes**, and the submitted hex is 4,816 characters. At the 256-destination maximum the image is **13,628 bytes**, 27,256 hex characters, which still fits the 30 KiB request cap. The command line always emits a 16-byte all-zero destination reference.

Attaching the signature applies the checks listed in [Transactions](#transactions). The transaction is then sealed: nonce 0 and `id = SHA-256(signed prefix ‖ WOTS+ validation block ‖ nonce)`, which is the id `/construction/submit` echoes.

### What submission establishes

A 200 from `/construction/submit` means the middleware handed the bytes to a set of nodes, wrote them to at least one node's socket, and echoed the id it computed from the bytes it received with the nonce forced to zero. It does not mean accepted, validated, or in a block; the middleware returns on the socket write without reading any reply from a node, and nothing on that path validates the transaction. Whether the spend landed is answered only by observing the chain afterwards, which is what `settle` does.

Every check the wallet runs is offline — layout, the fee floor, the destination rules, the WOTS+ recovery. A transaction that passes all of them can still be rejected by a node for a ledger reason the wallet cannot see: the exact balance tally at validation time, the block-to-live window, the destination-reference grammar, or the node's configured fee. That rejection is silent to this program.

The signed bytes are the **retry artifact**, and the wallet does not store them. They are printed once, by the command that made them. If they are lost while the reservation is open, `resign` reproduces them byte for byte from the store's own reservation; the key position cannot roll back, so that signature is the only way funds at the reserved key can move.

### The emptied-account window

The Mesh answers code 4, *Account not found*, in three states it does not distinguish: the ledger has no entry for the tag; the ledger holds the tag at **zero balance**, which the middleware's quorum discards; or the lookup failed — too few nodes answered, a node between blocks, a timeout. Three is the count of states the endpoint has, not of situations an operator can be in: the first state is what a never-funded tag, a node serving a different chain, and a tag derived from the wrong seed all produce alike, which is why [The wallet gate](#the-wallet-gate) names five readings over these three, and why the program's own report, having listed the three, ends by telling the operator to check the node and the seed. An account that has been spent to zero is therefore indistinguishable, through this endpoint, from one that never existed and from a transient failure.

`send <tag> <to> all` walks into this window deliberately, and its page says so before the artifact: the change is zero, the tag will read as not found once the spend lands, and `submit` is the route to the socket meanwhile. The same page is printed for any spend whose change is zero, since an operator who typed `balance − fee` by hand reaches the same state.

The wallet never picks a reading. It fails closed:

- `Wallet::open` reconciles every account and refuses **that account** on an unresolved tag, so `send`, `settle` and `resign` naming it exit 3 with a report that names all three readings and prefers none. `balance` reports the accounts that reconciled and lists the ones that did not, with the same report. Every page a started wallet produces carries every diverged account's report, whatever the command was. When *no* account reconciled there is nothing to operate and the wallet exits 2.
- `status` reports the same condition without refusing and exits 0.
- `restore` refuses and exits 3, and does **not** fall back to position 0.
- `submit` opens no store and sits behind no gate: an artifact already signed for the account can still reach the socket.

The consequence is a present-tense limit: **an account with a zero balance cannot be reconciled through this endpoint, and every operation on it is refused until it is paid again.**

The ledger has not lost it. The entry survives at the change address and keeps being rehashed, so a tag that is paid reappears at exactly the address the store derived for it — the change key of the spend that emptied it — and `settle` then resolves the reservation normally. What is missing is visibility, not state.

Nothing local recovers it, and that is measured rather than assumed. Querying `/account/balance` at the full 40-byte address does not get around the quorum's zero-discard: the same reconstruction against the same endpoint serves a non-zero balance and answers code 4 for a zero one. **So the recovery is an incoming payment, and where it comes from is the limit that remains.** Another account in the same store can pay it, which is why the refusal is per account and not per store. If the emptied account is the *only* account in the store, the wallet has nothing operable, does not start, and the payment has to come from outside it — another wallet, an exchange, any sender. No change to this program can remove that. `create` and `address` are outside that gate, as are `status`, `reconcile` and `restore` — which is why the fund-me address is obtainable before the account has ever been paid.

### The command line

`mcm-wallet --dir <DIR> [--node <URL>] [--allow-plaintext-node] <command>`

Arguments are parsed by hand. Flags take their value as a separate token — `--flag value`; `--flag=value` is not accepted. `help` as the command, or `-h`/`--help` before it, prints the help and exits 0; after the command any of the three is an unexpected token and a usage error like every other. `--dir` is always required. Any unrecognised `--flag` before the verb, any unrecognised or surplus token in a command's tail, and any flag given twice, global or tail, is a usage error rather than a silently ignored argument.

`--node` is required for exactly the thirteen commands that ask a node anything. `create` and `address` run without one.

A plaintext `--node` that is not on the loopback interface is refused at parse time, exit 1, unless `--allow-plaintext-node` is also given. `https://` is accepted with no flag, and so is `http://` to any address in `127.0.0.0/8`, to `::1`, or to the literal name `localhost`. The name is exempt on weaker grounds than the two literals — what it resolves to comes from the host's own configuration rather than from the argv — and is exempt anyway because it is how a local node is almost always spelled, and a gate that fires on the common local case trains an operator to pass the flag by habit. The refusal names what the link decides rather than the scheme: the balance a spend is laid out against, the ledger address reconciliation compares against, the chain tip a block-to-live is judged against, and the key position that says whether a key has signed. A rewritten balance does not move funds, because the node checks `send + change + fee` against the ledger; a rewritten reconciliation report is what `reconcile --advance-to` acts on. The gate is in the command line and not in the transport, which a library caller drives directly. A `--node` URL the program cannot use is validated and refused **before any password prompt and before any store or directory is touched**, for all fifteen verbs alike — including the two that never dial and the five that open no store.

| verb | argv | node | reads | writes | prints |
| --- | --- | --- | --- | --- | --- |
| `create` | `create [--from-phrase]` | no | nothing | the store directory, snapshot and lock | the destination, and the 24-word phrase once on the terminal |
| `address` | `address [<tag> \| --account <N>]` | no | store records; with a tag, derives one address; with `--account N`, derives account N from the master and stores nothing | — | with a tag: the destination on line 1, then the 40-byte ledger address as 80 hex and the position. With none: a count header, then one line per account — destination, position, `derived`/`imported`. With `--account N`: the destination on line 1, the position-0 ledger address, and that the account is not stored and `restore --account N` adds it once funded |
| `balance` | `balance` | yes | store + chain (one `/call` per account, plus one `/network/status` per account whose open reservation records a non-zero block-to-live) | — | per account: destination, balance right-aligned in a 20-wide column, position, state; reservation figures indented under an outstanding spend |
| `status` | `status <tag> [--scan-to <M>]` | yes | store + chain | nothing, ever | destination, balance, position, state; plus the ledger address when in sync, or the reservation figures, or a full divergence report |
| `send` | `send <tag> <to> <amount> [<to> <amount> …] [--fee N] [--btl N] [--ref TEXT]`, or `send <tag> --destinations <path> [--fee N] [--btl N]` | yes | store + chain | the reservation commit, before signing | the send total and the destination count, then every destination with its amount and its reference when it has one, then source, fee beside the floor it clears, change, block-to-live; then the full artifact hex; then the submission result |
| `settle` | `settle <tag>` | yes | store + chain | clears the open reservation when the chain shows the change key | settled with old and new position, or not-settled with the reservation's diagnosis, or nothing-pending |
| `resign` | `resign <tag> <to> <amount> [<to> <amount> …] [--fee N] [--btl N] [--ref TEXT]`, or `resign <tag> --destinations <path> [--fee N] [--btl N]` | yes | store + chain | nothing | the destination count and every destination, the block-to-live, the reproduced artifact, then the submission result |
| `submit` | `submit <artifact-hex>` | yes | nothing: no store is opened and no password asked; `--dir` is parsed as for every verb and not touched | nothing | the byte count and the source destination read from the artifact's own header, then the same `submitted:` block `send` prints; or, before any socket is opened, a refusal naming what the artifact is not — hex, a transaction, a whole image (it must parse and re-serialize byte for byte; layout only, nothing else is judged) |
| `reconcile` | `reconcile <tag> --advance-to <N>` | yes | store + chain, every account | the advance, only on an exact match | the whole store's divergence report first on every path that reconciled, success included, then the outcome |
| `restore` | `restore --account <N> [--scan-to <M>]` | yes | chain, scanning derived addresses | one `add` and its commit, only when the store does not already hold the tag | the restored account's destination, position, ledger address and balance |
| `discover` | `discover [--to <N>]` | yes | store records and the master seed; one `/call` per account index `0..=N` | nothing, ever | the extent searched and how many indices the node resolved, then one row per index the node resolved or this store holds — index, destination, balance, and a held marker — then the indices the node did not resolve, named as that and never as accounts that do not exist |
| `transaction` | `transaction <hash>` | yes | nothing: no store is opened and no password asked; `--dir` is parsed and not touched | nothing | the block it sits in, the timestamp, every operation in order with its type, address, amount in nanoMCM and MCM and memo, then the metadata in the endpoint's own spelling, then one line naming `/search/transactions` and its gross convention |
| `recent-transactions` | `recent-transactions <tag> [--count <N>]` | yes | nothing, as above | nothing | one row per transaction, newest first: block index, hash, direction as the tag sees it (`in`/`out`/`both`), the amount that touched the tag, and the memo. A tag the index has never seen is an empty table and exit 0 |
| `block` | `block <number \| hash>` | yes | nothing, as above | nothing | index, hash, parent, timestamp, the reward and who received it, the spend count, the total delivered to payees, the fee total, then one row per spend; then one line naming `/block` and its net convention |
| `blocks` | `blocks [--count <N>]` | yes | nothing, as above | nothing | the tip from `/network/status`, then one row per block below it: index, hash, timestamp, transaction count |

`resign` takes the **whole spend again** — every destination, every amount, the fee, the block-to-live and every reference. It rebuilds the reserved plan and compares digests; anything else is refused as a different transaction, and nothing is signed. A reservation the chain has already moved past is refused before that comparison, as a landed spend rather than as a divergence, and the page names `settle` — see [The three states](#the-three-states). The **order** is not part of it: the plan builder sorts the destinations by their 44-byte image before laying anything out, so a list retyped in another order sorts to the same list and reproduces the same bytes. The reserved record holds the digest and the two figures, not the destinations, so `resign` cannot list what was reserved — the operator's own record of the spend is the only copy. What it produces is byte-identical to what the original signing produced, because the reserved key signs the reserved digest and the signature scheme is deterministic. Since it submits what it reproduces, recovery from a lost artifact completes without any hand-built request.

An amount is always in nanoMochimo, of which one MCM is 1,000,000,000 — the reference's own conversion constant at the corpus's pinned commit, `tene9 = 1000000000`, commented "Satoshi per Chi" (`src/bin/wallet.c:1488`), and the same figure its fee line prints, `MFEE` 500 rendered as `0.000000500` Chi (`:1840`). `--fee` defaults to `500 × N` for the N destinations given — the node's own floor, and so 500 for one — and `--btl` to 0; `--ref` defaults to sixteen zero bytes and takes up to sixteen characters the node's reference rule accepts, refused as a usage error before any prompt otherwise, and is accepted only with a single destination. `--scan-to` and `--advance-to` walk key positions 0 through the number given, at one key derivation per position, and refuse `u32::MAX`; without them the scan walks 0 through 9,999, and the divergence diagnostic additionally walks 20 positions either side of the local position. A search that finds the account stops there and pays for nothing beyond it; only a search that finds nothing pays for the whole ceiling, about sixteen seconds.

**Destinations.** A `<tag>` or `<to>` argument is accepted in the two forms described in [Addresses and tags](#addresses-and-tags): Base58 over the tag and its CRC-16, or `0x` followed by exactly 40 hex characters, with the input trimmed first.

**The all-zero tag is refused in both forms.** Its CRC-16 is zero, so the checksum that catches every other mistyped destination cannot catch this one; it is what an uninitialised or truncated buffer produces, the chain credits it, and nothing can ever spend it.

Where the program is *answering* the question "where do funds go", it prints Base58. Where it is *echoing back* something the operator typed that it does not recognise — an unknown tag — it prints hex, so an unpayable string never appears in the shape that means payable.

### Exit codes

| code | name | meaning |
| --- | --- | --- |
| 0 | Ok | the command did what it says |
| 1 | Usage | argv did not parse, including a missing `--node` on a command that needs one |
| 2 | StartupRefused | nothing ran: an unusable `--node`, no terminal, no entropy source, the store would not open, or reconciliation explained **no** account in it, which leaves the wallet nothing to operate. A divergence on its own is not this code: the account is refused with 3 and its siblings run |
| 3 | Refused | the command was refused — every refusal from the eleven verbs that open no wallet at all (`create`, `address`, `discover`, `status`, `reconcile`, `restore`, `submit`, and the four read-only verbs `transaction`, `recent-transactions`, `block`, `blocks`), and every refusal from a command that did open one: an operation on an account the partition could not explain, a digest mismatch on `resign`, a `resign` whose reservation the chain has already moved past, and a socket write that failed |

The four codes are 0, 1, 2, 3 and no refusal is 0. The report goes to **stdout on code 0 and to stderr on every non-zero code**, routed by the code alone. This matters on one path: when `send` reserves a key, signs, and the socket write then fails, the exit code is 3 and the whole page — the retry artifact included — is on stderr, with stdout empty. A `send` whose write is refused leaves the reservation open and says on the page that the artifact printed is the only copy; a `resign` whose write is refused says the store is unchanged, that whether the bytes reached a node is not knowable there, and that `settle` answers it once the chain has moved.

### The password prompt and the terminal

Five commands prompt for no password because they open no store: `submit`, and the four read-only verbs `transaction`, `recent-transactions`, `block` and `blocks`, whose whole input is the node. `create` asks for one but has no store to open yet. Every other command prompts `password: ` once. The store is encrypted, so nothing in it — not even the account list — can be read without it, and there is no read-only or scriptable mode for a command that does open it.

**The prompt is read from `/dev/tty`, not stdin**, opened read-write, with terminal echo turned off by a guard that is acquired before anything is read and restored on drop. If echo cannot be turned off, the read is refused *before* the prompt is printed and nothing is read. If `/dev/tty` cannot be opened the command refuses and says so: **the program cannot be driven from a pipe, a cron job or a harness without a controlling terminal.** Each such invocation also draws 32 bytes from `/dev/urandom` as a per-open nonce seed; `create` instead draws three separate values — phrase entropy, the KDF salt and a nonce seed.

`create` acquires the terminal before anything else it does, and writes its prompts and the phrase to that terminal rather than to stdout or stderr — so no shell redirection can separate a phrase from the question about it. Its order is:

1. acquire the terminal, echo off — nothing below runs without somewhere to confirm;
2. refuse a directory that already holds a store snapshot;
3. read a new password twice, echo off, and require the two to match;
4. `--from-phrase`: read an existing phrase (the prompt says 12 or 24 words; 12, 15, 18, 21 and 24 are all accepted) and go straight to the write. Otherwise: draw 32 bytes of entropy, generate a 24-word phrase and display it once;
5. on the generate path only, ask for words **1, 12 and 24** back, **with echo on**, case-insensitively, as a single space-separated line;
6. only then write the store and derive account 0.

A password shorter than **12 characters** (Unicode scalar values, not bytes) is refused — a length floor only, with no rule about digits or symbols. No refusal before step 6 leaves a store behind, and every one of them ends "Nothing was created." — the occupied-directory refusal after saying that nothing was shown and nothing was changed, and a refusal that comes from the terminal itself or from the entropy source after its own words.

### The lock

A store directory holds `accounts.mks` (the snapshot, written through a temporary file beside it) and `keystore.lock`, whose semantics are in [The keystore file](#the-keystore-file-format-version-4). A second process attempting to open the same store while another holds it is refused with a message naming the lock.

---

## Invariants

The crate holds eight numbered invariants. Each exists because violating it destroys funds or destroys the security of a key, and each is held by a named mechanism: a type whose shape makes the violation unrepresentable, a gate that must be passed, or a scan over the crate's own source that runs as part of the test suite.

| # | property | what holds it |
| --- | --- | --- |
| I1 | a WOTS+ secret key signs at most once, per keystore | the raw signer is crate-private; two public routes to a signature, one gated by a receipt consumed by value, one with no digest to pass |
| I2 | the advanced position is durable before a signature is released | a witness token, produced only by a completed four-step commit, required to mint the receipt the signer consumes |
| I3 | spend-related state advances atomically | one image write per transition, through a sealed four-step typestate |
| I4 | every account reconciles before that account acts | the wallet's only constructor reconciles every account, refuses every operation on the ones it cannot explain, and refuses outright a store in which none reconciled |
| I5 | restore derives the position from the chain, never from zero | a target-directed scan that stops on the match, with no fallback outcome |
| I6 | key material does not leave the process in readable form | zeroizing storage, hand-written redacting `Debug`, an AEAD at rest |
| I7 | no self-referential transaction struct is ever a Rust value | the transaction is plain Rust with a serializer at the boundary; the C layout is a wire format only |
| I8 | an imported account keeps a path back to its key material | an account model in which "seed present, position absent" is representable |

---

### I1 — a WOTS+ secret key signs at most once, per keystore

Winternitz one-time signatures leak secret key material with each use, and two signatures under one key make forgery tractable. The raw signing function is not reachable from outside the crate: `wots::sign` and the `wots::internals` module are crate-private, and the whole `backend` module is public only under the `raw-backend` feature, which the default feature set does not contain. Exactly two public functions return a spend signature, and their gates are described in [Reservation, signing and reconciliation](#reservation-signing-and-reconciliation): `Keystore::sign_spend`, which consumes an `AdvanceReceipt` by value and takes no tag, because the account is the receipt's — so a receipt for one account used to sign for another is unrepresentable rather than refused — and `Keystore::resign_reserved`, which takes neither a receipt nor a digest. An error from `sign_spend` still consumes the receipt, so a refused spend skips the key rather than reusing it; a separate check function runs the same checks on a borrowed receipt, so a wrong passphrase costs nothing.

Key-stream aliasing is closed within a store. Every record carries a 20-byte key-stream identity: the address tag of the key at rotation 0, which is a pure function of the account seed and therefore the same value whether the account was derived or imported. Adding an account recomputes the incoming account's identity from its own key material rather than reading it off a record — from the root for an imported account, and for a derived one from the master seed the store holds — refuses a derived record whose stored tag or identity is not what its seed produces, and refuses a duplicate across kinds in either insertion order. A store holding no master cannot recompute a derived account's identity and cannot sign for the account either; there the value the account carries is the one compared, and `sign_spend` re-derives it from the master seed and refuses a disagreement the day one is in hand — for every derived record, including one added before the store held its master. The same path refuses an imported root already stored, compared in constant time.

**Mechanism.** A source scan classifies every wallet-visible function that produces a signature-bearing value or reaches the signer. Exactly one may be a plain signer. A re-signer must take no 32-byte array parameter and its body must read the reservation; a composer must call the gated signer and must not name a raw signer port; an entry point must reach the signer only through a reconciled wallet and must name neither public signing route directly; a reader must take no key material and reach no signer. A function fitting none of these classes fails the scan, so a new route fails it without anyone having guessed its name, and an allow-list row matching nothing fails too. Beside it, a compile-fail partition pins the signer and its internals unnameable and the receipt consumed and un-`Clone`, and a real compile of a dependent crate built without `raw-backend` confirms both spellings of the raw signer are refused while the legitimate path builds.

**Bound.** One keystore. Two stores over one seed — a copied directory, a seed re-derived into a fresh store after it has spent — each sign position *k* once, and nothing in this invariant sees it; that is I4's and I5's subject. In-crate code and the crate's own test targets can still call the raw signer, which they reach through the crate's dev-dependency on itself. What is enforced is that the crate offers no signer outside these two routes.

### I2 — the advanced position is durable before a signature is released

A crash between signing and persisting leaves the on-disk position pointing at a key that has already signed, and nothing about that failure is visible at the time. Only on the success of all four steps of the keystore's commit does it return a durability witness. That witness is a unit struct with a private field, constructed at exactly one site outside the crate's own unit tests, and the advance receipt can only be minted by a crate-private constructor that demands one. So a receipt cannot exist unless the four durable steps ran to completion, and `sign_spend` consumes a receipt — the signature is withheld because the receipt is. Any error inside the commit poisons the handle: the store moves to a poisoned state, no further medium call is made on that path, and the answer is to drop and reopen, never to retry.

**Mechanism.** The witness token, plus a source scan that holds its construction count at exactly one and at the commit function. Items under a test configuration are excluded on purpose — the receipt's own unit tests need a witness, and a test-only mint cannot reach a release build. The behavioural proof drives four interruption points between the first write and the receipt's return, restarts from the on-disk state, and shows the previous position unreachable with no receipt escaped.

**Limit, stated.** The crash model is a kill at a syscall boundary: everything a completed syscall left behind is visible to the reopen. Power loss, an `fsync` that returns success without flushing, and page loss after an I/O error are outside what anything here establishes. There is no oracle for this property and there cannot be one — the reference is a node and persists a ledger, not a key position.

### I3 — spend-related state advances atomically

The account's key position, the store generation, the open reservation and the retained settled block must not be able to disagree with each other. A partial write that advances one but not the others is indistinguishable from corruption, and corruption and a half-completed spend have different correct recoveries. Every transition serialises the whole store into one image and commits it through the same four steps. The steps are a typestate: writing the temp returns a written token, the file fsync consumes it and returns a synced token, the rename consumes that and returns a renamed token, the directory fsync consumes that. The tokens have private fields and cannot be forged, and the medium trait is sealed, so nothing outside the crate can supply the primitives. A reorder is a compile error, not a review finding. Three individually atomic writes would satisfy "never torn" for each member and still let the members disagree between them; that is precisely what this forbids.

**Mechanism.** The typestate and the single-image commit, plus an instrumented medium that records every call with its arguments and can be told to stop after call *k*, modelling a process that died after the syscall completed. The proof interrupts after each of the four steps, reopens from disk, and finds position, generation, reservation and retained block all fully pre-spend or all fully post-spend together, with the sibling account's position and the imported root untouched. Recording arguments is what makes the recorder non-decorative: an fsync on the wrong path keeps every count and every byte assertion passing and is visible only in the recorded sequence, which the uninterrupted control asserts element by element.

**Limit.** The same crash model as I2. Nothing mechanical fixes the membership of "spend-related state": a fifth member added later is covered by this invariant's prose and by no check here.

**On Windows, the power-loss half has no mechanism.** I2 already places power loss outside what anything here establishes; on Unix the directory `fsync` is the mechanism aimed at it, untested against a real power cut. On Windows the fourth step performs no I/O, because Win32 documents no call that commits a directory entry on NTFS, so there is not even a mechanism to leave untested. *How a file is replaced* states the hazard that leaves.

### I4 — every account reconciles before that account acts

When an account's local key position and the chain disagree, that account does not act. The wallet type has one constructor and it reconciles every account against the chain, partitioning them: the accounts the node confirmed, and the accounts it could not explain. Every operation on an account in the second set is refused by name and carries that account's whole report. A store in which *no* account reconciled offers no action at all and is refused outright, which is what the startup refusal is for. The wallet hands out a read-only view of its store and has no mutable counterpart.

**Why the property is per account.** The hazard is key reuse, and a key signs twice or it does not — that is a fact about one key stream, and two accounts share none. Reconciling an account means the node returned *exactly* the address this store derived at its stored position. That is a positive confirmation, not an absence of bad news: a wrong seed does not derive it, a wrong chain does not hold it, and a lying node cannot fabricate a match at an address only the chain can produce. Index confirmed, so the next key is provably unused, so signing it is not reuse. None of the machinery that enforces this — the receipt minted only after the advanced index is durable, the signature released only against that receipt, the refusal to roll a position back — reads another account.

**Why the refusal stops at the account.** An account emptied by a supported command is the case that decides it: the Mesh answers *account not found* for a tag it holds at zero balance, so that account cannot be reconciled, and the way back is a payment into it. A refusal that took the whole store with it would withhold the only wallet that can send that payment, so the condition would have to be resolved from outside a store that is otherwise entirely healthy. Refusing the account and leaving its siblings operable costs nothing the hazard cares about, because nothing that keeps a key from signing twice reads a sibling. The divergence report names four things in every arm: what diverged, both positions (or why there is no second one), the size of the gap, and the action to take. Where a bounded search cannot distinguish causes, the report names every cause that fits what was observed and prefers none.

Advancing is never automatic. The operator acknowledgement is constructible only from a divergence, and only for the one shape advancing is a remedy for — the chain found ahead of the local position — so advancing without having read a report is unrepresentable. The advance path re-runs the comparison at the moment of the write and refuses unless the live divergence names the same tag and the same target; the store then refuses any target not strictly ahead of its stored position on its own account, so backwards is unrepresentable whatever the caller. The diagnostic walks 20 positions either side of the local position first and then the recovery range, so a gap of two is found at position 22 exactly as at position 2. A position the operator names only raises the walk's ceiling; the advance lands only at a position the walk actually matched to the chain, which may be below the one named, and an acknowledgement naming any other position is refused — a number typed at the command line never becomes the answer by being typed.

**Why refuse rather than advance and warn.** Divergence has three causes — a crash between signing and persisting, a restored seed with incomplete history, or two wallet instances live on one seed — with three different correct recoveries, and the divergence alone does not say which occurred. Advancing to match the chain is right for the first and catastrophic for the third, where the other instance is still running and will reuse every key skipped past. WOTS+ key reuse has no repair after the fact.

**Mechanism.** The single reconciling constructor, the acknowledgement type, and the re-check at the write. The proof drives divergence in both directions against a scripted chain and asserts the rendered text of a real run names all four required facts, because failure-path text is invisible to a passing suite. A terminal-driven run of the shipped binary takes the refusal, the refused over-advance, the acknowledged advance and the far-along search end to end against a loopback ledger, including a far-along position the operator names that the walk does not confirm.

**Limit, stated.** Message quality is part of the requirement and no mechanism here reaches it. A refusal that says only "state mismatch" satisfies the letter of this invariant and manufactures the workaround it exists to prevent. The four facts are asserted; whether the wording is good enough for an operator in a panic is not something any check sees.

### I5 — restore derives the position from the chain, never assuming zero

A restored wallet that assumes position zero re-signs with every key the original already used, and it does so at exactly the moment a user is stressed and not reading warnings. Restore resolves the account tag to its current ledger address in one query, then derives the key at position 0, 1, 2 …, hashes each to an address, and stops on the match. The matched position is the position and it is exact. The bound of 10,000 is a ceiling on the failing search only — it never enters the ordinary case — and the caller can set it for one invocation. Three things produce a failed walk and it cannot tell them apart: the account has spent more times than the positions walked, this seed does not own this tag, or the wallet is pointed at another chain; the failure names all three and prefers none. Every other outcome is a failure too, and none is a fallback: an unreachable chain, a tag the ledger does not answer for, a scan that cannot run, a walk that completes with no match, and a store that refuses the account after the chain has named its position are five separate refusals, and nothing is written unless the chain confirmed the position. Zero is returned only when position 0's address is the one the chain holds, which is a match like any other and never a default.

**Why the scan has this shape.** The chain cannot be asked for a tag's usage history. The ledger holds one current entry per tag — the merge compares entries by tag, every equal-tag transaction applies to that one entry, and a new tag's entry is created once — so a query answers *is this the tag's current address* and never *was this address ever used*. Every position except the current one reads as unused, including every position already spent from, so a gap scan's stopping signal — a run of consecutive unused positions — is not a fact this chain produces. What is retrievable in one query is the tag's whole ledger entry, address included, because the balance handler copies the entire entry back on a hit, and that is what makes a target-directed scan available. The 10,000 is not a convention borrowed from anywhere: it is what the shipped browser extension walks over the same key positions, and its users' funds are what a restored phrase has to reach. It is not I4's divergence window, which is 20: the two are separate quantities, and one number serving both would make the difference between them unobservable.

**Mechanism.** A scan scope carrying a ceiling and an optional window, a walk that returns on the first match, and a failure type with no fallback variant. The proof finds each of 20 positions exactly at a ceiling it names, asserts both edges of that bound — the last position inside is found, the first outside is refused with the bound reported — and drives three failing paths that return no position at all. It walks a named ceiling rather than the default because the walk's cost is one key derivation per position and exhausting 10,000 of them takes minutes in a test build and hours for the one-restore-per-position loop; the default's own value, and the sentences a failure at that value prints, are pinned without a walk. **Nothing in the test tree walks ten thousand positions end to end**, which is stated rather than implied: a clamp inside the walk that silently capped a large ceiling would not be caught.

### I6 — key material does not leave the process in readable form

Secrets are held in one type, a fixed-width byte array wrapped in a zeroizing container, so the bytes are overwritten on drop. It has no `Display`, no `AsRef<[u8]>` and no derived `Debug`; its hand-written `Debug` renders `Secret<N>(<redacted>)`, and reading the bytes is a conspicuously named method so it shows up in review. Comparison is absent by design — a derived comparison over key material is variable-time and short-circuits on the first differing byte — and the crate's comparison of key material goes through a crate-private constant-time equality. The store's corruption errors carry an offset and never a byte.

At rest, the store's record body and body header — which together carry every imported root and the master seed — are sealed as described in [The keystore file](#the-keystore-file-format-version-4). What that transfers is stated rather than implied: a stolen store yields nothing without the password and everything with it, so password strength is inside the threat model, and the wallet refuses a password shorter than 12 characters rather than warning about it.

**Mechanism.** Four, each covering what the others cannot. A source scan walks every `.rs` file under the crate sources, treats an item as a holder if any field or variant type mentions a secret or zeroizing type *or* mentions a type already found to be a holder — so wrappers are covered transitively — and rejects a derived `Debug` on any of them; it also asserts at least one direct struct holder exists, so it cannot pass over an empty set, and an allow-list row naming no holder is itself a failure. Per type, unit tests pin the exact rendering of each hand-written `Debug`, which is the half no scan can see. A parsed scan of the secret type's own module rejects any derive or any impl of `PartialEq`, `Eq`, `PartialOrd` or `Ord`, matching the item forms that grant comparison rather than searching for the trait names, so the constant-time trait is not caught by it; two compile-fail cases with pinned compiler output hold the same rule at the compiler, and the scan requires both the cases and the run that compiles them. A drop-witness test reads back the memory a secret occupied after it is dropped, at two widths, which is the only way to observe zeroization surviving optimisation. A separate test asserts the sealed image never contains the imported root.

**Residue, stated.** Every rewrite copies the store into a new inode, and old inodes are ciphertext under the same key, because the salt lives in the header and only the nonce moves with the generation. A recovered old inode is readable by whoever has the password and worthless to whoever does not.

That is the residue on disk. The residue in memory is not covered by anything here: the process's pages are not locked and core dumps are not suppressed, so a secret this invariant overwrites on drop may already have reached swap or a core file. Stated as a limit under [Limits and known-open items](#limits-and-known-open-items), with the reason it is not mitigated.

### I7 — no self-referential transaction struct is ever a Rust value

The node's in-memory transaction is a 13,628-byte buffer, a size field and fifteen pointers into that same buffer, all set at construction; relocating such a struct leaves every pointer aimed at the old address. In C nothing copies one without re-initialising it. In Rust a move is a memcpy and moves are implicit, so a struct of that shape must never exist as a Rust value.

This crate holds no such struct. Its transaction is `tx::wire::Transaction`: ordinary owned fields (header values, a vector of destinations, the WOTS+ validation block, the trailer) and a serializer that lays them out in the wire format described under Transactions and parses them back. Offsets are computed from the destination count at serialization time and stored nowhere. The invariant is satisfied by construction, and the 13,628-byte figure is the maximum wire length of a transaction (256 destinations), not the size of anything the crate keeps in memory.

**Mechanism.** Every group D wire image parses, re-serializes byte for byte, and reports the offsets the vector records (group D; the round trip runs on every replay). Nothing in the crate names a C struct type: the feature that once provided a foreign-function handle, and the handle with it, were stripped from the repository, and no `cfg` attribute under `crates/` names the feature (`documented_counts_match_the_artifacts` holds that absence).

### I8 — an imported account keeps a path back to its key material

There are two kinds of account and only one is derivable. A derived account carries an account index and holds no secret: its seed is a pure function of the master seed at that index, so it can be rebuilt from the recovery phrase alone. An imported account carries no index, and its stored root is the only copy of its key material in existence — it came out of an exported key file, not out of the master seed, and no index reproduces it.

A wallet modelled as "master seed plus index" — the obvious model, and the one every derivation vector describes — restores the phrase, rebuilds the derived accounts, and silently drops the imported ones. The accounts stay exactly as real on chain, funds still addressable at their tag, and the one key that could move them is gone. Nothing errors; the user sees a smaller balance and no diagnostic. The account model therefore distinguishes stored key material from derived, and the persistent record type carries the asymmetry structurally: the derived arm has no root field, so a restore path typed over records can neither fabricate imported key material nor lose it by rebuilding what it can, and the compiler demands the imported arm. An account type that cannot represent "seed present, position absent" fails this by construction.

An imported account's first key needs more than the root. Its public components — a public seed and a hash address — come from the master seed's generator in the wallet the account was exported from, not from the account seed, and the funds an imported account was imported holding sit at that first address. The record therefore carries 64 bytes beside the root: the public seed and the hash-address image, the tail of the 2,208-byte exported address. The import constructor takes the root and the full first address together, refuses a first address the root does not reproduce, and computes the account tag from the verified public key, so an imported account with a forged tag or an unreachable first key is unconstructible rather than refused at signing time. Every rotation from position 1 onward re-derives from the root and never needed this.

**Mechanism.** The enum shape, plus a round trip through the persistent record types that returns the imported root byte-identical to an independent literal, extended through real storage by a create-write-reopen cycle that recovers the root from disk. For the first key, a test refuses a forged pair, round-trips an imported account through a keystore reopen, signs at position 0, recovers the public key from the signature, and asserts it is the stored first public key and that its address is implicit under the account tag.

**No fixture covers the restore path.** The derivation corpus captures derivation, and derivation is exactly what an imported account does not do (group F). The property is that a *non*-derived account survives a restore, and no derivation vector can express it.

---

### Standing properties

These are not numbered and are enforced the same way.

**Secrets are zeroized on drop.** The wallet's own key material lives in one secret type, which wraps a zeroizing array. Two further pieces of derived key material are zeroizing containers of their own rather than that type: the store's Argon2 working memory, and the store key, held for the life of an open. Zeroization is an absence property with no counterpart in the C reference, so it is witnessed by a drop test that reads the memory back rather than by asserting the wrapper is present in the type.

**Secrets are never `Debug`-printed.** No holder of key material derives `Debug`, transitively through wrappers. A secret's rendering is pinned exactly, per type, beside its implementation.

**Secret comparison is constant-time.** The secret type grants no equality and no ordering, derived or hand-written. The crate's one comparison of key material goes through `subtle`'s constant-time equality over the slices, and it has two call sites: refusing an imported root the store already holds, and refusing a derived seed that is also stored as an imported root.

**No native-endian conversion exists anywhere in the crate.** The decision is to normalise rather than to reproduce the reference's host dependence, so the wallet is byte-identical on every host instead of bug-compatible with the machine it was built on. The rule is held by a token-level scan, not a text search: every source file is lexed and every identifier compared against `from_ne_bytes`, `to_ne_bytes` and `target_endian`, the last because a per-host conditional pair reproduces the host dependence without spelling either conversion. Spacing is not representable in a token stream and a name inside a string literal cannot match. A file that fails to lex is a hard failure, never a skipped file; no walked file may lex to zero identifiers; and the floors the scan asserts are on files walked *and* on identifiers examined, never on bytes read. Big-endian byte order survives only where the reference puts it explicitly: the address-word serialisation the WOTS+ hash consumes, written as an explicit decreasing loop with no byte-order conversion named, and the four-byte index encoding the shipped derivation scheme specifies, which is the crate's one big-endian conversion.

*What the scan cannot see, stated:* it matches three identifiers, so it sees a violation only when the violation is spelled with one of them. A `transmute`, byte-order arithmetic written by hand, a cast through a zero-copy crate, a union or a raw pointer, or anything reached through a rename or a type alias passes it. Hand-written byte assembly is how the reference itself does this, so it is the first thing a porter reaches for. A differential against the C cannot close the gap: on a little-endian host the native-endian and little-endian conversions compile to the same instruction, so the two agree for every input.

**The plaintext store image never leaves pure Rust.** The KDF and the AEAD are pure-Rust crates, and nothing in the sealed path reaches the backend seam, which once resolved to a linked C and is now a plain alias of the native module. The one primitive the sealed path does call — the hash that derives the per-commit nonce — is called as the native implementation directly rather than through the backend selector, so that a second backend could not be selected under it by an alias flip alone. This holds by construction rather than by a check: no scan would fail if a future function on the sealed path called through the selector.

**There is exactly one route to Argon2.** Across every `.rs` file under the crates directory, comments stripped, the Argon2 context is constructed once, in the store's crypt module, by the secret-taking constructor, with the algorithm fixed to Argon2id and the version to 0x13. The no-secret constructor is called nowhere, and aliasing the type is forbidden by the same scan, because an alias would let a second construction escape both needles. Key derivation for a store is that one path with an empty secret and no associated data; the published test vector is replayed through the same path with a secret and associated data, which is why the branch between the two constructors was removed rather than covered. A second construction anywhere — a second derivation function, a future open path deriving differently — fails the scan whether or not it computes the same bytes today. Test modules are inside the scan's walk deliberately: a test-only second route is exactly the kind it exists to name.

---

## Limits and known-open items

Everything below is a present-tense property of the wallet as it ships. None of it is scheduled work.

### The platforms are Unix and Windows

This wallet targets Unix and Windows. It is built and tested on **Linux** and **macOS**. **The Windows arms compile and pass clippy for `x86_64-pc-windows-msvc`, and have not run**: no board has been recorded on Windows, and `RELEASE.md` is where one will be. A build for any other target fails at compile time rather than degrading: `lib.rs` names the three interfaces the crate needs and `keystore` names the storage guarantees it rests on.

Three things make it so, and none of them is a convenience:

| interface | Unix | Windows |
| --- | --- | --- |
| the keystore's permission model, a check against another local user | mode bits: the store is created `0600` and its directory `0700`, and both creating and opening a store refuse a directory that is group- or world-writable (`Error::UnsafePermissions`) | access lists: the directory and every file are created under a protected list granting this user alone, and both creating and opening a store refuse a directory anyone but this user, `SYSTEM` or the Administrators group can write to, or that another user owns (`Error::UnsafeAcl`) |
| where the password and the recovery phrase are read, so that neither can be piped or redirected | `/dev/tty`, opened by path; echo turned off by `stty` | the console's own buffers, `CONIN$` and `CONOUT$`, opened by name; echo turned off in the console mode; read and written as UTF-16, so a password is the same bytes on every platform |
| the salt and the nonce seed the binary supplies to the keystore | `/dev/urandom`, read through `std::fs` | `BCryptGenRandom`, the system-preferred generator |

The keystore additionally rests on storage primitives that are not the same on the two, which is why that module carries its own statement: on Unix, POSIX rename atomicity, directory `fsync` and `flock`; on Windows, the replacing move, `LockFileEx`, and no directory flush at all — *How a file is replaced* says what that last one leaves.

The BSDs have all of these. Nothing in this repository builds or tests against them, so they are neither supported nor known to fail.

### A locally valid transaction can still be rejected by a node

The spend builder refuses, offline, everything it can decide on its own:

| condition | refusal |
| --- | --- |
| the ledger's address for the tag is not the key this store would sign with | `ChainAddressMismatch` |
| fewer than 1 or more than 256 destinations | `Range { what: "destination count" }` |
| a destination amount of 0 | `ZeroAmount` |
| a destination tag equal to the source tag | `DestinationIsSource` |
| fee below 500 nanoMochimo per destination | `FeeBelowMinimum` |
| balance below send total plus fee | `InsufficientBalance` |

The node applies three further rules, and the wallet evaluates none of them:

- **Exact balance equality.** The node requires `send_total + change_total + fee_total` to equal the ledger balance exactly at validation time. The wallet computes change as `balance − send − fee` from the balance it read when the plan was built. A credit that lands between that read and validation makes the signed bytes permanently unacceptable: a deposit credits the tag in place without moving the address, so while the spend has not landed the balance can only rise.
- **The block-to-live window.** A non-zero block-to-live must be at least the current block number and at most that number plus 256 at the moment of arrival. The plan builder takes no block number at all, so `--btl` below the tip or more than 256 blocks ahead builds, signs and submits, and is then refused as bad transaction data — a verdict that also pinklists the peer that delivered the frame, which is the middleware's node and not the wallet.
- **One outstanding transaction per source tag.** The node's queue admits one transaction per source tag; a second on the same tag is dropped before validation.

A fourth is the node's source-address lookup, and it runs last: the ledger entry is fetched only after the destination array and the signature have been checked, and a source address the ledger does not hold is refused there. The wallet cannot be in that state when the plan is built — it builds against the entry the node reported — only between the plan and the transaction's arrival.

The fixture corpus records the same boundary. No vector in group D carries a result from the full validator; the wire images record at most the two validators that run without a ledger — the destination-array check and the WOTS+ check — and four vectors state in their own field that the full rule was not evaluated for want of a ledger. The corpus pins layout, encoding and two offline rules. It pins no acceptance.

### Acceptance is inferred, and authorship is recorded nowhere

A successful submit returns a transaction id the middleware computes locally from the bytes it received. The middleware hands the image to several picked nodes at once, each as a single raw frame on its own socket, reads no reply from any of them, and answers success as soon as one of those writes completes — an error only when every one of them fails.

The only acceptance signal the wallet has is the ledger moving, which is what `settle` observes. Until that observation the account cannot spend again.

**No record ties a mined transaction to this wallet.** A block's rendering of a transaction is byte-identical to what it would be had any other wallet built the same spend; the mempool endpoint answers *Transaction not found* once a transaction is mined; and no endpoint echoes a submitted image. The corpus carries this as an open want (group N) whose evidence can only be recorded by the submitting process at the moment it submits — the request body, the reply, and the signed image as it left the builder — because none of the three is retrievable afterwards.

Submitting the same bytes twice is one signature produced twice, not two signatures. The second copy is discarded — by the per-tag queue check while the first is pending, by the ledger lookup once the first has landed — and neither path penalises the sender, because both refusals are errors rather than bad-data verdicts.

### Which submission errors come back

The middleware's own refusals arrive as **HTTP 200** carrying `{code, message, retriable}`. Three are reachable on the submit path:

| code | message | retriable | cause |
| --- | --- | --- | --- |
| 1 | Invalid request | false | the request body does not decode |
| 5 | Wrong network identifier | false | the identifier is not `mochimo` / `mainnet` |
| 2 | Internal general error | true | every write to a node failed |

There is no fourth. The submit handler does not validate the signed transaction before forwarding it, so an image the node will reject submits successfully and disappears silently. A reply that is not a 200 at all is reported as a status rather than as one of these codes.

Code **4, Account not found (retriable)**, is what tag resolution answers, and it conflates the three states [The emptied-account window](#the-emptied-account-window) enumerates — three for the endpoint, five for an operator, since no ledger entry for the tag is what never funded, the wrong chain and the wrong seed all produce. An account spent down to zero therefore cannot be located or reconciled through this endpoint until it is paid again; the funds are not lost, and the tag resolves again after a credit.

Two caps apply before the socket. The request body is refused above 30 KiB, the middleware's own limit enforced locally first. The response cap is the endpoint's, because two of them scale with what they report and the rest do not.

| endpoints | cap | what it holds |
| --- | --- | --- |
| `/block`, `/search/transactions` | 256 KiB | 214 search rows against `--count`'s ceiling of 100, or 256 block transactions, each measured at the widest the captured corpus records — 1,221 bytes for a row and 1,020 for a transaction |
| everything else | 8 KiB | twelve times the widest reply the client asks for (`/network/status`, 664 bytes) and eight times the widest any parser here reads (`/network/options`, 964) |

The split exists because a single number sized from the small endpoints is a bound the command line can walk into: `--count` accepts up to 100, and a hundred rows is about 122,100 bytes. A flag the parser accepts and the transport refuses is a defect on its own, so the two agree — the cap accommodates the range rather than the range shrinking to the cap.

The tight cap stays tight deliberately. It bounds an allocation whose size a remote server chooses, and on the reconciliation endpoints there is nothing for extra room to buy. What the loose cap does not hold is a block whose transactions each pay hundreds of destinations: a transaction renders about 337 bytes per operation, so one with 256 destinations is around 87 KiB and three of them exceed the cap. That block is a named refusal rather than an unbounded allocation, which is the trade a cap is.

A reply that parses but is off the documented shape is reported by field name, never by dumping bytes.

### The second account

There are exactly two routes into the store, and neither adds an account past account index 0 before the chain has seen it; the destination of such an account is printable before that, without storing it, and the chain is askable about a range of them without storing anything either.

- **`create` derives account 0 and nothing else.** The account index is the literal `0` in the command's body; the store it makes holds that one account. `create` refuses a directory that already holds a store, so it cannot be run again to add another.
- **`restore --account N` asks the chain first.** It resolves the tag, walks key positions to find the one whose address the ledger holds, and only then derives the account and writes it — in one commit, at the found key position. If the node does not resolve the tag it refuses; it never places an account at key position 0 as a fallback, and there is no fallback variant in its failure type.
- **There is no third route into the store.** The store's `add` has two call sites in the shipped source, one per command above. There is no `import` verb.
- **`discover [--to N]` asks the chain about a range of them, and stores nothing.** It derives the tags of accounts `0..=N` from the master the store holds, resolves each against the node at one `/call` per index, and prints what the node said for every index together with the extent it searched. `N` defaults to 64 and runs 1 to 1,024 — a ceiling this program sets, because each index is one call and an unbounded `--to` puts thousands of round trips behind a typo. The two ends of that range are refused with two different sentences: zero is told what a sweep bounded at zero could observe, and a value above the ceiling is told that every index is a call and to name a bound at or below 1,024. One sentence for both ends answers the wrong end of the range for whichever operator meets it, and the over-ceiling typo is the one an operator actually makes. A store holding no master is refused before any call. **It never reports an account as absent.** Code 4 conflates three states the endpoint does not distinguish and the first of them has three readings of its own, so the page says *the node did not resolve these indices* and nothing further; an operator who expected an index to appear and does not see it is told to check the node and the seed, not given a verdict. That is why the default of 64 is defensible: not because 64 is the right number of accounts to look for, but because the number searched is on the page and `--to` changes it. Accounts the store already holds are shown and marked, including one the node does not resolve — a report that omits what you have is one you cannot check against your own store. A sweep that resolves nothing is exit 0, a successful observation; a node that cannot be reached is exit 3, and the page then reports **no** extent for the indices it never asked about, because a partial sweep printed as a whole one would assert absence by omission.
- **`address --account N` derives without storing.** From the master the store holds, it computes account N's tag and position-0 address and prints them exactly as `address <tag>` does, says the account is not stored, and writes nothing, reserves nothing and asks no node. A store holding no master (imported accounts only) is refused, and so is an account the store already holds, which `address <tag>` answers for. The route to a second account's destination goes around `Wallet::open`'s refusal on a never-funded account, not through it — the account is funded first and `restore --account N` then adds it at the position the chain holds, 0 for a first credit.

### Key access is chosen per account

`address`, `send`, `settle` and `resign` choose key access per account, as `status`, `reconcile` and the reconciliation the wallet runs when it opens always did: the master seed for a derived account, the stored root for an imported one. A derived account in a store that holds no master is refused with a key-access mismatch; an **imported** account living in a store that also holds a master is signed for by its root. (`tests/spend.rs` holds both directions.) `restore` never asks the question at all — it derives from the master seed and refuses a store that holds none. Through the command line a store holding both kinds is unreachable, because there is no verb that imports an account; it is reachable by a library caller.

### The command-line surface

| limit | behaviour |
| --- | --- |
| destinations | `send` and `resign` take 1 to 256, in either of two exclusive forms: positional `<to> <amount>` pairs, or `--destinations <path>`, a file whose non-empty lines are `<to> <amount> [<ref>]` with `#` starting a comment. `--ref` names one destination's reference and is taken only with a single destination; with several, the file's third column gives one per line. Every reference is validated by the node's rule at parse time, and a field not named is zero. Two destinations sharing a tag are a usage error — the node accepts them, but one tag twice in one spend is almost always a mistyped payee |
| repeated flags | a flag given twice, global or tail, is a usage error naming the flag (exit 1); neither occurrence wins |
| help | recognised where a verb or a global flag is: `help` as the command, `-h`/`--help` before it. After the command all three are unexpected tokens, refused by name (exit 1) |
| end of input | Ctrl-D at a prompt is end-of-file, refused in the prompt's own words before anything is compared: exit 2 at the password prompt (nothing ran), exit 3 inside `create`, which says nothing was created |
| `<amount>` | a whole number of nanoMochimo, or the keyword `all` — the balance less the fee, read from the same ledger observation the plan is built against, so the change is zero. `all` is refused for anything but a single destination |
| `--btl` | a bare unsigned integer, default 0, with no range check and no unit |
| `resign` | needs the whole spend retyped — destination, amount, fee, block-to-live and reference — because the rebuilt plan must reproduce the reserved digest exactly, and what the store holds is that digest and the two figures rather than the destination, the amount, the fee and the reference |
| raw bytes | `submit <artifact-hex>` writes a saved artifact to the socket as it is, checked for layout only: it must parse and re-serialize byte for byte, and nothing else is judged. It opens no store, so it is the route to the socket in the emptied-account window, where `resign` cannot run |
| streams | any non-zero exit writes the whole page to stderr, including a refused `resign` page with the artifact on it; only a successful page goes to stdout |

An unknown global flag and an unexpected argument in a command's tail are both refused.

### What this crate does not do

- **It has no transaction validator.** Layout, the fee floor, destination ordering and amounts, totals, and the WOTS+ recovery check are applied before a spend leaves the wallet, and every one of them is offline; the ledger-side rules -- the balance, the block-to-live window, the source/change relation -- are the node's, and a transaction that passes every local check can still be refused on arrival. The recorded verdicts in group D are the reference validators' answers, carried as specification, and this crate reproduces the layout half of them, not the verdict half.
- **The three diagnostic-string functions panic.** The validation-code name, the errno name and the errno text are the node software's own spellings; a Rust restatement would compare the crate's naming against its own, so they are left unimplemented and nothing on the wallet path calls them.
- **There is no differential check against another implementation at run time.** The fixture corpus is what the crate is checked against: a frozen artifact, produced by executing the reference implementations and replayed here, never regenerated.
- **The shipped binary requires the `mesh-https` transport feature**, which pulls in a TLS stack with its own C (`ring`). Every test target builds without it; the pty tests build the binary as a subprocess.

### The process's memory is not locked, and core dumps are not suppressed

The master seed, the decrypted store body, the password and the expanded WOTS+ private keys live in ordinary pageable memory while they are in use. `Zeroizing` overwrites each on drop, which is what I6 establishes and is the whole of what it establishes: it does nothing about a page the kernel has already written to swap, a core dump taken while the process is live, a hibernation image, or a debugger attached to the running process. I6's *Residue, stated* covers old store inodes on disk; this is the same question about memory, and the answer is that nothing here addresses it.

This is a decision rather than an omission. Locking pages (`mlock`) and disabling core dumps (`setrlimit`) both require `unsafe` through `libc` or a dependency that wraps it, and `invariants.rs::unsafe_is_confined_to_declared_files` asserts an empty allow-list against zero `unsafe` keywords under `src/`. What the mitigations defend against is an attacker who can already read this machine's swap, core files or process memory — who, at that point, can also read the keystore file and wait for the password. The property they would cost is machine-checked and applies to every build; the property they would buy is partial and applies to one class of local attacker. The trade is refused.

An operator who needs it has the platform's own tools: swap encryption, and a core-dump limit set outside this process.

### Two defects in the reference implementation that the corpus works around

| class | what the reference does | what the wallet does |
| --- | --- | --- |
| Base58 decode of an all-`'1'` string | the length probe returns 21 for the 22-character encoding of an all-zero payload — one short — and the decoding call itself computes a copy length of `(size_t)(-1)` and dies | answers the class itself: *n* `'1'` characters decode to *n* zero bytes. The value has no reference behind it and is stated as a requirement (group C), with an independent implementation pinning it (group CX). The probe still reports the reference's own number, because recording that defect is what the probe exists for |
| RIPEMD-160 where `len % 64 >= 56` | the finalisation routine writes part of the length past the end of its 64-byte block buffer and then hashes up to 72 bytes out of it | computes the whole domain with an implementation that is defined on it, anchored over that class by 26 vectors against an independent implementation of the published algorithm (group RX), since the reference cannot be asked for a digest it dies producing |

Both classes are excluded from the differential comparison, because a differential is structurally unable to see a class it skips.

### The block-to-live sits inside the signed digest

`blk_to_live` is the last field of the 116-byte transaction header and the signature is over the header and the destination array, so the block-to-live is inside it: it cannot be adjusted after signing, and reproducing a lost artifact requires the same value.

- **0 never expires**, and a node holding the transaction keeps the tag occupied without bound, since its queue admits one transaction per source tag.
- **Non-zero expires.** The last block that can carry a transaction with block-to-live *N* is block *N*. Once the tip reaches *N* the artifact can never be included, even though a node still accepts the submit at exactly *N* and drops it at its next cleanup.

The store records the value alongside the reserved balance, so a reservation can be classified from the store and the chain alone. A reservation written by an older store format carries neither figure, and is reported as neither live nor dead. A dead reservation has no route out: the whole balance at the reserved key is reachable only by a signature from that key, and the only signature this wallet will ever produce from that key is the one already produced. No command offers a second one, on purpose: a second, different signature under one WOTS+ key is the reuse I1 exists to prevent, and its price would be the whole balance at that key. The page that reports a dead reservation says the same, in the same words.

### Seed derivation is captured, not confirmed

The derivation this wallet implements is the one the shipped browser extension's source performs, and a fixture group pins it end to end (group F). Those vectors are a **specification capture, not a cross-check**: one implementation, no second opinion. A port that reproduces them has proven it matches that source and nothing more. What is not decidable from anything in this repository is whether funds already held were created under that scheme; the five distinct derivations that exist across the vendored sources are tabulated in [Seed derivation and mnemonic](#seed-derivation-and-mnemonic).

### Open items

| item | state |
| --- | --- |
| authorship of a submitted transaction | no capture exists; it can only be recorded by the submitting process at submit time, on a funded account, driven by an operator at a terminal |
| the node's own packet framing | recorded as field offsets and quoted framing lines only (group E). The reference builds, checksums and sends a packet inside one function that needs a socket, so no packet bytes and no rejection verdicts are pinned; confirming them needs a live peer |
| one validation predicate | the opcode-range check is restated rather than called — it is a function-like macro in a file that cannot be linked — and it is the single deliberate exception in the corpus. Its bounds are read from the reference and its whole input domain is enumerated against them |
| release | **closed.** The crate is version `1.0.0`. A release is tagged `v` followed by that version, and `git tag` says which tags the repository holds. The crate is not published to any registry; the binary is built from source with the `mesh-https` transport feature enabled, and the minimum supported Rust version is 1.89. `README.md` and `LICENSE.md` are both at the root, the licence being the Mochimo Cryptocurrency Engine License Agreement, version 1.0, which the workspace declares as `license-file` and the crate inherits. There is no `CHANGELOG`: the wallet is not published and is built from source, so nobody holds a previous release to read a delta against, and what a reader of a release needs — what it does, what it requires, what it refuses and where its limits are — is `README.md` and this document, both of which checks hold to the code. A fourth document restating them would drift from them with nothing to catch it. Every verb has been exercised against a live chain, `restore` included: a mainnet run on 2026-09-15 between blocks 1,086,967 and 1,086,987, in which `restore` reproduced a funded account from the phrase alone and `reconcile` caught a store up after a spend it did not make. One exercise is not coverage — the transaction shapes that run did not have are listed in `mesh`'s module documentation, and the node's own ledger checks sit behind them |

---

## The fixture corpus as the specification

`fixtures/` is the executable specification for this crate. It holds 15 JSON files and the 145 `.bin` sidecars they name, 5,364 vectors in total. Almost every value in it is produced by executing something: the vendored C reference, a published TypeScript package run under `node`, or one live HTTP deployment answering a real request. The exception is six literals transcribed out of upstream test files, three in group C and three in group CX, and each of those sits beside an executed value the harness compares it against. Nothing in the corpus is edited — a value that looks wrong is a finding about the generator, never an occasion to change the value.

The corpus is the boundary a reimplementation has to satisfy, and it is not uniform. The C-derived groups and the executed crosschecks are conformance: replay them and agree field for field and you have reproduced this wallet's cryptography, its address scheme, its transaction wire format, its key derivation and its Mesh codec. Two groups are not conformance at all. One is a capture of a live server's answers; the other is a capture of a shipped client, and reproducing its behaviour is a defect rather than a pass.

### The shape of a vector

Every fixture file is one JSON object with a header and a `vectors` array. Each element of `vectors` is a flat object.

| key | type | presence |
| --- | --- | --- |
| `id` | string | every vector; unique within its file |
| `source` | string | every vector; names the reference function that produced the value |
| `note` | string | every vector; prose, never an input |
| `falsifies` | string | every vector of every C-derived group and of every crosscheck group; absent from the mesh capture, the live capture, and eighteen of the derivation group's vectors |
| everything else | the data | the inputs and the outputs |

`source` is the dispatch key, not `id`. It names one function in one reference implementation. Most spell that as `file:line`; nine name a file with no line, or a package and a version where the function has no file in the tree. Vectors sharing a `source` share a replay handler, not necessarily a shape: three of the transaction group's handlers receive vectors of differing shape and have to span them.

Byte values are lowercase hex, no `0x` prefix, no separators. A value the generator writes through its blob helper obeys a width rule and always carries a length beside it:

- **64 bytes or fewer** — inline, as `"<key>": "<hex>"` plus `"<key>_len": <n>`.
- **more than 64 bytes** — in a sidecar, as `"<key>_file": "<name>.bin"` plus `"<key>_len": <n>`. The `.bin` file sits beside the JSON and holds the raw bytes.

`<key>_len` is written in both of those cases, so a consumer reads the length from the vector and checks it against what it loaded. Most inline hex is not written through that helper and carries no `_len` at all — the value's own width is the length. A `_file` key naming another group's artifact rather than this vector's own carries no length either.

Group D's transaction-hash vectors are the one place where a `_len` key sits beside a value of a different length: `message_hash_len` and `id_hash_len` record the length of the byte range that was hashed, not the length of the 32-byte digest. The byte range itself is carried separately as `message_hash_input`.

Sidecars are shared. One `.bin` file is named by more than one group where the same artifact is the subject of both — the mesh-client capture and the live capture both cite group D's wire images by filename.

Integer arrays (`adrs_in_words`, `lengths`, `checksum_digits`) are inline JSON arrays. Booleans are JSON booleans and are recorded verdicts, not decoration: the generator computes them from reference or capture output, and a replay recomputes them from the same bytes.

### The groups

| id | file | subject | vectors | sources |
| --- | --- | --- | ---: | ---: |
| A | `group_a_keygen.json` | WOTS+ key generation on edge inputs: `wots_pkgen`, `prf`, `thash_f`, `expand_seed`. Whole 2,144-byte public keys and private-key expansions as sidecars. Carries a `constants` block. | 11 | 4 |
| B | `group_b_sign.json` | WOTS+ signing, public-key recovery and `chain_lengths`. Whole 2,144-byte signatures, plus a digit sweep: base-w digit values 1 through 14, each a complete signature under one key. The endpoints are pinned separately — digit 15 by another vector under that same key, digit 0 by one under a different key. | 33 | 3 |
| C | `group_c_addr.json` | Address derivation, Base58 and CRC-16: `addr_hash_generate`, `addr_from_wots`, `addr_from_implicit`, `base58_encode`/`base58_decode`, tag encoding. Also carries a 1,000-entry `crc16_base58_corpus`. | 29 | 10 |
| CX | `group_c_crosscheck.json` | Every vector in group C recomputed by the TypeScript implementation from the same inputs, one for one. | 29 | 8 |
| D | `group_d_tx.json` | Transaction layout offsets, `tx_hash`, `mdst_val`, `tx_val__wots`, and a destination-count sweep at 22 counts. Carries `layout_table`, `txentry_layout` and a fixed `identity`. | 72 | 11 |
| E | `group_e_net.json` | Packet framing constants, the `TX` struct's offsets, `put16`/`get16` round trip and CRC-16. Carries a `gaps` block for what has no callable entry point. | 10 | 3 |
| F | `group_f_derivation.json` | The browser extension's seed derivation: its PRNG, `deriveSeed`, `deriveWotsSeedAndAddress`, account derivation, tag derivation and the BIP39 phrase round trip; a 64-vector rotation sweep at rotations 1 through 20 and at the boundaries either side of selected powers of two up to 65,536, for two accounts; thirteen account-derivation vectors at indices from 0 to 65,536; and six captures of the BIP39 library itself. | 96 | 15 |
| RX | `group_rx_ripemd.json` | RIPEMD-160 at the input lengths the vendored C cannot compute. | 26 | 1 |
| M | `group_m_mesh_client.json` | The shipped mesh client executed under a recording fetch double. | 6 | 6 |
| N | `group_n_mesh_live.json` | Request/response pairs captured from the live Mesh API at one block, for the reads the client makes and the error shapes the middleware returns. Carries a `gaps` block. Three of its vectors are what the explorer verbs replay: `N-submit-block` (`/block` by index), `N-submit-block-transaction` and `N-submit-search`, the last two being the same transaction rendered by the two computations the client keeps apart. Two request shapes the verbs build have **no** vector — a search by account, and a block by hash — and are pinned only by the middleware's Go source at the commit `pin.mochimo_mesh_commit` names. | 22 | 12 |
| AK | `group_ak_keygen_bulk.json` | Bulk key generation: 1,000 `wots_pkgen` keys (public key as a digest, plus the 40-byte v3 address derived from it; half of them under a non-zero `adrs`), and 128 each of `expand_seed`, `prf`, `thash_f` and `gen_chain`. | 1512 | 5 |
| BK | `group_bk_sign_bulk.json` | Bulk signing: 1,000 `(msg, secret, pub_seed, adrs)` tuples with signature and public key as digests, the recovery verdict, and the same recovery over the signature with one recorded bit flipped; plus 128 `chain_lengths`. | 1128 | 2 |
| HS | `group_hs_hash_sweep.json` | The three hash primitives at every input length across two block boundaries: SHA-256 at 0–129 (130 vectors), SHA3-512 at 0–145 (146 vectors), RIPEMD-160 at 0–129 outside the faulting class (114 vectors). | 390 | 3 |
| AKX | `group_akx_keygen_bulk_crosscheck.json` | AK's thousand key-generation inputs recomputed by the TypeScript: the SHA-256 of the resulting public key and the address derived from it. The key's own bytes are not carried. | 1000 | 1 |
| CK | `group_ck_tag_crosscheck.json` | Group C's thousand `(tag, crc16, base58)` triples recomputed by the TypeScript. | 1000 | 1 |

One group carries a population that is not in `vectors` and is replayed by a walk of its own: group C's `crc16_base58_corpus`, 1,000 entries keyed by `i` rather than `id`, each a 20-byte tag with the reference's CRC-16 and Base58 encoding of it.

Group HS omits exactly 16 RIPEMD-160 lengths — every length in 0–129 with `len % 64 >= 56`, which is 56–63 and 120–127 — and lists them in `ripemd160_omitted`. The vendored RIPEMD-160 writes its length field past the end of a one-block stack buffer for those lengths, so the call cannot be made; that includes two of RIPEMD-160's own published test vectors, at 56 and 62 bytes. Group RX carries a second implementation's answers for exactly that class, at 24 synthetic lengths spanning 0–200 — residues 56–63 at three successive block counts — plus the two published vectors. Every length in 0–129 is answered by exactly one of the two files, by neither twice and by neither not at all.

### Artifact policy: whole bytes or a digest

Each file may declare an `artifacts` policy in its header. Absent means `"whole"`, and a third word is a hard failure.

| policy | groups | rule |
| --- | --- | --- |
| `whole` | A, B, C, CX, D, E, F, RX, M, N, HS, AKX, CK | values are carried as bytes — inline hex, or a sidecar over 64 bytes. No vector may carry a key ending `_sha256`. |
| `digest` | AK, BK | every value longer than 64 bytes is recorded as its SHA-256 — computed by the reference over reference output — and never as a sidecar. No vector may carry a key ending `_file`. |

The two policies are exclusive by group, not by vector: a digest group never spills a sidecar and a whole-artifact group never substitutes a digest for bytes. The digest groups exist so that 3,128 artifacts — a thousand public keys and a thousand signatures in one file, a thousand public keys and 128 private-key expansions in the other — fit in two files instead of that many sidecars. Groups A and B carry the whole-artifact vectors for the same functions, so the bytes of a key, of a private-key expansion and of a signature are pinned somewhere.

A digest vector records the artifact as a pair: `<key>_len` (the artifact's true length, 2,144 for a key or a signature) and `<key>_sha256` (32 bytes). A consumer produces the artifact, checks its length, hashes it and compares.

### Oracle classes

A file that is not derived from the vendored C carries a `pin` block naming the commits and package versions it ran against, and an `oracle` block stating what kind of evidence it is. The two are required together: a pin with no oracle declaration, or an oracle declaration with no pin, is a defect.

| `oracle.class` | groups | what it establishes | what it does not |
| --- | --- | --- | --- |
| `specification-capture` | F, M, N | one implementation, executed and recorded. Agreeing with it proves you match that implementation. | nothing about whether that implementation is correct. There is no second opinion, so these vectors carry no error-detecting power. |
| `executed-crosscheck` | CX, AKX, CK | two implementations of one algorithm, sharing no code, computing the same values from the same inputs. They can disagree, so agreement is evidence. | — |
| `executed-crosscheck-no-reference` | RX | two independent implementations of a published algorithm, neither being the other's specification. Error detection, not conformance. | anything about Mochimo. Nothing Mochimo-specific is computed in the group. |

A class that is none of these routes to the specification-capture arm and is reported there, so an invented fourth class is a provenance claim nothing checks rather than a claim nothing notices.

The distinction is load-bearing for group M in particular. It records what the shipped mesh client does — it signs the SHA-256 of whatever unsigned transaction the server returned, it sends a change address as a bare 20-byte hash with no tag, and it builds a 2,304-byte transaction locally and discards it. Agreement between this crate and group M would be a defect, not evidence, and its replay asserts the capture has that shape rather than asserting this crate reproduces it.

The C-derived groups (A, B, C, D, E, AK, BK, HS) carry no `oracle` or `pin` block. Their header instead carries `group`, `pins` (the survey section), `generator`, `rule`, and a `reference` object naming the exact commits of the C the generator linked against.

### `manifest.toml`

One TOML file beside the JSON. A `[corpus]` table and one `[[group]]` table per fixture file:

| field | meaning | editable |
| --- | --- | --- |
| `id` | the group letter | no |
| `file` | the JSON filename | no |
| `name` | the group's subject, in words | no |
| `status` | `active` or `deferred`; every group is `active` | no |
| `vectors` | how many vectors the file holds | no |
| `sources` | how many distinct `source` strings the file holds | no |
| `reason` | prose about the group: what it establishes, what it does not, what the next reader must know | **yes** — this is the designated place for a finding |
| `pending` | array of strings: generator work the group is owed. Printed in every run, asserted by nothing. Not a skip list; every vector still runs | yes |
| `activated`, `still_deferred` | on a `deferred` group only: which vectors replay anyway, and how many do not | no |
| `total_vectors` (in `[corpus]`) | 5364 | no |
| `reference_pin` (in `[corpus]`) | the short SHA of the C the generator compiled against | no |

Every count in the file that anything reads is asserted against reality rather than trusted. The harness compares each group's `vectors` and `sources` to what the file actually holds, compares the manifest's file list to the directory in both directions — a JSON file on disk and not in the manifest is a failure, and so is the reverse — and sums the per-group figures against an independently written total of 5,364 held in the test source. The duplication is the mechanism: without a second total written by hand, the sum would have one degree of freedom and could not fail. `total_vectors` is the exception: no check reads that key, so it holds only because nobody edits it.

A `deferred` group must carry a `reason`. An `active` group may not carry `activated` or `still_deferred`. `still_deferred` is read from the file, never computed as `vectors - activated.len()`, because a derived remainder moves with the list and an id dropped from `activated` would silently stop being replayed with every total still agreeing.

### How the harness replays

**Dispatch is on `source`.** The replay matches the vector's `source` string against a table of registered reference functions. An unregistered `source` is a hard failure with the fixture, the vector id and the unknown string in the message — not a skip. That is what makes "every vector runs" structural rather than conventional: a vector added upstream cannot slip through unexecuted.

**Every field must be read or the vector fails.** The accessors record which keys they were asked for. After a handler returns, the harness walks the vector's own keys and reports any that were never read. The only exemptions are five metadata keys — `id`, `note`, `falsifies`, `source`, and `i` for corpus entries — and eight named prose keys. Five of those eight pair with a machine-readable counterpart that *is* asserted; the other three are a locator for the second implementation and two statements about a reference call that crashes, which is why there is no value to compare. The domain is derived from the artifact, not from a maintained list: a field added to a fixture is owed an assertion the moment it appears. Asking whether a key exists does not count as reading it.

**Nested fields must be descended into, not read.** A field holding an object, or an array of objects, is covered only if the handler iterated it and gave each element its own context and its own coverage walk. There is deliberately no accessor that returns a nested node, because reading the parent once would mark an entire subtree covered while covering none of it.

**Populations are asserted, not assumed.** Per-group, the number of vectors replayed is compared to the manifest. The two digest files state their own per-source populations in the header (`count_wots_pkgen = 1000`, `count_expand_seed = 128`, `count_wots_sign = 1000`, `count_chain_lengths = 128`, and so on); each is compared to what the `vectors` array holds, and for those two files the header counts must sum to the whole file, so a source nobody counted cannot hide. Group HS's sweeps are checked to cover every length in `0..=sha256_max_len` (129) and `0..=sha3_512_max_len` (145) with no gaps. Group C's corpus `count` is compared to its `entries` length. Across group D, 47 vectors carry a wire image and a signature offset and 40 of those carry a `VEOK` validation verdict; both figures are asserted, because a vector that stops carrying a verdict silently leaves the required set and only a count notices.

**A vacuity floor sits under the whole walk.** The total number of recorded field reads must be at least 400. If the coverage machinery ever went silent, every field would read as uncovered and the coverage failure would fire first; the floor catches the other order, where nothing is uncovered because nothing was recorded.

**Each leg of a crosscheck fails on its own.** A bulk crosscheck vector (AKX, CK) is compared three ways: the TypeScript's recorded value against this crate's freshly computed one, the C's recorded value — loaded from the upstream file the vector names, at the vector id or corpus index it names — against the same computed one, and, where a transcribed literal exists, the literal against the executed value. The upstream file is loaded once per process and the name it is loaded under is asserted, so a vector pointing at the wrong file fails rather than being compared against it.

**A refusal is a recorded answer.** Some vectors record that the reference was deliberately not called — an all-`1` Base58 string makes the C's decoder compute a negative copy length and reach `memcpy` with `SIZE_MAX`, so it cannot be invoked from either side. Those vectors carry a boolean saying so, which is asserted, and prose explaining why, which is not.

### Provenance

The C-generated groups (A, B, C, D, E, AK, BK, HS) are produced against `mochimo-core` at commit `bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4`, tagged `v3.1.0-beta`.

The TypeScript-generated groups pin what each of them actually runs, and the sets differ:

- CX, AKX and CK run `mochimo-wots` at `b583580bffcbe51dbcfd4e30aa711d0d2703b851`, resolved through `mochiwallet` at `af20bfccdde1b0dd75ac1a98f7c83b82ccf359a2`; CX and CK also pin `bs58`.
- F adds `mochimo-wallet` at `f4694cefd3fc4f15a9922db0bb2ca1c0f27ecb60`, plus the BIP39 and crypto library versions it captures.
- M runs `mochimo-mesh-api-client` at `6aba0f3720ef5c1229a85ffb7fa024a8a6b7fdeb` under a recording fetch double, with `mochimo-wots` and `mochiwallet` beneath it.
- RX pins `mochimo-wots` only, and the RIPEMD-160 package version resolved from it. It names neither `mochimo-wallet` nor `mochiwallet`, because it runs neither.

Group N is a live capture from a single deployment at a single block, and it is the one file whose values are not reproducible byte for byte: balances and block heights move. Asking the same node again answers a different block, so a fresh capture is a new observation to be read as one, never a check that this file is right. What the replay holds it to instead is the part that does not move: that this crate's request bodies are byte-equal to the ones that were sent, and that the parsers extract the values those recorded pairs independently determine.
