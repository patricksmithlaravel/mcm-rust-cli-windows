//! The signing path: [`Keystore::sign_spend`], the public route to a fresh
//! WOTS+ signature, behind the receipt the keystore mints (I1); its sibling
//! [`Keystore::resign_reserved`] reproduces the one already released.
//!
//! # The shape, and what each choice makes impossible
//!
//! * **The receipt is the only designator.** `sign_spend` takes no tag; the
//!   account is `receipt.tag()`, so "a receipt for A used to sign for B" is
//!   unrepresentable rather than checked. The receipt is consumed by value
//!   and has no `Clone`, so one receipt is at most one call, and it is minted
//!   only after the keystore's four durable steps (I2), so a signature is
//!   released only after its index is on disk.
//! * **The live state is re-checked.** A receipt witnesses the state it was
//!   minted for; `sign_spend` requires the store to still be in that state --
//!   index equal, a reservation present, its digest the one supplied -- so a
//!   hoarded receipt, a reconciliation receipt (`persist_advance_to` sets no
//!   reservation) and a settled one are refused, each by name.
//! * **The key is derived, never stored.** A derived account signs from the
//!   master seed the caller holds ([`KeyAccess::Master`]), borrowed for the
//!   call; the account's tag is recomputed from it and must match, so a
//!   wrong seed, a wrong position or a wrong tag is refused before anything
//!   signs. An imported account signs from its stored root
//!   ([`KeyAccess::StoredRoot`]); nothing is supplied and nothing can be
//!   supplied wrongly. The shapes are an enum so the caller must say which,
//!   and the wrong one is refused in both directions.
//! * **One key stream, one account.** A rotation key is a function of the
//!   32-byte seed alone, so a derived seed also stored as an imported root
//!   would be two indices over one stream; the derived path refuses it, and
//!   since format v2 `Keystore::add` refuses a duplicate stream identity
//!   across kinds, which is the half a drop-and-reopen would otherwise defeat.
//!   This path also re-derives the record's identity from the
//!   master and refuses a disagreement -- the only place a *derived*
//!   record's identity can be checked, since checking it needs the master.
//! * **Nothing is persisted here.** The advance was persisted by
//!   `persist_advance`; a signature adds nothing the store must remember, so
//!   "reserved" and "signed, possibly broadcast" are one on-disk state by
//!   design. What settles it is the chain (I4's reconciliation, not this
//!   module); until then the account cannot spend again, which is the
//!   fail-closed direction.
//! * **A refusal has no side effect** -- no medium call, no memory change --
//!   but **an `Err` from `sign_spend` still consumes the receipt**, so the
//!   reserved key is skipped, not reused. [`Keystore::check_spend`] runs the
//!   same checks on a borrowed receipt so a wrong passphrase costs nothing.
//!
//! # Where the master seed lives
//!
//! With the caller, as a [`Secret`], zeroized on drop; borrowed for one call.
//! The crate retains nothing between calls: every derived intermediate
//! (`DerivedAccount`, `WotsKey`) holds a `Secret` and is dropped before this
//! module returns. `KeyAccess::StoredRoot` means possession of the keystore
//! directory *plus the password* is signing power for imported accounts.
//! Since format v3 the record body is sealed under an Argon2id key, so a
//! stolen directory alone yields nothing and
//! `imported_roots_and_the_master_seed_are_encrypted_at_rest` is green.
//!
//! # The imported first key
//!
//! Position 0 of an imported account signs from the **stored** public seed and
//! hash address, which is the only thing it could ever have done: those
//! components came from the master seed's generator and are not derivable
//! from the root -- three readings of the shipped code agree. Approximating
//! them is refused rather than attempted, because a plausible substitute
//! produces a valid signature under an address nobody funded -- and the funds
//! an imported account was imported holding sit at exactly that address. The
//! record carries the components since format v2 and `Account::import`
//! refuses a pair the root does not reproduce, so the arm derives.

use core::fmt;

use crate::account::{AccountKind, AdvanceReceipt, KeyMaterial, WotsIndex};
use crate::addr::{self, Tag};
use crate::consts::SEED_LEN;
use crate::derive::{self, WotsKey};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::wots::{self, Adrs, PublicKey, Signature};

use super::format::Slot;
use super::{Keystore, Medium};

/// How `sign_spend` reaches an account's key material.
///
/// Two shapes because the two kinds need different things: a derived
/// account's material is a pure function of the master seed the caller
/// holds, an imported account's is the root the store holds. The wrong shape
/// for the account's kind is refused ([`Error::KeyAccessMismatch`]) rather
/// than ignored, so a caller cannot hand a master to an account that signs
/// from something else without noticing.
///
/// Holds a reference to a [`Secret`], so `Debug` is hand-written and redacts
/// it (`no_holder_of_key_material_derives_debug`).
pub enum KeyAccess<'a> {
    /// The master seed a derived account was derived from.
    Master(&'a Secret<SEED_LEN>),
    /// Nothing: the account's key material is its stored root.
    StoredRoot,
}

impl fmt::Debug for KeyAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAccess::Master(_) => f.write_str("Master(<redacted>)"),
            KeyAccess::StoredRoot => f.write_str("StoredRoot"),
        }
    }
}

/// What `sign_spend` releases: the signature and the public parts of the key
/// that made it, which a transaction's `WOTSVAL` carries beside it. All
/// public data -- the secret was dropped before this was built. `Debug`
/// prints the position and the key's address hash rather than 4,320 bytes.
pub struct SpendSignature {
    /// The position of the key that signed: the reservation's `spent_index`.
    pub spent_index: WotsIndex,
    /// The 2144-byte WOTS+ signature over the reserved digest.
    pub signature: Signature,
    /// The signing key's public seed.
    pub pub_seed: [u8; SEED_LEN],
    /// The hash address the signature started from -- the same words
    /// `pkgen` started from, before either mutated them.
    pub adrs: Adrs,
    /// The signing key's public key, so a caller can recover it from the
    /// signature with `wots::pk_from_sig` and compare.
    pub public_key: PublicKey,
}

impl fmt::Debug for SpendSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = addr::from_wots(&self.public_key);
        let hash: String = addr::hash_of(&address).iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("SpendSignature")
            .field("spent_index", &self.spent_index)
            .field("address_hash", &hash)
            .finish_non_exhaustive()
    }
}

impl<M: Medium> Keystore<M> {
    /// Run every check `sign_spend` runs, on a borrowed receipt, and derive
    /// (then drop) the key it would sign with. `Ok(())` means the same call
    /// to `sign_spend` on this handle, with nothing else done in between,
    /// will sign -- so a caller can confirm a passphrase before spending the
    /// receipt it cannot get back.
    pub fn check_spend(&self, digest: &[u8; 32], receipt: &AdvanceReceipt, access: &KeyAccess<'_>) -> Result<()> {
        self.resolve(digest, receipt, access).map(|_| ())
    }

    /// Re-produce the signature an outstanding reservation already released,
    /// from the store's own record. **The one recovery for a lost retry
    /// artifact** (as corrected by the audit that retired `abandon_reservation`).
    ///
    /// # Why this is not a second signature
    ///
    /// There is **no digest parameter.** The digest is `Pending::digest` and
    /// the position is `Pending::spent_index`, both read from the store, so
    /// signing over anything other than the reserved digest is
    /// unrepresentable rather than refused. WOTS+ signing is deterministic
    /// (asserted by `tests/recon.rs`), so calling this after
    /// `sign_spend` yields **byte-identical output**: one signature produced
    /// twice, not two signatures. I1's property is about distinct signatures
    /// under one key, and the count of those stays at one — the leakage from
    /// re-emitting identical bytes is identical.
    ///
    /// # Why it has to exist
    ///
    /// Rolling the index back to `spent_index` is correctly forbidden — that
    /// is the road to a second, *different* digest under one key, which is
    /// the catastrophe every invariant here exists to prevent. So a signature
    /// from that key is the **only** way the funds at its address can ever
    /// move, and if the artifact is gone this is the only way to that
    /// signature. It is the only possible recovery, not the preferred one.
    /// Without it, losing the artifact strands the account's whole balance
    /// and every later deposit — verified end to end in the audit, which
    /// is what retired `abandon_reservation`.
    ///
    /// No receipt: nothing advances, nothing persists, `&self`. A receipt
    /// witnesses an advance and there is no advance to witness.
    ///
    /// It reads the OPEN reservation and never the retained settled block. A
    /// retained block is sent again as the saved bytes it was signed into.
    /// `recon::resubmit_reverted_settle` is the checked route to that, and signs
    /// nothing. The raw `submit` verb also writes saved bytes to the socket,
    /// checking their layout only.
    pub fn resign_reserved(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendSignature> {
        let (_, slots) = self.live()?;
        let slot: &Slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        let pending = slot.pending.ok_or(Error::NothingPending)?;
        let key = self.key_at(slots, slot, pending.spent_index, access)?;
        let mut working = key.adrs();
        let signature = wots::sign(&pending.digest, key.secret(), key.pub_seed(), &mut working);
        Ok(SpendSignature {
            spent_index: pending.spent_index,
            signature,
            pub_seed: *key.pub_seed(),
            adrs: key.adrs(),
            public_key: Box::new(*key.public_key()),
        })
    }

    /// Sign `digest` with the key `receipt` reserved for it, consuming the
    /// receipt. Module doc for the contract; every refusal is an [`Error`]
    /// variant that names its reason, none has a side effect, and all of
    /// them consume the receipt.
    pub fn sign_spend(
        &mut self,
        digest: &[u8; 32],
        receipt: AdvanceReceipt,
        access: KeyAccess<'_>,
    ) -> Result<SpendSignature> {
        let (spent_index, key) = self.resolve(digest, &receipt, &access)?;
        // The signer starts from the words `pkgen` started from and mutates
        // its own copy; the receipt is dropped here, spent whichever way this
        // returns.
        let mut working = key.adrs();
        let signature = wots::sign(digest, key.secret(), key.pub_seed(), &mut working);
        Ok(SpendSignature {
            spent_index,
            signature,
            pub_seed: *key.pub_seed(),
            adrs: key.adrs(),
            public_key: Box::new(*key.public_key()),
        })
    }

    /// The checks, in the order the module doc gives them, and the key at
    /// the reserved position. `&self`: nothing here mutates.
    fn resolve(&self, digest: &[u8; 32], receipt: &AdvanceReceipt, access: &KeyAccess<'_>) -> Result<(WotsIndex, WotsKey)> {
        let (_, slots) = self.live()?;
        // (a) the receipt names an account this store holds.
        let slot: &Slot = slots.get(&receipt.tag()).ok_or(Error::NoSuchAccount)?;
        // (b) it names the store's live index -- a hoarded receipt is stale.
        let stored = slot.account.wots_index();
        if stored != receipt.index() {
            return Err(Error::StaleReceipt {
                attested: receipt.index().get(),
                stored: stored.get(),
            });
        }
        // (c) a key is reserved. `persist_advance_to` reserves none, and
        // `persist_settled` leaves `slot.pending` None by moving the block to
        // the retained `settled` field, so both of those receipts stop
        // here.
        let pending = slot.pending.ok_or(Error::NoReservation)?;
        // (c') DEFENSIVE, never demonstrated red: `persist_advance` writes
        // the reservation and the index in one commit and the parser refuses
        // any other relation between them, so no public-API input reaches
        // this arm. Kept because it is the statement of what a reservation
        // means, and a future writer of `pending` could break it.
        if pending.spent_index.advanced().ok() != Some(receipt.index()) {
            return Err(Error::NoReservation);
        }
        let spent_index = pending.spent_index;
        // (d) the digest is the reserved one (I3: the record names what was
        // signed).
        if pending.digest != *digest {
            return Err(Error::DigestMismatch);
        }
        // (e), (f), (f'), (g): the key, by kind.
        let key = self.key_at(slots, slot, spent_index, access)?;
        Ok((spent_index, key))
    }

    /// The key at `position` for `slot`'s account under `access`: checks
    /// (e), (f), (f') and (g) of the module doc, then the derivation. Shared
    /// by [`Keystore::sign_spend`] (the reserved position) and
    /// [`Keystore::spend_addresses`](super::spend) (the current position and
    /// the next), so what address a spend is built for and what key signs it
    /// cannot drift apart: one derivation, one set of refusals. Every
    /// `Secret` made here is in the returned key, which the caller drops.
    pub(super) fn key_at(
        &self,
        slots: &std::collections::BTreeMap<crate::addr::Tag, Slot>,
        slot: &Slot,
        position: WotsIndex,
        access: &KeyAccess<'_>,
    ) -> Result<WotsKey> {
        let key = match (slot.account.key_material(), access) {
            (KeyMaterial::Derived { .. }, KeyAccess::StoredRoot) => {
                return Err(Error::KeyAccessMismatch {
                    kind: AccountKind::Derived,
                })
            }
            (KeyMaterial::Imported { .. }, KeyAccess::Master(_)) => {
                return Err(Error::KeyAccessMismatch {
                    kind: AccountKind::Imported,
                })
            }
            (
                KeyMaterial::Derived {
                    account_index,
                    stream,
                },
                KeyAccess::Master(master),
            ) => {
                // (f) the master derives THIS account: its tag at its position.
                let derived = derive::derive_account(master, *account_index);
                if derived.tag() != slot.account.tag() {
                    return Err(Error::DerivedTagNotReproduced {
                        account_index: *account_index,
                    });
                }
                // (f') DEFENSIVE since format v2, and reachable only from a
                // hand-edited snapshot: the seed is not also an imported root
                // in this store. `Keystore::add` refuses that pair outright
                // now that both records carry a stream identity, so no
                // public-API sequence reaches this arm -- the one route left
                // is a file whose derived record carries a *forged* identity,
                // which is what let it past `add`, and (f'') below then fires
                // too. Ordered first so the more specific message wins.
                if self.imported_roots(slots).any(|root| root.ct_eq(derived.seed())) {
                    return Err(Error::KeyStreamSharedWithImportedAccount);
                }
                // (f'') the record's key-stream identity is the one this seed
                // produces. A derived record's identity cannot be checked at
                // parse time -- it needs the master -- so this is the ONLY
                // place it is checked at all, and a record that disagrees
                // with itself is refused rather than acted on.
                if derive::stream_id(derived.seed()) != *stream {
                    return Err(Error::StreamIdNotReproduced);
                }
                match position.rotation() {
                    None => derived.into_parts().2,
                    Some(rotation) => derive::derive_wots_key(derived.seed(), rotation),
                }
            }
            (KeyMaterial::Imported { root, first, .. }, KeyAccess::StoredRoot) => {
                match position.rotation() {
                    // (g) the first key, rebuilt from the components the
                    // record carries -- the same thing the shipped wallet
                    // does at `wotsIndex === -1`, which memcpys `faddress`
                    // back rather than deriving. A substitute for the
                    // components would sign under an address nobody funded,
                    // which is why the record carries them.
                    None => derive::first_key_from_components(
                        root.secret().duplicate(),
                        first.pub_seed(),
                        first.adrs(),
                    ),
                    Some(rotation) => derive::derive_wots_key(root.secret(), rotation),
                }
            }
        };
        Ok(key)
    }

    /// Every imported root the store holds, for the stream checks.
    pub(super) fn imported_roots<'s>(
        &'s self,
        slots: &'s std::collections::BTreeMap<crate::addr::Tag, Slot>,
    ) -> impl Iterator<Item = &'s Secret<SEED_LEN>> + 's {
        slots.values().filter_map(|s| match s.account.key_material() {
            KeyMaterial::Imported { root, .. } => Some(root.secret()),
            KeyMaterial::Derived { .. } => None,
        })
    }
}
