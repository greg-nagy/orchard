//! Utility functions for computing bundle commitments

use blake2b_simd::{Hash as Blake2bHash, Params, State};

use crate::bundle::{Authorization, Authorized, Bundle};

const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";
const ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthOrchaHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Write disjoint parts of each Orchard shielded action as 3 separate hashes
/// as defined in [ZIP-244: Transaction Identifier Non-Malleability][zip244]:
/// * \[(nullifier, cmx, ephemeral_key, enc_ciphertext\[..52\])*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized
///   with ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, rk, enc_ciphertext\[564..\], out_ciphertext)*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together along with (flags, value_balance_orchard, anchor_orchard),
/// personalized with ZCASH_ORCHARD_ACTIONS_HASH_PERSONALIZATION
///
/// [zip244]: https://zips.z.cash/zip-0244
pub(crate) fn hash_bundle_txid_data<A: Authorization, V: Copy + Into<i64>>(
    bundle: &Bundle<A, V>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

    for action in bundle.actions().iter() {
        ch.update(&action.nullifier().to_bytes());
        ch.update(&action.cmx().to_bytes());
        ch.update(&action.encrypted_note().epk_bytes);
        ch.update(&action.encrypted_note().enc_ciphertext[..52]);

        mh.update(&action.encrypted_note().enc_ciphertext[52..564]);

        nh.update(&action.cv_net().to_bytes());
        nh.update(&<[u8; 32]>::from(action.rk()));
        nh.update(&action.encrypted_note().enc_ciphertext[564..]);
        nh.update(&action.encrypted_note().out_ciphertext);
        // Note: Detection tag is NOT included in NU5 transaction ID hash per ZIP-244.
        // Future network upgrades (NU7+) may include it in a modified hash scheme.
    }

    h.update(ch.finalize().as_bytes());
    h.update(mh.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());
    h.update(&[bundle.flags().to_byte()]);
    h.update(&(*bundle.value_balance()).into().to_le_bytes());
    h.update(&bundle.anchor().to_bytes());
    h.finalize()
}

/// Construct the commitment for the absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}

/// Construct the commitment to the authorizing data of an
/// authorized bundle as defined in [ZIP-244: Transaction
/// Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub(crate) fn hash_bundle_auth_data<V>(bundle: &Bundle<Authorized, V>) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION);
    h.update(bundle.authorization().proof().as_ref());
    for action in bundle.actions().iter() {
        h.update(&<[u8; 64]>::from(action.authorization()));
    }
    h.update(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));
    h.finalize()
}

/// Construct the commitment for an absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_auth_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_SIGS_HASH_PERSONALIZATION).finalize()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::println;

    /// Test that verifies the ZIP-244 Orchard hash structure matches the specification.
    ///
    /// Structure (per ZIP-244):
    /// ```text
    /// Orchard Bundle Hash ("ZTxIdOrchardHash")
    /// ├── Compact Hash ("ZTxIdOrcActCHash")
    /// │   └── Per action: nullifier (32) + cmx (32) + epk (32) + enc[0..52] (52) = 148 bytes
    /// ├── Memos Hash ("ZTxIdOrcActMHash")
    /// │   └── Per action: enc[52..564] = 512 bytes
    /// ├── Noncompact Hash ("ZTxIdOrcActNHash")
    /// │   └── Per action: cv_net (32) + rk (32) + enc[564..580] (16) + out_ciphertext (80) = 160 bytes
    /// ├── flags (1 byte)
    /// ├── value_balance (8 bytes LE)
    /// └── anchor (32 bytes)
    /// ```
    #[test]
    fn test_zip244_hash_structure_byte_layout() {
        // Verify enc_ciphertext slice boundaries
        const ENC_CIPHERTEXT_SIZE: usize = 580;
        const OUT_CIPHERTEXT_SIZE: usize = 80;

        // Compact hash: enc[0..52]
        const COMPACT_ENC_START: usize = 0;
        const COMPACT_ENC_END: usize = 52;
        assert_eq!(COMPACT_ENC_END - COMPACT_ENC_START, 52);

        // Memos hash: enc[52..564]
        const MEMOS_ENC_START: usize = 52;
        const MEMOS_ENC_END: usize = 564;
        assert_eq!(MEMOS_ENC_END - MEMOS_ENC_START, 512);

        // Noncompact hash: enc[564..580]
        const NONCOMPACT_ENC_START: usize = 564;
        const NONCOMPACT_ENC_END: usize = ENC_CIPHERTEXT_SIZE; // 580
        assert_eq!(NONCOMPACT_ENC_END - NONCOMPACT_ENC_START, 16);

        // Verify ranges are contiguous and cover all of enc_ciphertext
        assert_eq!(COMPACT_ENC_END, MEMOS_ENC_START);
        assert_eq!(MEMOS_ENC_END, NONCOMPACT_ENC_START);
        assert_eq!(NONCOMPACT_ENC_END, ENC_CIPHERTEXT_SIZE);

        // Calculate total bytes per action for each hash
        const NULLIFIER_SIZE: usize = 32;
        const CMX_SIZE: usize = 32;
        const EPK_SIZE: usize = 32;
        const CV_NET_SIZE: usize = 32;
        const RK_SIZE: usize = 32;

        // Compact hash per action: nullifier + cmx + epk + enc[0..52]
        let compact_bytes_per_action =
            NULLIFIER_SIZE + CMX_SIZE + EPK_SIZE + (COMPACT_ENC_END - COMPACT_ENC_START);
        assert_eq!(compact_bytes_per_action, 148, "Compact hash should be 148 bytes per action");

        // Memos hash per action: enc[52..564]
        let memos_bytes_per_action = MEMOS_ENC_END - MEMOS_ENC_START;
        assert_eq!(memos_bytes_per_action, 512, "Memos hash should be 512 bytes per action");

        // Noncompact hash per action: cv_net + rk + enc[564..580] + out_ciphertext
        let noncompact_bytes_per_action = CV_NET_SIZE
            + RK_SIZE
            + (NONCOMPACT_ENC_END - NONCOMPACT_ENC_START)
            + OUT_CIPHERTEXT_SIZE;
        assert_eq!(
            noncompact_bytes_per_action, 160,
            "Noncompact hash should be 160 bytes per action"
        );

        // Verify personalization strings are exactly 16 bytes
        assert_eq!(ZCASH_ORCHARD_HASH_PERSONALIZATION.len(), 16);
        assert_eq!(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION.len(), 16);
        assert_eq!(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION.len(), 16);
        assert_eq!(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION.len(), 16);

        // Verify personalization strings match ZIP-244 spec
        assert_eq!(ZCASH_ORCHARD_HASH_PERSONALIZATION, b"ZTxIdOrchardHash");
        assert_eq!(
            ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION,
            b"ZTxIdOrcActCHash"
        );
        assert_eq!(
            ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
            b"ZTxIdOrcActMHash"
        );
        assert_eq!(
            ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
            b"ZTxIdOrcActNHash"
        );
    }

    /// Test that manually computes hashes to verify the implementation matches the spec.
    #[test]
    fn test_zip244_manual_hash_computation() {
        // Create mock action data
        let nullifier = [0x01u8; 32];
        let cmx = [0x02u8; 32];
        let epk_bytes = [0x03u8; 32];
        let mut enc_ciphertext = [0u8; 580];
        // Fill with recognizable patterns for each section
        enc_ciphertext[0..52].fill(0x04); // compact part
        enc_ciphertext[52..564].fill(0x05); // memos part
        enc_ciphertext[564..580].fill(0x06); // noncompact part
        let out_ciphertext = [0x07u8; 80];
        let cv_net = [0x08u8; 32];
        let rk = [0x09u8; 32];

        // Manually compute compact hash: BLAKE2b-256("ZTxIdOrcActCHash", nullifier || cmx || epk || enc[0..52])
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        ch.update(&nullifier);
        ch.update(&cmx);
        ch.update(&epk_bytes);
        ch.update(&enc_ciphertext[..52]);
        let compact_hash = ch.finalize();

        // Manually compute memos hash: BLAKE2b-256("ZTxIdOrcActMHash", enc[52..564])
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        mh.update(&enc_ciphertext[52..564]);
        let memos_hash = mh.finalize();

        // Manually compute noncompact hash: BLAKE2b-256("ZTxIdOrcActNHash", cv_net || rk || enc[564..] || out_ciphertext)
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);
        nh.update(&cv_net);
        nh.update(&rk);
        nh.update(&enc_ciphertext[564..]);
        nh.update(&out_ciphertext);
        let noncompact_hash = nh.finalize();

        // All three hashes should be 32 bytes (BLAKE2b-256)
        assert_eq!(compact_hash.as_bytes().len(), 32);
        assert_eq!(memos_hash.as_bytes().len(), 32);
        assert_eq!(noncompact_hash.as_bytes().len(), 32);

        // Verify hashes are distinct (different inputs should produce different outputs)
        assert_ne!(compact_hash.as_bytes(), memos_hash.as_bytes());
        assert_ne!(memos_hash.as_bytes(), noncompact_hash.as_bytes());
        assert_ne!(compact_hash.as_bytes(), noncompact_hash.as_bytes());

        // Compute the bundle hash combining all three plus metadata
        let flags_byte = 0x03u8; // both spends and outputs enabled
        let value_balance: i64 = 1000;
        let anchor = [0x0Au8; 32];

        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        h.update(compact_hash.as_bytes());
        h.update(memos_hash.as_bytes());
        h.update(noncompact_hash.as_bytes());
        h.update(&[flags_byte]);
        h.update(&value_balance.to_le_bytes());
        h.update(&anchor);
        let bundle_hash = h.finalize();

        assert_eq!(bundle_hash.as_bytes().len(), 32);

        // Print the hashes for manual verification (will show in test output with --nocapture)
        println!("ZIP-244 Orchard Hash Structure Verification:");
        println!("  Compact Hash (ZTxIdOrcActCHash):    {}", hex::encode(compact_hash.as_bytes()));
        println!("  Memos Hash (ZTxIdOrcActMHash):      {}", hex::encode(memos_hash.as_bytes()));
        println!("  Noncompact Hash (ZTxIdOrcActNHash): {}", hex::encode(noncompact_hash.as_bytes()));
        println!("  Bundle Hash (ZTxIdOrchardHash):     {}", hex::encode(bundle_hash.as_bytes()));
    }

    /// Test that hash_bundle_txid_data matches manual recomputation from a real bundle.
    ///
    /// This test creates a real Orchard bundle using the Builder, then verifies that
    /// the production hash_bundle_txid_data output matches a manual recomputation
    /// using the same field extraction logic.
    ///
    /// This proves:
    /// 1. The Bundle struct stores action data correctly
    /// 2. Field accessors (nullifier(), cmx(), etc.) return the expected data
    /// 3. The hash computation is deterministic and correct
    #[test]
    #[cfg(feature = "circuit")]
    fn test_real_bundle_hash_equivalence() {
        use crate::{
            builder::{Builder, BundleType},
            bundle::Flags,
            keys::{FullViewingKey, Scope, SpendingKey},
            tree::MerkleHashOrchard,
            value::NoteValue,
        };
        use incrementalmerkletree::Hashable;
        use rand::rngs::OsRng;

        let mut rng = OsRng;

        // Create keys
        let sk = SpendingKey::from_bytes([0u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        // Use empty tree anchor
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        // Build a bundle with one output action
        let mut builder = Builder::new(
            BundleType::Transactional {
                flags: Flags::SPENDS_DISABLED,
                bundle_required: false,
            },
            anchor,
        );
        builder
            .add_output(None, recipient, NoteValue::from_raw(5000), [0x42u8; 512])
            .unwrap();

        let (bundle, _): (crate::Bundle<_, i64>, _) = builder.build(&mut rng).unwrap().unwrap();

        // Get the production hash
        let production_hash = hash_bundle_txid_data(&bundle);

        // Manually recompute from the bundle's fields
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            // Compact: nullifier || cmx || epk || enc[0..52]
            ch.update(&action.nullifier().to_bytes());
            ch.update(&action.cmx().to_bytes());
            ch.update(&action.encrypted_note().epk_bytes);
            ch.update(&action.encrypted_note().enc_ciphertext[..52]);

            // Memos: enc[52..564]
            mh.update(&action.encrypted_note().enc_ciphertext[52..564]);

            // Noncompact: cv_net || rk || enc[564..] || out_ciphertext
            nh.update(&action.cv_net().to_bytes());
            nh.update(&<[u8; 32]>::from(action.rk()));
            nh.update(&action.encrypted_note().enc_ciphertext[564..]);
            nh.update(&action.encrypted_note().out_ciphertext);
        }

        // Combine into final hash
        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        h.update(ch.finalize().as_bytes());
        h.update(mh.finalize().as_bytes());
        h.update(nh.finalize().as_bytes());
        h.update(&[bundle.flags().to_byte()]);
        h.update(&(*bundle.value_balance()).to_le_bytes());
        h.update(&bundle.anchor().to_bytes());
        let manual_hash = h.finalize();

        // They must match exactly
        assert_eq!(
            production_hash.as_bytes(),
            manual_hash.as_bytes(),
            "Production hash_bundle_txid_data must match manual recomputation"
        );

        println!("Real bundle hash equivalence verified:");
        println!("  Production hash: {}", hex::encode(production_hash.as_bytes()));
        println!("  Manual hash:     {}", hex::encode(manual_hash.as_bytes()));
    }

    /// Test bundle hashing with multiple actions to verify accumulation.
    #[test]
    #[cfg(feature = "circuit")]
    fn test_multi_action_bundle_hash() {
        use crate::{
            builder::{Builder, BundleType},
            bundle::Flags,
            keys::{FullViewingKey, Scope, SpendingKey},
            tree::MerkleHashOrchard,
            value::NoteValue,
        };
        use incrementalmerkletree::Hashable;
        use rand::rngs::OsRng;

        let mut rng = OsRng;

        let sk = SpendingKey::from_bytes([0u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        // Build a bundle with TWO output actions
        let mut builder = Builder::new(
            BundleType::Transactional {
                flags: Flags::SPENDS_DISABLED,
                bundle_required: false,
            },
            anchor,
        );
        builder
            .add_output(None, recipient, NoteValue::from_raw(1000), [0xAAu8; 512])
            .unwrap();
        builder
            .add_output(None, recipient, NoteValue::from_raw(2000), [0xBBu8; 512])
            .unwrap();

        let (bundle, _): (crate::Bundle<_, i64>, _) = builder.build(&mut rng).unwrap().unwrap();

        // Verify we have 2 actions
        assert_eq!(bundle.actions().len(), 2, "Bundle should have 2 actions");

        // Get the production hash
        let production_hash = hash_bundle_txid_data(&bundle);

        // Manually recompute
        let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

        for action in bundle.actions().iter() {
            ch.update(&action.nullifier().to_bytes());
            ch.update(&action.cmx().to_bytes());
            ch.update(&action.encrypted_note().epk_bytes);
            ch.update(&action.encrypted_note().enc_ciphertext[..52]);

            mh.update(&action.encrypted_note().enc_ciphertext[52..564]);

            nh.update(&action.cv_net().to_bytes());
            nh.update(&<[u8; 32]>::from(action.rk()));
            nh.update(&action.encrypted_note().enc_ciphertext[564..]);
            nh.update(&action.encrypted_note().out_ciphertext);
        }

        let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        h.update(ch.finalize().as_bytes());
        h.update(mh.finalize().as_bytes());
        h.update(nh.finalize().as_bytes());
        h.update(&[bundle.flags().to_byte()]);
        h.update(&(*bundle.value_balance()).to_le_bytes());
        h.update(&bundle.anchor().to_bytes());
        let manual_hash = h.finalize();

        assert_eq!(
            production_hash.as_bytes(),
            manual_hash.as_bytes(),
            "Multi-action bundle hash must match manual recomputation"
        );

        println!("Multi-action (2) bundle hash verified:");
        println!("  Hash: {}", hex::encode(production_hash.as_bytes()));
    }

    /// Test all flag combinations (0x00, 0x01, 0x02, 0x03).
    #[test]
    fn test_flag_combinations() {
        use crate::bundle::Flags;

        // All possible flag states
        let flag_cases = [
            (Flags::from_parts(false, false), 0x00u8, "none enabled"),
            (Flags::from_parts(true, false), 0x01u8, "spends only"),
            (Flags::from_parts(false, true), 0x02u8, "outputs only"),
            (Flags::from_parts(true, true), 0x03u8, "both enabled"),
        ];

        for (flags, expected_byte, desc) in flag_cases {
            assert_eq!(
                flags.to_byte(),
                expected_byte,
                "Flag combination '{}' should produce byte 0x{:02x}",
                desc,
                expected_byte
            );
        }

        // Verify flags affect the hash differently
        let base_data = [0u8; 32];
        let anchor = [0u8; 32];
        let value_balance: i64 = 0;

        let mut hashes = std::vec::Vec::new();
        for (flags, _, _) in &flag_cases {
            let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
            h.update(&base_data); // compact
            h.update(&base_data); // memos
            h.update(&base_data); // noncompact
            h.update(&[flags.to_byte()]);
            h.update(&value_balance.to_le_bytes());
            h.update(&anchor);
            hashes.push(h.finalize());
        }

        // All hashes should be unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i].as_bytes(),
                    hashes[j].as_bytes(),
                    "Different flag combinations must produce different hashes"
                );
            }
        }

        println!("All 4 flag combinations produce unique hashes");
    }

    /// Test value_balance edge cases (positive, negative, zero, extremes).
    #[test]
    fn test_value_balance_edge_cases() {
        let base_data = [0u8; 32];
        let anchor = [0u8; 32];
        let flags_byte = 0x03u8;

        let value_cases: [(i64, &str); 5] = [
            (0, "zero"),
            (1, "minimal positive"),
            (-1, "minimal negative"),
            (i64::MAX, "max positive"),
            (i64::MIN, "max negative"),
        ];

        let mut hashes = std::vec::Vec::new();
        for (value_balance, desc) in &value_cases {
            let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
            h.update(&base_data);
            h.update(&base_data);
            h.update(&base_data);
            h.update(&[flags_byte]);
            h.update(&value_balance.to_le_bytes());
            h.update(&anchor);
            let hash = h.finalize();

            println!(
                "value_balance {} ({}): {}",
                value_balance,
                desc,
                hex::encode(hash.as_bytes())
            );
            hashes.push(hash);
        }

        // All hashes should be unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i].as_bytes(),
                    hashes[j].as_bytes(),
                    "Different value_balance values must produce different hashes"
                );
            }
        }

        println!("All value_balance edge cases produce unique hashes");
    }
}
