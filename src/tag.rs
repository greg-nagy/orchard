//! Detection tag generation for PIR-based transaction scanning.
//!
//! This module provides functionality for generating and matching detection tags
//! that enable wallets to filter relevant transactions without trial decryption.
//!
//! # Overview
//!
//! Detection tags are 16-byte values derived from a tag key and a payment index.
//! Senders generate tags when creating transactions, and recipients can efficiently
//! check if a tag matches their key without decrypting the note.
//!
//! # Security Properties
//!
//! - Tags are pseudorandom and indistinguishable from random bytes without the key
//! - Different indices produce different tags (with overwhelming probability)
//! - Knowing a tag does not reveal the key or other tags
//! - Tags enable PIR-based scanning but don't reveal transaction amounts or memos

use blake2b_simd::{Params, State};

const TAG_PERSONALIZATION: &[u8; 16] = b"Zcash_OrchardTag";
const TAG_LENGTH: usize = 16;

/// A key used to generate and match detection tags.
///
/// This should be derived from the recipient's incoming viewing key or
/// a dedicated tag key shared between sender and recipient.
#[derive(Clone, Debug)]
pub struct TaggingKey {
    key: [u8; 32],
}

impl TaggingKey {
    /// Creates a new tagging key from raw bytes.
    ///
    /// The key should be derived from cryptographically secure material,
    /// such as a viewing key or dedicated key derivation.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Returns the raw key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Generates a detection tag for the given payment index.
    ///
    /// Each payment to a recipient should use a unique index to ensure
    /// tags are distinguishable. The sender and recipient must coordinate
    /// on index allocation.
    ///
    /// # Arguments
    ///
    /// * `index` - A unique payment index for this tag
    ///
    /// # Returns
    ///
    /// A 16-byte detection tag
    pub fn generate_tag(&self, index: u64) -> [u8; 16] {
        let mut h = tag_hasher();
        h.update(&self.key);
        h.update(&index.to_le_bytes());
        
        let hash = h.finalize();
        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&hash.as_bytes()[..TAG_LENGTH]);
        tag
    }

    /// Checks if a tag matches any index in the given range.
    ///
    /// This performs a linear scan over the range, checking each possible
    /// index. For large ranges, consider using batch or PIR-based methods.
    ///
    /// # Arguments
    ///
    /// * `tag` - The tag to match against
    /// * `start` - Start of the index range (inclusive)
    /// * `end` - End of the index range (exclusive)
    ///
    /// # Returns
    ///
    /// The matching index if found, or `None` if no match in range
    pub fn match_tag(&self, tag: &[u8; 16], start: u64, end: u64) -> Option<u64> {
        for index in start..end {
            if &self.generate_tag(index) == tag {
                return Some(index);
            }
        }
        None
    }

    /// Checks if a tag matches a specific index.
    ///
    /// This is more efficient than `match_tag` when checking a single index.
    pub fn verify_tag(&self, tag: &[u8; 16], index: u64) -> bool {
        &self.generate_tag(index) == tag
    }
}

/// Creates a BLAKE2b hasher configured for tag generation.
fn tag_hasher() -> State {
    Params::new()
        .hash_length(32)
        .personal(TAG_PERSONALIZATION)
        .to_state()
}

/// Generates a random tag for dummy actions.
///
/// Dummy actions should use random tags to be indistinguishable from
/// real actions. This ensures that observers cannot identify dummy
/// actions by their tags.
pub fn random_tag(rng: &mut impl rand::RngCore) -> [u8; 16] {
    let mut tag = [0u8; 16];
    rng.fill_bytes(&mut tag);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_tag_generation_deterministic() {
        let key = TaggingKey::from_bytes([0x42; 32]);
        
        let tag1 = key.generate_tag(0);
        let tag2 = key.generate_tag(0);
        
        assert_eq!(tag1, tag2, "Same key and index should produce same tag");
    }

    #[test]
    fn test_different_indices_produce_different_tags() {
        let key = TaggingKey::from_bytes([0x42; 32]);
        
        let tag0 = key.generate_tag(0);
        let tag1 = key.generate_tag(1);
        
        assert_ne!(tag0, tag1, "Different indices should produce different tags");
    }

    #[test]
    fn test_different_keys_produce_different_tags() {
        let key1 = TaggingKey::from_bytes([0x42; 32]);
        let key2 = TaggingKey::from_bytes([0x43; 32]);
        
        let tag1 = key1.generate_tag(0);
        let tag2 = key2.generate_tag(0);
        
        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    #[test]
    fn test_tag_matching() {
        let key = TaggingKey::from_bytes([0x42; 32]);
        let index = 42u64;
        let tag = key.generate_tag(index);
        
        // Should find the tag in a range containing the index
        assert_eq!(key.match_tag(&tag, 0, 100), Some(index));
        
        // Should not find the tag in a range not containing the index
        assert_eq!(key.match_tag(&tag, 0, 42), None);
        assert_eq!(key.match_tag(&tag, 43, 100), None);
    }

    #[test]
    fn test_tag_verification() {
        let key = TaggingKey::from_bytes([0x42; 32]);
        let index = 42u64;
        let tag = key.generate_tag(index);
        
        assert!(key.verify_tag(&tag, index));
        assert!(!key.verify_tag(&tag, index + 1));
    }

    #[test]
    fn test_random_tag() {
        let mut rng = OsRng;
        let tag1 = random_tag(&mut rng);
        let tag2 = random_tag(&mut rng);
        
        // Random tags should be different (with overwhelming probability)
        assert_ne!(tag1, tag2);
    }
}
