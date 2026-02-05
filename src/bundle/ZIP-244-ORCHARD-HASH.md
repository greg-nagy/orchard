# ZIP-244 Orchard Bundle Hash Structure

Reference: https://zips.z.cash/zip-0244

## Overview

The Orchard bundle commitment is computed as a BLAKE2b-256 hash that combines three
separate action digests plus bundle metadata. This structure enables light clients to
verify transaction integrity using only the compact data they receive.

## Hash Structure

```
Orchard Bundle Hash ("ZTxIdOrchardHash")
├── Compact Hash ("ZTxIdOrcActCHash")      ─── 32 bytes
├── Memos Hash ("ZTxIdOrcActMHash")        ─── 32 bytes
├── Noncompact Hash ("ZTxIdOrcActNHash")   ─── 32 bytes
├── flags                                   ─── 1 byte
├── value_balance                           ─── 8 bytes (LE)
└── anchor                                  ─── 32 bytes
```

## Per-Action Data Layout

Each action contributes to all three sub-hashes. The `enc_ciphertext` (580 bytes total)
is split across the compact and noncompact hashes:

### Compact Hash (148 bytes per action)
```
BLAKE2b-256("ZTxIdOrcActCHash", for each action:
    nullifier      ─── 32 bytes
    cmx            ─── 32 bytes
    epk            ─── 32 bytes
    enc[0..52]     ─── 52 bytes (note commitment, value, etc.)
)
```

### Memos Hash (512 bytes per action)
```
BLAKE2b-256("ZTxIdOrcActMHash", for each action:
    enc[52..564]   ─── 512 bytes (encrypted memo)
)
```

### Noncompact Hash (160 bytes per action)
```
BLAKE2b-256("ZTxIdOrcActNHash", for each action:
    cv_net         ─── 32 bytes (value commitment)
    rk             ─── 32 bytes (randomized verification key)
    enc[564..580]  ─── 16 bytes (remaining ciphertext)
    out_ciphertext ─── 80 bytes
)
```

## enc_ciphertext Byte Ranges

```
┌─────────────────────────────────────────────────────────────────┐
│                    enc_ciphertext (580 bytes)                   │
├──────────────┬────────────────────────────┬─────────────────────┤
│   [0..52]    │        [52..564]           │     [564..580]      │
│   52 bytes   │        512 bytes           │      16 bytes       │
│   COMPACT    │         MEMOS              │     NONCOMPACT      │
└──────────────┴────────────────────────────┴─────────────────────┘
```

## Why This Structure?

The three-hash structure serves different use cases:

1. **Compact Hash**: Contains data needed by light clients to detect incoming
   transactions (nullifier, cmx, epk, and partial ciphertext for trial decryption)

2. **Memos Hash**: Separates the 512-byte memo field, which light clients can
   fetch on-demand after detecting a relevant transaction

3. **Noncompact Hash**: Contains data only needed for full validation (value
   commitments, verification keys, remaining ciphertext)

This allows light clients to verify transaction integrity without downloading
full transaction data.

## Implementation

See `commitments.rs` in this directory for the Rust implementation.

---

## Production Code Paths

### Zcash Stack (Zebra + librustzcash)

#### 1. Transaction ID (TXID) Computation

The orchard bundle hash is a component of the ZIP-244 transaction ID tree.

```
zebra-chain/src/transaction/txid.rs
  TxIdBuilder::txid_v5()
    → Transaction::to_librustzcash()
      → zcash_primitives::Transaction::read()
        → TransactionData::digest(TxIdDigester)
          → TxIdDigester::digest_orchard()
            → bundle.commitment()
              → hash_bundle_txid_data()  ← HERE
```

#### 2. Auth Commitment (WtxId)

The orchard bundle authorization data is hashed for witnessed transaction IDs.

```
zebra-chain/src/primitives/zcash_primitives.rs:352
  auth_digest()
    → tx.to_librustzcash().auth_commitment()
      → hash_bundle_auth_data()
```

#### 3. Signature Hash (SIGHASH) for Proof Verification

```
zebra-consensus/src/primitives/halo2.rs:72
  Item::new(bundle, sighash)
    → batch.add_bundle(&bundle, sighash.0)
      → Halo2 proof verification
```

#### 4. Consensus Validation

```
zebra-consensus/src/transaction.rs:990
  Verifier::verify_shielded_bundle()
    → Self::verify_orchard_bundle(orchard_bundle, &sighash)
      → Item::new() → Halo2 batch verification
```

### Zashi Stack (iOS Wallet)

#### 1. Transaction Decryption & Storage

```
zcash-light-client-ffi/rust/src/lib.rs:1971
  zcashlc_decrypt_and_store_transaction()  ← FFI boundary
    → Transaction::read(tx_bytes)
    → decrypt_and_store_transaction()
    → tx.txid()  ← uses orchard bundle hash
        ↓
zcash-swift-wallet-sdk/.../ZcashRustBackendWelding.swift:94
  decryptAndStoreTransaction(txBytes:, minedHeight:)
        ↓
  Used by: Block sync process
```

#### 2. Transaction Creation with Orchard

```
zcash-light-client-ffi/rust/src/lib.rs:2513
  zcashlc_create_proposed_transactions()  ← FFI boundary
    → create_proposed_transactions()
    → LocalTxProver (Halo2 proofs)
    → Returns txids (include orchard hash)
        ↓
zcash-swift-wallet-sdk/.../WalletTransactionEncoder.swift:107
  createProposedTransactions()
    → rustBackend.createProposedTransactions()
```

#### 3. Swift Entity Model

```
zcash-swift-wallet-sdk/.../TransactionEntity.swift:69
  ZcashTransaction.Output.Pool
    → .transparent | .sapling | .orchard
```

### Summary: Where Orchard Hash Is Used

| Context | Location | Purpose |
|---------|----------|---------|
| TXID computation | zebra-chain, librustzcash | ZIP-244 transaction identifier |
| Auth commitment | zebra-chain | Witnessed transaction ID (wtxid) |
| Proof verification | zebra-consensus | Halo2 batch validation |
| Nullifier checks | zebra-state | Double-spend prevention |
| Wallet decryption | zcash-light-client-ffi | Scan blocks for owned notes |
| Wallet tx creation | zcash-light-client-ffi | Build transactions with orchard outputs |
| iOS sync | zcash-swift-wallet-sdk | Full wallet synchronization |

---

## Test Verification

Run the verification tests from the orchard directory:
```bash
cargo test --lib bundle::commitments::tests -- --nocapture
```

### Tests Included

| Test | What it Proves |
|------|----------------|
| `test_zip244_hash_structure_byte_layout` | Byte counts (148/512/160) match spec, personalization strings exact |
| `test_zip244_manual_hash_computation` | Manual BLAKE2b computation produces valid hashes |
| `test_real_bundle_hash_equivalence` | Real bundle from Builder matches manual recomputation |
| `test_multi_action_bundle_hash` | 2-action accumulation works correctly |
| `test_flag_combinations` | All 4 flag states (0x00-0x03) produce unique hashes |
| `test_value_balance_edge_cases` | 0, ±1, i64::MAX, i64::MIN all produce unique hashes |

### Running Individual Tests

```bash
# All tests with output
cargo test --lib bundle::commitments::tests -- --nocapture

# Specific test
cargo test --lib test_real_bundle_hash_equivalence -- --nocapture

# Tests requiring circuit feature (real bundle tests)
cargo test --lib --features circuit bundle::commitments::tests -- --nocapture
```
