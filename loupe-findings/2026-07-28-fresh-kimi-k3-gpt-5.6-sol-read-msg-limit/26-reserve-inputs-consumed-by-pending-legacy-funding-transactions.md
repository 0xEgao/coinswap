# Reserve inputs consumed by pending Legacy funding transactions

- **Finding ID:** 26
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1210-1216
- **Job:** 3
- **CWE:** CWE-362
- **Fingerprint:** 2dd187862bbe47b434b12ea727d08c82402495fa61bb262e825c033fbe24be07

## Description

`collect_excluded_utxos` returns only each other swap's `reserve_utxo`. In the Legacy flow, however, `reserve_utxo` is populated with every output of the newly built funding transactions, while the transactions remain unbroadcast in `pending_funding_txes`. `Wallet::create_funding_txes` unlocks its selected inputs before returning. Those future output outpoints are not selectable UTXOs and therefore exclude nothing; the actual wallet inputs consumed by the pending transactions remain available to a concurrent swap. With a single maker UTXO large enough to satisfy two accepted reservations, two takers can make the maker construct conflicting funding transactions from that same input. Whichever swap broadcasts second fails after the taker has already confirmed its incoming contract, locking that participant's funds until refund/recovery and disrupting maker availability. A malicious concurrent taker can race an otherwise legitimate swap to induce this failure. The regression test creates a real pending Legacy funding transaction, stores it exactly as the current handler does, and asserts `collect_excluded_utxos` includes every consumed input; HEAD returns only transaction outputs and fails. The target method can derive input outpoints directly from the already-persisted `pending_funding_txes` (and retain any other valid reservations). Prior searches for `pending_funding_txes excluded inputs`, `reserve_utxo outputs inputs`, `concurrent Legacy funding double spend`, and `collect_excluded_utxos` returned no match.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -46,6 +46,7 @@
 mod hotpath_profile;
 mod legacy_malformed_contract;
 mod legacy_missing_contract_cache;
+mod legacy_pending_input_reservation;
 mod liquidity_test;
 mod offerbook_sync_race;
 mod taker_cli;
diff --git a/tests/integration/legacy_pending_input_reservation.rs b/tests/integration/legacy_pending_input_reservation.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/legacy_pending_input_reservation.rs
@@ -0,0 +1,95 @@
+//! Pending Legacy funding transactions must reserve the wallet inputs they
+//! consume. Reserving their not-yet-created outputs does not prevent another
+//! concurrent swap from selecting the same input and building a conflict.
+
+use bitcoin::{
+    hashes::{hash160, Hash},
+    secp256k1::{rand::thread_rng, Secp256k1, SecretKey},
+    Amount, OutPoint, PublicKey,
+};
+use coinswap::{
+    maker::{ConnectionState, MakerBehavior, MakerTrait, SwapPhase},
+    protocol::common_messages::ProtocolVersion,
+    utill::MIN_FEE_RATE,
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn pending_legacy_funding_inputs_are_excluded_from_other_swaps() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8892, Some(21201))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    // A single UTXO is sufficient for two swaps by value. If its first pending
+    // spend is not reserved, the second swap can select it again.
+    fund_makers(
+        &makers,
+        &test_framework.bitcoind,
+        1,
+        Amount::from_sat(1_000_000),
+        AddressType::P2TR,
+    );
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    let secp = Secp256k1::new();
+    let next_multisig_secret = SecretKey::new(&mut thread_rng());
+    let next_hashlock_secret = SecretKey::new(&mut thread_rng());
+    let next_multisig_pubkey = PublicKey {
+        compressed: true,
+        inner: bitcoin::secp256k1::PublicKey::from_secret_key(
+            &secp,
+            &next_multisig_secret,
+        ),
+    };
+    let next_hashlock_pubkey = PublicKey {
+        compressed: true,
+        inner: bitcoin::secp256k1::PublicKey::from_secret_key(
+            &secp,
+            &next_hashlock_secret,
+        ),
+    };
+    let hashvalue = hash160::Hash::hash(b"pending-input-reservation");
+
+    let (funding_txes, outgoing_swapcoins, _) = maker
+        .initialize_coinswap(
+            Amount::from_sat(200_000),
+            &[next_multisig_pubkey],
+            &[next_hashlock_pubkey],
+            hashvalue,
+            20,
+            MIN_FEE_RATE,
+            None,
+        )
+        .unwrap();
+    let pending_inputs = funding_txes
+        .iter()
+        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
+        .collect::<Vec<OutPoint>>();
+    assert!(!pending_inputs.is_empty());
+
+    let mut first_swap = ConnectionState::new(ProtocolVersion::Legacy);
+    first_swap.swap_id = Some("pending-first-swap".to_string());
+    first_swap.swap_amount = Amount::from_sat(200_000);
+    first_swap.phase = SwapPhase::AwaitingSignaturesOrPreimage;
+    first_swap.outgoing_swapcoins = outgoing_swapcoins;
+    first_swap.pending_funding_txes = funding_txes.clone();
+    // This mirrors the current Legacy handler: it records every output of the
+    // pending transaction, even though those outputs do not exist in the
+    // wallet UTXO set until this transaction is broadcast and confirmed.
+    first_swap.reserve_utxo = funding_txes
+        .iter()
+        .flat_map(|tx| {
+            (0..tx.output.len()).map(move |vout| OutPoint::new(tx.compute_txid(), vout as u32))
+        })
+        .collect();
+    maker
+        .store_connection_state("pending-first-swap", &first_swap)
+        .unwrap();
+
+    let excluded_for_second = maker.collect_excluded_utxos("second-swap");
+    let all_inputs_reserved = pending_inputs
+        .iter()
+        .all(|outpoint| excluded_for_second.contains(outpoint));
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        all_inputs_reserved,
+        "collect_excluded_utxos omitted inputs consumed by a pending Legacy funding transaction"
+    );
+}

```
