# Keep Taproot funding inputs reserved until broadcast

- **Finding ID:** 28
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:893-927
- **Job:** 3
- **CWE:** CWE-362
- **Fingerprint:** 0f10ea9834225f24581865df34f1f9a4992411021e9312a9180dfb57f1670120

## Description

`create_funding_transaction` returns an unbroadcast Taproot contract transaction without retaining any reservation on its selected wallet inputs. The in-tree `Wallet::create_funding_txes` unlocks all selected UTXOs before returning. In `process_taproot_contract`, the transaction is only broadcast after all outgoing swapcoins are constructed and saved; its state reservations are persisted still later. During that window, another swap can enter this method. Its `collect_excluded_utxos` snapshot contains no inputs from the first in-progress Taproot handler, so a maker with one sufficiently large UTXO can construct two conflicting contract transactions from that same input even though the sum of both accepted swap amounts fits its advertised balance. The first broadcast wins and the other swap fails after its taker has already confirmed incoming contract funds, disrupting the maker and locking that participant's funds until protocol recovery/refund. This is independent of the separately reported Legacy bug, where already-persisted `pending_funding_txes` are excluded incorrectly; Taproot has no persisted pending state during this creation-to-broadcast interval. The PoC deterministically calls the production method twice against one real wallet UTXO without broadcasting the first transaction, and requires the second call either to reject or use disjoint inputs. HEAD reuses the same outpoint. Prior searches for `Taproot concurrent funding same input`, `create_funding_transaction UTXO unlock broadcast race`, `Taproot spent_inputs cross swap`, and `create_funding_txes unlock_all_utxos concurrent` returned no match.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -53,2 +53,3 @@
 mod taproot_contract_validation;
+mod taproot_pending_input_reservation;
 mod taproot_taker_contract_validation;
diff --git a/tests/integration/taproot_pending_input_reservation.rs b/tests/integration/taproot_pending_input_reservation.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/taproot_pending_input_reservation.rs
@@ -0,0 +1,78 @@
+//! Unbroadcast Taproot contract transactions must keep their wallet inputs
+//! unavailable to other swaps until broadcast or explicit rollback.
+
+use std::collections::HashSet;
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::{MakerBehavior, MakerTrait},
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn unbroadcast_taproot_funding_inputs_cannot_be_selected_twice() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8882, Some(21101))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    // Both requested values fit the balance, but there is only one wallet UTXO.
+    // Until the first transaction is broadcast, its change does not exist and a
+    // safe second call must reject or select a different input, never reuse it.
+    fund_makers(
+        &makers,
+        &test_framework.bitcoind,
+        1,
+        Amount::from_sat(1_000_000),
+        AddressType::P2TR,
+    );
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    let first_address = maker
+        .wallet
+        .write()
+        .unwrap()
+        .get_next_external_address(AddressType::P2TR)
+        .unwrap();
+    let second_address = maker
+        .wallet
+        .write()
+        .unwrap()
+        .get_next_external_address(AddressType::P2TR)
+        .unwrap();
+
+    let (first_tx, _) = maker
+        .create_funding_transaction(Amount::from_sat(200_000), first_address, None)
+        .unwrap();
+    let first_inputs = first_tx
+        .input
+        .iter()
+        .map(|input| input.previous_output)
+        .collect::<HashSet<_>>();
+    assert!(!first_inputs.is_empty());
+
+    let second = maker.create_funding_transaction(
+        Amount::from_sat(200_000),
+        second_address,
+        None,
+    );
+    let no_conflict = second.is_err()
+        || second.unwrap().0.input.iter().all(|input| {
+            !first_inputs.contains(&input.previous_output)
+        });
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        no_conflict,
+        "a second unbroadcast Taproot funding transaction reused an input already pending in the first"
+    );
+}

```
