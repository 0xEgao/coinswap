# Preserve the accepted fee duration across swap reconnections

- **Finding ID:** 20
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1152-1194
- **Job:** 3
- **CWE:** CWE-664
- **Fingerprint:** 31bd8e65cf2f45aca719fbbee054e753595842462609cb6c6e94df73719a8b6f

## Description

`ConnectionState::refund_locktime_offset` is accepted from `SwapDetails` and is the duration used for the final Taproot service-fee calculation, but `SwapState` has no corresponding field. Consequently, `store_connection_state` silently drops it and `get_connection_state` reconstructs a `ConnectionState` with the default value zero. The reconnect dispatcher then restores this stored state before processing Taproot contract data. A taker can negotiate a nonzero, correctly priced duration, disconnect, and resume by swap id; after the round trip the maker calculates the final fee with zero blocks and omits its advertised time-relative component. This remains exploitable even if initial `SwapDetails` validation is fixed to reject inconsistent fee offsets, so it is distinct from the separate input-validation finding. The PoC round-trips a nonzero offset through the real MakerServer state methods and shows it becomes zero on HEAD. A complete fix needs to add the field to `SwapState`, copy it in both directions here, and propagate it in the reconnect restore path. Prior searches for `refund_locktime_offset reconnect store_connection_state`, `SwapState refund fee persistence`, and `reconnection time fee zero` returned no findings.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -50,6 +50,7 @@
 mod offerbook_sync_race;
 mod taker_cli;
 mod taproot_concurrent_takers;
 mod taproot_contract_validation;
+mod swap_fee_state_persistence;
 mod taproot_taker_contract_validation;
 mod utxo_behavior;
diff --git a/tests/integration/swap_fee_state_persistence.rs b/tests/integration/swap_fee_state_persistence.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/swap_fee_state_persistence.rs
@@ -0,0 +1,43 @@
+//! The accepted fee-duration offset must survive MakerServer state storage.
+//! Reconnected Taproot handlers calculate the final service fee from this field.
+
+use coinswap::{
+    maker::{ConnectionState, MakerBehavior, MakerTrait, SwapPhase},
+    protocol::common_messages::ProtocolVersion,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn stored_swap_state_preserves_refund_locktime_offset() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8972, Some(21701))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    let mut accepted = ConnectionState::new(ProtocolVersion::Taproot);
+    accepted.swap_id = Some("fee-state-roundtrip".to_string());
+    accepted.phase = SwapPhase::AwaitingContractData;
+    accepted.refund_locktime_offset = 150;
+
+    maker
+        .store_connection_state("fee-state-roundtrip", &accepted)
+        .unwrap();
+    let restored = maker
+        .get_connection_state("fee-state-roundtrip")
+        .expect("stored swap state must be retrievable");
+    let restored_offset = restored.refund_locktime_offset;
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert_eq!(
+        restored_offset, 150,
+        "MakerServer dropped the fee duration while storing the swap state"
+    );
+}
+
```
