# Bind Taproot fee duration to the actual contract timelock

- **Finding ID:** 18
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:825-875
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 07f6fbff399d6ffb29e079fafade9d94520ec3456ee838b6a55d0facb3fcac32

## Description

`validate_swap_parameters` validates the Taproot absolute `timelock` only for nonzero (and, separately reported in #2, not against chain height), but never validates `refund_locktime_offset`. These two taker-controlled fields have different security roles: the contract scripts use `details.timelock`, while `handle_swap_details` and the final Taproot handler pass `refund_locktime_offset` to `calculate_swap_fee`. A taker can therefore choose a valid far-future CLTV height while setting the fee duration to zero. The maker funds a contract for the full requested lock interval but silently omits the advertised time-relative fee, causing repeatable economic loss whose size scales with amount, lock duration, and the configured percentage. The PoC funds a real test maker, constructs a 500-block-future Taproot proposal with a zero fee offset, and asserts parameter validation rejects it; HEAD accepts it. A fix must bind the charged duration to the actual remaining absolute timelock (with an appropriate height tolerance) rather than trusting an independent lower taker value. Prior searches for `refund_locktime_offset fee validation`, `time relative fee bypass timelock`, and `SwapDetails refund offset` returned no findings; #2 is distinct because it addresses already-expired CLTV values, not fee underpricing of otherwise future contracts.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -51,5 +51,6 @@
 mod taker_cli;
 mod taproot_concurrent_takers;
 mod taproot_contract_validation;
+mod taproot_fee_offset_validation;
 mod taproot_taker_contract_validation;
 mod utxo_behavior;
diff --git a/tests/integration/taproot_fee_offset_validation.rs b/tests/integration/taproot_fee_offset_validation.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/taproot_fee_offset_validation.rs
@@ -0,0 +1,56 @@
+//! A Taproot taker must not be allowed to price a future absolute timelock as
+//! zero blocks. The maker uses refund_locktime_offset for its time-based fee.
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::{MakerBehavior, MakerTrait},
+    protocol::common_messages::{ProtocolVersion, SwapDetails},
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn maker_rejects_zero_fee_offset_for_future_taproot_timelock() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8962, Some(21601))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    fund_makers(
+        &makers,
+        &test_framework.bitcoind,
+        2,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    let current_height = maker.get_current_height().unwrap();
+    let future_blocks = 500u16;
+    let details = SwapDetails {
+        id: "zero-priced-timelock".to_string(),
+        protocol_version: ProtocolVersion::Taproot,
+        amount: Amount::from_sat(100_000),
+        tx_count: 1,
+        timelock: current_height + future_blocks as u32,
+        // This is the value calculate_swap_fee uses, independently of the
+        // actual 500-block contract lock above.
+        refund_locktime_offset: 0,
+    };
+
+    let accepted = maker.validate_swap_parameters(&details).is_ok();
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        !accepted,
+        "maker accepted a 500-block Taproot lock while charging a zero-block time fee"
+    );
+}
+
```
