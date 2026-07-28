# Bind Legacy fee duration to the validated timelock

- **Finding ID:** 36
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:826-885
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 0700bfc9798ced81321c941944244d8ab7fe72bb7172cbac37e7c5502d4c237f

## Description

`validate_swap_parameters` applies the Legacy minimum-reaction-time check only to `SwapDetails::timelock`, but `calculate_swap_fee` is called with the independent, taker-controlled `refund_locktime_offset`. The in-tree taker sets these fields to the same relative duration for Legacy swaps, yet the maker never enforces that invariant or even requires a nonzero fee offset. A remote taker can therefore propose `timelock = 20` (passing the safety check) and `refund_locktime_offset = 0`; the maker accepts and records a fee with no time-relative component. The later Legacy `ProofOfFunding::refund_locktime` is also independently taker-controlled and is used to overwrite the final service fee, so the peer can keep the duration at zero through completion while supplying incoming contracts with the required reaction-time delta. This repeatably bypasses the maker's advertised time-relative fee without requiring a malformed contract. The PoC funds a real maker, submits otherwise-valid Legacy details with the split values, and requires parameter validation to reject them; HEAD returns `Ok`. A fix should bind Legacy pricing to the validated relative timelock (and enforce the same value in later proof-of-funding processing). Prior finding #18 was reviewed and is distinct: it covers pricing a future absolute Taproot CLTV height with an unrelated offset, whereas this report covers the Legacy relative-timelock branch and its later Legacy proof field.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -46,6 +46,7 @@
 mod hotpath_profile;
 mod legacy_malformed_contract;
 mod legacy_missing_contract_cache;
+mod legacy_fee_offset_validation;
 mod liquidity_test;
 mod offerbook_sync_race;
 mod taker_cli;
diff --git a/tests/integration/legacy_fee_offset_validation.rs b/tests/integration/legacy_fee_offset_validation.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/legacy_fee_offset_validation.rs
@@ -0,0 +1,53 @@
+//! Legacy swap pricing must use the same relative lock duration that the maker
+//! validates for contract safety.
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
+fn maker_rejects_zero_priced_legacy_timelock() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8982, Some(21801))],
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
+    let details = SwapDetails {
+        id: "0011223344556677".to_string(),
+        protocol_version: ProtocolVersion::Legacy,
+        amount: Amount::from_sat(100_000),
+        tx_count: 1,
+        // This duration passes the Legacy safety check.
+        timelock: 20,
+        // This independent value is what calculate_swap_fee actually uses.
+        refund_locktime_offset: 0,
+    };
+    let accepted = maker.validate_swap_parameters(&details).is_ok();
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        !accepted,
+        "maker accepted a 20-block Legacy lock while charging a zero-block time fee"
+    );
+}

```
