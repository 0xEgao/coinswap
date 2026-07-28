# Reject oversized swap identifiers before storing protocol state

- **Finding ID:** 24
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:825-877
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** e316011ebd6674e89a63923119abce0c43dbe92d187375b9fb686d54e420c229

## Description

`SwapDetails` documents `id` as a unique 8-byte identifier (the in-tree taker renders those eight bytes as 16 hex characters), but `validate_swap_parameters` imposes no length or format bound. The network layer accepts messages up to 10 MiB. After validation, the attacker-controlled string is cloned into the per-connection state, cloned again as the `ongoing_swaps` HashMap key, and repeatedly logged. Accepted entries live for at least the idle timeout and reserve only the chosen swap amount, so a funded maker can accumulate many multi-megabyte identifiers; concurrent rejected connections also cause large transient allocations. This permits unauthenticated memory and log-volume exhaustion far beyond the fixed-size identifier the protocol requires. The PoC gives a real funded MakerServer otherwise-valid Legacy details with a one-megabyte id and asserts validation rejects it. HEAD accepts it. A fix should enforce the canonical 8-byte/16-hex representation before any state insertion or logging of the full identifier. Prior searches for `SwapDetails id length memory`, `oversized swap id denial service`, and `validate swap id 8 byte` returned no findings. Prior #3 concerns duplicate canonical IDs and is not this unbounded-size defect.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -47,6 +47,7 @@
 mod hotpath_profile;
 mod legacy_malformed_contract;
 mod legacy_missing_contract_cache;
 mod liquidity_test;
+mod oversized_swap_id;
 mod offerbook_sync_race;
 mod taker_cli;
diff --git a/tests/integration/oversized_swap_id.rs b/tests/integration/oversized_swap_id.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/oversized_swap_id.rs
@@ -0,0 +1,52 @@
+//! Swap identifiers are fixed-size protocol identifiers, not bulk payload storage.
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
+fn maker_rejects_oversized_swap_identifier() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8992, Some(21901))],
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
+        // The wire reader permits payloads up to 10 MiB. One MiB is sufficient
+        // to prove validation treats attacker bulk data as a state-map key.
+        id: "a".repeat(1024 * 1024),
+        protocol_version: ProtocolVersion::Legacy,
+        amount: Amount::from_sat(100_000),
+        tx_count: 1,
+        timelock: 20,
+        refund_locktime_offset: 20,
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
+        "maker accepted a one-megabyte swap id despite the protocol's fixed 8-byte identifier"
+    );
+}

```
