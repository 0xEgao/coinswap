# Expire pre-funding swaps that permanently reserve liquidity

- **Finding ID:** 17
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:741-746
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** d25a90c9a9b01470c6f496981ff29cf45e89c4ca8ccdfdadea7605144c61feda

## Description

`drain_idle_swaps` only selects stale entries whose `outgoing_swapcoins` vector is non-empty. A remotely initiated swap is inserted into `ongoing_swaps` as soon as `SwapDetails` is accepted, with its full `swap_amount` but before any outgoing swapcoin exists. If the taker disconnects at that point, the entry can never satisfy this filter and is never removed. `store_connection_state` later sums every non-completed entry (including these abandoned pre-funding states) as `reserved_liquidity`, so one taker can reserve the maker's advertised capacity indefinitely and cause all subsequent swaps to be rejected until process restart. No Bitcoin funds need to be committed and no continued connection is required. The PoC drives the real `handle_message` path to accept `SwapDetails`, makes the state idle, calls the production cleanup method, and shows `has_ongoing_swaps()` remains true on HEAD. A fix should remove stale pre-funding entries without launching fund recovery, while continuing to return funded swaps for recovery. Prior finding #3 was fetched and ruled out: #3 concerns duplicate-id state clobbering, whereas this defect occurs with a fresh unique id and ordinary disconnect.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -40,6 +40,7 @@ mod wallet_backup;
 
 mod concurrent_takers;
 mod duplicate_funding_outpoint;
+mod idle_prefunding_swap;
 mod fidelity_timelock_violation;
 mod funding_dynamic_splits;
 #[cfg(feature = "hotpath")]
diff --git a/tests/integration/idle_prefunding_swap.rs b/tests/integration/idle_prefunding_swap.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/idle_prefunding_swap.rs
@@ -0,0 +1,74 @@
+//! Pre-funding swaps must expire even though they have no swapcoins to recover.
+//! Otherwise their liquidity reservation survives forever after a disconnect.
+
+use std::{thread, time::Duration};
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::{handle_message, ConnectionState, MakerBehavior, SwapPhase},
+    protocol::common_messages::{
+        MakerToTakerMessage, ProtocolVersion, SwapDetails, TakerToMakerMessage,
+    },
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn idle_prefunding_swap_releases_its_liquidity_reservation() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8952, Some(21501))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    // Give validate_swap_parameters and store_connection_state real liquidity
+    // against which to account this remote swap request.
+    fund_makers(
+        &makers,
+        &test_framework.bitcoind,
+        2,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    // This is the state reached after the remote peer completes
+    // TakerHello -> GetOffer and then sends SwapDetails.
+    let mut connection = ConnectionState::new(ProtocolVersion::Legacy);
+    connection.phase = SwapPhase::AwaitingSwapDetails;
+    let response = handle_message(
+        maker,
+        &mut connection,
+        TakerToMakerMessage::SwapDetails(SwapDetails {
+            id: "abandoned-before-funding".to_string(),
+            protocol_version: ProtocolVersion::Legacy,
+            amount: Amount::from_sat(100_000),
+            tx_count: 1,
+            timelock: 20,
+            refund_locktime_offset: 20,
+        }),
+    )
+    .expect("valid swap details must be accepted");
+    assert!(matches!(
+        response,
+        Some(MakerToTakerMessage::AckSwapDetails(_))
+    ));
+    assert!(maker.has_ongoing_swaps());
+
+    // The peer disconnects before sending any contract data, so there are no
+    // outgoing_swapcoins. Once idle, the entry still has to be removed: it is
+    // counted as reserved liquidity by store_connection_state.
+    thread::sleep(Duration::from_millis(1));
+    let _ = maker.drain_idle_swaps(Duration::ZERO);
+    let reservation_leaked = maker.has_ongoing_swaps();
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        !reservation_leaked,
+        "idle pre-funding swap remained in ongoing_swaps and reserved liquidity forever"
+    );
+}
+
```
