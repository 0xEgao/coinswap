# Honor the configured confirmation depth for Legacy funding

- **Finding ID:** 21
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1299-1364
- **Job:** 3
- **CWE:** CWE-693
- **Fingerprint:** f6a9fbb606c154ceee956ab2dc84b2d31e994a4dd562c733b8869df0f4bad5d5

## Description

`verify_proof_of_funding` imports the global `REQUIRED_CONFIRMS` constant (fixed at 1) and compares every Legacy funding output against it, ignoring `self.config.required_confirms`. The maker advertises the configurable value in its `Offer`, and the Taproot path correctly uses `self.config.required_confirms.max(1)`, so an operator who requires a deeper confirmation margin receives no such protection for Legacy swaps. A taker can intentionally proceed after one confirmation; the maker then constructs and ultimately broadcasts its outgoing funding even when configured to require substantially more depth. This exposes principal to exactly the shallow reorganization/double-spend risk the setting is intended to bound. Exploiting a confirmed replacement may require a chain reorganization or miner cooperation, so severity is kept at medium. The PoC configures one real Legacy maker to require 100 confirmations while the taker waits for one. On HEAD the normal swap continues because the verifier checks the constant; after a fix it is rejected before outgoing funding. Prior search `Legacy confirmations REQUIRED_CONFIRMS config` and `verify_proof_of_funding required_confirms` returned no findings.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -46,5 +46,6 @@
 #[cfg(feature = "hotpath")]
 mod hotpath_profile;
 mod legacy_malformed_contract;
 mod legacy_missing_contract_cache;
+mod legacy_required_confirmations;
 mod liquidity_test;
diff --git a/tests/integration/legacy_required_confirmations.rs b/tests/integration/legacy_required_confirmations.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/legacy_required_confirmations.rs
@@ -0,0 +1,80 @@
+//! Legacy proof-of-funding must honor the maker's advertised confirmation depth.
+
+use std::{sync::atomic::Ordering::Relaxed, thread};
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::{start_server, MakerBehavior},
+    protocol::common_messages::ProtocolVersion,
+    taker::{SwapParams, TakerBehavior},
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+#[test]
+fn legacy_maker_requires_its_configured_confirmation_depth() {
+    let (test_framework, mut takers, mut makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8982, Some(21801)), (18982, Some(21802))],
+            vec![TakerBehavior::Normal],
+            vec![MakerBehavior::Normal, MakerBehavior::Normal],
+        );
+
+    // The taker will intentionally wait for only one confirmation. Whichever
+    // route position this maker occupies, its advertised policy must prevail.
+    std::sync::Arc::get_mut(&mut makers[0])
+        .expect("maker Arc must still be uniquely owned before server startup")
+        .config
+        .required_confirms = 100;
+
+    let bitcoind = &test_framework.bitcoind;
+    let taker = &mut takers[0];
+    fund_taker(
+        taker,
+        bitcoind,
+        3,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+    fund_makers(
+        &makers,
+        bitcoind,
+        4,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+
+    let maker_threads = makers
+        .iter()
+        .map(|maker| {
+            let maker = maker.clone();
+            thread::spawn(move || start_server(maker).unwrap())
+        })
+        .collect::<Vec<_>>();
+    wait_for_makers_setup(&makers, 120);
+    for maker in &makers {
+        maker.wallet.write().unwrap().sync_and_save().unwrap();
+    }
+
+    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
+        .with_tx_count(3)
+        .with_required_confirms(1);
+    generate_blocks(bitcoind, 1);
+    let summary = taker.prepare_coinswap(params).unwrap();
+    let result = taker.start_coinswap(&summary.swap_id);
+
+    makers
+        .iter()
+        .for_each(|maker| maker.shutdown.store(true, Relaxed));
+    maker_threads
+        .into_iter()
+        .for_each(|handle| handle.join().unwrap());
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        result.is_err(),
+        "Legacy maker accepted one-confirmation funding despite requiring 100 confirmations"
+    );
+}

```
