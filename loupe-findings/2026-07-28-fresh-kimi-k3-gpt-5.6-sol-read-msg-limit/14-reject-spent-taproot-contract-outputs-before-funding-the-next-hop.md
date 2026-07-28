# Reject spent Taproot contract outputs before funding the next hop

- **Finding ID:** 14
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:949-959
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 144ade4e8ed8430615231cccd3786d95ceacbc027f9149f8718bf8ec02b8eebf

## Description

`verify_contract_tx_on_chain` treats a successful verbose transaction lookup with enough confirmations as proof that the incoming Taproot contract still contributes value. It never queries the contract output's UTXO status. `process_taproot_contract` calls this check for each taker-supplied contract tx and, after it succeeds, sums the advertised (and transaction-bound) outputs and creates/broadcasts maker-funded outgoing contracts. A remote taker can therefore present a genuinely confirmed contract transaction after its output has already been spent (for example after its refund path matures); the historical transaction still reports confirmations, so the maker allocates outgoing funds against no live incoming asset. This can lose the outgoing swap amount. The regression test creates a confirmed output, spends and confirms that exact outpoint, verifies the node reports it absent from the UTXO set, then shows `verify_contract_tx_on_chain` still returns `Ok` on HEAD. A fix should bind the check to the expected output index and require `get_tx_out(..., include_mempool)` to return a live output at the required depth. Prior finding #2 was reviewed and is distinct: it covers accepting an already-expired absolute timelock, while this finding covers failure to establish that a confirmed contract output remains unspent, including delayed/raced contracts.

## Proof of Concept

```diff
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -52,4 +52,5 @@
 mod taproot_concurrent_takers;
 mod taproot_contract_validation;
+mod taproot_spent_contract;
 mod taproot_taker_contract_validation;
 mod utxo_behavior;
--- /dev/null
+++ b/tests/integration/taproot_spent_contract.rs
@@ -0,0 +1,79 @@
+//! A confirmed transaction is not proof that its output remains available.
+//! The maker must reject a Taproot incoming contract after its output is spent.
+
+use bitcoin::Amount;
+use bitcoind::bitcoincore_rpc::RpcApi;
+use coinswap::{
+    maker::{MakerBehavior, MakerTrait},
+    utill::MIN_FEE_RATE,
+    wallet::{AddressType, Destination},
+};
+
+use super::test_framework::*;
+
+#[test]
+fn maker_rejects_spent_confirmed_taproot_contract() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8902, Some(21401))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let bitcoind = &test_framework.bitcoind;
+    let maker = &makers[0];
+
+    // Create and confirm an output owned by the maker wallet. It stands in for
+    // the output of the incoming Taproot contract transaction.
+    let contract_address = maker
+        .wallet
+        .write()
+        .unwrap()
+        .get_next_external_address(AddressType::P2TR)
+        .unwrap();
+    let contract_txid = send_to_address(bitcoind, &contract_address, Amount::from_sat(100_000));
+    generate_blocks(bitcoind, 1);
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    let contract_coin = maker
+        .wallet
+        .read()
+        .unwrap()
+        .list_descriptor_utxo_spend_info()
+        .into_iter()
+        .find(|(utxo, _)| utxo.txid == contract_txid)
+        .expect("confirmed contract output must be visible");
+    let contract_vout = contract_coin.0.vout;
+
+    // Spend that exact output and confirm the spend. The original transaction
+    // remains confirmed, but it no longer contributes any value to the swap.
+    let sink = bitcoind
+        .client
+        .get_new_address(None, None)
+        .unwrap()
+        .assume_checked();
+    let spend = maker
+        .wallet
+        .write()
+        .unwrap()
+        .spend_from_wallet(MIN_FEE_RATE, Destination::Sweep(sink), &[contract_coin])
+        .unwrap();
+    bitcoind.client.send_raw_transaction(&spend).unwrap();
+    generate_blocks(bitcoind, 1);
+    assert!(
+        bitcoind
+            .client
+            .get_tx_out(&contract_txid, contract_vout, None)
+            .unwrap()
+            .is_none(),
+        "test setup must spend the contract output"
+    );
+
+    let result = maker.verify_contract_tx_on_chain(&contract_txid);
+    assert!(
+        result.is_err(),
+        "maker accepted a confirmed transaction whose contract output was already spent"
+    );
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+}

```
