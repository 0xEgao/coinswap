# Require claimed Taproot contract outpoints to remain unspent

- **Finding ID:** 4
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/taproot_verification.rs:93-101
- **Job:** 2
- **CWE:** CWE-672
- **Fingerprint:** 7f4ab3790bb504971709daba3bb9f26ae491492b0943ae77e58208c3f8ee4ea2

## Description

The duplicate check only proves that each claimed `(txid, 0)` is distinct, while the per-transaction checks prove only that output zero once had the advertised value and script. They do not prove that the output is still unspent. The sole caller then invokes `verify_contract_tx_on_chain`, which checks transaction confirmations via `get_raw_transaction_info` but does not query the UTXO set, and sums every advertised amount before funding the next hop.

Consequently, confirmed transaction history can be counted as current backing. This includes a set where a later confirmed transaction spends an earlier claimed contract output and recreates another matching output, as well as replay of an already-consumed contract transaction. Both transaction IDs can satisfy the confirmation check and their output outpoints are distinct, but only the live output backs the maker's outgoing allocations. After an otherwise valid handover, the maker can release outgoing keys for the inflated total while being unable to sweep the spent incoming claims.

The regression test models the direct chained case by making the second claimed transaction consume the first claim; HEAD accepts both and double-counts the amount. A complete fix should verify each exact outpoint is currently unspent before committing outgoing funds. Searches for `spent contract output`, `funding replay`, and `duplicate funding` returned no prior matches.

## Proof of Concept

```diff
diff --git a/src/maker/taproot_verification.rs b/src/maker/taproot_verification.rs
--- a/src/maker/taproot_verification.rs
+++ b/src/maker/taproot_verification.rs
@@ -484,4 +484,21 @@ mod tests {
 
         assert!(verify_taproot_contract_data(&data, MAKER_TIMELOCK, 0).is_err());
     }
+
+    #[test]
+    fn rejects_contract_output_spent_by_another_claimed_contract() {
+        let mut data = valid_contract_data();
+        let spent_outpoint = OutPoint::new(data.contract_txs[0].compute_txid(), 0);
+        let mut replacement = data.contract_txs[0].clone();
+        replacement.input[0].previous_output = spent_outpoint;
+
+        data.pubkeys.push(data.pubkeys[0]);
+        data.internal_keys.push(data.internal_keys[0]);
+        data.tap_tweaks.push(data.tap_tweaks[0].clone());
+        data.timelock_scripts.push(data.timelock_scripts[0].clone());
+        data.contract_txs.push(replacement);
+        data.amounts.push(data.amounts[0]);
+
+        assert!(verify_taproot_contract_data(&data, MAKER_TIMELOCK, 0).is_err());
+    }
 }

```
