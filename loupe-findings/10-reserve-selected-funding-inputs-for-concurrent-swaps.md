# Reserve selected funding inputs for concurrent swaps

- **Finding ID:** 10
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/api.rs
- **Lines:** 1152-1158
- **CWE:** CWE-362
- **Fingerprint:** 2dd187862bbe47b434b12ea727d08c82402495fa61bb262e825c033fbe24be07

## Description

`collect_excluded_utxos` is the API used to prevent concurrent maker swaps from selecting coins already committed to another in-flight swap, but the state it returns is populated with the newly-created funding transaction outputs rather than the wallet input outpoints consumed by those funding transactions. The wallet coin selector excludes by spendable UTXO outpoint, so excluding the pending contract/funding outputs has no effect on the original wallet coins. With one large maker UTXO and two simultaneous swaps whose total amount is within the liquidity accounting, both swaps can select and sign funding transactions spending the same wallet input. One broadcast succeeds and the other fails or leaves the peer in recovery after it has already locked its own contract funds, making this a remotely triggerable funds-locking/DoS race against maker liquidity. I searched prior findings for `reserve_utxo collect_excluded_utxos funding transaction outputs inputs double spend liquidity` and `collect_excluded_utxos reserve_utxo funding outputs selected inputs concurrent takers double spend`; neither matched. A fix should carry the selected input outpoints from `create_funding_txes` into `reserve_utxo` and keep them excluded until the swap completes or recovery releases them.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
index dc113ce..1d11d42 100644
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -1527,3 +1527,18 @@ impl MakerRpc for MakerServer {
         )
     }
 }
+
+#[cfg(test)]
+mod reservation_security_tests {
+    #[test]
+    fn swap_reservations_record_wallet_inputs_not_created_contract_outputs() {
+        let legacy = include_str!("legacy_handlers.rs");
+        let taproot = include_str!("taproot_handlers.rs");
+
+        assert!(
+            !legacy.contains("(0..tx.output.len()).map(move |vout| bitcoin::OutPoint")
+                && !taproot.contains("state.reserve_utxo = vec![contract_outpoint]"),
+            "reserved UTXOs must be the wallet input outpoints selected for the maker funding transaction; recording newly-created funding outputs does not exclude the spent wallet coins from concurrent swaps"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

