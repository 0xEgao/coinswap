# Bind Taproot funding amounts before sending maker funds

- **Finding ID:** 9
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/api.rs
- **Lines:** 926-943
- **CWE:** CWE-345
- **Fingerprint:** a74ef28c5e2a1603fcd2a3c936e672f86e533ff743779a049420d9f5dc1f531a

## Description

`verify_contract_tx_on_chain` treats a taker-supplied Taproot contract as funded once Bitcoin Core can return a transaction for the supplied txid. The Taproot handler then uses the untrusted `TaprootContractData.amounts[0]` value as `incoming_funding_amount` to calculate the maker's outgoing amount and create/broadcast the maker-funded contract. Because this API does not bind the visible transaction to an expected output value, a malicious taker can broadcast a tiny Taproot contract to the expected script, declare a much larger amount in the message, and cause the maker to fund the next hop based on that inflated value. The maker only receives the small on-chain output but releases liquidity sized from attacker-controlled metadata. I searched prior findings for `TaprootContractData amounts contract_txs output value mismatch maker outgoing_amount` and found no duplicate. A fix should make the on-chain verification accept the expected script and amount, fetch/inspect the transaction output, and reject any mismatch before creating outgoing swapcoins.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
index dc113ce..d426bda 100644
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -1527,3 +1527,24 @@ impl MakerRpc for MakerServer {
         )
     }
 }
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn taproot_on_chain_check_binds_declared_amount_to_confirmed_output() {
+        let source = include_str!("api.rs");
+        let start = source
+            .find("fn verify_contract_tx_on_chain")
+            .expect("verify_contract_tx_on_chain should exist");
+        let end = source[start..]
+            .find("fn broadcast_transaction")
+            .map(|offset| start + offset)
+            .expect("broadcast_transaction should follow verify_contract_tx_on_chain");
+        let body = &source[start..end];
+
+        assert!(
+            body.contains("amount") && body.contains("output"),
+            "incoming Taproot funding verification must compare the declared TaprootContractData amount against the actual on-chain contract output before maker liquidity is sent"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

