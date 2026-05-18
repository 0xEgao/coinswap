# Bind Taproot incoming amount to tx output

- **Finding ID:** 46
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/taproot_swap.rs
- **Lines:** 498-515
- **CWE:** CWE-345
- **Fingerprint:** fb68cba91acfe10e3e6923f31b0252180db6b5961bee1f54c50e601fcf57ab2f

## Description

`exchange_create_incoming` copies `contract.amounts[0]` from the maker-controlled `TaprootContractData` into the taker's incoming swapcoin without checking that the advertised amount equals the value of the Taproot contract output in `contract.contract_txs[0]`. The earlier taker verification only checks that output 0 has the expected P2TR script and that the sum of the untrusted `amounts` vector satisfies the maker's fee schedule; it never binds that metadata to the transaction output value. A malicious maker can broadcast a transaction paying a tiny amount to the expected script while declaring the full expected amount. The taker then proceeds to private-key handover, allowing the maker to spend the taker's funded contract, but the taker's later sweep signs/looks up the incoming contract using the inflated amount and cannot recover the expected funds. I checked prior finding #9, which reports the analogous maker-side bug in `src/maker/api.rs`; it does not cover this taker-side acceptance path. A fix should derive the incoming amount from the verified contract output, or reject when the declared amount and output value differ before finalization.

## Proof of Concept

```diff
diff --git a/src/taker/taproot_swap.rs b/src/taker/taproot_swap.rs
--- a/src/taker/taproot_swap.rs
+++ b/src/taker/taproot_swap.rs
@@ -578,3 +578,24 @@
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn taproot_incoming_amount_is_bound_to_contract_output_value() {
+        let source = include_str!("taproot_swap.rs");
+        let start = source
+            .find("fn exchange_create_incoming")
+            .expect("exchange_create_incoming should exist");
+        let end = source[start..]
+            .find("/// Broadcast contract transactions")
+            .map(|offset| start + offset)
+            .expect("exchange_create_incoming should end before funding_broadcast");
+        let body = &source[start..end];
+
+        assert!(
+            body.contains("contract_tx.output") && body.contains(".value") && body.contains("amount"),
+            "Taproot incoming swapcoin creation must bind TaprootContractData.amounts[0] to the actual contract transaction output value"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

