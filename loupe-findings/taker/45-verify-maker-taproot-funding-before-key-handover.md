# Verify maker Taproot funding before key handover

- **Finding ID:** 45
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/taproot_swap.rs
- **Lines:** 281-363
- **CWE:** CWE-345
- **Fingerprint:** 4d96ad722cdd2e3de2bd69c04353a53fdad4cbc490068f4150deaddba4afe985

## Description

`exchange_taproot` accepts a maker's `TaprootContractData`, creates the taker's incoming swapcoin, and later finalization sends the taker's outgoing private key to that maker chain without first proving the maker's advertised Taproot contract transaction is actually confirmed or even present on chain. The maker-side handler verifies the taker's funding tx before proceeding, and the legacy taker path waits for each maker funding transaction, but this Taproot taker path only waits for the taker's own outgoing funding. A malicious last maker can return a well-formed but unbroadcast contract transaction, then during finalization receive the taker's outgoing private key and spend the taker's confirmed outgoing contract while the taker's incoming sweep later finds no maker-funded UTXO to claim. I searched prior findings for `taproot maker contract on chain confirmation private key handover taker exchange_taproot` and found no duplicate. A fix should verify each maker contract txid/output is on chain with the required confirmations before allowing private-key handover.

## Proof of Concept

```diff
diff --git a/src/taker/taproot_swap.rs b/src/taker/taproot_swap.rs
--- a/src/taker/taproot_swap.rs
+++ b/src/taker/taproot_swap.rs
@@ -576,5 +576,29 @@
 
         log::info!("Contract transactions broadcast and confirmed");
         Ok(())
+    }
+}
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn taproot_exchange_waits_for_maker_contracts_before_handover() {
+        let source = include_str!("taproot_swap.rs");
+        let start = source
+            .find("pub(crate) fn exchange_taproot")
+            .expect("exchange_taproot should exist");
+        let end = source[start..]
+            .find("/// Build contract data from our outgoing swapcoins")
+            .map(|offset| start + offset)
+            .expect("exchange_taproot should end before exchange_build_from_outgoing");
+        let body = &source[start..end];
+
+        assert!(
+            body.contains("maker_contract")
+                && (body.contains("wait_for_tx_confirmation")
+                    || body.contains("verify_contract_tx_on_chain")
+                    || body.contains("get_tx_out")),
+            "Taproot taker must verify each maker contract transaction is actually on chain before proceeding to private-key handover"
+        );
     }
 }

```

## Suggested Fix

```diff
No suggested fix emitted.
```

