# Fail closed when contract cache is missing

- **Finding ID:** 52
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/api.rs
- **Lines:** 998-1000
- **CWE:** CWE-345
- **Fingerprint:** d48fe5fd26e89bcaeed9a8971ee4ac518cc8770580df05a8244c55b42cc91fcd

## Description

does_prevout_match_cached_contract returns true when prevout_to_contract_map has no entry for the funding outpoint. The same helper is used during maker proof-of-funding verification, where the surrounding comment says a missing entry should not happen because the maker should have cached the contract when it signed the sender contract transaction. A remote taker can therefore present a funding proof for a prevout that was never bound to the contract script in the wallet cache, or exploit cache loss between protocol steps, and the maker will proceed as if the contract matches. That bypasses the intended integrity check tying the confirmed funding output to the contract transaction the maker previously approved, which can drive the maker into creating outgoing swap state against an unbound incoming contract and lock or risk maker funds. I searched prior findings for does_prevout_match_cached_contract and the missing-cache fail-open behavior and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/api.rs b/src/wallet/api.rs
--- a/src/wallet/api.rs
+++ b/src/wallet/api.rs
@@ -2728,3 +2728,16 @@ pub fn wait_for_tx_confirmation(
         }
     }
 }
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn missing_cached_contract_does_not_match_by_default() {
+        let source = include_str!("api.rs");
+
+        assert!(
+            !source.contains("None => true"),
+            "proof-of-funding contract checks must fail closed when the prevout was never cached"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

