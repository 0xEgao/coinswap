# Preserve unrelated UTXO locks during funding

- **Finding ID:** 59
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/funding.rs
- **Lines:** 139-288
- **CWE:** CWE-362
- **Fingerprint:** 19616ee0241c27498a4708abad174db8ca1d14f28d567bd6cfbc592dc3861bbb

## Description

The funding builders clear the entire Bitcoin Core wallet lock table with `unlock_unspent_all()` before and after selecting coins. These functions then lock only the UTXOs they select, but the final cleanup again releases every lock in the wallet rather than just the outpoints reserved by this funding attempt. Bitcoin Core wallet locks are process-wide state: if another swap or wallet operation has reserved UTXOs at the same time, either funding path can release those unrelated locks. A second concurrent funding attempt can then select and sign transactions spending the same coins. In a coinswap flow this can double-spend a participant's own funding transactions, invalidate already-negotiated contract transactions, and leave the participant unable to complete or recover the intended swap path. I did not rely on Bitcoin Core internals beyond the in-tree RPC usage semantics exposed here: the code explicitly calls the RPC to unlock all wallet UTXOs and then only tracks its own `locked_utxos` locally. Prior finding search for `funding unlock_unspent_all lock_unspent race UTXO locks` returned no matches.

## Proof of Concept

```diff
diff --git a/src/wallet/funding.rs b/src/wallet/funding.rs
--- a/src/wallet/funding.rs
+++ b/src/wallet/funding.rs
@@ -290,3 +290,46 @@ impl Wallet {
         result
     }
 }
+
+#[cfg(test)]
+mod tests {
+    fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
+        let sig = format!("fn {name}");
+        let start = source.find(&sig).expect("function signature exists");
+        let open = source[start..]
+            .find('{')
+            .map(|offset| start + offset)
+            .expect("function body starts");
+
+        let mut depth = 0usize;
+        for (offset, ch) in source[open..].char_indices() {
+            match ch {
+                '{' => depth += 1,
+                '}' => {
+                    depth -= 1;
+                    if depth == 0 {
+                        return &source[open..=open + offset];
+                    }
+                }
+                _ => {}
+            }
+        }
+        panic!("function body closes");
+    }
+
+    #[test]
+    fn funding_paths_do_not_clear_unrelated_wallet_locks() {
+        let source = include_str!("funding.rs");
+
+        for name in [
+            "create_funding_txes_regular_swaps",
+            "create_funding_txes_random_amounts",
+        ] {
+            let body = function_body(source, name);
+            assert!(
+                !body.contains("unlock_unspent_all"),
+                "{name} must not call unlock_unspent_all(); clearing the whole Bitcoin Core wallet lock table releases UTXOs reserved by concurrent swaps or other wallet operations"
+            );
+        }
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

