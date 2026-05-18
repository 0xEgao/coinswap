# Propagate descriptor import failures before marking wallet synced

- **Finding ID:** 60
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/rpc.rs
- **Lines:** 168-237
- **CWE:** CWE-252
- **Fingerprint:** d62085cc581e4359a88fbc3c01c3a7fe69503c4e95dff427f47c9dbf5126509f

## Description

`sync` calls `self.import_descriptors(...)` and discards the `Result`, then records `last_synced_height = node_synced` and rebuilds the UTXO cache. `import_descriptors` also discards the `importdescriptors` response body, even though Bitcoin Core reports per-descriptor failures as result objects rather than necessarily failing the whole RPC. If any HD, swapcoin, contract, or fidelity descriptor is not actually imported, the wallet advances its sync checkpoint and proceeds as if it is watching those scripts. An attacker who can trigger an import failure during a swap, or an untrusted/malicious RPC backend returning `success:false`, can leave contract/fidelity outputs unwatched while the protocol continues, causing missed recovery or claim windows and potential fund loss. The fix should propagate the RPC error from `sync` and inspect every `importdescriptors` result for `success == true` before updating sync state. I searched prior findings for `import_descriptors importdescriptors success false ignored rpc wallet last_synced_height` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/rpc.rs b/src/wallet/rpc.rs
index 19e6c65..e6c765d 100644
--- a/src/wallet/rpc.rs
+++ b/src/wallet/rpc.rs
@@ -258,3 +258,21 @@ impl Wallet {
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod tests {
+    #[test]
+    fn descriptor_import_failures_are_not_ignored() {
+        let source = include_str!("rpc.rs");
+
+        assert!(
+            !source.contains("let _ = self.import_descriptors"),
+            "sync must propagate descriptor import RPC failures before advancing last_synced_height"
+        );
+
+        assert!(
+            !source.contains("let _res: Vec<Value> = self.rpc.call(\"importdescriptors\"")
+                && !source.contains("let _: Vec<Value> = self.rpc.call(\"importdescriptors\""),
+            "import_descriptors must inspect every importdescriptors result object for success=false"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

