# Constrain GUI restore wallet filename to basename

- **Finding ID:** 55
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/ffi.rs
- **Lines:** 49-55
- **CWE:** CWE-22
- **Fingerprint:** 77c007c24d391e44512f123a1c478f82a181dec6c76e95aaf9d73896a72ce676

## Description

`restore_wallet_gui_app` treats the FFI `wallet_file_name` parameter as a path component and appends it directly below `{data_dir}/wallets`. A GUI or other FFI caller that intends to let an untrusted user choose only a wallet filename can be bypassed with values such as `../outside-wallet` or nested paths. The restore path then escapes the intended `wallets/` directory before being handed to `Wallet::restore`, which initializes and writes a wallet store at that path before later RPC synchronization. This gives the attacker an arbitrary file creation/truncation primitive within the process permissions, and can overwrite files outside the wallet directory with serialized wallet contents. I searched prior findings for `restore_wallet_gui_app wallet_file_name path traversal wallets join` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/ffi.rs b/src/wallet/ffi.rs
--- a/src/wallet/ffi.rs
+++ b/src/wallet/ffi.rs
@@ -173,3 +173,24 @@ impl Wallet {
         Ok(txid)
     }
 }
+
+#[cfg(test)]
+mod ffi_restore_path_tests {
+    use std::path::{Component, PathBuf};
+
+    #[test]
+    fn restore_wallet_gui_app_rejects_parent_dir_wallet_file_names() {
+        let data_dir = PathBuf::from("/tmp/coinswap-ffi-restore");
+        let wallet_file_name = "../outside-wallet".to_string();
+
+        let restored_wallet_path = data_dir
+            .clone()
+            .join("wallets")
+            .join(wallet_file_name);
+
+        assert!(
+            !restored_wallet_path
+                .components()
+                .any(|component| matches!(component, Component::ParentDir)),
+            "GUI restore wallet names must be constrained to a single file name under wallets/"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

