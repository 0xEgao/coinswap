# Treat empty GUI backup password as no encryption

- **Finding ID:** 56
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/ffi.rs
- **Lines:** 94-101
- **CWE:** CWE-521
- **Fingerprint:** 2ce0ccb53c343df9c8097ffbf86e7952eb1e466073983b8f4f01eb6256805609

## Description

`backup_wallet_gui_app` passes the FFI password option directly to `KeyMaterial::new_from_password`. The wrapper documentation says `None` or an empty string should create a plaintext backup, but `Some("")` instead derives AES-GCM key material from an empty passphrase and writes an `EncryptedData` backup. That produces a file that appears encrypted to the application, while anyone who obtains it can decrypt the wallet master key using the well-known empty password. This is especially easy for GUI bindings to hit because empty password fields are commonly represented as `Some("")` rather than `None`. The wrapper should normalize empty strings before constructing key material, or reject them when encryption is requested. I searched prior findings for `backup_wallet_gui_app empty password KeyMaterial new_from_password encrypted empty passphrase` and `KeyMaterial new_from_password empty password backup encryption wallet backup`; neither returned a duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/ffi.rs b/src/wallet/ffi.rs
--- a/src/wallet/ffi.rs
+++ b/src/wallet/ffi.rs
@@ -173,3 +173,18 @@ impl Wallet {
         Ok(txid)
     }
 }
+
+#[cfg(test)]
+mod ffi_backup_password_tests {
+    use crate::security::KeyMaterial;
+
+    #[test]
+    fn empty_gui_backup_password_does_not_create_empty_passphrase_encryption() {
+        let key_material = KeyMaterial::new_from_password(Some(String::new()));
+
+        assert!(
+            key_material.is_none(),
+            "empty GUI backup passwords must be treated the same as no password"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

