# Generate a fresh AES-GCM nonce for every wallet encryption

- **Finding ID:** 33
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/security.rs
- **Lines:** 241-256
- **CWE:** CWE-323
- **Fingerprint:** cde07c0249bdb2d31064f558f0a815352f7d6a1ea166cccfe8c8c849e4ec86d3

## Description

`KeyMaterial` stores a single AES-GCM nonce and `encrypt_struct` copies `enc_material.nonce` into every `EncryptedData` it produces. Wallet loading preserves that same `KeyMaterial` in `Wallet::store_enc_material`, and repeated calls to `WalletStore::write_to_disk`/`sync_and_save` encrypt changing wallet state with the same passphrase-derived key and nonce. AES-GCM requires nonce uniqueness per key; reusing a nonce across snapshots leaks relationships between plaintexts and can enable practical recovery of wallet fields when an attacker can read two encrypted versions of the wallet file from backups, filesystem snapshots, sync tooling, or another local read primitive. The plaintext format is structured CBOR and wallet saves occur frequently as indexes, UTXO state, swapcoins, and secrets are updated, so this is not just theoretical helper misuse. I searched prior findings for `security encrypt_struct AES GCM nonce reuse KeyMaterial wallet write_to_disk` and `nonce reuse AES-GCM wallet encryption` and found no duplicate. A fix should generate a fresh random nonce inside each encryption operation and store that nonce alongside the ciphertext, while keeping only the PBKDF2 salt/key material reusable.

## Proof of Concept

```diff
diff --git a/src/security.rs b/src/security.rs
index 4c7f1a2..0000000 100644
--- a/src/security.rs
+++ b/src/security.rs
@@ -336,3 +336,26 @@ pub fn load_sensitive_struct<T: DeserializeOwned, F: SerdeFormat>(
 
     (sensitive_struct, encryption_material)
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[derive(Serialize)]
+    struct SecretSnapshot {
+        counter: u64,
+        secret: String,
+    }
+
+    #[test]
+    fn encrypt_struct_uses_a_fresh_nonce_for_each_encryption() {
+        let material = KeyMaterial::new_from_password(Some("wallet-passphrase".to_string()))
+            .expect("password should produce key material");
+
+        let first = encrypt_struct(
+            SecretSnapshot { counter: 1, secret: "wallet seed and swap state".to_string() },
+            &material,
+        ).unwrap();
+        let second = encrypt_struct(
+            SecretSnapshot { counter: 2, secret: "wallet seed and swap state".to_string() },
+            &material,
+        ).unwrap();
+
+        assert_ne!(first.nonce, second.nonce, "AES-GCM nonce must not be reused with the same key");
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

