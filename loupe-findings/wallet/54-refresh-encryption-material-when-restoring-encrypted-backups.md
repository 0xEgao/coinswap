# Refresh encryption material when restoring encrypted backups

- **Finding ID:** 54
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/backup.rs
- **Lines:** 113-120
- **CWE:** CWE-323
- **Fingerprint:** 3893e0b801104a8db4b4d97ce906ed71f25febab6b1057fe464a2c65ef672223

## Description

`Wallet::restore` forwards the supplied `restored_enc_material` directly into `WalletStore::init`. For encrypted backup flows that pass through the backup's decryption material, this reuses the exact AES-GCM key and nonce that protected the backup when encrypting the restored wallet store. AES-GCM requires a nonce to be unique for every plaintext encrypted under a key; reusing it turns the encryption into a two-time pad for the CTR keystream and can leak relationships between the encrypted backup plaintext (`WalletBackup`, including the xpriv) and the restored wallet store plaintext (`WalletStore`, also containing wallet secrets). An attacker who can read both encrypted files, such as a low-privilege local process, cloud-sync reader, or backup collector, does not need the passphrase to exploit the nonce reuse cryptographically. I searched prior findings for `restore encrypted backup KeyMaterial nonce reuse AES GCM WalletStore init` and found no matching report. The fix should derive or generate fresh encryption material, at minimum a fresh nonce, for the restored wallet store instead of persisting with the backup file's nonce.

## Proof of Concept

```diff
diff --git a/src/wallet/backup.rs b/src/wallet/backup.rs
index 5af1493..e15dbb4 100644
--- a/src/wallet/backup.rs
+++ b/src/wallet/backup.rs
@@ -208,3 +208,54 @@ impl Wallet {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    fn encrypted_cbor_nonce(path: &Path) -> Vec<u8> {
+        let content = std::fs::read(path).unwrap();
+        let value: serde_cbor::Value = serde_cbor::from_slice(&content).unwrap();
+        let serde_cbor::Value::Map(entries) = value else {
+            panic!("encrypted wallet store must be a CBOR map");
+        };
+
+        for (key, value) in entries {
+            if key == serde_cbor::Value::Text("nonce".to_string()) {
+                let serde_cbor::Value::Bytes(nonce) = value else {
+                    panic!("nonce must be encoded as bytes");
+                };
+                return nonce;
+            }
+        }
+
+        panic!("encrypted wallet store did not include a nonce");
+    }
+
+    #[test]
+    fn restoring_from_encrypted_backup_must_not_reuse_backup_nonce() {
+        let key_material = KeyMaterial::new_from_password(Some("backup password".to_string()))
+            .expect("password creates key material");
+        let master_key = Xpriv::new_master(Network::Bitcoin, &[7u8; 16]).unwrap();
+        let backup = WalletBackup {
+            network: Network::Bitcoin,
+            master_key,
+            wallet_birthday: Some(1),
+            file_name: "victim-wallet".to_string(),
+        };
+
+        let encrypted_backup = encrypt_struct(backup, &key_material).unwrap();
+        let backup_json = serde_json::to_value(&encrypted_backup).unwrap();
+        let backup_nonce = backup_json["nonce"]
+            .as_array()
+            .unwrap()
+            .iter()
+            .map(|byte| byte.as_u64().unwrap() as u8)
+            .collect::<Vec<_>>();
+
+        let temp_dir = bitcoind::tempfile::tempdir().unwrap();
+        let restored_wallet_path = temp_dir.path().join("restored-wallet");
+        WalletStore::init(
+            "restored-wallet".to_string(),
+            &restored_wallet_path,
+            Network::Bitcoin,
+            master_key,
+            Some(1),
+            &Some(key_material),
+        )
+        .unwrap();
+
+        assert_ne!(backup_nonce, encrypted_cbor_nonce(&restored_wallet_path));
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

