# Require encryption before serializing wallet backup secrets

- **Finding ID:** 53
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/backup.rs
- **Lines:** 69-72
- **CWE:** CWE-312
- **Fingerprint:** f6f8d865b8a2aa5205d7b14f86af385ad6b54467a455ae5c1eba9925c3df6735

## Description

When `Wallet::backup` is called without `backup_enc_material`, it serializes `WalletBackup` directly as pretty JSON. `WalletBackup` includes the wallet `master_key` (`Xpriv`), so the resulting backup file contains the complete private root key in cleartext. The CLI backup flow defaults to this branch unless the user passes `--encrypt`, and `File::create` writes the file using normal process umask-derived permissions. On common multi-user systems or in backup/sync folders, another local user, indexing service, or compromised low-privilege process that can read the backup JSON can recover the xpriv and spend all funds controlled by that wallet. I searched prior findings for `backup master_key plaintext unencrypted wallet backup file permissions` and found no matching report. The PoC adds a regression test showing that the unencrypted serialization path exposes the exact master xpriv; a fix could require encryption for backups, refuse `None`, or otherwise avoid writing raw `Xpriv` material to plaintext JSON.

## Proof of Concept

```diff
diff --git a/src/wallet/backup.rs b/src/wallet/backup.rs
index 5af1493..4fd8b7a 100644
--- a/src/wallet/backup.rs
+++ b/src/wallet/backup.rs
@@ -208,3 +208,22 @@ impl Wallet {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn unencrypted_wallet_backup_does_not_expose_master_key() {
+        let master_key = Xpriv::new_master(Network::Bitcoin, &[7u8; 16]).unwrap();
+        let master_key_text = master_key.to_string();
+        let backup = WalletBackup {
+            network: Network::Bitcoin,
+            master_key,
+            wallet_birthday: Some(1),
+            file_name: "victim-wallet".to_string(),
+        };
+
+        let serialized = serde_json::to_string_pretty(&backup).unwrap();
+
+        assert!(!serialized.contains(&master_key_text));
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

