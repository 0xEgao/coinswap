# Rotate AES-GCM nonce on every wallet save

- **Finding ID:** 61
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/storage.rs
- **Lines:** 124-131
- **CWE:** CWE-323
- **Fingerprint:** 3360ee258a4da1413b71fe1a05e52234da9c44f3b25c4084ab29b4fd632fa407

## Description

`WalletStore::write_to_disk` encrypts every wallet save with the `KeyMaterial` stored on the `Wallet`, and `encrypt_struct` uses the nonce embedded in that material. `KeyMaterial` is generated once when the wallet is created or loaded, then reused for subsequent `save_to_disk` calls. As a result, an encrypted wallet file is repeatedly written under the same AES-GCM key/nonce pair as wallet state changes. An adversary who can read multiple versions of the encrypted wallet file, for example through backups, file sync history, or local read access over time, can compare ciphertexts encrypted with the same GCM stream and learn relationships between the serialized wallet plaintexts; GCM nonce reuse also weakens authenticity and can enable forgeries once enough information is known. The wallet plaintext includes the master extended private key and swap/private-key material, so cryptographic leakage from repeated saves has direct fund-exfiltration impact. I searched prior findings for `WalletStore write_to_disk AES GCM nonce reuse KeyMaterial nonce encrypted wallet storage` and found no duplicate. A fix should generate a fresh random nonce for each encryption and persist that nonce with the ciphertext, updating the in-memory material or separating static key material from per-write nonces.

## Proof of Concept

```diff
diff --git a/src/wallet/storage.rs b/src/wallet/storage.rs
--- a/src/wallet/storage.rs
+++ b/src/wallet/storage.rs
@@ -157,7 +157,15 @@ mod tests {
     use super::*;
     use bip39::rand::{thread_rng, Rng};
     use bitcoind::tempfile::tempdir;
+    use serde::Deserialize;
 
+    #[derive(Deserialize)]
+    struct StoredEncryptedData {
+        nonce: [u8; 12],
+        encrypted_payload: Vec<u8>,
+        pbkdf2_salt: [u8; 16],
+    }
+
     #[test]
     fn test_write_and_read_wallet_to_disk() {
         let temp_dir = tempdir().unwrap();
@@ -185,4 +193,43 @@ mod tests {
         let (read_wallet, _nonce) = WalletStore::read_from_disk(&file_path, String::new()).unwrap();
         assert_eq!(original_wallet_store, read_wallet);
     }
+
+    #[test]
+    fn encrypted_wallet_save_rotates_aes_gcm_nonce() {
+        let temp_dir = tempdir().unwrap();
+        let file_path = temp_dir.path().join("encrypted_wallet.cbor");
+        let enc_material = KeyMaterial::new_from_password(Some("correct horse battery staple".to_string()))
+            .unwrap();
+
+        let master_key = {
+            let seed: [u8; 16] = thread_rng().gen();
+            Xpriv::new_master(Network::Bitcoin, &seed).unwrap()
+        };
+
+        let mut wallet_store = WalletStore::init(
+            "encrypted_wallet".to_string(),
+            &file_path,
+            Network::Bitcoin,
+            master_key,
+            None,
+            &Some(enc_material.clone()),
+        )
+        .unwrap();
+
+        let first_write: StoredEncryptedData =
+            serde_cbor::from_slice(&fs::read(&file_path).unwrap()).unwrap();
+
+        wallet_store.external_index = wallet_store.external_index.saturating_add(1);
+        wallet_store
+            .write_to_disk(&file_path, &Some(enc_material))
+            .unwrap();
+
+        let second_write: StoredEncryptedData =
+            serde_cbor::from_slice(&fs::read(&file_path).unwrap()).unwrap();
+
+        assert_ne!(
+            first_write.nonce, second_write.nonce,
+            "each AES-GCM encryption under the same wallet key must use a fresh nonce"
+        );
+    }
 }

```

## Suggested Fix

```diff
No suggested fix emitted.
```

