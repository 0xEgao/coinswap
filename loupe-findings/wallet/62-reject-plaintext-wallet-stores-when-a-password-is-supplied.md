# Reject plaintext wallet stores when a password is supplied

- **Finding ID:** 62
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/storage.rs
- **Lines:** 148-149
- **CWE:** CWE-345
- **Fingerprint:** 4ecca3689a32353ee9b12116a8efeecd3b0f850aa42ba4ce5ce749140d877879

## Description

`WalletStore::read_from_disk` always delegates to `load_sensitive_struct` with `Some(password)`, but that loader first attempts to parse the file as a plaintext `WalletStore` and returns it before trying the encrypted wrapper. Therefore a caller that supplies a non-empty wallet password does not actually require the wallet file to be encrypted or authenticated. An attacker with write access to the wallet path, but without the victim's wallet passphrase, can replace an encrypted wallet store with a plaintext store containing an attacker-chosen master key, matching `file_name`, and the expected network. On the next load, the password is ignored because plaintext parsing succeeds, `store_enc_material` becomes `None`, and later saves continue in plaintext. Existing funds under the old key are not immediately spendable by the attacker, but future deposits or newly generated receive/change addresses can be redirected to keys the attacker controls, and the encrypted-at-rest guarantee is silently downgraded. I searched prior findings for `WalletStore read_from_disk plaintext encrypted downgrade password load_sensitive_struct unencrypted wallet` and found no duplicate. A fix should make `read_from_disk` preserve encryption intent: if a non-empty password is supplied, require the encrypted wrapper path and reject plaintext stores, or store an authenticated encryption marker/policy in the file.

## Proof of Concept

```diff
diff --git a/src/wallet/storage.rs b/src/wallet/storage.rs
--- a/src/wallet/storage.rs
+++ b/src/wallet/storage.rs
@@ -185,4 +185,36 @@ mod tests {
         let (read_wallet, _nonce) = WalletStore::read_from_disk(&file_path, String::new()).unwrap();
         assert_eq!(original_wallet_store, read_wallet);
     }
+
+    #[test]
+    fn read_with_password_rejects_plaintext_wallet_file() {
+        let temp_dir = tempdir().unwrap();
+        let file_path = temp_dir.path().join("plaintext_wallet.cbor");
+
+        let master_key = {
+            let seed: [u8; 16] = thread_rng().gen();
+            Xpriv::new_master(Network::Bitcoin, &seed).unwrap()
+        };
+
+        let attacker_controlled_wallet_store = WalletStore::init(
+            "plaintext_wallet".to_string(),
+            &file_path,
+            Network::Bitcoin,
+            master_key,
+            None,
+            &None,
+        )
+        .unwrap();
+
+        attacker_controlled_wallet_store
+            .write_to_disk(&file_path, &None)
+            .unwrap();
+
+        let loaded = WalletStore::read_from_disk(&file_path, "victim password".to_string());
+
+        assert!(
+            loaded.is_err(),
+            "a non-empty wallet password must not silently accept an unauthenticated plaintext store"
+        );
+    }
 }

```

## Suggested Fix

```diff
No suggested fix emitted.
```

