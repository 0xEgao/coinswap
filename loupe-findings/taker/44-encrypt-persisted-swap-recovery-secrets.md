# Encrypt persisted swap recovery secrets

- **Finding ID:** 44
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/swap_tracker.rs
- **Lines:** 249-268
- **CWE:** CWE-312
- **Fingerprint:** 9fcf67f2b3d1ff73f431b235696a487243bbe0ca4106e25d06b5c30c132a50d2

## Description

`SwapRecord` contains the taker swap preimage plus `multisig_nonces` and `hashlock_nonces`, and `SwapTracker::flush` serializes the entire record directly to `{data_dir}/swap_tracker.cbor` with `serde_cbor::to_vec` and `std::fs::write`. This creates a plaintext recovery file containing material that is normally only needed by the wallet/recovery path. A local adversary, backup/indexing process, or less-privileged account that can read the data directory can recover these bytes without knowing any wallet passphrase or going through the encrypted sensitive-struct loader used elsewhere in the tree. The preimage is the hashlock secret for the swap, and the nonce secret keys are explicitly stored for recovery/proof-of-funding flows; disclosure gives an attacker information needed to race or reconstruct recovery/spend paths instead of merely observing public swap metadata. I found no prior Loupe finding for `swap_tracker plaintext preimage hashlock_nonces SerializableSecretKey secrets world readable`. The PoC adds a regression test that saves a record with sentinel preimage and nonce secret-key bytes, reads `swap_tracker.cbor`, and fails on HEAD because those exact byte sequences are present in the file.

## Proof of Concept

```diff
diff --git a/src/taker/swap_tracker.rs b/src/taker/swap_tracker.rs
--- a/src/taker/swap_tracker.rs
+++ b/src/taker/swap_tracker.rs
@@ -636,6 +636,36 @@ mod tests {
         assert_eq!(incomplete[0].swap_id, "swap1");
         assert_eq!(incomplete[0].phase, SwapPhase::FundsBroadcast);
     }
+
+    #[test]
+    fn test_tracker_file_does_not_store_recovery_secrets_in_plaintext() {
+        fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
+            haystack.windows(needle.len()).any(|window| window == needle)
+        }
+
+        let dir = TempDir::new().unwrap();
+        let mut tracker = SwapTracker::load_or_create(dir.path()).unwrap();
+
+        let preimage = [0x42u8; 32];
+        let multisig_secret = [0x11u8; 32];
+        let hashlock_secret = [0x22u8; 32];
+
+        let mut record = make_test_record("swap1", SwapPhase::FundsBroadcast);
+        record.preimage = preimage;
+        record.multisig_nonces = vec![SerializableSecretKey(
+            SecretKey::from_slice(&multisig_secret).unwrap(),
+        )];
+        record.hashlock_nonces = vec![SerializableSecretKey(
+            SecretKey::from_slice(&hashlock_secret).unwrap(),
+        )];
+
+        tracker.save_record(&record).unwrap();
+        let persisted = std::fs::read(dir.path().join("swap_tracker.cbor")).unwrap();
+
+        assert!(!contains_subslice(&persisted, &preimage));
+        assert!(!contains_subslice(&persisted, &multisig_secret));
+        assert!(!contains_subslice(&persisted, &hashlock_secret));
+    }
 
     #[test]
     fn test_remove_record() {

```

## Suggested Fix

```diff
No suggested fix emitted.
```

