# Reject missing legacy contract signatures in verifier

- **Finding ID:** 17
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/legacy_verification.rs
- **Lines:** 121-124
- **CWE:** CWE-345
- **Fingerprint:** a38b03dcbb88fa2632b06bfd9ad43b29dbb0f6dffdf37e5a17e6c80c3544ae53

## Description

`verify_contract_sigs` verifies signatures by zipping each supplied signature vector with the corresponding swapcoin vector, but it never checks that the lengths match. If this verifier is called with fewer signatures than swapcoins, the unmatched swapcoins are skipped and the function returns `Ok(())`; with empty signature slices it performs no cryptographic checks at all. The current legacy handler performs length checks before this call, but that security property is outside the verifier and can be lost by any other in-crate caller or future refactor. The verification helper should reject mismatched receiver and sender signature counts itself before any `zip` iteration. Prior search for `legacy_verification verify_contract_sigs signature length zip` returned no matching findings.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -230,4 +230,49 @@ pub(crate) fn verify_legacy_privkey_handover(
         privkeys.len()
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        secp256k1::SecretKey,
+        transaction::Version,
+        Amount, ScriptBuf, Transaction,
+    };
+
+    fn pubkey_from_secret(bytes: [u8; 32]) -> PublicKey {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let key = SecretKey::from_slice(&bytes).unwrap();
+        PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key),
+        }
+    }
+
+    fn empty_tx() -> Transaction {
+        Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![],
+            output: vec![],
+        }
+    }
+
+    #[test]
+    fn contract_sig_verifier_rejects_missing_receiver_signatures() {
+        let incoming = IncomingSwapCoin::new_legacy(
+            SecretKey::from_slice(&[8; 32]).unwrap(),
+            pubkey_from_secret([9; 32]),
+            empty_tx(),
+            ScriptBuf::new(),
+            SecretKey::from_slice(&[10; 32]).unwrap(),
+            Amount::from_sat(1_000),
+        );
+
+        let result = verify_contract_sigs(&[], &[], &[incoming], &[], 0);
+
+        assert!(
+            result.is_err(),
+            "missing receiver signatures must not verify successfully"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

