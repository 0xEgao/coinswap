# Reject overflowing legacy refund locktime before adding step

- **Finding ID:** 16
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/legacy_verification.rs
- **Lines:** 38-38
- **CWE:** CWE-190
- **Fingerprint:** 4e6ab09b7285abf484f9654985f1a596fcf507698d29d87f04bbede7906b8736

## Description

`verify_req_contract_sigs_for_sender` adds the taker-controlled `locktime` to `REFUND_LOCKTIME_STEP` using `u16` arithmetic before validating the value. A taker can send a `ReqContractSigsForSender` with `locktime` near `u16::MAX`. In debug/test builds this panics, allowing a malformed network message to abort maker processing. In release builds the addition wraps, so the maker validates the sender contract output against a much smaller CSV value than intended. That can break the legacy timelock staggering invariant before the maker signs the contract transaction. The function should use checked/widened arithmetic and reject values that cannot include the refund step. Prior searches for `legacy_verification locktime overflow REFUND_LOCKTIME_STEP` and `verify_req_contract_sigs_for_sender taker_locktime overflow` returned no matching findings.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -230,4 +230,65 @@ pub(crate) fn verify_legacy_privkey_handover(
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
+        hashes::Hash as _,
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
+    fn req_contract_sigs_rejects_locktime_overflow_without_panicking() {
+        let txinfo = crate::protocol::legacy_messages::ContractTxInfoForSender {
+            multisig_nonce: SecretKey::from_slice(&[2; 32]).unwrap(),
+            hashlock_nonce: SecretKey::from_slice(&[3; 32]).unwrap(),
+            timelock_pubkey: pubkey_from_secret([4; 32]),
+            senders_contract_tx: empty_tx(),
+            multisig_redeemscript: ScriptBuf::new(),
+            funding_input_value: Amount::from_sat(1_000),
+        };
+
+        let tweakable_pubkey = pubkey_from_secret([5; 32]);
+        let hashvalue = crate::protocol::Hash160::hash(&[7; 32]);
+
+        let result = std::panic::catch_unwind(|| {
+            verify_req_contract_sigs_for_sender(
+                &[txinfo],
+                &tweakable_pubkey,
+                &hashvalue,
+                u16::MAX,
+                0,
+            )
+        });
+
+        assert!(result.is_ok(), "untrusted locktime must not panic the maker");
+        assert!(
+            result.unwrap().is_err(),
+            "overflowing locktime should be rejected before signature generation"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

