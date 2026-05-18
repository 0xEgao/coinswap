# Reject expired fidelity certificates during offer verification

- **Finding ID:** 58
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/fidelity.rs
- **Lines:** 135-141
- **CWE:** CWE-613
- **Fingerprint:** 07d00b858be972bcf687c0ed0ae5b720ae579a60308a0d10bf9714ecfd4e3302

## Description

`FidelityBond::cert_expiry` is included in the signed certificate hash and `FidelityError::CertExpired` exists, but `verify_fidelity_checks` never compares the certificate expiry period with the current chain height. The offerbook verifier therefore accepts a maker proof whose certificate has expired as long as the bond output script and signature match. A maker, or anyone able to replay an old offer for the same maker address, can keep an expired certificate active until some other check fails, weakening the intended certificate-rotation and freshness boundary for advertised fidelity bonds. Prior searches for `fidelity certificate expiry cert_expiry verify_fidelity_checks` and `FidelityError CertExpired unused` returned no duplicates. Prior finding #40 is unrelated because it covers missing amount validation.

## Proof of Concept

```diff
diff --git a/src/wallet/fidelity.rs b/src/wallet/fidelity.rs
--- a/src/wallet/fidelity.rs
+++ b/src/wallet/fidelity.rs
@@ -588,7 +588,74 @@ fn encode_fidelity_op_return(
 #[cfg(test)]
 mod test {
     use super::*;
+    use bitcoin::{hashes::Hash as _, secp256k1::SecretKey, transaction::Version, TxOut};
+
+    fn signed_test_fidelity_proof(
+        maker_addr: &str,
+        conf_height: u32,
+        lock_height: u32,
+        cert_expiry: u32,
+    ) -> (FidelityProof, Transaction) {
+        let secp = Secp256k1::new();
+        let secret_key = SecretKey::from_slice(&[7; 32]).expect("valid secret key");
+        let pubkey = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
+            &secp,
+            &secret_key,
+        ));
+
+        let bond = FidelityBond {
+            outpoint: OutPoint {
+                txid: Txid::from_slice(&[8; 32]).expect("valid txid"),
+                vout: 0,
+            },
+            amount: Amount::from_sat(5_000_000),
+            lock_time: LockTime::from_height(lock_height).expect("valid height locktime"),
+            pubkey,
+            conf_height: Some(conf_height),
+            cert_expiry: Some(cert_expiry),
+            is_spent: false,
+        };
+
+        let cert_hash = bond
+            .generate_cert_hash(maker_addr)
+            .expect("cert_expiry set");
+        let cert_message = Message::from_digest_slice(cert_hash.as_byte_array()).unwrap();
+        let cert_sig = secp.sign_ecdsa(&cert_message, &secret_key);
+        let script_pubkey = bond.script_pub_key();
+        let proof = FidelityProof {
+            bond,
+            cert_hash,
+            cert_sig,
+        };
+        let tx = Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![],
+            output: vec![TxOut {
+                value: Amount::from_sat(5_000_000),
+                script_pubkey,
+            }],
+        };
+
+        (proof, tx)
+    }
 
     #[test]
+    fn verify_rejects_expired_fidelity_certificate() {
+        let current_height = 30_000;
+        let conf_height = current_height;
+        let lock_height = current_height + MIN_FIDELITY_TIMELOCK;
+        let expired_cert_period = 1;
+        let (proof, tx) = signed_test_fidelity_proof(
+            "makeraddress.onion",
+            conf_height,
+            lock_height,
+            expired_cert_period,
+        );
+
+        assert!(verify_fidelity_checks(&proof, "makeraddress.onion", tx, current_height as u64).is_err());
+    }
+
+    #[test]
     fn test_fidelity_bond_value_function_behavior() {
         const EPSILON: f64 = 0.000001;
         const YEAR: f64 = 60.0 * 60.0 * 24.0 * 365.2425;

```

## Suggested Fix

```diff
No suggested fix emitted.
```

