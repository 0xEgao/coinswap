# Bind fidelity timelock checks to the real confirmation height

- **Finding ID:** 57
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/fidelity.rs
- **Lines:** 114-119
- **CWE:** CWE-345
- **Fingerprint:** 93442e3e95b0a4735a1bf11e84ed7b48b52cf144f0038262f98cfb27a394cb01

## Description

`verify_fidelity_checks` computes the advertised bond duration from `proof.bond.lock_time - proof.bond.conf_height`, but `conf_height` is supplied by the remote maker inside the serialized `FidelityBond`. The verifier fetches only the raw transaction by `proof.bond.outpoint.txid`; it never proves that the transaction was confirmed at the supplied height, or even obtains the actual confirmation height from chain data. A malicious maker that controls the bond key can create a valid timelocked output with only a small remaining lock period, set `conf_height` far enough in the past to make `lock_time - conf_height` fall inside `MIN_FIDELITY_TIMELOCK..=MAX_FIDELITY_TIMELOCK`, sign the resulting certificate hash, and pass offerbook verification. This bypasses the fidelity-bond time-cost assumption used for Sybil resistance. I considered prior finding #40, but it covers missing output amount validation, not spoofed confirmation height.

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
+    fn verify_rejects_fidelity_proof_with_spoofed_confirmation_height() {
+        let current_height = 30_000;
+        let lock_height = current_height + 10;
+        let claimed_conf_height = lock_height - MIN_FIDELITY_TIMELOCK;
+        let cert_expiry = FidelityBond::get_fidelity_expiry(claimed_conf_height);
+        let (proof, tx) = signed_test_fidelity_proof(
+            "makeraddress.onion",
+            claimed_conf_height,
+            lock_height,
+            cert_expiry,
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

