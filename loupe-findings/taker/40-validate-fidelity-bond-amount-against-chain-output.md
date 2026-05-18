# Validate fidelity bond amount against chain output

- **Finding ID:** 40
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/offers.rs
- **Lines:** 435-437
- **CWE:** CWE-345
- **Fingerprint:** b2f8b4df96031f4f41ee87d2793c13883407633e502560a7edc2b3da52e8be48

## Description

The offer sync path accepts a maker as Good after verify_fidelity_proof succeeds, but the fidelity proof validation used here only checks that the fetched transaction output has the expected timelocked script and that the maker signed a certificate containing its self-reported bond amount. It does not compare proof.bond.amount to the actual txout.value at proof.bond.outpoint.vout. A malicious maker can therefore lock a dust output to the right script, advertise a much larger FidelityBond.amount, sign that inflated value, and be admitted to the taker's offerbook as if it had posted the larger bond. This weakens the fidelity-bond Sybil resistance relied on by maker discovery. I searched prior findings for `fidelity bond amount tx_out value verify_fidelity_checks offerbook` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/taker/offers.rs b/src/taker/offers.rs
--- a/src/taker/offers.rs
+++ b/src/taker/offers.rs
@@ -930,7 +930,7 @@ mod tests {
         absolute::LockTime,
         hashes::Hash,
         secp256k1::{Message, Secp256k1, SecretKey},
-        Amount, OutPoint, Txid,
+        transaction::Version, Amount, OutPoint, Transaction, TxOut, Txid,
     };
 
     fn addr(id: &str) -> MakerAddress {
@@ -980,6 +980,67 @@ mod tests {
         }
     }
 
+    fn fidelity_proof_and_chain_tx(
+        maker_addr: &str,
+        advertised_amount: Amount,
+        chain_amount: Amount,
+    ) -> (FidelityProof, Transaction) {
+        let secp = Secp256k1::new();
+        let secret_key = SecretKey::from_slice(&[3; 32]).expect("valid secret key");
+        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
+        let pubkey = bitcoin::PublicKey::new(secp_pubkey);
+        let conf_height = 1_000;
+        let lock_height = conf_height + crate::wallet::MIN_FIDELITY_TIMELOCK;
+
+        let bond = crate::wallet::FidelityBond {
+            outpoint: OutPoint {
+                txid: Txid::from_slice(&[4; 32]).expect("valid txid"),
+                vout: 0,
+            },
+            amount: advertised_amount,
+            lock_time: LockTime::from_height(lock_height).expect("valid height locktime"),
+            pubkey,
+            conf_height: Some(conf_height),
+            cert_expiry: Some(crate::wallet::FidelityBond::get_fidelity_expiry(conf_height)),
+            is_spent: false,
+        };
+
+        let cert_hash = bond
+            .generate_cert_hash(maker_addr)
+            .expect("cert_expiry set");
+        let msg = Message::from_digest_slice(cert_hash.as_byte_array()).expect("32-byte digest");
+        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);
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
+                value: chain_amount,
+                script_pubkey,
+            }],
+        };
+
+        (proof, tx)
+    }
+
+    #[test]
+    fn fidelity_verification_rejects_advertised_amount_above_chain_output() {
+        let maker_addr = "testmaker6106.onion";
+        let (proof, chain_tx) = fidelity_proof_and_chain_tx(
+            maker_addr,
+            Amount::from_sat(50_000_000),
+            Amount::from_sat(1),
+        );
+
+        assert!(verify_fidelity_checks(&proof, maker_addr, chain_tx, 1_001).is_err());
+    }
+
     #[test]
     fn mark_failure_state_and_backoff_growth() {
         let now_ts = 170000;

```

## Suggested Fix

```diff
No suggested fix emitted.
```

