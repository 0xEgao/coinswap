# Reject shortened receiver signature responses

- **Finding ID:** 38
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/legacy_verification.rs
- **Lines:** 132-136
- **CWE:** CWE-345
- **Fingerprint:** 48efc5d2db64414c0cba49414be3f3d5a14c0ba6b83c2ae948c429c8a4b7bd26

## Description

`verify_receiver_sigs` iterates with nested `zip` and never checks that the maker returned one signature for every receiver contract and previous sender-info entry. A malicious last maker can return an empty or shortened `RespContractSigsForRecvr`; the verifier returns `Ok` because the loop never visits the missing item, and the caller stores signatures with another `zip`. The taker can therefore persist incoming swapcoins without `others_contract_sig`. If that maker then aborts before private-key handover, the recovery path cannot broadcast the incoming contract transaction because it only does so when `others_contract_sig` is present, leaving the taker unable to claim the maker-side funds. I searched prior findings for `legacy verify_receiver_sigs missing signature length zip final maker incoming recovery others_contract_sig` and found no duplicate. Other zip-based verifiers should also be length-checked, but this report is for the exploitable final receiver-signature path.

## Proof of Concept

```diff
diff --git a/src/taker/legacy_verification.rs b/src/taker/legacy_verification.rs
index 7e7eb5d..5e91d33 100644
--- a/src/taker/legacy_verification.rs
+++ b/src/taker/legacy_verification.rs
@@ -355,3 +355,61 @@ impl Taker {
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        secp256k1::SecretKey,
+        transaction::Version,
+        OutPoint, Sequence, TxIn, TxOut, Txid, Witness,
+    };
+
+    fn stateless_taker_verifier() -> &'static Taker {
+        // verify_receiver_sigs does not read self; this avoids booting a wallet/RPC
+        // stack just to exercise the verifier's length validation.
+        unsafe { &*std::ptr::NonNull::<Taker>::dangling().as_ptr() }
+    }
+
+    fn dummy_tx() -> Transaction {
+        Transaction {
+            input: vec![TxIn {
+                previous_output: OutPoint::new(Txid::all_zeros(), 0),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+                script_sig: ScriptBuf::new(),
+            }],
+            output: vec![TxOut {
+                script_pubkey: ScriptBuf::new(),
+                value: Amount::from_sat(1_000),
+            }],
+            lock_time: LockTime::ZERO,
+            version: Version::TWO,
+        }
+    }
+
+    fn dummy_sender_info() -> SenderContractTxInfo {
+        let nonce = SecretKey::from_slice(&[1; 32]).unwrap();
+        SenderContractTxInfo {
+            funding_tx: dummy_tx(),
+            contract_tx: dummy_tx(),
+            timelock_pubkey: PublicKey::from_slice(&[2; 33]).unwrap(),
+            multisig_redeemscript: ScriptBuf::new(),
+            contract_redeemscript: ScriptBuf::new(),
+            funding_amount: Amount::from_sat(1_000),
+            multisig_nonce: nonce,
+            hashlock_nonce: nonce,
+        }
+    }
+
+    #[test]
+    fn rejects_missing_receiver_signature_response() {
+        let receivers_txs = vec![dummy_tx()];
+        let prev_senders_info = vec![dummy_sender_info()];
+
+        assert!(
+            stateless_taker_verifier()
+                .verify_receiver_sigs(&[], &receivers_txs, &prev_senders_info)
+                .is_err(),
+            "a response with fewer signatures than receiver contracts must be rejected"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

