# Require maker key for receiver signatures

- **Finding ID:** 39
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/legacy_verification.rs
- **Lines:** 141-156
- **CWE:** CWE-347
- **Fingerprint:** 0cce24e322b93fb3faa9e6dc606a18ca7e3b0d4ec1ce0585e500f009765d7519

## Description

`verify_receiver_sigs` accepts a receiver-contract signature if it verifies under either public key in the 2-of-2 multisig redeemscript. For receiver signatures, the taker needs the counterparty maker's signature specifically. In the last-hop legacy flow the maker has already received the taker's signature for the same contract in `RespContractSigsForRecvrAndSender`; it can replay that signature in `RespContractSigsForRecvr`. This verifier accepts it, and the caller stores it as `others_contract_sig`. If the maker then aborts before private-key handover, taker recovery tries to build a 2-of-2 contract transaction with two taker signatures and no maker signature, which is invalid on chain. I searched prior findings for `verify_receiver_sigs either pubkey replay taker signature maker receiver signature multisig` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/taker/legacy_verification.rs b/src/taker/legacy_verification.rs
index 7e7eb5d..c1ac4cb 100644
--- a/src/taker/legacy_verification.rs
+++ b/src/taker/legacy_verification.rs
@@ -355,3 +355,86 @@ impl Taker {
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey},
+        transaction::Version,
+        OutPoint, Sequence, TxIn, TxOut, Txid, Witness,
+    };
+
+    use crate::protocol::contract::{
+        create_contract_redeemscript, create_multisig_redeemscript, create_senders_contract_tx,
+        sign_contract_tx,
+    };
+
+    fn test_keypair(byte: u8) -> (SecretKey, PublicKey) {
+        let secp = Secp256k1::new();
+        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
+        let pubkey = PublicKey {
+            compressed: true,
+            inner: SecpPublicKey::from_secret_key(&secp, &secret),
+        };
+        (secret, pubkey)
+    }
+
+    fn stateless_taker_verifier() -> &'static Taker {
+        // verify_receiver_sigs does not read self; this avoids booting a wallet/RPC
+        // stack just to exercise signer-identity validation.
+        unsafe { &*std::ptr::NonNull::<Taker>::dangling().as_ptr() }
+    }
+
+    fn dummy_funding_tx() -> Transaction {
+        Transaction {
+            input: vec![TxIn {
+                previous_output: OutPoint::new(Txid::all_zeros(), 0),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+                script_sig: ScriptBuf::new(),
+            }],
+            output: vec![TxOut {
+                script_pubkey: ScriptBuf::new(),
+                value: Amount::from_sat(50_000),
+            }],
+            lock_time: LockTime::ZERO,
+            version: Version::TWO,
+        }
+    }
+
+    #[test]
+    fn rejects_receiver_signature_from_taker_key() {
+        let (maker_secret, maker_pubkey) = test_keypair(2);
+        let (taker_secret, taker_pubkey) = test_keypair(3);
+        let multisig_redeemscript = create_multisig_redeemscript(&maker_pubkey, &taker_pubkey);
+        let contract_redeemscript = create_contract_redeemscript(
+            &taker_pubkey,
+            &maker_pubkey,
+            &Hash160::hash(b"test preimage"),
+            &10,
+        );
+        let funding_tx = dummy_funding_tx();
+        let funding_amount = Amount::from_sat(50_000);
+        let contract_tx = create_senders_contract_tx(
+            OutPoint::new(funding_tx.compute_txid(), 0),
+            funding_amount,
+            &contract_redeemscript,
+        )
+        .unwrap();
+        let taker_sig = sign_contract_tx(
+            &contract_tx,
+            &multisig_redeemscript,
+            funding_amount,
+            &taker_secret,
+        )
+        .unwrap();
+
+        let info = SenderContractTxInfo {
+            funding_tx,
+            contract_tx: contract_tx.clone(),
+            timelock_pubkey: maker_pubkey,
+            multisig_redeemscript,
+            contract_redeemscript,
+            funding_amount,
+            multisig_nonce: maker_secret,
+            hashlock_nonce: maker_secret,
+        };
+
+        assert!(
+            stateless_taker_verifier()
+                .verify_receiver_sigs(&[taker_sig], &[contract_tx], &[info])
+                .is_err(),
+            "receiver signatures must be made by the maker, not by the taker key"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

