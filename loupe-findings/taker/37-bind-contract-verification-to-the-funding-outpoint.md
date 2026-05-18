# Bind contract verification to the funding outpoint

- **Finding ID:** 37
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/legacy_verification.rs
- **Lines:** 331-333
- **CWE:** CWE-345
- **Fingerprint:** b3e09dcbb41e122ab2fc17ad554fb54442444a45a058fbe6050ab3006eebfb6d

## Description

`verify_maker_receiver_contracts` accepts a receiver contract transaction when its input txid matches any expected funding transaction, but it never checks the input vout or that the referenced funding output pays the advertised 2-of-2 multisig script/value. A malicious maker can return a real funding transaction plus a pre-signed contract that spends a nonexistent or unrelated output of that tx. The verifier accepts it because the txid matches and the contract output pays the expected HTLC script, but the contract transaction is not spendable on chain. In the legacy flow this can leave the taker believing the maker funded its side while any later recovery path that relies on broadcasting that contract fails, risking loss of the swap amount. I searched prior findings for `legacy_verification funding txid outpoint vout multisig verify_maker_receiver_contracts verify_maker_sender_contracts` and found no duplicate. The same txid-only assumption also appears in sender-contract verification; the PoC below demonstrates the receiver verifier accepting the wrong funding vout.

## Proof of Concept

```diff
diff --git a/src/taker/legacy_verification.rs b/src/taker/legacy_verification.rs
index 7e7eb5d..4d4dd0f 100644
--- a/src/taker/legacy_verification.rs
+++ b/src/taker/legacy_verification.rs
@@ -355,3 +355,74 @@ impl Taker {
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
+        OutPoint, Sequence, TxIn, TxOut, Witness,
+    };
+
+    use crate::{
+        protocol::contract::{
+            create_contract_redeemscript, create_multisig_redeemscript,
+            create_senders_contract_tx,
+        },
+        utill::redeemscript_to_scriptpubkey,
+    };
+
+    fn test_pubkey(byte: u8) -> PublicKey {
+        let secp = Secp256k1::new();
+        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
+        PublicKey {
+            compressed: true,
+            inner: SecpPublicKey::from_secret_key(&secp, &secret),
+        }
+    }
+
+    fn stateless_taker_verifier() -> &'static Taker {
+        // verify_maker_receiver_contracts does not read self; this avoids booting a
+        // wallet/RPC stack just to exercise the verifier's input validation.
+        unsafe { &*std::ptr::NonNull::<Taker>::dangling().as_ptr() }
+    }
+
+    #[test]
+    fn rejects_receiver_contract_spending_wrong_funding_vout() {
+        let maker_pubkey = test_pubkey(2);
+        let taker_pubkey = test_pubkey(3);
+        let multisig_redeemscript = create_multisig_redeemscript(&maker_pubkey, &taker_pubkey);
+        let multisig_spk = redeemscript_to_scriptpubkey(&multisig_redeemscript).unwrap();
+
+        let funding_tx = Transaction {
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+                script_sig: ScriptBuf::new(),
+            }],
+            output: vec![
+                TxOut {
+                    script_pubkey: ScriptBuf::new(),
+                    value: Amount::from_sat(50_000),
+                },
+                TxOut {
+                    script_pubkey: multisig_spk,
+                    value: Amount::from_sat(50_000),
+                },
+            ],
+            lock_time: LockTime::ZERO,
+            version: Version::TWO,
+        };
+
+        let contract_redeemscript = create_contract_redeemscript(
+            &maker_pubkey,
+            &taker_pubkey,
+            &Hash160::hash(b"test preimage"),
+            &10,
+        );
+        let wrong_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
+        let contract_tx = create_senders_contract_tx(
+            wrong_outpoint,
+            Amount::from_sat(50_000),
+            &contract_redeemscript,
+        )
+        .unwrap();
+
+        assert!(
+            stateless_taker_verifier()
+                .verify_maker_receiver_contracts(&[contract_tx], &[funding_tx], &[contract_redeemscript])
+                .is_err(),
+            "receiver contract must spend the funding output that pays the advertised multisig"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

