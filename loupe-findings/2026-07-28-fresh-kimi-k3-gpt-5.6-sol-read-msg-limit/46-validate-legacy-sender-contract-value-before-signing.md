# Validate Legacy sender contract value before signing

- **Finding ID:** 46
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_verification.rs:91-98
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** a042f826fd6047fcd00e4d17501ab01d6cca3433be105e378cd428382883e119

## Description

`verify_req_contract_sigs_for_sender` checks the sender contract's input/output counts and expected P2WSH script, but `is_contract_out_valid` does not inspect `TxOut::value`. The taker-supplied `funding_input_value` is likewise not related to the output value before `verify_and_sign_sender_contract_txs` passes it into `sign_contract_tx`. A malicious taker can therefore request a valid maker signature for a one-input contract transaction whose advertised funding input is the full swap amount but whose sole contract output is only dust; the remainder becomes transaction fee. This is reachable before funding, and the accepted script is cached for later proof. After proof, the maker reconstructs a normal-value incoming recovery transaction and obtains the taker's signature on that different transaction before broadcasting its outgoing funding. The taker still retains the maker's earlier signature on the fee-burning version and can confirm that conflicting spend first. This destroys most or all incoming value while the maker's outgoing value has already entered the swap route, exposing the maker to loss at comparatively low cost to the counterparty. The regression mutates only the output value of an otherwise canonical contract from 100,000 sats to 1 sat; HEAD returns `Ok`. Validate the output against `funding_input_value` and the protocol's expected contract fee before signing. Prior #6 concerns arbitrary receiver-side output scripts after maker funding; #7 and #30 concern locktime overflow and signature sighash metadata, so none duplicate this value invariant.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -231,3 +231,70 @@ pub(crate) fn verify_legacy_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{hashes::Hash, secp256k1::SecretKey, Amount, OutPoint, PublicKey};
+
+    fn pubkey(secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>, byte: u8) -> PublicKey {
+        PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(
+                secp,
+                &SecretKey::from_slice(&[byte; 32]).unwrap(),
+            ),
+        }
+    }
+
+    #[test]
+    fn sender_contract_verification_rejects_excessive_transaction_fee() {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let tweakable_pubkey = pubkey(&secp, 10);
+        let multisig_nonce = SecretKey::from_slice(&[11; 32]).unwrap();
+        let hashlock_nonce = SecretKey::from_slice(&[12; 32]).unwrap();
+        let maker_multisig_pubkey =
+            calculate_pubkey_from_nonce(&tweakable_pubkey, &multisig_nonce).unwrap();
+        let other_multisig_pubkey = pubkey(&secp, 13);
+        let multisig_redeemscript =
+            create_multisig_redeemscript(&maker_multisig_pubkey, &other_multisig_pubkey);
+        let hashlock_pubkey =
+            calculate_pubkey_from_nonce(&tweakable_pubkey, &hashlock_nonce).unwrap();
+        let timelock_pubkey = pubkey(&secp, 15);
+        let hashvalue = Hash160::from_slice(&[14; 20]).unwrap();
+        let funding_amount = Amount::from_sat(100_000);
+        let contract_redeemscript = crate::protocol::contract::create_contract_redeemscript(
+            &hashlock_pubkey,
+            &timelock_pubkey,
+            &hashvalue,
+            &(100 + REFUND_LOCKTIME_STEP),
+        );
+        let mut senders_contract_tx = crate::protocol::contract::create_senders_contract_tx(
+            OutPoint::null(),
+            funding_amount,
+            &contract_redeemscript,
+        )
+        .unwrap();
+        senders_contract_tx.output[0].value = Amount::from_sat(1);
+        let txinfo = ContractTxInfoForSender {
+            multisig_nonce,
+            hashlock_nonce,
+            timelock_pubkey,
+            senders_contract_tx,
+            multisig_redeemscript,
+            funding_input_value: funding_amount,
+        };
+
+        assert!(
+            verify_req_contract_sigs_for_sender(
+                &[txinfo],
+                &tweakable_pubkey,
+                &hashvalue,
+                100,
+                6102,
+            )
+            .is_err(),
+            "maker must not sign a contract transaction that burns nearly all funding as fees"
+        );
+    }
+}

```
