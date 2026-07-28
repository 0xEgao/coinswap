# Reject duplicate prevouts before signing Legacy contracts

- **Finding ID:** 44
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_verification.rs:40-102
- **Job:** 3
- **CWE:** CWE-694
- **Fingerprint:** e7c747ae4539e794a6608e5dfa28efdaf43392a224266d0ebeb476dc06e2a2eb

## Description

`verify_req_contract_sigs_for_sender` validates every `ContractTxInfoForSender` independently but never requires their single inputs to reference distinct funding outpoints. Consequently, one taker request can contain two otherwise-valid contract transactions that spend the same prospective 2-of-2 output into different contracts, and both pass verification. This reaches a fund-safety boundary: `verify_and_sign_sender_contract_txs` builds all prevout/script bindings, calls `cache_prevout_to_contract`, and then signs every transaction. The cache's conflict pre-check compares each binding only with entries already in the stored map; duplicate keys inside a new batch are not compared with each other, and `HashMap::extend` merely retains the last script. The maker therefore returns valid signatures for both conflicting spends while persisting only one contract for later proof/state recovery. After the maker accepts proof and commits its outgoing funding, the counterparty can confirm the alternative signed contract; the maker's stored contract transaction/signature and cached recovery metadata then describe a conflicting transaction, potentially preventing it from recovering the corresponding incoming value after the downstream side is claimed. The regression supplies two valid contracts with one prevout and distinct scripts; HEAD returns `Ok`. Require unique `previous_output` values before any caching/signing. Prior #6 is a distinct receiver-side output-validation bug; #7 and #30 cover locktime overflow and sighash-type validation respectively.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -231,3 +231,83 @@ pub(crate) fn verify_legacy_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        hashes::Hash, secp256k1::SecretKey, Amount, OutPoint, PublicKey, Txid,
+    };
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
+    fn sender_contract_verification_rejects_duplicate_funding_prevouts() {
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
+        let hashvalue = Hash160::from_slice(&[14; 20]).unwrap();
+        let funding_prevout = OutPoint::new(Txid::all_zeros(), 0);
+        let funding_amount = Amount::from_sat(100_000);
+        let taker_locktime = 100 + REFUND_LOCKTIME_STEP;
+
+        let make_info = |timelock_secret_byte| {
+            let timelock_pubkey = pubkey(&secp, timelock_secret_byte);
+            let contract_redeemscript = crate::protocol::contract::create_contract_redeemscript(
+                &hashlock_pubkey,
+                &timelock_pubkey,
+                &hashvalue,
+                &taker_locktime,
+            );
+            let senders_contract_tx = crate::protocol::contract::create_senders_contract_tx(
+                funding_prevout,
+                funding_amount,
+                &contract_redeemscript,
+            )
+            .unwrap();
+            ContractTxInfoForSender {
+                multisig_nonce,
+                hashlock_nonce,
+                timelock_pubkey,
+                senders_contract_tx,
+                multisig_redeemscript: multisig_redeemscript.clone(),
+                funding_input_value: funding_amount,
+            }
+        };
+
+        let first = make_info(15);
+        let conflicting = make_info(16);
+        assert_ne!(
+            first.senders_contract_tx.output[0].script_pubkey,
+            conflicting.senders_contract_tx.output[0].script_pubkey
+        );
+
+        assert!(
+            verify_req_contract_sigs_for_sender(
+                &[first, conflicting],
+                &tweakable_pubkey,
+                &hashvalue,
+                100,
+                6102,
+            )
+            .is_err(),
+            "one request must not obtain maker signatures for conflicting spends of one funding prevout"
+        );
+    }
+}

```
