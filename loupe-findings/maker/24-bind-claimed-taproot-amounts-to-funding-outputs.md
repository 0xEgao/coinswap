# Bind claimed Taproot amounts to funding outputs

- **Finding ID:** 24
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_verification.rs
- **Lines:** 157-178
- **CWE:** CWE-345
- **Fingerprint:** 9a39dab3887cdab0f26894f45ec6d131f647bc49274cfa1648b0868c957cd71c

## Description

`verify_taproot_contract_data` only checks that `contract_txs.len() == amounts.len()` and that each first output pays to the reconstructed P2TR script. It never verifies that `data.amounts[i]` equals the actual value of `data.contract_txs[i].output[0]`. `process_taproot_contract` later trusts `data.amounts.first()` as `incoming_funding_amount` to calculate how much maker money to lock in the outgoing contract. A malicious taker can broadcast a valid P2TR contract output with a dust value, claim a much larger amount in `amounts`, pass this verifier, and cause the maker to fund the next hop based on the inflated value. The taker can then spend the maker-funded outgoing Taproot contract with the preimage while the maker only has the underfunded incoming contract. I searched prior findings for `taproot amount output mismatch verify_taproot_contract_data` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/taproot_verification.rs b/src/maker/taproot_verification.rs
--- a/src/maker/taproot_verification.rs
+++ b/src/maker/taproot_verification.rs
@@ -231,3 +231,96 @@ pub(crate) fn verify_taproot_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::verify_taproot_contract_data;
+    use crate::protocol::{
+        contract2::{create_hashlock_script, create_timelock_script},
+        taproot_messages::{SerializableScalar, TaprootContractData},
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{sha256, Hash},
+        secp256k1::{Keypair, Secp256k1, SecretKey},
+        transaction::Version,
+        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
+    };
+
+    fn secret(byte: u8) -> SecretKey {
+        SecretKey::from_slice(&[byte; 32]).unwrap()
+    }
+
+    fn valid_contract_data(output_amount: Amount, claimed_amount: Amount) -> TaprootContractData {
+        let secp = Secp256k1::new();
+        let hashlock_privkey = secret(1);
+        let hashlock_keypair = Keypair::from_secret_key(&secp, &hashlock_privkey);
+        let hashlock_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&hashlock_keypair).0;
+        let hash = sha256::Hash::hash(b"preimage").to_byte_array();
+        let hashlock_script = create_hashlock_script(&hash, &hashlock_xonly);
+
+        let timelock_privkey = secret(2);
+        let timelock_keypair = Keypair::from_secret_key(&secp, &timelock_privkey);
+        let timelock_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&timelock_keypair).0;
+        let maker_timelock = 100;
+        let taker_locktime = maker_timelock + crate::taker::api::REFUND_LOCKTIME_STEP as u32;
+        let timelock_script = create_timelock_script(
+            LockTime::from_height(taker_locktime).unwrap(),
+            &timelock_xonly,
+        );
+
+        let internal_privkey = secret(3);
+        let internal_keypair = Keypair::from_secret_key(&secp, &internal_privkey);
+        let internal_key = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&internal_keypair).0;
+        let tap_info = bitcoin::taproot::TaprootBuilder::new()
+            .add_leaf(1, hashlock_script.clone())
+            .unwrap()
+            .add_leaf(1, timelock_script.clone())
+            .unwrap()
+            .finalize(&secp, internal_key)
+            .unwrap();
+        let script_pubkey = ScriptBuf::new_p2tr_tweaked(tap_info.output_key());
+        let contract_tx = Transaction {
+            version: Version(2),
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::MAX,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: output_amount,
+                script_pubkey,
+            }],
+        };
+        let next_hop_privkey = secret(4);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+
+        TaprootContractData::new(
+            "amount-mismatch".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(tap_info.tap_tweak().to_scalar().to_be_bytes().to_vec()),
+            hashlock_script,
+            timelock_script,
+            vec![contract_tx],
+            vec![claimed_amount],
+            Some(hashlock_privkey),
+            None,
+        )
+    }
+
+    #[test]
+    fn maker_rejects_taproot_amount_not_backed_by_contract_output() {
+        let data = valid_contract_data(Amount::from_sat(1), Amount::from_sat(50_000_000));
+
+        assert!(
+            verify_taproot_contract_data(&data, 100, 0).is_err(),
+            "maker must reject claimed Taproot amounts that do not equal the funding output value"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

