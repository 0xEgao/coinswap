# Bind Taproot contract amounts to funded outputs

- **Finding ID:** 21
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_handlers.rs
- **Lines:** 111-138
- **CWE:** CWE-345
- **Fingerprint:** f15fbf574acd611292b7e0aaa6657fe0c1c79192af69e4b4c94ac1e7cce9c5ac

## Description

`process_taproot_contract` trusts `data.amounts.first()` as the value of the taker's incoming Taproot contract and uses it to compute the maker's outgoing payment. The maker-side verifier only checks that `contract_txs` and `amounts` have matching lengths and that output 0 pays to the expected P2TR script; it never checks that `contract_txs[i].output[0].value == data.amounts[i]`. A malicious taker can broadcast a tiny contract output to the correct script, advertise a much larger amount in `TaprootContractData.amounts`, pass `verify_contract_tx_on_chain`, and make the maker fund an outgoing contract based on the inflated value. During private-key handover the taker can provide the expected private key and receive the maker's outgoing private key, stealing the maker-funded output while the maker's incoming swapcoin is backed only by the smaller on-chain value. I searched prior findings for `taproot contract data amounts output value maker underfunded funding amount` and found no duplicate.

## Proof of Concept

```diff
--- a/src/maker/taproot_handlers.rs	2026-05-17 18:14:18
+++ b/src/maker/taproot_handlers.rs	2026-05-17 18:14:18
@@ -433,6 +433,120 @@
     Ok(Some(MakerToTakerMessage::TaprootPrivateKeyHandover(
         response,
     )))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::super::taproot_verification::verify_taproot_contract_data;
+    use crate::protocol::{
+        contract::calculate_pubkey_from_nonce,
+        contract2::{create_hashlock_script, create_timelock_script},
+        taproot_messages::{SerializableScalar, TaprootContractData},
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{sha256, Hash},
+        secp256k1::{Keypair, Scalar, Secp256k1, SecretKey},
+        transaction::Version,
+        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
+    };
+
+    fn secret(byte: u8) -> SecretKey {
+        SecretKey::from_slice(&[byte; 32]).unwrap()
+    }
+
+    fn malicious_taproot_contract_data(
+        actual_output_value: Amount,
+        advertised_amount: Amount,
+        tap_tweak: Option<Scalar>,
+    ) -> TaprootContractData {
+        let secp = Secp256k1::new();
+        let tweakable_privkey = secret(1);
+        let tweakable_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &tweakable_privkey),
+        };
+        let hashlock_nonce = secret(2);
+        let hashlock_pubkey = calculate_pubkey_from_nonce(&tweakable_pubkey, &hashlock_nonce)
+            .expect("hashlock pubkey");
+        let hashlock_xonly = bitcoin::key::XOnlyPublicKey::from(hashlock_pubkey.inner);
+
+        let hash = sha256::Hash::hash(b"attacker preimage").to_byte_array();
+        let hashlock_script = create_hashlock_script(&hash, &hashlock_xonly);
+
+        let timelock_privkey = secret(3);
+        let timelock_keypair = Keypair::from_secret_key(&secp, &timelock_privkey);
+        let timelock_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&timelock_keypair).0;
+        let maker_timelock = 100;
+        let taker_refund_locktime =
+            maker_timelock + crate::taker::api::REFUND_LOCKTIME_STEP as u32;
+        let timelock_script = create_timelock_script(
+            LockTime::from_height(taker_refund_locktime).unwrap(),
+            &timelock_xonly,
+        );
+
+        let internal_privkey = secret(4);
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
+
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
+                value: actual_output_value,
+                script_pubkey,
+            }],
+        };
+
+        let next_hop_privkey = secret(5);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+        let scalar = tap_tweak.unwrap_or_else(|| tap_info.tap_tweak().to_scalar());
+
+        TaprootContractData::new(
+            "underfunded".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(scalar.to_be_bytes().to_vec()),
+            hashlock_script,
+            timelock_script,
+            vec![contract_tx],
+            vec![advertised_amount],
+            Some(hashlock_nonce),
+            None,
+        )
+    }
+
+    #[test]
+    fn maker_rejects_taproot_contract_when_advertised_amount_exceeds_output_value() {
+        let data = malicious_taproot_contract_data(
+            Amount::from_sat(1_000),
+            Amount::from_sat(500_000),
+            None,
+        );
+
+        assert!(
+            verify_taproot_contract_data(&data, 100, 0).is_err(),
+            "maker must reject Taproot contract data whose advertised amount is not backed by tx output[0]"
+        );
+    }
 }
 
 /// Emit a maker success report after private key handover.

```

## Suggested Fix

```diff
No suggested fix emitted.
```

