# Validate Taproot key-path parameters before handover

- **Finding ID:** 22
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_handlers.rs
- **Lines:** 124-131
- **CWE:** CWE-345
- **Fingerprint:** 03358a4af0776f9555be144d29f9aa5d5d02ccbc7509b338d3f7706d6bd55212

## Description

`process_taproot_contract` stores `data.internal_key` and `data.tap_tweak_scalar()` from the taker-controlled `TaprootContractData` on the maker's incoming swapcoin, but the maker-side contract verification only recomputes the P2TR script from the internal key and scripts. It never checks that the advertised tap tweak is the tweak for that output, nor that the internal key is the MuSig aggregate of the maker's key and the counterparty key that will later be verified in `process_taproot_handover`. An attacker can send a contract output whose script path passes verification while supplying a different valid `tap_tweak`; after sending a private key that matches `data.pubkeys[0]`, `verify_taproot_privkey_handover` succeeds and the maker releases its outgoing private key. The maker's later cooperative sweep signs with the attacker-supplied tweak, producing an invalid key-path spend for the incoming output, so the attacker can take the maker-funded outgoing output while the maker cannot spend the incoming contract cooperatively. I searched prior findings for `taproot tap_tweak internal_key private key handover maker` and found no duplicate.

## Proof of Concept

```diff
--- a/src/maker/taproot_handlers.rs	2026-05-17 18:15:54
+++ b/src/maker/taproot_handlers.rs	2026-05-17 18:15:54
@@ -434,7 +434,114 @@
         response,
     )))
 }
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
 
+    fn secret(byte: u8) -> SecretKey {
+        SecretKey::from_slice(&[byte; 32]).unwrap()
+    }
+
+    fn taproot_contract_data(tap_tweak: Scalar) -> TaprootContractData {
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
+        let amount = Amount::from_sat(500_000);
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
+                value: amount,
+                script_pubkey,
+            }],
+        };
+
+        let next_hop_privkey = secret(5);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+
+        TaprootContractData::new(
+            "bad-tweak".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(tap_tweak.to_be_bytes().to_vec()),
+            hashlock_script,
+            timelock_script,
+            vec![contract_tx],
+            vec![amount],
+            Some(hashlock_nonce),
+            None,
+        )
+    }
+
+    #[test]
+    fn maker_rejects_taproot_contract_with_wrong_tap_tweak() {
+        let wrong_tweak = Scalar::from_be_bytes([9u8; 32]).unwrap();
+        let data = taproot_contract_data(wrong_tweak);
+
+        assert!(
+            verify_taproot_contract_data(&data, 100, 0).is_err(),
+            "maker must reject contract data whose tap_tweak does not match the advertised P2TR output"
+        );
+    }
+}
+
 /// Emit a maker success report after private key handover.
 #[hotpath::measure]
 fn emit_maker_success_report<M: Maker>(maker: &Arc<M>, state: &ConnectionState, swap_id: &str) {

```

## Suggested Fix

```diff
No suggested fix emitted.
```

