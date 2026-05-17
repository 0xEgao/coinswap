# Reject replaceable incoming Taproot contracts

- **Finding ID:** 26
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_verification.rs
- **Lines:** 157-162
- **CWE:** CWE-362
- **Fingerprint:** 00fc925062665b7401e5fba37d6cc0a66c0b7852aea5f81a1f185db84d8854be

## Description

The maker accepts a taker-provided Taproot contract transaction as long as it has at least one input and the first output pays to the expected P2TR script. It does not reject opt-in replaceable inputs before `process_taproot_contract` funds the outgoing contract after only observing the incoming transaction in the mempool. A malicious taker can send a valid-looking contract tx with `nSequence` below the BIP125 final threshold, let the maker see it and fund the next hop, then replace the incoming transaction with a double-spend that does not pay the maker. The taker can still spend the maker-funded outgoing contract using the known preimage, leaving the maker without the incoming funds it accepted. I searched prior findings for `taproot contract tx RBF sequence unconfirmed maker verify_contract_tx_on_chain`, `maker accepts unconfirmed replaceable contract transaction RBF`, and `contract tx sequence max RBF coinswap maker`; none matched.

## Proof of Concept

```diff
diff --git a/src/maker/taproot_verification.rs b/src/maker/taproot_verification.rs
--- a/src/maker/taproot_verification.rs
+++ b/src/maker/taproot_verification.rs
@@ -231,3 +231,92 @@ pub(crate) fn verify_taproot_privkey_handover(
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
+    #[test]
+    fn maker_rejects_replaceable_taproot_contract_tx() {
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
+        let amount = Amount::from_sat(500_000);
+        let contract_tx = Transaction {
+            version: Version(2),
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: amount,
+                script_pubkey: ScriptBuf::new_p2tr_tweaked(tap_info.output_key()),
+            }],
+        };
+        let next_hop_privkey = secret(4);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+        let data = TaprootContractData::new(
+            "rbf-contract".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(tap_info.tap_tweak().to_scalar().to_be_bytes().to_vec()),
+            hashlock_script,
+            timelock_script,
+            vec![contract_tx],
+            vec![amount],
+            Some(hashlock_privkey),
+            None,
+        );
+
+        assert!(
+            verify_taproot_contract_data(&data, maker_timelock, 0).is_err(),
+            "maker must not fund the next hop based on a replaceable, unconfirmed incoming contract tx"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

