# Enforce Taproot hashlock script opcodes

- **Finding ID:** 23
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_handlers.rs
- **Lines:** 90-99
- **CWE:** CWE-345
- **Fingerprint:** d198c7fda66536582f4419dc3651ba11369f73e7b579afa2558de42d4355a551

## Description

`process_taproot_contract` relies on `check_taproot_hashlock_has_pubkey` and `verify_taproot_contract_data` before accepting the taker's incoming Taproot contract, but those checks do not enforce the hashlock script template. `extract_hash_from_hashlock` only reads instruction 1, `check_taproot_hashlock_has_pubkey` only reads instruction 3, and the verifier only checks that there are five instructions. A taker can therefore build the incoming P2TR output with a leaf such as `OP_SHA256 <hash> OP_EQUALVERIFY <maker_xonly> OP_FALSE`, which passes the current checks but cannot be spent by the maker via the hashlock path. If the taker then spends the maker's outgoing contract via hashlock and reveals the preimage, maker recovery observes the preimage but signs an invalid incoming hashlock spend; the taker can later recover their own incoming contract by timelock while keeping the maker-funded outgoing output. I searched prior findings for `taproot hashlock script opcode format OP_CHECKSIG maker recovery` and found no duplicate.

## Proof of Concept

```diff
--- a/src/maker/taproot_handlers.rs	2026-05-17 18:17:48
+++ b/src/maker/taproot_handlers.rs	2026-05-17 18:17:48
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
+        contract2::{check_taproot_hashlock_has_pubkey, create_timelock_script},
+        taproot_messages::{SerializableScalar, TaprootContractData},
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{sha256, Hash},
+        opcodes::all::{OP_EQUALVERIFY, OP_FALSE, OP_SHA256},
+        script,
+        secp256k1::{Keypair, Secp256k1, SecretKey},
+        transaction::Version,
+        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
+    };
 
+    fn secret(byte: u8) -> SecretKey {
+        SecretKey::from_slice(&[byte; 32]).unwrap()
+    }
+
+    #[test]
+    fn maker_rejects_malformed_taproot_hashlock_template() {
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
+        let hash = sha256::Hash::hash(b"attacker preimage").to_byte_array();
+        let malformed_hashlock_script = script::Builder::new()
+            .push_opcode(OP_SHA256)
+            .push_slice(hash)
+            .push_opcode(OP_EQUALVERIFY)
+            .push_x_only_key(&hashlock_xonly)
+            .push_opcode(OP_FALSE)
+            .into_script();
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
+            .add_leaf(1, malformed_hashlock_script.clone())
+            .unwrap()
+            .add_leaf(1, timelock_script.clone())
+            .unwrap()
+            .finalize(&secp, internal_key)
+            .unwrap();
+        let script_pubkey = ScriptBuf::new_p2tr_tweaked(tap_info.output_key());
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
+        let next_hop_privkey = secret(5);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+        let data = TaprootContractData::new(
+            "bad-script".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(tap_info.tap_tweak().to_scalar().to_be_bytes().to_vec()),
+            malformed_hashlock_script,
+            timelock_script,
+            vec![contract_tx],
+            vec![amount],
+            Some(hashlock_nonce),
+            None,
+        );
+
+        assert!(
+            check_taproot_hashlock_has_pubkey(&data.hashlock_script, &tweakable_pubkey, &hashlock_nonce).is_err()
+                || verify_taproot_contract_data(&data, 100, 0).is_err(),
+            "maker must reject hashlock scripts that are not OP_SHA256 <hash> OP_EQUALVERIFY <pubkey> OP_CHECKSIG"
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

