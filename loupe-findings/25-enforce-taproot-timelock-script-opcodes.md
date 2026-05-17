# Enforce Taproot timelock script opcodes

- **Finding ID:** 25
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/taproot_verification.rs
- **Lines:** 61-126
- **CWE:** CWE-345
- **Fingerprint:** 4f8acb1abcdc0bcda91b520e8130957ab66cb0a29cd7aaa7213bef10d1d7171f

## Description

`verify_taproot_contract_data` treats a timelock leaf as valid when it has five instructions and its first instruction decodes to the expected locktime. It does not verify that the rest of the template is `OP_CLTV OP_DROP <pubkey> OP_CHECKSIG`. A malicious taker can therefore fund the incoming P2TR contract with a leaf whose first instruction is the expected locktime but whose remaining instructions simply drop it and leave true on the stack. The maker accepts the contract and funds its outgoing Taproot contract; the taker can immediately spend back the incoming contract through this bogus timelock path without waiting for CLTV or needing the intended key, while also spending the maker-funded outgoing contract via the known preimage. I checked prior findings: #23 covers the analogous hashlock opcode omission, but `timelock OP_CLTV OP_DROP OP_CHECKSIG maker taproot` returned no matching prior finding.

## Proof of Concept

```diff
diff --git a/src/maker/taproot_verification.rs b/src/maker/taproot_verification.rs
--- a/src/maker/taproot_verification.rs
+++ b/src/maker/taproot_verification.rs
@@ -231,3 +231,95 @@ pub(crate) fn verify_taproot_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::verify_taproot_contract_data;
+    use crate::protocol::{
+        contract2::create_hashlock_script,
+        taproot_messages::{SerializableScalar, TaprootContractData},
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{sha256, Hash},
+        opcodes::all::{OP_DROP, OP_TRUE},
+        script,
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
+    fn maker_rejects_taproot_timelock_without_cltv_template() {
+        let secp = Secp256k1::new();
+        let hashlock_privkey = secret(1);
+        let hashlock_keypair = Keypair::from_secret_key(&secp, &hashlock_privkey);
+        let hashlock_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&hashlock_keypair).0;
+        let hash = sha256::Hash::hash(b"preimage").to_byte_array();
+        let hashlock_script = create_hashlock_script(&hash, &hashlock_xonly);
+
+        let maker_timelock = 100;
+        let taker_locktime = maker_timelock + crate::taker::api::REFUND_LOCKTIME_STEP as u32;
+        let malformed_timelock_script = script::Builder::new()
+            .push_lock_time(LockTime::from_height(taker_locktime).unwrap())
+            .push_opcode(OP_DROP)
+            .push_opcode(OP_TRUE)
+            .push_opcode(OP_TRUE)
+            .push_opcode(OP_TRUE)
+            .into_script();
+
+        let internal_privkey = secret(2);
+        let internal_keypair = Keypair::from_secret_key(&secp, &internal_privkey);
+        let internal_key = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&internal_keypair).0;
+        let tap_info = bitcoin::taproot::TaprootBuilder::new()
+            .add_leaf(1, hashlock_script.clone())
+            .unwrap()
+            .add_leaf(1, malformed_timelock_script.clone())
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
+        let next_hop_privkey = secret(3);
+        let next_hop_point = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_hop_privkey),
+        };
+        let data = TaprootContractData::new(
+            "bad-timelock".to_string(),
+            vec![next_hop_point],
+            next_hop_point,
+            internal_key,
+            SerializableScalar::from_bytes(tap_info.tap_tweak().to_scalar().to_be_bytes().to_vec()),
+            hashlock_script,
+            malformed_timelock_script,
+            vec![contract_tx],
+            vec![amount],
+            Some(hashlock_privkey),
+            None,
+        );
+
+        assert!(
+            verify_taproot_contract_data(&data, maker_timelock, 0).is_err(),
+            "maker must reject timelock leaves that do not enforce <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

