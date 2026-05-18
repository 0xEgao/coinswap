# Require exact Taproot timelock script opcodes

- **Finding ID:** 48
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/taproot_verification.rs
- **Lines:** 71-151
- **CWE:** CWE-347
- **Fingerprint:** e8d6b1c80251c6c73a44e6e8455666b2d23aa8a63282d295f39c1c34ded2d69c

## Description

`verify_maker_taproot_contract` only counts five instructions in `timelock_script` and checks that the first push equals the negotiated locktime. It never verifies that instruction 2 is `OP_CLTV`, instruction 3 is `OP_DROP`, or that the script ends with the expected x-only pubkey and `OP_CHECKSIG`. A malicious maker can therefore return a Taproot output whose second leaf begins with the expected locktime but omits CLTV, for example `<locktime> OP_DROP <maker_pubkey> OP_CHECKSIG 1`. The taker reconstructs the P2TR output from that malicious leaf and accepts every contract tx paying to it. Once the tx is broadcast, the maker can spend the supposed refund/timelock path immediately with its own key instead of waiting for the negotiated timeout, depriving the taker of the expected hashlock output and breaking the swap’s atomicity. I searched prior findings for `verify_maker_taproot_contract timelock script OP_CLTV OP_CHECKSIG opcode` and `taproot hashlock timelock script format instructions count`; no duplicates were found.

## Proof of Concept

```diff
diff --git a/src/taker/taproot_verification.rs b/src/taker/taproot_verification.rs
index 1f8a0d7..7c92d71 100644
--- a/src/taker/taproot_verification.rs
+++ b/src/taker/taproot_verification.rs
@@ -223,3 +223,126 @@ impl Taker {
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::protocol::{
+        common_messages::ProtocolVersion,
+        contract2::{create_hashlock_script, create_timelock_script},
+        taproot_messages::SerializableScalar,
+    };
+    use crate::taker::{
+        api::OngoingSwapState,
+        swap_tracker::SwapPhase,
+        SwapParams,
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        opcodes::all::{OP_CHECKSIG, OP_DROP},
+        script::Builder,
+        secp256k1::{rand::thread_rng, Keypair, Secp256k1, SecretKey},
+        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
+        transaction::Version,
+    };
+    use std::mem::MaybeUninit;
+
+    const PREIMAGE: [u8; 32] = [42u8; 32];
+    const EXPECTED_LOCKTIME: u32 = 144;
+
+    fn taker_with_preimage() -> &'static Taker {
+        let mut boxed = Box::new(MaybeUninit::<Taker>::uninit());
+        let ptr = boxed.as_mut_ptr();
+        std::mem::forget(boxed);
+
+        unsafe {
+            std::ptr::addr_of_mut!((*ptr).ongoing_swap).write(Some(OngoingSwapState {
+                id: "test-swap".to_string(),
+                preimage: PREIMAGE,
+                params: SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(100_000), 1),
+                makers: Vec::new(),
+                outgoing_swapcoins: Vec::new(),
+                incoming_swapcoins: Vec::new(),
+                watchonly_swapcoins: Vec::new(),
+                multisig_nonces: Vec::new(),
+                hashlock_nonces: Vec::new(),
+                spare_makers: Vec::new(),
+                phase: SwapPhase::Initialized,
+                reference_height: None,
+            }));
+            &*ptr
+        }
+    }
+
+    fn contract_tx(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
+        Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut { value, script_pubkey }],
+        }
+    }
+
+    fn contract_for_scripts(
+        hashlock_script: ScriptBuf,
+        timelock_script: ScriptBuf,
+        tx_value: Amount,
+        claimed_amount: Amount,
+    ) -> TaprootContractData {
+        let secp = Secp256k1::new();
+        let internal_secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
+        let internal_keypair = Keypair::from_secret_key(&secp, &internal_secret);
+        let internal_key = internal_keypair.x_only_public_key().0;
+        let tap_info = bitcoin::taproot::TaprootBuilder::new()
+            .add_leaf(1, hashlock_script.clone())
+            .unwrap()
+            .add_leaf(1, timelock_script.clone())
+            .unwrap()
+            .finalize(&secp, internal_key)
+            .unwrap();
+        let script_pubkey = ScriptBuf::new_p2tr_tweaked(tap_info.output_key());
+
+        TaprootContractData::new(
+            "test-swap".to_string(),
+            Vec::new(),
+            bitcoin::PublicKey::new(internal_secret.public_key(&secp)),
+            internal_key,
+            SerializableScalar::from_bytes(tap_info.tap_tweak().to_scalar().to_be_bytes().to_vec()),
+            hashlock_script,
+            timelock_script,
+            vec![contract_tx(script_pubkey, tx_value)],
+            vec![claimed_amount],
+            None,
+            None,
+        )
+    }
+
+    fn valid_hashlock_script() -> ScriptBuf {
+        let secp = Secp256k1::new();
+        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
+        let xonly = keypair.x_only_public_key().0;
+        let hash = sha256::Hash::hash(&PREIMAGE).to_byte_array();
+        create_hashlock_script(&hash, &xonly)
+    }
+
+    #[test]
+    fn rejects_taproot_timelock_script_without_cltv() {
+        let secp = Secp256k1::new();
+        let maker_keypair = Keypair::new(&secp, &mut thread_rng());
+        let maker_xonly = maker_keypair.x_only_public_key().0;
+        let locktime = LockTime::from_height(EXPECTED_LOCKTIME).unwrap();
+        let immediately_spendable_timelock = Builder::new()
+            .push_lock_time(locktime)
+            .push_opcode(OP_DROP)
+            .push_x_only_key(&maker_xonly)
+            .push_opcode(OP_CHECKSIG)
+            .push_int(1)
+            .into_script();
+        let contract = contract_for_scripts(
+            valid_hashlock_script(),
+            immediately_spendable_timelock,
+            Amount::from_sat(100_000),
+            Amount::from_sat(100_000),
+        );
+
+        assert!(
+            taker_with_preimage()
+                .verify_maker_taproot_contract(&contract, 0, EXPECTED_LOCKTIME, Some(Amount::from_sat(90_000)))
+                .is_err(),
+            "verification accepted a timelock script that omits OP_CLTV"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

