# Bind claimed Taproot amounts to verified outputs

- **Finding ID:** 49
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/taproot_verification.rs
- **Lines:** 184-209
- **CWE:** CWE-345
- **Fingerprint:** 62acff379b7913dd7ddd79c030b2e467480646aec5d07b4fc516e7722b8c5e35

## Description

`verify_maker_taproot_contract` verifies only that each transaction's first output pays to the reconstructed Taproot script, then enforces the maker fee floor by summing `contract.amounts`. It never checks that `contract.amounts[i]` equals `contract.contract_txs[i].output[0].value`, nor that the vectors have matching lengths. A malicious maker can therefore return a contract transaction paying a tiny value to the expected P2TR script while claiming a large amount in `amounts`. The taker accepts the response because the claimed total satisfies `min_expected_amount`, then records the bogus amount in its incoming/watch-only swapcoin state. When the taker later tries to sweep or finalize, the on-chain output is underfunded relative to the accepted route; in a multi-hop swap this lets the maker underpay the taker while still causing upstream contracts to proceed based on the advertised amount. I searched prior findings for `taproot contract amounts output value verify_maker_taproot_contract`; no duplicate was found.

## Proof of Concept

```diff
diff --git a/src/taker/taproot_verification.rs b/src/taker/taproot_verification.rs
index 1f8a0d7..5cbb49e 100644
--- a/src/taker/taproot_verification.rs
+++ b/src/taker/taproot_verification.rs
@@ -223,3 +223,118 @@ impl Taker {
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
+        secp256k1::{Keypair, Secp256k1, SecretKey},
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
+    fn valid_scripts() -> (ScriptBuf, ScriptBuf) {
+        let secp = Secp256k1::new();
+        let hashlock_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
+        let timelock_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[8u8; 32]).unwrap());
+        let hash = sha256::Hash::hash(&PREIMAGE).to_byte_array();
+        let locktime = LockTime::from_height(EXPECTED_LOCKTIME).unwrap();
+        (
+            create_hashlock_script(&hash, &hashlock_keypair.x_only_public_key().0),
+            create_timelock_script(locktime, &timelock_keypair.x_only_public_key().0),
+        )
+    }
+
+    #[test]
+    fn rejects_claimed_amount_that_exceeds_verified_output_value() {
+        let (hashlock_script, timelock_script) = valid_scripts();
+        let contract = contract_for_scripts(
+            hashlock_script,
+            timelock_script,
+            Amount::from_sat(1_000),
+            Amount::from_sat(100_000),
+        );
+
+        assert!(
+            taker_with_preimage()
+                .verify_maker_taproot_contract(&contract, 0, EXPECTED_LOCKTIME, Some(Amount::from_sat(90_000)))
+                .is_err(),
+            "verification trusted the claimed amount instead of the contract output value"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

