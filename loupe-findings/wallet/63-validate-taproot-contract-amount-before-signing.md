# Validate Taproot contract amount before signing

- **Finding ID:** 63
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/swapcoin.rs
- **Lines:** 530-538
- **CWE:** CWE-20
- **Fingerprint:** 035fa88b4cc64d47b0a6f01812478db7e69e57f1a4d45982e393abe0500fbb0b

## Description

`IncomingSwapCoin::get_contract_output_vout` selects the Taproot contract output by matching `output.value == self.funding_amount`, but silently returns vout 0 when no output has that amount. `sign_taproot_spend` then constructs the prevout with `value: self.funding_amount` while taking only the script from the selected transaction output. A counterparty-controlled Taproot contract can therefore carry a P2TR output with the correct script but a smaller value while the swap metadata claims the expected amount. The swapcoin accepts that state and later produces a hashlock spend signature over the claimed amount rather than the actual UTXO amount, so the sweep transaction is invalid and the victim cannot claim the advertised incoming contract via the hashlock path after revealing/learning the preimage. This depends on the surrounding protocol accepting claimed Taproot amounts from messages; I did not rely on out-of-tree behavior. Prior search `swapcoin Taproot funding_amount get_contract_output_vout output value mismatch` returned no matching findings.

## Proof of Concept

```diff
diff --git a/src/wallet/swapcoin.rs b/src/wallet/swapcoin.rs
--- a/src/wallet/swapcoin.rs
+++ b/src/wallet/swapcoin.rs
@@ -1245,3 +1245,84 @@ impl WatchOnlySwapCoin {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{sha256, Hash},
+        secp256k1::{Keypair, Secp256k1},
+        transaction::Version,
+        OutPoint, Sequence, TxIn, TxOut,
+    };
+
+    #[test]
+    fn taproot_hashlock_spend_rejects_missing_claimed_contract_amount() {
+        let secp = Secp256k1::new();
+        let preimage = [42u8; 32];
+        let hash = sha256::Hash::hash(&preimage).to_byte_array();
+
+        let hashlock_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let hashlock_keypair = Keypair::from_secret_key(&secp, &hashlock_privkey);
+        let (hashlock_xonly, _) = hashlock_keypair.x_only_public_key();
+
+        let timelock_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let timelock_keypair = Keypair::from_secret_key(&secp, &timelock_privkey);
+        let (timelock_xonly, _) = timelock_keypair.x_only_public_key();
+
+        let internal_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
+        let internal_keypair = Keypair::from_secret_key(&secp, &internal_privkey);
+        let (internal_xonly, _) = internal_keypair.x_only_public_key();
+
+        let hashlock_script = crate::protocol::contract2::create_hashlock_script(
+            &hash,
+            &hashlock_xonly,
+        );
+        let timelock_script = crate::protocol::contract2::create_timelock_script(
+            LockTime::from_height(500).unwrap(),
+            &timelock_xonly,
+        );
+        let (contract_script, _) = crate::protocol::contract2::create_taproot_script(
+            hashlock_script.clone(),
+            timelock_script.clone(),
+            internal_xonly,
+        )
+        .unwrap();
+
+        let actual_contract_amount = Amount::from_sat(50_000);
+        let claimed_contract_amount = Amount::from_sat(60_000);
+        let contract_tx = Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut { value: actual_contract_amount, script_pubkey: contract_script }],
+        };
+
+        let mut swapcoin = IncomingSwapCoin::new_taproot(
+            hashlock_privkey,
+            hashlock_script,
+            timelock_script,
+            contract_tx,
+            claimed_contract_amount,
+        );
+        swapcoin.internal_key = Some(internal_xonly);
+        swapcoin.set_preimage(preimage);
+
+        let signed = swapcoin.sign_spend_transaction(
+            actual_contract_amount,
+            &ScriptBuf::new(),
+            1.0,
+        );
+
+        assert!(
+            signed.is_err(),
+            "taproot signing must reject contract transactions whose outputs do not match the recorded funding_amount"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

