# Validate Legacy ECDSA sighash type before funding

- **Finding ID:** 30
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_verification.rs:137-172
- **Job:** 3
- **CWE:** CWE-347
- **Fingerprint:** 1a5d0b606a8963bc495243e119fe59bf2d16b1f636b3e89067c3cb2a2bd7d6f0

## Description

`verify_contract_sigs` verifies only `bitcoin::ecdsa::Signature::signature` against a sighash computed with `EcdsaSighashType::All`; it never checks the wrapper's `sighash_type`. A malicious taker can therefore sign the expected `ALL` digest correctly, replace only the serialized sighash type with `None`, `Single`, or an `AnyoneCanPay` variant, and pass both receiver and sender verification. The caller then stores the complete attacker-supplied wrappers in `others_contract_sig` and broadcasts the maker's pending funding transactions (`legacy_handlers.rs:474-558`). During abort recovery, `create_signed_contract_tx` serializes each stored wrapper with `Signature::to_vec()` into the 2-of-2 witness (`wallet/swapcoin.rs:281-310`, `protocol/contract.rs:74-91`). Consensus interprets the attacker-selected byte and checks a different digest, so the contract transaction cannot spend the funding output. If the taker withholds handover/cooperation, the maker cannot move its outgoing funding into the timelocked contract and can permanently lose the funded swap amount, while the taker can later recover its own earlier-hop funding. The regression constructs a valid `ALL` scalar, wraps it as `None`, and shows this verifier accepts it on HEAD. Fix by rejecting every wrapper whose `sighash_type != EcdsaSighashType::All` before scalar verification. Prior searches for `legacy maker sighash type verify_contract_sigs`, `ECDSA sighash byte signature verification witness`, and `others_contract_sig sighash_type` returned no matches; prior #7 concerns a distinct locktime overflow.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -231,3 +231,71 @@ pub(crate) fn verify_legacy_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime, hashes::Hash, transaction::Version, Amount, EcdsaSighashType,
+        OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+    };
+
+    #[test]
+    fn contract_signature_rejects_mismatched_serialized_sighash_type() {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let my_secret = bitcoin::secp256k1::SecretKey::from_slice(&[1_u8; 32]).unwrap();
+        let other_secret = bitcoin::secp256k1::SecretKey::from_slice(&[2_u8; 32]).unwrap();
+        let hashlock_secret = bitcoin::secp256k1::SecretKey::from_slice(&[3_u8; 32]).unwrap();
+        let my_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &my_secret),
+        };
+        let other_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_secret),
+        };
+        let funding_amount = Amount::from_sat(50_000);
+        let contract_tx = Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint {
+                    txid: Txid::all_zeros(),
+                    vout: 0,
+                },
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: Amount::from_sat(49_000),
+                script_pubkey: ScriptBuf::new(),
+            }],
+        };
+        let multisig_redeemscript = create_multisig_redeemscript(&my_pubkey, &other_pubkey);
+        let all_signature = crate::protocol::contract::sign_contract_tx(
+            &contract_tx,
+            &multisig_redeemscript,
+            funding_amount,
+            &other_secret,
+        )
+        .unwrap();
+        let mismatched_signature = bitcoin::ecdsa::Signature {
+            signature: all_signature.signature,
+            sighash_type: EcdsaSighashType::None,
+        };
+        let incoming = IncomingSwapCoin::new_legacy(
+            my_secret,
+            other_pubkey,
+            contract_tx,
+            ScriptBuf::new(),
+            hashlock_secret,
+            funding_amount,
+        );
+
+        assert!(
+            verify_contract_sigs(&[mismatched_signature], &[], &[incoming], &[], 6102).is_err(),
+            "a signature verified over SIGHASH_ALL must not be accepted with a different witness sighash byte"
+        );
+    }
+}

```
