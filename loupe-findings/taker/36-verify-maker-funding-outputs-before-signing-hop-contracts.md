# Verify maker funding outputs before signing hop contracts

- **Finding ID:** 36
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/legacy_swap.rs
- **Lines:** 977-990
- **CWE:** CWE-345
- **Fingerprint:** 65c776305b0a092ff7014b9215263b20beca8b89c4dc96077182ca22aac7ee2c

## Description

In the legacy ProofOfFunding path, the taker accepts a maker's SenderContractTxInfo after verify_maker_sender_contracts only checks that the contract input txid equals funding_tx.compute_txid() and that the contract output pays to the advertised contract redeem script. It does not verify that the referenced funding outpoint exists, that its vout pays to the advertised 2-of-2 multisig redeemscript, or that the actual output value equals funding_amount. A malicious maker can therefore return an already-confirmed or otherwise unrelated funding transaction with a non-multisig output, build an unsigned contract transaction that merely references that txid/vout, and claim a large funding_amount. The taker later waits for that txid to confirm and then sends the maker signatures for the maker's incoming/previous-hop contract. The maker can redeem the previous hop while never locking equivalent funds for the next hop/taker, breaking atomicity and causing loss/stuck funds. I searched prior findings for `legacy verify_maker_sender_contracts funding_tx output multisig funding_amount` and `sender contracts funding transaction output unchecked`; no matching prior finding was returned.

## Proof of Concept

```diff
diff --git a/src/taker/legacy_verification.rs b/src/taker/legacy_verification.rs
--- a/src/taker/legacy_verification.rs
+++ b/src/taker/legacy_verification.rs
@@ -355,3 +355,96 @@ impl Taker {
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::Hash,
+        secp256k1::{rand::thread_rng, SecretKey},
+        transaction::Version,
+        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
+    };
+
+    use crate::{
+        protocol::{
+            contract::{create_contract_redeemscript, create_multisig_redeemscript, create_senders_contract_tx},
+            legacy_messages::SenderContractTxInfo,
+        },
+        utill::{generate_keypair, redeemscript_to_scriptpubkey},
+    };
+
+    #[test]
+    fn maker_sender_contract_must_be_backed_by_advertised_multisig_output() {
+        let (maker_multisig_pubkey, _) = generate_keypair();
+        let (next_multisig_pubkey, _) = generate_keypair();
+        let (next_hashlock_pubkey, _) = generate_keypair();
+        let (timelock_pubkey, _) = generate_keypair();
+        let hashvalue = Hash160::hash(&[7u8; 32]);
+        let locktime = 20;
+
+        let multisig_redeemscript =
+            create_multisig_redeemscript(&maker_multisig_pubkey, &next_multisig_pubkey);
+        let contract_redeemscript = create_contract_redeemscript(
+            &next_hashlock_pubkey,
+            &timelock_pubkey,
+            &hashvalue,
+            &locktime,
+        );
+
+        let claimed_amount = Amount::from_sat(100_000);
+        let funding_tx = Transaction {
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+                script_sig: ScriptBuf::new(),
+            }],
+            output: vec![TxOut {
+                value: claimed_amount,
+                script_pubkey: ScriptBuf::new(),
+            }],
+            lock_time: LockTime::ZERO,
+            version: Version::TWO,
+        };
+        let contract_tx = create_senders_contract_tx(
+            OutPoint {
+                txid: funding_tx.compute_txid(),
+                vout: 0,
+            },
+            claimed_amount,
+            &contract_redeemscript,
+        )
+        .unwrap();
+
+        let info = SenderContractTxInfo {
+            funding_tx,
+            contract_tx,
+            timelock_pubkey,
+            multisig_redeemscript,
+            contract_redeemscript,
+            funding_amount: claimed_amount,
+            multisig_nonce: SecretKey::new(&mut thread_rng()),
+            hashlock_nonce: SecretKey::new(&mut thread_rng()),
+        };
+
+        check_reedemscript_is_multisig(&info.multisig_redeemscript).unwrap();
+        assert_eq!(
+            info.contract_tx.input[0].previous_output.txid,
+            info.funding_tx.compute_txid()
+        );
+        validate_contract_tx(&info.contract_tx, None, &info.contract_redeemscript).unwrap();
+        assert_eq!(
+            read_hashvalue_from_contract(&info.contract_redeemscript).unwrap(),
+            hashvalue
+        );
+        assert_eq!(
+            read_hashlock_pubkey_from_contract(&info.contract_redeemscript).unwrap(),
+            next_hashlock_pubkey
+        );
+
+        let funding_output = &info.funding_tx.output[info.contract_tx.input[0].previous_output.vout as usize];
+        assert_eq!(funding_output.value, info.funding_amount);
+        assert_eq!(
+            funding_output.script_pubkey,
+            redeemscript_to_scriptpubkey(&info.multisig_redeemscript).unwrap()
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

