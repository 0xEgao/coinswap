# Signs arbitrary receiver contract transactions

- **Finding ID:** 14
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/legacy_handlers.rs
- **Lines:** 568-590
- **CWE:** CWE-345
- **Fingerprint:** 064082db75c346ecffcadddde9682da7350d9f142f37d98d1d1e3e99cd33f339

## Description

`process_req_contract_sigs_for_recvr` looks up an outgoing legacy swapcoin solely by the caller-supplied multisig redeemscript and then signs the caller-supplied `contract_tx`. The only transaction validation is input/output count plus an optional funding txid check, but maker-created `OutgoingSwapCoin::new_legacy` leaves `funding_tx` unset in this flow, and the handler never checks that the input outpoint, funding value, or output script match the negotiated `outgoing.contract_tx`/`outgoing.contract_redeemscript`. A malicious taker/next hop that knows the other multisig key can wait until the maker reaches `AwaitingPrivateKeyHandover`, send `ReqContractSigsForRecvr` with the correct multisig script but an arbitrary one-input transaction paying outside the HTLC, receive the maker's ECDSA signature, add its own signature, and spend the maker's funding output without the agreed hashlock/timelock protections. I searched prior findings for this handler and arbitrary signing issue and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_handlers.rs b/src/maker/legacy_handlers.rs
--- a/src/maker/legacy_handlers.rs
+++ b/src/maker/legacy_handlers.rs
@@ -781,3 +781,194 @@ fn emit_maker_success_report<M: Maker>(maker: &Arc<M>, state: &ConnectionState,
         log::warn!("Failed to save maker success report: {:?}", e);
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        blockdata::{opcodes::all::OP_TRUE, script::Builder},
+        hashes::{hash160, Hash},
+        transaction::Version,
+        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+    };
+
+    use crate::{
+        protocol::{
+            common_messages::{FidelityProof, Offer, ProtocolVersion, SwapDetails},
+            legacy_messages::{ContractTxInfoForRecvr, ReqContractSigsForRecvr},
+        },
+        wallet::swapcoin::OutgoingSwapCoin,
+    };
+
+    struct SigningOnlyMaker {
+        outgoing: OutgoingSwapCoin,
+    }
+
+    impl Maker for SigningOnlyMaker {
+        fn network_port(&self) -> u16 {
+            0
+        }
+
+        fn network(&self) -> bitcoin::Network {
+            bitcoin::Network::Regtest
+        }
+
+        fn get_tweakable_keypair(&self) -> Result<(SecretKey, PublicKey), MakerError> {
+            unimplemented!()
+        }
+
+        fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
+            unimplemented!()
+        }
+
+        fn get_config(&self) -> super::super::handlers::MakerConfig {
+            super::super::handlers::MakerConfig {
+                base_fee: 0,
+                amount_relative_fee_pct: 0.0,
+                time_relative_fee_pct: 0.0,
+                min_swap_amount: 0,
+                max_swap_amount: u64::MAX,
+                required_confirms: 0,
+                supported_protocols: vec![ProtocolVersion::Legacy],
+            }
+        }
+
+        fn validate_swap_parameters(&self, _details: &SwapDetails) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn calculate_swap_fee(&self, _amount: Amount, _timelock: u32) -> Amount {
+            Amount::ZERO
+        }
+
+        fn create_funding_transaction(
+            &self,
+            _amount: Amount,
+            _address: bitcoin::Address,
+            _excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
+        ) -> Result<(Transaction, u32), MakerError> {
+            unimplemented!()
+        }
+
+        fn broadcast_transaction(&self, _tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
+            unimplemented!()
+        }
+
+        fn save_incoming_swapcoin(
+            &self,
+            _swapcoin: &crate::wallet::swapcoin::IncomingSwapCoin,
+        ) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn save_outgoing_swapcoin(&self, _swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn register_watch_outpoint(&self, _outpoint: bitcoin::OutPoint) {}
+
+        fn unwatch_outpoint(&self, _outpoint: bitcoin::OutPoint) {}
+
+        fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn store_connection_state(
+            &self,
+            _swap_id: &str,
+            _state: &ConnectionState,
+        ) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn get_connection_state(&self, _swap_id: &str) -> Option<ConnectionState> {
+            None
+        }
+
+        fn remove_connection_state(&self, _swap_id: &str) {}
+
+        fn data_dir(&self) -> &std::path::Path {
+            std::path::Path::new(".")
+        }
+
+        fn collect_excluded_utxos(&self, _current_swap_id: &str) -> Vec<bitcoin::OutPoint> {
+            Vec::new()
+        }
+
+        fn get_current_height(&self) -> Result<u32, MakerError> {
+            Ok(0)
+        }
+
+        fn verify_contract_tx_on_chain(&self, _txid: &bitcoin::Txid) -> Result<(), MakerError> {
+            Ok(())
+        }
+
+        fn verify_and_sign_sender_contract_txs(
+            &self,
+            _txs_info: &[crate::protocol::legacy_messages::ContractTxInfoForSender],
+            _hashvalue: &crate::protocol::Hash160,
+            _locktime: u16,
+        ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError> {
+            unimplemented!()
+        }
+
+        fn verify_proof_of_funding(
+            &self,
+            _message: &crate::protocol::legacy_messages::ProofOfFunding,
+        ) -> Result<crate::protocol::Hash160, MakerError> {
+            unimplemented!()
+        }
+
+        fn initialize_coinswap(
+            &self,
+            _send_amount: Amount,
+            _next_multisig_pubkeys: &[PublicKey],
+            _next_hashlock_pubkeys: &[PublicKey],
+            _hashvalue: crate::protocol::Hash160,
+            _locktime: u16,
+            _contract_feerate: f64,
+            _excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
+        ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError> {
+            unimplemented!()
+        }
+
+        fn find_outgoing_swapcoin(
+            &self,
+            multisig_redeemscript: &bitcoin::ScriptBuf,
+        ) -> Option<OutgoingSwapCoin> {
+            let computed = create_multisig_redeemscript(
+                &self.outgoing.my_pubkey.unwrap(),
+                &self.outgoing.other_pubkey.unwrap(),
+            );
+            if &computed == multisig_redeemscript {
+                Some(self.outgoing.clone())
+            } else {
+                None
+            }
+        }
+    }
+
+    fn one_input_tx(output_script: ScriptBuf) -> Transaction {
+        Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::new(Txid::from_slice(&[9u8; 32]).unwrap(), 0),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: Amount::from_sat(50_000),
+                script_pubkey: output_script,
+            }],
+        }
+    }
+
+    #[test]
+    fn receiver_sig_request_rejects_unnegotiated_contract_tx() {
+        let maker_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let counterparty_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let timelock_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let counterparty_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &counterparty_sk),
+        };
+
+        let negotiated_redeemscript = crate::protocol::contract::create_contract_redeemscript(
+            &counterparty_pubkey,
+            &counterparty_pubkey,
+            &hash160::Hash::from_slice(&[4u8; 20]).unwrap(),
+            &20,
+        );
+        let outgoing = OutgoingSwapCoin::new_legacy(
+            maker_sk,
+            counterparty_pubkey,
+            one_input_tx(redeemscript_to_scriptpubkey(&negotiated_redeemscript).unwrap()),
+            negotiated_redeemscript,
+            timelock_sk,
+            Amount::from_sat(50_000),
+        );
+        let multisig_redeemscript = create_multisig_redeemscript(
+            &outgoing.my_pubkey.unwrap(),
+            &outgoing.other_pubkey.unwrap(),
+        );
+
+        let mut state = ConnectionState::new(ProtocolVersion::Legacy);
+        state.phase = SwapPhase::AwaitingPrivateKeyHandover;
+        state.swap_id = Some("swap".to_string());
+        let maker = Arc::new(SigningOnlyMaker { outgoing });
+        let malicious_tx = one_input_tx(Builder::new().push_opcode(OP_TRUE).into_script());
+        let req = ReqContractSigsForRecvr {
+            id: "swap".to_string(),
+            txs: vec![ContractTxInfoForRecvr {
+                multisig_redeemscript,
+                contract_tx: malicious_tx,
+            }],
+        };
+
+        let result = process_req_contract_sigs_for_recvr(&maker, &mut state, req);
+
+        assert!(
+            result.is_err(),
+            "maker signed a transaction that does not pay to the negotiated contract"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

