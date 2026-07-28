# Maker signs taker-supplied receiver contract tx without validating its output, enabling theft of the maker's broadcast funding output

- **Finding ID:** 6
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_handlers.rs:649-705
- **Job:** 3
- **CWE:** CWE-345
- **Fingerprint:** d56217588c021a46813fd6e3b51d57f95874961c2138ff45360163c47878cd34

## Description

process_req_contract_sigs_for_recvr handles ReqContractSigsForRecvr in phase AwaitingPrivateKeyHandover — i.e. AFTER the maker has already broadcast its own funding transaction (state.funding_broadcast is set in process_resp_contract_sigs_for_recvr_and_sender, line 573). Before signing with the maker's 2-of-2 multisig key it only checks: (a) the tx has 1 input/1 output, and (b) the input's previous_output.txid equals the funding txid. It never validates the contract tx's single output — neither that the script_pubkey is the P2WSH of the agreed hashlock/timelock contract redeemscript (stored in outgoing.contract_redeemscript), nor the value, nor even that the tx matches the honest contract tx the maker itself built and advertised (outgoing.contract_tx). sign_contract_tx (src/protocol/contract.rs:467) signs with SIGHASH_ALL over exactly the tx the taker supplied, so a malicious taker can send a contract tx spending the maker's multisig funding outpoint to an output paying 100% to a taker-controlled address; the maker returns a valid signature, the taker adds its own multisig signature, broadcasts, and steals the maker's entire outgoing amount. The taker then aborts before private-key handover and later refunds its own incoming funds via timelock, losing nothing. The sibling sender-side path (verify_req_contract_sigs_for_sender in src/maker/legacy_verification.rs) does perform output validation via is_contract_out_valid, confirming this check was intended here too. No prior findings matched (searched: contract tx output validation, ReqContractSigsForRecvr). The PoC adds a unit test with a mock Maker: the honest contract tx is signed (sane baseline), while a tampered tx with the same funding outpoint but a taker-owned P2WPKH output is also signed on HEAD — the assertion that it must be rejected fails on HEAD and passes once the output is validated.

## Proof of Concept

```diff
--- a/src/maker/legacy_handlers.rs
+++ b/src/maker/legacy_handlers.rs
@@ -885,4 +885,288 @@
     if let Err(e) = report.save_for_wallet(maker.data_dir(), Some(maker.wallet_name())) {
         log::warn!("Failed to save maker success report: {:?}", e);
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::{
+        protocol::{
+            common_messages::ProtocolVersion,
+            contract::{create_contract_redeemscript, create_senders_contract_tx},
+            legacy_messages::{ContractTxInfoForRecvr, ReqContractSigsForRecvr},
+        },
+        wallet::swapcoin::OutgoingSwapCoin,
+    };
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{hash160, Hash},
+        transaction::Version,
+        OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
+    };
+
+    /// Minimal Maker stub: only the methods exercised by
+    /// `process_req_contract_sigs_for_recvr` are real; the rest panic.
+    struct MockMaker {
+        coin: OutgoingSwapCoin,
+        multisig_redeemscript: ScriptBuf,
+    }
+
+    impl Maker for MockMaker {
+        fn network_port(&self) -> u16 {
+            6102
+        }
+
+        fn network(&self) -> bitcoin::Network {
+            bitcoin::Network::Regtest
+        }
+
+        fn find_outgoing_swapcoin(
+            &self,
+            multisig_redeemscript: &bitcoin::ScriptBuf,
+        ) -> Option<OutgoingSwapCoin> {
+            if *multisig_redeemscript == self.multisig_redeemscript {
+                Some(self.coin.clone())
+            } else {
+                None
+            }
+        }
+
+        fn get_tweakable_keypair(
+            &self,
+        ) -> Result<(SecretKey, PublicKey, bitcoin::bip32::ChainCode), MakerError> {
+            unimplemented!()
+        }
+        fn get_fidelity_proof(
+            &self,
+        ) -> Result<crate::protocol::common_messages::FidelityProof, MakerError> {
+            unimplemented!()
+        }
+        fn get_config(&self) -> crate::maker::handlers::MakerConfig {
+            unimplemented!()
+        }
+        fn validate_swap_parameters(
+            &self,
+            _details: &crate::protocol::common_messages::SwapDetails,
+        ) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn calculate_swap_fee(&self, _amount: Amount, _timelock: u32) -> Amount {
+            unimplemented!()
+        }
+        fn create_funding_transaction(
+            &self,
+            _amount: Amount,
+            _address: bitcoin::Address,
+            _excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
+        ) -> Result<(Transaction, u32), MakerError> {
+            unimplemented!()
+        }
+        fn broadcast_transaction(&self, _tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
+            unimplemented!()
+        }
+        fn is_transaction_known(&self, _txid: &bitcoin::Txid) -> bool {
+            unimplemented!()
+        }
+        fn save_incoming_swapcoin(&self, _swapcoin: &IncomingSwapCoin) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn save_outgoing_swapcoin(&self, _swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn register_watch_outpoint(
+            &self,
+            _outpoint: bitcoin::OutPoint,
+            _script_pubkey: bitcoin::ScriptBuf,
+        ) {
+            unimplemented!()
+        }
+        fn unwatch_outpoint(&self, _outpoint: bitcoin::OutPoint, _script_pubkey: bitcoin::ScriptBuf) {
+            unimplemented!()
+        }
+        fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn store_connection_state(
+            &self,
+            _swap_id: &str,
+            _state: &ConnectionState,
+        ) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn get_connection_state(&self, _swap_id: &str) -> Option<ConnectionState> {
+            unimplemented!()
+        }
+        fn remove_connection_state(&self, _swap_id: &str) {
+            unimplemented!()
+        }
+        fn data_dir(&self) -> &std::path::Path {
+            unimplemented!()
+        }
+        fn wallet_name(&self) -> &str {
+            unimplemented!()
+        }
+        fn collect_excluded_utxos(&self, _current_swap_id: &str) -> Vec<bitcoin::OutPoint> {
+            unimplemented!()
+        }
+        fn get_current_height(&self) -> Result<u32, MakerError> {
+            unimplemented!()
+        }
+        fn verify_contract_tx_on_chain(&self, _txid: &bitcoin::Txid) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+        fn verify_and_sign_sender_contract_txs(
+            &self,
+            _txs_info: &[crate::protocol::legacy_messages::ContractTxInfoForSender],
+            _hashvalue: &crate::protocol::Hash160,
+            _locktime: u16,
+        ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError> {
+            unimplemented!()
+        }
+        fn verify_proof_of_funding(
+            &self,
+            _message: &crate::protocol::legacy_messages::ProofOfFunding,
+        ) -> Result<crate::protocol::Hash160, MakerError> {
+            unimplemented!()
+        }
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
+        #[cfg(feature = "integration-test")]
+        fn behavior(&self) -> crate::maker::handlers::MakerBehavior {
+            unimplemented!()
+        }
+    }
+
+    /// The maker must not sign a receiver contract tx whose output has been
+    /// swapped for one paying the taker directly. On HEAD the maker signs it,
+    /// letting the taker steal the already-broadcast funding output.
+    #[test]
+    fn req_contract_sigs_for_recvr_rejects_tampered_contract_output() {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let maker_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let taker_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let hashlock_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
+        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();
+        let to_pub = |sk: &SecretKey| PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, sk),
+        };
+        let maker_pubkey = to_pub(&maker_privkey);
+        let taker_pubkey = to_pub(&taker_privkey);
+
+        let multisig_redeemscript = create_multisig_redeemscript(&maker_pubkey, &taker_pubkey);
+        let multisig_spk = redeemscript_to_scriptpubkey(&multisig_redeemscript).unwrap();
+
+        let funding_amount = Amount::from_sat(100_000);
+        let funding_tx = Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::null(),
+                sequence: Sequence::MAX,
+                script_sig: ScriptBuf::new(),
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: funding_amount,
+                script_pubkey: multisig_spk,
+            }],
+        };
+        let funding_outpoint = OutPoint {
+            txid: funding_tx.compute_txid(),
+            vout: 0,
+        };
+
+        // The honest contract tx the maker itself constructed and advertised.
+        let hashvalue = hash160::Hash::hash(&[7u8; 32]);
+        let contract_redeemscript = create_contract_redeemscript(
+            &to_pub(&hashlock_privkey),
+            &to_pub(&timelock_privkey),
+            &hashvalue,
+            &50,
+        );
+        let honest_contract_tx =
+            create_senders_contract_tx(funding_outpoint, funding_amount, &contract_redeemscript)
+                .unwrap();
+
+        let mut outgoing = OutgoingSwapCoin::new_legacy(
+            maker_privkey,
+            taker_pubkey,
+            honest_contract_tx,
+            contract_redeemscript,
+            timelock_privkey,
+            funding_amount,
+        );
+        outgoing.funding_tx = Some(funding_tx);
+
+        // Malicious contract tx: same funding outpoint and multisig, but the
+        // output pays the full amount to the taker's own P2WPKH address
+        // instead of the agreed hashlock/timelock contract.
+        let taker_wpkh = taker_pubkey.wpubkey_hash().unwrap();
+        let theft_tx = Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: funding_outpoint,
+                sequence: Sequence::ZERO,
+                script_sig: ScriptBuf::new(),
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: funding_amount - Amount::from_sat(500),
+                script_pubkey: ScriptBuf::new_p2wpkh(&taker_wpkh),
+            }],
+        };
+
+        let maker = Arc::new(MockMaker {
+            coin: outgoing,
+            multisig_redeemscript: multisig_redeemscript.clone(),
+        });
+
+        let mut state = ConnectionState::new(ProtocolVersion::Legacy);
+        state.phase = SwapPhase::AwaitingPrivateKeyHandover;
+        state.swap_id = Some("swap1".to_string());
+
+        // Sanity: the honest contract tx must be accepted for signing.
+        let honest_msg = LegacyTakerMessage::ReqContractSigsForRecvr(ReqContractSigsForRecvr {
+            id: "swap1".to_string(),
+            txs: vec![ContractTxInfoForRecvr {
+                multisig_redeemscript: multisig_redeemscript.clone(),
+                contract_tx: maker.coin.contract_tx.clone(),
+            }],
+        });
+        let honest = handle_legacy_message(&maker, &mut state, honest_msg);
+        assert!(
+            honest.is_ok(),
+            "honest contract tx must be accepted: {:?}",
+            honest.err()
+        );
+
+        // The tampered contract tx must be rejected.
+        let theft_msg = LegacyTakerMessage::ReqContractSigsForRecvr(ReqContractSigsForRecvr {
+            id: "swap1".to_string(),
+            txs: vec![ContractTxInfoForRecvr {
+                multisig_redeemscript,
+                contract_tx: theft_tx,
+            }],
+        });
+        let tampered = handle_legacy_message(&maker, &mut state, theft_msg);
+        assert!(
+            tampered.is_err(),
+            "maker signed a contract tx paying the funding output directly to the taker"
+        );
+    }
+}

```
