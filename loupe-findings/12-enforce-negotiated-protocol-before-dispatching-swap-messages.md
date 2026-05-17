# Enforce negotiated protocol before dispatching swap messages

- **Finding ID:** 12
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/handlers.rs
- **Lines:** 547-570
- **CWE:** CWE-284
- **Fingerprint:** c70b19451be344ac9ddd1fce2c1c27d718b85a73e2366d725b6258d0a71b299e

## Description

After SwapDetails is accepted, state.protocol records the negotiated and configured protocol version, but the top-level dispatcher ignores it for subsequent protocol-specific messages. Any Legacy enum variant is routed into legacy_handlers and any Taproot enum variant is routed into taproot_handlers solely based on the message variant. A peer can therefore negotiate Taproot with a maker whose supported_protocols excludes Legacy, then send Legacy ReqContractSigsForSender/ProofOfFunding messages using the same swap id. Because handle_legacy_dispatch restores state and immediately calls handle_legacy_message without checking state.protocol, the maker can sign or fund a Legacy flow that its configuration did not offer. The symmetric issue exists for Taproot messages after Legacy negotiation. This is a real authorization/policy bypass: protocol support is an explicit maker policy and may be used to disable an older or experimental protocol, but the network peer can bypass that policy after the initial validation. I searched prior findings for `handlers protocol dispatch legacy taproot SwapDetails state.protocol` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -569,3 +569,123 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::hashes::Hash as _;
+    use std::path::Path;
+
+    struct TaprootOnlyMaker;
+
+    impl Maker for TaprootOnlyMaker {
+        fn network_port(&self) -> u16 {
+            0
+        }
+
+        fn network(&self) -> bitcoin::Network {
+            bitcoin::Network::Regtest
+        }
+
+        fn get_tweakable_keypair(
+            &self,
+        ) -> Result<(bitcoin::secp256k1::SecretKey, PublicKey), MakerError> {
+            unimplemented!()
+        }
+
+        fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
+            unimplemented!()
+        }
+
+        fn get_config(&self) -> MakerConfig {
+            MakerConfig {
+                base_fee: 0,
+                amount_relative_fee_pct: 0.0,
+                time_relative_fee_pct: 0.0,
+                min_swap_amount: 0,
+                max_swap_amount: 1_000_000,
+                required_confirms: 0,
+                supported_protocols: vec![ProtocolVersion::Taproot],
+            }
+        }
+
+        fn validate_swap_parameters(&self, _details: &SwapDetails) -> Result<(), MakerError> {
+            Ok(())
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
+        fn save_incoming_swapcoin(&self, _swapcoin: &IncomingSwapCoin) -> Result<(), MakerError> {
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
+        fn data_dir(&self) -> &Path {
+            Path::new(".")
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
+            Ok(Vec::new())
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
+            _multisig_redeemscript: &bitcoin::ScriptBuf,
+        ) -> Option<OutgoingSwapCoin> {
+            None
+        }
+    }
+
+    #[test]
+    fn rejects_legacy_message_after_taproot_negotiation() {
+        let maker = Arc::new(TaprootOnlyMaker);
+        let mut state = ConnectionState::new(ProtocolVersion::Taproot);
+        state.swap_id = Some("swap-1".to_string());
+        state.swap_amount = Amount::from_sat(100_000);
+        state.timelock = 100;
+        state.phase = SwapPhase::AwaitingContractData;
+
+        let message = TakerToMakerMessage::ReqContractSigsForSender(
+            crate::protocol::legacy_messages::ReqContractSigsForSender {
+                id: "swap-1".to_string(),
+                txs_info: Vec::new(),
+                hashvalue: crate::protocol::Hash160::all_zeros(),
+                locktime: MIN_CONTRACT_REACTION_TIME,
+            },
+        );
+
+        let result = handle_message(&maker, &mut state, message);
+
+        assert!(
+            result.is_err(),
+            "legacy messages must be rejected once the swap negotiated Taproot"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

