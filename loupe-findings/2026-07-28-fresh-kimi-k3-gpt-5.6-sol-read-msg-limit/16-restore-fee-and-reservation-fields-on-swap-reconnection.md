# Restore fee and reservation fields on swap reconnection

- **Finding ID:** 16
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:530-553
- **Job:** 3
- **CWE:** CWE-665
- **Fingerprint:** 40fd66f423bddcd13179a72cabb0b25ad896726df0b61c6c1da004048667d9b2

## Description

`restore_state_if_needed` reconstructs a reconnecting connection field-by-field but omits `refund_locktime_offset` and `reserve_utxo`. Reconnection is an explicit protocol path: a new connection sends a protocol-specific message containing the swap ID, which causes this function to load the persisted state. For a Taproot swap interrupted after `AckSwapDetails` but before `TaprootContractData`, the fresh `ConnectionState` retains the default offset of zero. `process_taproot_contract` subsequently recomputes the service fee using `state.refund_locktime_offset`, so the maker silently waives the configured time-relative fee; a taker can trigger this simply by disconnecting and resuming. For later-phase reconnects, omitting `reserve_utxo` can also cause the next persistence write to replace the stored reservation set with an empty vector, corrupting concurrent-selection bookkeeping. The production `MakerServer` snapshot layer in `src/maker/api.rs` also fails to persist `refund_locktime_offset`, so a complete fix must preserve it there as well; `reserve_utxo` is already returned by that layer and is lost specifically here. The PoC supplies a fully populated state through the public `Maker` persistence contract and confirms both fields vanish on HEAD. Prior finding #3 was reviewed and is distinct: it concerns duplicate-ID overwrite, not incomplete restoration. Searches for `refund_locktime_offset reconnect restore state fee` found no prior match.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -613,3 +613,198 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod reconnect_state_tests {
+    use super::*;
+    use std::{collections::HashMap, path::PathBuf, sync::Mutex};
+
+    struct MockMaker {
+        states: Mutex<HashMap<String, ConnectionState>>,
+        data_dir: PathBuf,
+    }
+
+    impl MockMaker {
+        fn new() -> Self {
+            Self {
+                states: Mutex::new(HashMap::new()),
+                data_dir: PathBuf::from("/tmp/coinswap-reconnect-test"),
+            }
+        }
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
+        fn get_tweakable_keypair(
+            &self,
+        ) -> Result<(bitcoin::secp256k1::SecretKey, PublicKey, ChainCode), MakerError> {
+            unimplemented!()
+        }
+
+        fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
+            unimplemented!()
+        }
+
+        fn get_config(&self) -> MakerConfig {
+            unimplemented!()
+        }
+
+        fn validate_swap_parameters(&self, _details: &SwapDetails) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn calculate_swap_fee(&self, _amount: Amount, _timelock: u32) -> Amount {
+            unimplemented!()
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
+        fn is_transaction_known(&self, _txid: &bitcoin::Txid) -> bool {
+            unimplemented!()
+        }
+
+        fn save_incoming_swapcoin(&self, _swapcoin: &IncomingSwapCoin) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn save_outgoing_swapcoin(&self, _swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn register_watch_outpoint(
+            &self,
+            _outpoint: bitcoin::OutPoint,
+            _script_pubkey: bitcoin::ScriptBuf,
+        ) {
+        }
+
+        fn unwatch_outpoint(
+            &self,
+            _outpoint: bitcoin::OutPoint,
+            _script_pubkey: bitcoin::ScriptBuf,
+        ) {
+        }
+
+        fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
+            unimplemented!()
+        }
+
+        fn store_connection_state(
+            &self,
+            swap_id: &str,
+            state: &ConnectionState,
+        ) -> Result<(), MakerError> {
+            self.states
+                .lock()
+                .unwrap()
+                .insert(swap_id.to_string(), state.clone());
+            Ok(())
+        }
+
+        fn get_connection_state(&self, swap_id: &str) -> Option<ConnectionState> {
+            self.states.lock().unwrap().get(swap_id).cloned()
+        }
+
+        fn remove_connection_state(&self, swap_id: &str) {
+            self.states.lock().unwrap().remove(swap_id);
+        }
+
+        fn data_dir(&self) -> &std::path::Path {
+            &self.data_dir
+        }
+
+        fn wallet_name(&self) -> &str {
+            "mock"
+        }
+
+        fn collect_excluded_utxos(&self, _current_swap_id: &str) -> Vec<bitcoin::OutPoint> {
+            Vec::new()
+        }
+
+        fn get_current_height(&self) -> Result<u32, MakerError> {
+            unimplemented!()
+        }
+
+        fn verify_contract_tx_on_chain(&self, _txid: &bitcoin::Txid) -> Result<(), MakerError> {
+            unimplemented!()
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
+            _multisig_redeemscript: &bitcoin::ScriptBuf,
+        ) -> Option<OutgoingSwapCoin> {
+            unimplemented!()
+        }
+    }
+
+    #[test]
+    fn reconnect_restores_fee_locktime_and_reserved_utxos() {
+        let maker = Arc::new(MockMaker::new());
+        let mut stored = ConnectionState::new(ProtocolVersion::Taproot);
+        stored.swap_id = Some("reconnect".to_string());
+        stored.swap_amount = Amount::from_sat(100_000);
+        stored.phase = SwapPhase::AwaitingContractData;
+        stored.refund_locktime_offset = 75;
+        stored.reserve_utxo = vec![bitcoin::OutPoint::null()];
+        maker
+            .store_connection_state("reconnect", &stored)
+            .unwrap();
+
+        let mut reconnected = ConnectionState::default();
+        restore_state_if_needed(&maker, &mut reconnected, "reconnect");
+
+        assert_eq!(reconnected.refund_locktime_offset, 75);
+        assert_eq!(reconnected.reserve_utxo, stored.reserve_utxo);
+    }
+}

```
