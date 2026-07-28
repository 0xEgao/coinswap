# Reject funding keepalives after the confirmation phase

- **Finding ID:** 19
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:389-400
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** a95082af3f73eaf7949ad405b33a697fd56ea9aa9fc001911ad9e3268605f2b8

## Description

`WaitingFundingConfirmation` refreshes any persisted swap named by the peer without checking the stored swap phase, `funding_broadcast`, or whether the connection is associated with that swap. `MakerServer::store_connection_state` resets the persisted `last_activity` timestamp, and `drain_idle_swaps` only starts dropped-swap recovery after that timestamp exceeds the idle timeout. The swap ID is generated and known by the taker, so after the maker has broadcast its outgoing funding and entered `AwaitingPrivateKeyHandover`, a taker that stops progressing can keep sending this pre-funding keepalive from fresh connections. Each message refreshes the safety/recovery timeout even though no funding confirmation is pending, indefinitely postponing the maker's designed timelock-recovery path and keeping committed funds and liquidity tied up. The legitimate in-tree sender uses this message only while waiting for the taker's incoming funding transaction to confirm, when the persisted maker state is still `AwaitingContractData`; restricting refreshes to that state preserves the intended behavior. The PoC seeds a funded swap in `AwaitingPrivateKeyHandover`, sends one keepalive through `handle_message`, and asserts that persistence was not invoked. It fails on HEAD because the timeout is refreshed unconditionally. Searches for `WaitingFundingConfirmation keepalive phase recovery timeout unauthorized` found no prior match; prior finding #3 concerns duplicate-ID overwrite and is distinct.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -613,3 +613,213 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod keepalive_phase_tests {
+    use super::*;
+    use std::{
+        collections::HashMap,
+        path::PathBuf,
+        sync::{
+            atomic::{AtomicUsize, Ordering},
+            Mutex,
+        },
+    };
+
+    struct MockMaker {
+        states: Mutex<HashMap<String, ConnectionState>>,
+        stores: AtomicUsize,
+        data_dir: PathBuf,
+    }
+
+    impl MockMaker {
+        fn new() -> Self {
+            Self {
+                states: Mutex::new(HashMap::new()),
+                stores: AtomicUsize::new(0),
+                data_dir: PathBuf::from("/tmp/coinswap-keepalive-test"),
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
+            self.stores.fetch_add(1, Ordering::SeqCst);
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
+    fn keepalive_cannot_refresh_a_funded_swap_waiting_for_handover() {
+        let maker = Arc::new(MockMaker::new());
+        let mut funded = ConnectionState::new(ProtocolVersion::Taproot);
+        funded.swap_id = Some("funded".to_string());
+        funded.swap_amount = Amount::from_sat(100_000);
+        funded.phase = SwapPhase::AwaitingPrivateKeyHandover;
+        funded.funding_broadcast = true;
+        maker.store_connection_state("funded", &funded).unwrap();
+        let stores_before = maker.stores.load(Ordering::SeqCst);
+
+        let mut connection = ConnectionState::default();
+        let _ = handle_message(
+            &maker,
+            &mut connection,
+            TakerToMakerMessage::WaitingFundingConfirmation("funded".to_string()),
+        );
+
+        assert_eq!(
+            maker.stores.load(Ordering::SeqCst),
+            stores_before,
+            "a keepalive outside the funding-confirmation phase refreshed recovery timeout"
+        );
+    }
+}

```
