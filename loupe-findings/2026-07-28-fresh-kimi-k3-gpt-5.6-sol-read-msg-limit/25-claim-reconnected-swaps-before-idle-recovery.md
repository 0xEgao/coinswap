# Claim reconnected swaps before idle recovery

- **Finding ID:** 25
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:530-555
- **Job:** 3
- **CWE:** CWE-362
- **Fingerprint:** 7dcf097b8589bb7c3481edd72c392e29cabd7c78957e769a44b640f03170683e

## Description

`restore_state_if_needed` clones a persisted swap into the reconnecting connection but neither refreshes nor atomically claims the persisted entry. `handle_message` only touches the new connection-local state. In the production `MakerServer`, `get_connection_state` leaves `SwapState.last_activity` unchanged, while the background `drain_idle_swaps` removes any stale entry with outgoing swapcoins and immediately launches recovery. A valid reconnect can therefore clone a swap just after its idle deadline; before the resumed protocol handler stores its next phase, the idle checker can remove the same entry and start `recover_from_swap`. The active handler and recovery thread then operate concurrently on the same funded swap, allowing conflicting wallet writes and settlement/recovery spends and potentially aborting an otherwise valid settlement. The PoC reproduces the exact ordering with the production drain predicate: it seeds a funded stale state, restores it successfully, then shows it is still immediately drainable. It fails on HEAD. Restoration should atomically refresh/claim the entry under the same synchronization used by idle draining, not merely copy it. Prior #16 concerns omitted restored fields and #19 concerns attacker keepalives; neither covers this reconnect-versus-reaper race.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -613,3 +613,252 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod reconnect_idle_claim_tests {
+    use super::*;
+    use std::{
+        collections::HashMap,
+        path::PathBuf,
+        sync::Mutex,
+        time::Duration,
+    };
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
+                data_dir: PathBuf::from("/tmp/coinswap-reconnect-idle-test"),
+            }
+        }
+
+        fn insert_without_touch(&self, id: &str, state: ConnectionState) {
+            self.states.lock().unwrap().insert(id.to_string(), state);
+        }
+
+        fn drain_idle(&self, timeout: Duration) -> bool {
+            let mut states = self.states.lock().unwrap();
+            let stale = states
+                .get("stale-funded")
+                .is_some_and(|state| {
+                    state.last_activity.elapsed() > timeout
+                        && !state.outgoing_swapcoins.is_empty()
+                });
+            if stale {
+                states.remove("stale-funded");
+            }
+            stale
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
+            let mut refreshed = state.clone();
+            refreshed.touch();
+            self.states
+                .lock()
+                .unwrap()
+                .insert(swap_id.to_string(), refreshed);
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
+
+        #[cfg(feature = "integration-test")]
+        fn behavior(&self) -> MakerBehavior {
+            MakerBehavior::Normal
+        }
+    }
+
+    fn dummy_outgoing_swapcoin() -> OutgoingSwapCoin {
+        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let other_pubkey = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
+            &secp, &secret,
+        ));
+        let tx = Transaction {
+            version: bitcoin::transaction::Version::TWO,
+            lock_time: bitcoin::absolute::LockTime::ZERO,
+            input: Vec::new(),
+            output: Vec::new(),
+        };
+        OutgoingSwapCoin::new_legacy(
+            secret,
+            other_pubkey,
+            tx,
+            bitcoin::ScriptBuf::new(),
+            secret,
+            Amount::from_sat(1),
+        )
+    }
+
+    #[test]
+    fn reconnect_claims_state_before_idle_recovery_can_drain_it() {
+        let maker = Arc::new(MockMaker::new());
+        let mut stored = ConnectionState::new(ProtocolVersion::Legacy);
+        stored.swap_id = Some("stale-funded".to_string());
+        stored.swap_amount = Amount::from_sat(100_000);
+        stored.phase = SwapPhase::AwaitingPrivateKeyHandover;
+        stored.outgoing_swapcoins.push(dummy_outgoing_swapcoin());
+        stored.funding_broadcast = true;
+        stored.last_activity = Instant::now() - Duration::from_secs(901);
+        maker.insert_without_touch("stale-funded", stored);
+
+        let mut reconnected = ConnectionState::default();
+        restore_state_if_needed(&maker, &mut reconnected, "stale-funded");
+        assert_eq!(reconnected.swap_id.as_deref(), Some("stale-funded"));
+
+        assert!(
+            !maker.drain_idle(Duration::from_secs(900)),
+            "a successfully restored active swap remained stale and was drained for recovery"
+        );
+    }
+}

```
