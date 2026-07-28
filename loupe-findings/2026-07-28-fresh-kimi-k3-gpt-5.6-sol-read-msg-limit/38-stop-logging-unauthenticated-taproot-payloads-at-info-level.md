# Stop logging unauthenticated Taproot payloads at info level

- **Finding ID:** 38
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:604-609
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** bb0ddb2d88920db0caac6d1ee406739cb0f009820af1e01cb6bd2549e6fcaabb

## Description

`handle_taproot_dispatch` formats the complete `TaprootTakerMessage` with `{:?}` at info level before state restoration or `ensure_negotiated_protocol`. The production maker logger writes `coinswap::maker` info records to `debug.log`, and the network reader accepts frames up to 10 MiB. Consequently, a peer does not need a handshake, a known swap, or valid phase state: it can repeatedly send a syntactically valid Taproot private-key-handover containing a large vector, have the connection rejected immediately afterward, and still force the maker to format and persist the entire attacker-controlled vector. The regression uses the canonical 16-character swap ID and 4,096 key records; on HEAD the rejected message produces a 299,149-byte info record. Repetition consumes disk and formatting resources until logging or the host filesystem becomes unavailable. This report does not claim raw key disclosure: the pinned Bitcoin type's observed Debug output is redacted. A fix should log only bounded metadata such as the variant and element count, ideally after cheap protocol/phase checks. Prior #24 concerns oversized identifiers retained in state and #15 concerns permanently leaked mismatch strings; both were reviewed and are distinct because this test uses a canonical ID and exercises full-vector info logging before validation.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -613,3 +613,238 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod taproot_logging_tests {
+    use super::*;
+    use crate::protocol::common_messages::{PrivateKeyHandover, SwapPrivkey};
+    use std::{
+        path::{Path, PathBuf},
+        sync::{Mutex, Once},
+    };
+
+    static INIT_LOGGER: Once = Once::new();
+    static CAPTURED_DISPATCH: Mutex<Option<String>> = Mutex::new(None);
+
+    struct DispatchLogger;
+
+    impl log::Log for DispatchLogger {
+        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
+            metadata.level() <= log::Level::Info
+        }
+
+        fn log(&self, record: &log::Record<'_>) {
+            if self.enabled(record.metadata()) {
+                let rendered = record.args().to_string();
+                if rendered.contains("Dispatching Taproot message") {
+                    *CAPTURED_DISPATCH.lock().unwrap() = Some(rendered);
+                }
+            }
+        }
+
+        fn flush(&self) {}
+    }
+
+    static DISPATCH_LOGGER: DispatchLogger = DispatchLogger;
+
+    struct LogOnlyMaker {
+        data_dir: PathBuf,
+    }
+
+    impl LogOnlyMaker {
+        fn new() -> Self {
+            Self {
+                data_dir: PathBuf::from("."),
+            }
+        }
+    }
+
+    impl Maker for LogOnlyMaker {
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
+            unreachable!()
+        }
+
+        fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
+            unreachable!()
+        }
+
+        fn get_config(&self) -> MakerConfig {
+            unreachable!()
+        }
+
+        fn validate_swap_parameters(&self, _details: &SwapDetails) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn calculate_swap_fee(&self, _amount: Amount, _timelock: u32) -> Amount {
+            unreachable!()
+        }
+
+        fn create_funding_transaction(
+            &self,
+            _amount: Amount,
+            _address: bitcoin::Address,
+            _excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
+        ) -> Result<(Transaction, u32), MakerError> {
+            unreachable!()
+        }
+
+        fn broadcast_transaction(&self, _tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
+            unreachable!()
+        }
+
+        fn is_transaction_known(&self, _txid: &bitcoin::Txid) -> bool {
+            unreachable!()
+        }
+
+        fn save_incoming_swapcoin(&self, _swapcoin: &IncomingSwapCoin) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn save_outgoing_swapcoin(&self, _swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn register_watch_outpoint(
+            &self,
+            _outpoint: bitcoin::OutPoint,
+            _script_pubkey: bitcoin::ScriptBuf,
+        ) {
+            unreachable!()
+        }
+
+        fn unwatch_outpoint(
+            &self,
+            _outpoint: bitcoin::OutPoint,
+            _script_pubkey: bitcoin::ScriptBuf,
+        ) {
+            unreachable!()
+        }
+
+        fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn store_connection_state(
+            &self,
+            _swap_id: &str,
+            _state: &ConnectionState,
+        ) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn get_connection_state(&self, _swap_id: &str) -> Option<ConnectionState> {
+            None
+        }
+
+        fn remove_connection_state(&self, _swap_id: &str) {
+            unreachable!()
+        }
+
+        fn data_dir(&self) -> &Path {
+            &self.data_dir
+        }
+
+        fn wallet_name(&self) -> &str {
+            "log-only"
+        }
+
+        fn collect_excluded_utxos(&self, _current_swap_id: &str) -> Vec<bitcoin::OutPoint> {
+            unreachable!()
+        }
+
+        fn get_current_height(&self) -> Result<u32, MakerError> {
+            unreachable!()
+        }
+
+        fn verify_contract_tx_on_chain(&self, _txid: &bitcoin::Txid) -> Result<(), MakerError> {
+            unreachable!()
+        }
+
+        fn verify_and_sign_sender_contract_txs(
+            &self,
+            _txs_info: &[crate::protocol::legacy_messages::ContractTxInfoForSender],
+            _hashvalue: &crate::protocol::Hash160,
+            _locktime: u16,
+        ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError> {
+            unreachable!()
+        }
+
+        fn verify_proof_of_funding(
+            &self,
+            _message: &crate::protocol::legacy_messages::ProofOfFunding,
+        ) -> Result<crate::protocol::Hash160, MakerError> {
+            unreachable!()
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
+            unreachable!()
+        }
+
+        fn find_outgoing_swapcoin(
+            &self,
+            _multisig_redeemscript: &bitcoin::ScriptBuf,
+        ) -> Option<OutgoingSwapCoin> {
+            unreachable!()
+        }
+
+        #[cfg(feature = "integration-test")]
+        fn behavior(&self) -> MakerBehavior {
+            MakerBehavior::Normal
+        }
+    }
+
+    #[test]
+    fn unauthenticated_taproot_dispatch_does_not_log_the_full_payload() {
+        INIT_LOGGER.call_once(|| {
+            log::set_logger(&DISPATCH_LOGGER).unwrap();
+            log::set_max_level(log::LevelFilter::Info);
+        });
+        *CAPTURED_DISPATCH.lock().unwrap() = None;
+
+        let key = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
+        let item = SwapPrivkey {
+            identifier: bitcoin::ScriptBuf::new(),
+            key,
+        };
+        let message = TakerToMakerMessage::TaprootPrivateKeyHandover(PrivateKeyHandover {
+            id: "0123456789abcdef".to_string(),
+            privkeys: vec![item; 4096],
+        });
+
+        let maker = Arc::new(LogOnlyMaker::new());
+        let mut state = ConnectionState::default();
+        assert!(handle_message(&maker, &mut state, message).is_err());
+
+        if let Some(logged) = CAPTURED_DISPATCH.lock().unwrap().as_ref() {
+            assert!(
+                logged.len() < 4096,
+                "an unauthenticated protocol payload expanded to {} bytes in the persistent info log",
+                logged.len()
+            );
+        }
+    }
+}

```
