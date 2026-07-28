# Persist partial Legacy funding broadcasts before returning errors

- **Finding ID:** 29
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_handlers.rs:526-591
- **Job:** 3
- **CWE:** n/a
- **Fingerprint:** 1cab66fbe0672f4d6b346a899f8e9891411f0c98f5b8db309bb3ab3d39900dbe

## Description

The handler broadcasts every pending funding transaction, but sets `state.funding_broadcast = true` and persists the state only after the entire loop succeeds. If an earlier transaction is accepted and a later broadcast returns an error that `is_transaction_known` cannot resolve, line 566 returns with the previously persisted swap state still marked unfunded. This is practically reachable for multi-transaction swaps (the taker controls the `next_coinswap_info` count), transient backend failures, or conflicting pending transactions. The swapcoins carrying the counterparty contract signatures were saved immediately before broadcasting, but the idle recovery path later treats an explicit `funding_broadcast=false` tracker record as safe to discard and deletes those records. For an already-broadcast 2-of-2 output, deleting the saved counterparty signature and randomly generated timelock key can make the maker's on-chain funds unrecoverable. The regression test supplies valid contract signatures, injects success for the first funding transaction and failure for the second, and requires the partial-broadcast fact to be marked and persisted before the error escapes; it fails on HEAD. Prior finding #6 concerns signing an attacker-selected contract, and #26 concerns reserving funding outputs instead of inputs; neither covers this partial-broadcast state-loss path.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_handlers.rs b/src/maker/legacy_handlers.rs
--- a/src/maker/legacy_handlers.rs
+++ b/src/maker/legacy_handlers.rs
@@ -886,3 +886,7 @@
         log::warn!("Failed to save maker success report: {:?}", e);
     }
 }
+
+#[cfg(test)]
+#[path = "legacy_handlers_partial_broadcast_test.rs"]
+mod partial_broadcast_regression;
diff --git a/src/maker/legacy_handlers_partial_broadcast_test.rs b/src/maker/legacy_handlers_partial_broadcast_test.rs
new file mode 100644
--- /dev/null
+++ b/src/maker/legacy_handlers_partial_broadcast_test.rs
@@ -0,0 +1,300 @@
+use super::*;
+use crate::{
+    maker::handlers::MakerConfig,
+    protocol::{
+        common_messages::{FidelityProof, ProtocolVersion, SwapDetails},
+        contract::{create_multisig_redeemscript, sign_contract_tx},
+        legacy_messages::{
+            ContractTxInfoForSender, ProofOfFunding, RespContractSigsForRecvrAndSender,
+        },
+        Hash160,
+    },
+    wallet::swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
+};
+use bitcoin::{
+    absolute::LockTime, bip32::ChainCode, transaction::Version, Address, Network, OutPoint,
+    Sequence, Transaction, TxIn, TxOut, Witness,
+};
+use std::{
+    path::Path,
+    sync::{
+        atomic::{AtomicUsize, Ordering},
+        Mutex,
+    },
+};
+
+struct PartialBroadcastMaker {
+    broadcasts: AtomicUsize,
+    persisted_broadcast_flags: Mutex<Vec<bool>>,
+}
+
+impl PartialBroadcastMaker {
+    fn new() -> Self {
+        Self {
+            broadcasts: AtomicUsize::new(0),
+            persisted_broadcast_flags: Mutex::new(Vec::new()),
+        }
+    }
+}
+
+impl Maker for PartialBroadcastMaker {
+    fn network_port(&self) -> u16 {
+        6102
+    }
+
+    fn network(&self) -> Network {
+        Network::Regtest
+    }
+
+    fn broadcast_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid, MakerError> {
+        if self.broadcasts.fetch_add(1, Ordering::SeqCst) == 0 {
+            Ok(tx.compute_txid())
+        } else {
+            Err(MakerError::General("injected second broadcast failure"))
+        }
+    }
+
+    fn is_transaction_known(&self, _txid: &bitcoin::Txid) -> bool {
+        false
+    }
+
+    fn save_incoming_swapcoin(&self, _swapcoin: &IncomingSwapCoin) -> Result<(), MakerError> {
+        Ok(())
+    }
+
+    fn save_outgoing_swapcoin(&self, _swapcoin: &OutgoingSwapCoin) -> Result<(), MakerError> {
+        Ok(())
+    }
+
+    fn store_connection_state(
+        &self,
+        _swap_id: &str,
+        state: &ConnectionState,
+    ) -> Result<(), MakerError> {
+        self.persisted_broadcast_flags
+            .lock()
+            .unwrap()
+            .push(state.funding_broadcast);
+        Ok(())
+    }
+
+    fn get_tweakable_keypair(&self) -> Result<(SecretKey, PublicKey, ChainCode), MakerError> {
+        unimplemented!()
+    }
+
+    fn get_fidelity_proof(&self) -> Result<FidelityProof, MakerError> {
+        unimplemented!()
+    }
+
+    fn get_config(&self) -> MakerConfig {
+        unimplemented!()
+    }
+
+    fn validate_swap_parameters(&self, _details: &SwapDetails) -> Result<(), MakerError> {
+        unimplemented!()
+    }
+
+    fn calculate_swap_fee(&self, _amount: Amount, _timelock: u32) -> Amount {
+        unimplemented!()
+    }
+
+    fn create_funding_transaction(
+        &self,
+        _amount: Amount,
+        _address: Address,
+        _excluded_outpoints: Option<Vec<OutPoint>>,
+    ) -> Result<(Transaction, u32), MakerError> {
+        unimplemented!()
+    }
+
+    fn register_watch_outpoint(&self, _outpoint: OutPoint, _script_pubkey: ScriptBuf) {
+        unimplemented!()
+    }
+
+    fn unwatch_outpoint(&self, _outpoint: OutPoint, _script_pubkey: ScriptBuf) {
+        unimplemented!()
+    }
+
+    fn sync_and_save_wallet(&self) -> Result<(), MakerError> {
+        unimplemented!()
+    }
+
+    fn sweep_incoming_swapcoins(&self) -> Result<(), MakerError> {
+        unimplemented!()
+    }
+
+    fn get_connection_state(&self, _swap_id: &str) -> Option<ConnectionState> {
+        unimplemented!()
+    }
+
+    fn remove_connection_state(&self, _swap_id: &str) {
+        unimplemented!()
+    }
+
+    fn data_dir(&self) -> &Path {
+        unimplemented!()
+    }
+
+    fn wallet_name(&self) -> &str {
+        unimplemented!()
+    }
+
+    fn collect_excluded_utxos(&self, _current_swap_id: &str) -> Vec<OutPoint> {
+        unimplemented!()
+    }
+
+    fn get_current_height(&self) -> Result<u32, MakerError> {
+        unimplemented!()
+    }
+
+    fn verify_contract_tx_on_chain(&self, _txid: &bitcoin::Txid) -> Result<(), MakerError> {
+        unimplemented!()
+    }
+
+    fn verify_and_sign_sender_contract_txs(
+        &self,
+        _txs_info: &[ContractTxInfoForSender],
+        _hashvalue: &Hash160,
+        _locktime: u16,
+    ) -> Result<Vec<bitcoin::ecdsa::Signature>, MakerError> {
+        unimplemented!()
+    }
+
+    fn verify_proof_of_funding(&self, _message: &ProofOfFunding) -> Result<Hash160, MakerError> {
+        unimplemented!()
+    }
+
+    fn initialize_coinswap(
+        &self,
+        _send_amount: Amount,
+        _next_multisig_pubkeys: &[PublicKey],
+        _next_hashlock_pubkeys: &[PublicKey],
+        _hashvalue: Hash160,
+        _locktime: u16,
+        _contract_feerate: f64,
+        _excluded_outpoints: Option<Vec<OutPoint>>,
+    ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError> {
+        unimplemented!()
+    }
+
+    fn find_outgoing_swapcoin(
+        &self,
+        _multisig_redeemscript: &ScriptBuf,
+    ) -> Option<OutgoingSwapCoin> {
+        unimplemented!()
+    }
+
+    #[cfg(feature = "integration-test")]
+    fn behavior(&self) -> crate::maker::handlers::MakerBehavior {
+        crate::maker::handlers::MakerBehavior::Normal
+    }
+}
+
+fn test_transaction(value: u64) -> Transaction {
+    Transaction {
+        version: Version::TWO,
+        lock_time: LockTime::ZERO,
+        input: vec![TxIn {
+            previous_output: OutPoint::null(),
+            script_sig: ScriptBuf::new(),
+            sequence: Sequence::ZERO,
+            witness: Witness::new(),
+        }],
+        output: vec![TxOut {
+            value: Amount::from_sat(value),
+            script_pubkey: ScriptBuf::new(),
+        }],
+    }
+}
+
+fn pubkey(
+    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
+    key: &SecretKey,
+) -> PublicKey {
+    PublicKey {
+        compressed: true,
+        inner: bitcoin::secp256k1::PublicKey::from_secret_key(secp, key),
+    }
+}
+
+#[test]
+fn partial_funding_broadcast_is_persisted_before_returning_error() {
+    let secp = bitcoin::secp256k1::Secp256k1::new();
+    let incoming_maker_key = SecretKey::from_slice(&[1; 32]).unwrap();
+    let incoming_other_key = SecretKey::from_slice(&[2; 32]).unwrap();
+    let incoming_other_pubkey = pubkey(&secp, &incoming_other_key);
+    let incoming_contract_tx = test_transaction(99_000);
+    let incoming = IncomingSwapCoin::new_legacy(
+        incoming_maker_key,
+        incoming_other_pubkey,
+        incoming_contract_tx,
+        ScriptBuf::new(),
+        SecretKey::from_slice(&[3; 32]).unwrap(),
+        Amount::from_sat(100_000),
+    );
+    let incoming_multisig = create_multisig_redeemscript(
+        &incoming.my_pubkey.unwrap(),
+        &incoming.other_pubkey.unwrap(),
+    );
+    let incoming_other_sig = sign_contract_tx(
+        &incoming.contract_tx,
+        &incoming_multisig,
+        incoming.funding_amount,
+        &incoming_other_key,
+    )
+    .unwrap();
+
+    let outgoing_maker_key = SecretKey::from_slice(&[4; 32]).unwrap();
+    let outgoing_other_key = SecretKey::from_slice(&[5; 32]).unwrap();
+    let outgoing_other_pubkey = pubkey(&secp, &outgoing_other_key);
+    let outgoing_contract_tx = test_transaction(89_000);
+    let outgoing = OutgoingSwapCoin::new_legacy(
+        outgoing_maker_key,
+        outgoing_other_pubkey,
+        outgoing_contract_tx,
+        ScriptBuf::new(),
+        SecretKey::from_slice(&[6; 32]).unwrap(),
+        Amount::from_sat(90_000),
+    );
+    let outgoing_multisig = create_multisig_redeemscript(
+        &outgoing.my_pubkey.unwrap(),
+        &outgoing.other_pubkey.unwrap(),
+    );
+    let outgoing_other_sig = sign_contract_tx(
+        &outgoing.contract_tx,
+        &outgoing_multisig,
+        outgoing.funding_amount,
+        &outgoing_other_key,
+    )
+    .unwrap();
+
+    let maker = Arc::new(PartialBroadcastMaker::new());
+    let mut state = ConnectionState::new(ProtocolVersion::Legacy);
+    state.swap_id = Some("partial-broadcast".to_string());
+    state.phase = SwapPhase::AwaitingSignaturesOrPreimage;
+    state.incoming_swapcoins = vec![incoming];
+    state.outgoing_swapcoins = vec![outgoing];
+    state.pending_funding_txes = vec![test_transaction(80_000), test_transaction(70_000)];
+
+    let result = process_resp_contract_sigs_for_recvr_and_sender(
+        &maker,
+        &mut state,
+        RespContractSigsForRecvrAndSender {
+            id: "partial-broadcast".to_string(),
+            receivers_sigs: vec![incoming_other_sig],
+            senders_sigs: vec![outgoing_other_sig],
+        },
+    );
+
+    assert!(result.is_err(), "the injected second broadcast must fail");
+    assert_eq!(maker.broadcasts.load(Ordering::SeqCst), 2);
+    assert!(
+        state.funding_broadcast,
+        "one successful broadcast must prevent recovery from treating the swap as unfunded"
+    );
+    assert_eq!(
+        maker.persisted_broadcast_flags.lock().unwrap().last(),
+        Some(&true),
+        "the partial-broadcast state must be persisted before the handler returns"
+    );
+}

```
