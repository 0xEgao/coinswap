# Reject duplicate funding proofs

- **Finding ID:** 15
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/legacy_handlers.rs
- **Lines:** 169-215
- **CWE:** CWE-345
- **Fingerprint:** accd105bd5d1af28e01c469a2f3920384f5e7b28789650933a1f3a6af5275a16

## Description

`process_proof_of_funding` iterates every `FundingTxInfo` in `confirmed_funding_txes`, finds the matching multisig output, creates an incoming swapcoin, and adds that output value to `incoming_amount`. It never records the `(funding_txid, vout)` pairs it has already accepted. A malicious taker can repeat the same confirmed funding output multiple times in one `ProofOfFunding`; the proof verifier only establishes that each entry names an existing confirmed output, while this handler counts each duplicate as additional incoming value. The inflated `incoming_amount` is then used to initialize the maker's outgoing coinswap, causing the maker to allocate and later broadcast more outgoing funds than the taker actually locked. The duplicated incoming swapcoins all spend the same outpoint, so the maker cannot recover equivalent value. I searched prior findings for duplicate `ProofOfFunding`/funding-output counting and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_handlers.rs b/src/maker/legacy_handlers.rs
--- a/src/maker/legacy_handlers.rs
+++ b/src/maker/legacy_handlers.rs
@@ -781,3 +781,224 @@ fn emit_maker_success_report<M: Maker>(maker: &Arc<M>, state: &ConnectionState,
         log::warn!("Failed to save maker success report: {:?}", e);
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        hashes::{hash160, Hash},
+        transaction::Version,
+        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+    };
+    use std::sync::Mutex;
+
+    use crate::{
+        protocol::{
+            common_messages::{FidelityProof, ProtocolVersion, SwapDetails},
+            legacy_messages::{FundingTxInfo, NextHopInfo, ProofOfFunding},
+        },
+        wallet::swapcoin::OutgoingSwapCoin,
+    };
+
+    struct ProofOnlyMaker {
+        tweakable_privkey: SecretKey,
+        tweakable_pubkey: PublicKey,
+        initialized_amount: Mutex<Option<Amount>>,
+    }
+
+    impl Maker for ProofOnlyMaker {
+        fn network_port(&self) -> u16 {
+            0
+        }
+
+        fn network(&self) -> bitcoin::Network {
+            bitcoin::Network::Regtest
+        }
+
+        fn get_tweakable_keypair(&self) -> Result<(SecretKey, PublicKey), MakerError> {
+            Ok((self.tweakable_privkey, self.tweakable_pubkey))
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
+            _message: &ProofOfFunding,
+        ) -> Result<crate::protocol::Hash160, MakerError> {
+            Ok(hash160::Hash::from_slice(&[8u8; 20]).unwrap())
+        }
+
+        fn initialize_coinswap(
+            &self,
+            send_amount: Amount,
+            _next_multisig_pubkeys: &[PublicKey],
+            _next_hashlock_pubkeys: &[PublicKey],
+            _hashvalue: crate::protocol::Hash160,
+            _locktime: u16,
+            _contract_feerate: f64,
+            _excluded_outpoints: Option<Vec<bitcoin::OutPoint>>,
+        ) -> Result<(Vec<Transaction>, Vec<OutgoingSwapCoin>, Amount), MakerError> {
+            *self.initialized_amount.lock().unwrap() = Some(send_amount);
+            Err(MakerError::General("stop after amount calculation"))
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
+    fn dummy_tx(output: TxOut) -> Transaction {
+        Transaction {
+            version: Version::TWO,
+            lock_time: LockTime::ZERO,
+            input: vec![TxIn {
+                previous_output: OutPoint::new(Txid::from_slice(&[7u8; 32]).unwrap(), 0),
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::ZERO,
+                witness: Witness::new(),
+            }],
+            output: vec![output],
+        }
+    }
+
+    #[test]
+    fn proof_of_funding_rejects_duplicate_funding_outpoints() {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let maker_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let maker_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &maker_sk),
+        };
+        let multisig_nonce = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let maker_multisig_sk = maker_sk.add_tweak(&multisig_nonce.into()).unwrap();
+        let maker_multisig_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &maker_multisig_sk),
+        };
+        let other_sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
+        let other_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_sk),
+        };
+        let hashlock_nonce = SecretKey::from_slice(&[4u8; 32]).unwrap();
+        let hashlock_sk = maker_sk.add_tweak(&hashlock_nonce.into()).unwrap();
+        let hashlock_pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &hashlock_sk),
+        };
+        let multisig_redeemscript = create_multisig_redeemscript(&maker_multisig_pubkey, &other_pubkey);
+        let contract_redeemscript = crate::protocol::contract::create_contract_redeemscript(
+            &hashlock_pubkey,
+            &other_pubkey,
+            &hash160::Hash::from_slice(&[8u8; 20]).unwrap(),
+            &30,
+        );
+        let funding_output = TxOut {
+            value: Amount::from_sat(100_000),
+            script_pubkey: redeemscript_to_scriptpubkey(&multisig_redeemscript).unwrap(),
+        };
+        let funding_info = FundingTxInfo {
+            funding_tx: dummy_tx(funding_output),
+            funding_tx_merkleproof: String::new(),
+            multisig_redeemscript,
+            multisig_nonce,
+            contract_redeemscript,
+            hashlock_nonce,
+        };
+        let pof = ProofOfFunding {
+            id: "swap".to_string(),
+            confirmed_funding_txes: vec![funding_info.clone(), funding_info],
+            next_coinswap_info: vec![NextHopInfo {
+                next_multisig_pubkey: other_pubkey,
+                next_hashlock_pubkey: hashlock_pubkey,
+                next_multisig_nonce: other_sk,
+                next_hashlock_nonce: hashlock_sk,
+            }],
+            refund_locktime: 10,
+            contract_feerate: 1.0,
+        };
+        let maker = Arc::new(ProofOnlyMaker {
+            tweakable_privkey: maker_sk,
+            tweakable_pubkey: maker_pubkey,
+            initialized_amount: Mutex::new(None),
+        });
+        let mut state = ConnectionState::new(ProtocolVersion::Legacy);
+        state.phase = SwapPhase::AwaitingContractData;
+        state.swap_id = Some("swap".to_string());
+
+        let _ = process_proof_of_funding(&maker, &mut state, pof);
+
+        assert!(
+            maker.initialized_amount.lock().unwrap().is_none(),
+            "duplicate funding outpoints must be rejected before maker liquidity is allocated"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

