# Reject incoming funding outpoints reused across swap IDs

- **Finding ID:** 39
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1318-1347
- **Job:** 3
- **CWE:** CWE-294
- **Fingerprint:** 769d479b903d479755ee29afa622aed7f7c81095f1a322b55ae28f7240d8434a

## Description

`verify_proof_of_funding` tracks `seen_outpoints` only for the current `ProofOfFunding` message. The accepted outpoint is never atomically claimed by `swap_id` in `ongoing_swaps`, and the persistent contract cache is keyed only by outpoint/script. A taker can therefore negotiate multiple Legacy swaps, request the same valid sender contract under each ID, and replay one confirmed, unspent funding outpoint in every proof. Each proof passes the per-message set and cache check, after which the maker independently constructs outgoing funding for that swap. Once the taker supplies the expected signatures, all non-conflicting outgoing transactions can be broadcast even though only one incoming coin backs them; revealing the shared hash preimage lets the taker claim every outgoing contract while the maker can recover the incoming outpoint only once. This is a direct multi-swap fund-loss invariant failure. The regression test models the post-verification state transition and shows that HEAD stores the same Legacy funding outpoint under two independent swap IDs. A fix should atomically reserve protocol-specific incoming outpoints across active/completed-unsettled swaps before funding any next hop and release them only when safe. Prior #26 concerns maker input reservation for pending Legacy funding, #37 bounds vector sizes, and #14 concerns spent Taproot outputs; none prevents replay of one valid incoming Legacy outpoint across swap IDs.

## Proof of Concept

```diff
diff --git a/src/wallet/mod.rs b/src/wallet/mod.rs
--- a/src/wallet/mod.rs
+++ b/src/wallet/mod.rs
@@ -29,3 +29,5 @@ pub(crate) use fidelity::{
 pub use report::{MakerFeeInfo, MakerReport, RecoveryReport, SwapRole, SwapStatus, TakerReport};
 pub use spend::Destination;
 pub use storage::AddressType;
+#[cfg(feature = "integration-test")]
+pub use swapcoin::IncomingSwapCoin;
diff --git a/src/wallet/swapcoin.rs b/src/wallet/swapcoin.rs
--- a/src/wallet/swapcoin.rs
+++ b/src/wallet/swapcoin.rs
@@ -98,6 +98,7 @@ pub struct IncomingSwapCoin {
 }
 
 impl IncomingSwapCoin {
+    /// Creates an incoming Legacy swap coin.
     pub fn new_legacy(
         my_privkey: SecretKey,
         other_pubkey: PublicKey,
diff --git a/tests/replayed_incoming_outpoint.rs b/tests/replayed_incoming_outpoint.rs
new file mode 100644
--- /dev/null
+++ b/tests/replayed_incoming_outpoint.rs
@@ -0,0 +1,97 @@
+#![cfg(feature = "integration-test")]
+
+#[macro_use]
+#[path = "integration/test_framework/mod.rs"]
+mod test_framework;
+
+use bitcoin::{
+    absolute::LockTime,
+    hashes::Hash,
+    secp256k1::{Secp256k1, SecretKey},
+    transaction::Version,
+    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+};
+use coinswap::{
+    maker::{ConnectionState, MakerBehavior, MakerTrait, SwapPhase},
+    protocol::common_messages::ProtocolVersion,
+    wallet::{AddressType, IncomingSwapCoin},
+};
+use test_framework::*;
+
+fn incoming_coin(swap_id: &str) -> IncomingSwapCoin {
+    let secp = Secp256k1::new();
+    let my_privkey = SecretKey::from_slice(&[1; 32]).unwrap();
+    let other_privkey = SecretKey::from_slice(&[2; 32]).unwrap();
+    let other_pubkey = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
+        &secp,
+        &other_privkey,
+    ));
+    let contract_tx = Transaction {
+        version: Version::TWO,
+        lock_time: LockTime::ZERO,
+        input: vec![TxIn {
+            previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
+            script_sig: ScriptBuf::new(),
+            sequence: Sequence::ZERO,
+            witness: Witness::new(),
+        }],
+        output: vec![TxOut {
+            value: Amount::from_sat(100_000),
+            script_pubkey: ScriptBuf::new(),
+        }],
+    };
+    let mut coin = IncomingSwapCoin::new_legacy(
+        my_privkey,
+        other_pubkey,
+        contract_tx,
+        ScriptBuf::new(),
+        SecretKey::from_slice(&[3; 32]).unwrap(),
+        Amount::from_sat(100_000),
+    );
+    coin.swap_id = Some(swap_id.to_string());
+    coin
+}
+
+#[test]
+fn maker_rejects_incoming_outpoint_replayed_across_swap_ids() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8984, Some(21821))],
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+    let maker = &makers[0];
+
+    fund_makers(
+        &makers,
+        &test_framework.bitcoind,
+        2,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+    maker.wallet.write().unwrap().sync_and_save().unwrap();
+
+    let mut first = ConnectionState::new(ProtocolVersion::Legacy);
+    first.phase = SwapPhase::AwaitingSignaturesOrPreimage;
+    first.swap_amount = Amount::from_sat(100_000);
+    first.incoming_swapcoins = vec![incoming_coin("first-swap")];
+
+    let mut replay = ConnectionState::new(ProtocolVersion::Legacy);
+    replay.phase = SwapPhase::AwaitingSignaturesOrPreimage;
+    replay.swap_amount = Amount::from_sat(100_000);
+    replay.incoming_swapcoins = vec![incoming_coin("second-swap")];
+
+    let first_result = maker.store_connection_state("first-swap", &first);
+    let replay_result = maker.store_connection_state("second-swap", &replay);
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(first_result.is_ok(), "initial incoming claim should store");
+    assert!(
+        replay_result.is_err(),
+        "the same funding outpoint backed two independent swap IDs"
+    );
+}

```
