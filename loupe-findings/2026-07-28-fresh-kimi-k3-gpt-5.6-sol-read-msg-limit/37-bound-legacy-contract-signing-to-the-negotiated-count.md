# Bound Legacy contract signing to the negotiated count

- **Finding ID:** 37
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1220-1254
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** dd3a4242816457a521cdfb13848a6bf017a9ba232b3199634ac7cc130b6a3bcf

## Description

`SwapDetails::tx_count` documents the number of contract transactions being negotiated, but the maker neither validates nor retains it in `SwapState`. Consequently, `verify_and_sign_sender_contract_txs` accepts every element in a taker-supplied `txs_info` slice and then calls `cache_prevout_to_contract` for every fabricated previous outpoint before signing. The initial signing handler deliberately remains callable in `AwaitingContractData` (and on retries), so a remote peer that reserved only the minimum swap amount can repeatedly submit fresh, structurally valid sender-contract batches without ever proving or broadcasting the referenced funding transactions. Each batch performs script validation and ECDSA signing and permanently extends `prevout_to_contract_map`; that map is serialized by `cache_prevout_to_contract`, making the resource consumption persistent in both memory and the wallet file. The 10 MiB per-message wire cap does not bound cumulative growth. The regression test negotiates exactly one Legacy contract and then supplies two valid contract infos; HEAD returns signatures and persists both bindings, while a fixed maker must reject the count mismatch before caching or signing. A complete fix should validate a reasonable nonzero `tx_count`, preserve it across connection state storage, and enforce it on every protocol vector. Prior searches for `verify_and_sign_sender_contract_txs tx_count cache` and `cache_prevout_to_contract unbounded contract signatures memory disk` returned no matching finding.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -46,4 +46,5 @@
 mod hotpath_profile;
+mod legacy_contract_count;
 mod legacy_malformed_contract;
 mod legacy_missing_contract_cache;
 mod liquidity_test;
diff --git a/tests/integration/legacy_contract_count.rs b/tests/integration/legacy_contract_count.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/legacy_contract_count.rs
@@ -0,0 +1,189 @@
+//! Contract-signing requests must be bound to the transaction count accepted in
+//! SwapDetails; otherwise each request can grow the persistent contract cache.
+
+use bitcoin::{
+    absolute::LockTime,
+    blockdata::{opcodes, script::Builder},
+    hashes::{hash160, Hash},
+    secp256k1::{rand::thread_rng, Secp256k1, SecretKey},
+    transaction::Version,
+    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+};
+use coinswap::{
+    maker::{handle_message, ConnectionState, MakerBehavior, MakerTrait, SwapPhase},
+    protocol::{
+        common_messages::{ProtocolVersion, SwapDetails, TakerToMakerMessage},
+        legacy_messages::{ContractTxInfoForSender, ReqContractSigsForSender},
+    },
+    wallet::AddressType,
+};
+
+use super::test_framework::*;
+
+fn tweaked_pubkey(base: &PublicKey, nonce: &SecretKey) -> PublicKey {
+    let secp = Secp256k1::new();
+    let nonce_point = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, nonce);
+    PublicKey {
+        compressed: true,
+        inner: base.inner.combine(&nonce_point).unwrap(),
+    }
+}
+
+fn multisig_script(first: &PublicKey, second: &PublicKey) -> ScriptBuf {
+    let mut keys = [*first, *second];
+    keys.sort_by_key(|key| key.inner.serialize());
+    Builder::new()
+        .push_int(2)
+        .push_key(&keys[0])
+        .push_key(&keys[1])
+        .push_int(2)
+        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
+        .into_script()
+}
+
+fn contract_script(
+    hashlock_pubkey: &PublicKey,
+    timelock_pubkey: &PublicKey,
+    hashvalue: &hash160::Hash,
+    locktime: u16,
+) -> ScriptBuf {
+    Builder::new()
+        .push_opcode(opcodes::all::OP_SIZE)
+        .push_opcode(opcodes::all::OP_SWAP)
+        .push_opcode(opcodes::all::OP_HASH160)
+        .push_slice(hashvalue.to_byte_array())
+        .push_opcode(opcodes::all::OP_EQUAL)
+        .push_opcode(opcodes::all::OP_IF)
+        .push_key(hashlock_pubkey)
+        .push_int(32)
+        .push_int(0)
+        .push_opcode(opcodes::all::OP_ELSE)
+        .push_key(timelock_pubkey)
+        .push_int(0)
+        .push_int(locktime as i64)
+        .push_opcode(opcodes::all::OP_ENDIF)
+        .push_opcode(opcodes::all::OP_CSV)
+        .push_opcode(opcodes::all::OP_DROP)
+        .push_opcode(opcodes::all::OP_ROT)
+        .push_opcode(opcodes::all::OP_EQUALVERIFY)
+        .push_opcode(opcodes::all::OP_CHECKSIG)
+        .into_script()
+}
+
+fn sender_contract_info(
+    tweakable_pubkey: &PublicKey,
+    hashvalue: &hash160::Hash,
+    refund_locktime: u16,
+    tag: u8,
+) -> ContractTxInfoForSender {
+    let secp = Secp256k1::new();
+    let multisig_nonce = SecretKey::new(&mut thread_rng());
+    let hashlock_nonce = SecretKey::new(&mut thread_rng());
+    let other_key = SecretKey::new(&mut thread_rng());
+    let timelock_key = SecretKey::new(&mut thread_rng());
+    let maker_multisig_pubkey = tweaked_pubkey(tweakable_pubkey, &multisig_nonce);
+    let other_multisig_pubkey = PublicKey::new(
+        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_key),
+    );
+    let hashlock_pubkey = tweaked_pubkey(tweakable_pubkey, &hashlock_nonce);
+    let timelock_pubkey = PublicKey::new(
+        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &timelock_key),
+    );
+    let multisig_redeemscript =
+        multisig_script(&maker_multisig_pubkey, &other_multisig_pubkey);
+
+    // REFUND_LOCKTIME_STEP is 75 under the integration-test feature.
+    let contract_redeemscript = contract_script(
+        &hashlock_pubkey,
+        &timelock_pubkey,
+        hashvalue,
+        refund_locktime + 75,
+    );
+    let funding_input_value = Amount::from_sat(100_000);
+    let senders_contract_tx = Transaction {
+        version: Version::TWO,
+        lock_time: LockTime::ZERO,
+        input: vec![TxIn {
+            previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
+            script_sig: ScriptBuf::new(),
+            sequence: Sequence::ZERO,
+            witness: Witness::new(),
+        }],
+        output: vec![TxOut {
+            value: Amount::from_sat(99_000),
+            script_pubkey: ScriptBuf::new_p2wsh(&contract_redeemscript.wscript_hash()),
+        }],
+    };
+
+    ContractTxInfoForSender {
+        multisig_nonce,
+        hashlock_nonce,
+        timelock_pubkey,
+        senders_contract_tx,
+        multisig_redeemscript,
+        funding_input_value,
+    }
+}
+
+#[test]
+fn maker_rejects_more_contracts_than_negotiated() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8977, Some(21751))],
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
+
+    let mut state = ConnectionState::new(ProtocolVersion::Legacy);
+    state.phase = SwapPhase::AwaitingSwapDetails;
+    handle_message(
+        maker,
+        &mut state,
+        TakerToMakerMessage::SwapDetails(SwapDetails {
+            id: "0123456789abcdef".to_string(),
+            protocol_version: ProtocolVersion::Legacy,
+            amount: Amount::from_sat(100_000),
+            tx_count: 1,
+            timelock: 150,
+            refund_locktime_offset: 150,
+        }),
+    )
+    .unwrap();
+
+    let (_, tweakable_pubkey, _) = maker.get_tweakable_keypair().unwrap();
+    let hashvalue = hash160::Hash::hash(b"bounded-contract-request");
+    let request = ReqContractSigsForSender {
+        id: "0123456789abcdef".to_string(),
+        txs_info: vec![
+            sender_contract_info(&tweakable_pubkey, &hashvalue, 150, 1),
+            sender_contract_info(&tweakable_pubkey, &hashvalue, 150, 2),
+        ],
+        hashvalue,
+        locktime: 150,
+    };
+
+    let result = handle_message(
+        maker,
+        &mut state,
+        TakerToMakerMessage::ReqContractSigsForSender(request),
+    );
+
+    maker.watch_service.shutdown();
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        result.is_err(),
+        "maker signed and persistently cached two contracts after negotiating one"
+    );
+}

```
