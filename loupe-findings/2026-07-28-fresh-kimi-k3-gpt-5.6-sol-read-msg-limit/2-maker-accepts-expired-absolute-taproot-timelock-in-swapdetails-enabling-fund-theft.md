# Maker accepts expired absolute Taproot timelock in SwapDetails, enabling fund theft

- **Finding ID:** 2
- **Severity:** High
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:862-875
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 3d8bc8cd11da1af0a32bd68c76c2f3300900db9acc1e543e8a8d79b6b2e0af03

## Description

For Taproot swaps, `SwapDetails::timelock` is an absolute CLTV block height chosen by the remote taker, but `validate_swap_parameters` (src/maker/api.rs:862-875) only rejects a zero value for Taproot, while the Legacy branch enforces a minimum reaction-time margin. The taker's incoming contract is then verified against `state.timelock + REFUND_LOCKTIME_STEP` (src/maker/taproot_verification.rs:104,196) and the maker's own outgoing timelock script is built directly from `state.timelock` (src/maker/taproot_handlers.rs:226-230) — neither is ever compared to the current block height. A malicious taker can therefore propose a timelock that is already expired (e.g. height 1): the taker's refund path on the incoming contract is immediately spendable, so after the maker funds its outgoing contract the taker refunds its own contract and still claims the maker's outgoing funds with the hashlock preimage it generated, stealing the full swap amount with no recourse for the maker. No prior findings exist on this repo (queried: "taproot timelock validation", "validate_swap_parameters timelock", "maker"). The PoC adds an integration test that drives the cleartext protocol against a real maker (TestFramework + bitcoind regtest): a future timelock is accepted (sanity), while an expired absolute timelock must be rejected — on HEAD the maker replies `AckSwapDetails::accept`, failing the test. The test requires the `integration-test` feature and the repo's bitcoind test framework, matching the pattern of existing security regression tests such as tests/integration/duplicate_funding_outpoint.rs.

## Proof of Concept

```diff
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -52,4 +52,5 @@
 mod taproot_concurrent_takers;
 mod taproot_contract_validation;
 mod taproot_taker_contract_validation;
+mod taproot_expired_timelock;
 mod utxo_behavior;
--- /dev/null
+++ b/tests/integration/taproot_expired_timelock.rs
@@ -0,0 +1,137 @@
+//! A malicious taker can propose a Taproot swap whose absolute CLTV timelock is
+//! already at or below the current block height. For Taproot,
+//! `SwapDetails::timelock` is an absolute block height, but the maker only
+//! rejects a zero value in `validate_swap_parameters`
+//! (src/maker/api.rs). The taker's incoming contract is then required to carry
+//! a refund timelock of `timelock + REFUND_LOCKTIME_STEP`
+//! (src/maker/taproot_verification.rs), which is expired as well, so the taker
+//! can refund its own contract immediately after the maker funds the outgoing
+//! contract and still claim the maker's outgoing funds with the hashlock
+//! preimage it generated — stealing the full swap amount.
+//!
+//! The maker must reject any Taproot timelock that is not sufficiently ahead
+//! of the current block height, while still accepting a valid future one.
+
+use std::{net::TcpStream, sync::atomic::Ordering::Relaxed, thread, time::Duration};
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::{start_server, MakerBehavior},
+    protocol::common_messages::{
+        GetOffer, MakerToTakerMessage, ProtocolVersion, SwapDetails, TakerHello,
+        TakerToMakerMessage,
+    },
+    utill::{read_message, send_message},
+    wallet::{AddressType, Blockchain},
+};
+
+use super::test_framework::*;
+
+/// Drives the cleartext handshake up to `SwapDetails` and returns the maker's
+/// response (`None` when the maker rejects by closing the connection).
+fn propose_swap_details(
+    stream: &mut TcpStream,
+    details: SwapDetails,
+) -> Option<MakerToTakerMessage> {
+    send_message(stream, &TakerToMakerMessage::TakerHello(TakerHello)).unwrap();
+    let hello: MakerToTakerMessage =
+        serde_cbor::from_slice(&read_message(stream).unwrap()).unwrap();
+    assert!(matches!(hello, MakerToTakerMessage::MakerHello(_)));
+
+    send_message(stream, &TakerToMakerMessage::GetOffer(GetOffer)).unwrap();
+    let _: MakerToTakerMessage = serde_cbor::from_slice(&read_message(stream).unwrap()).unwrap();
+
+    send_message(stream, &TakerToMakerMessage::SwapDetails(details)).unwrap();
+    read_message(stream)
+        .ok()
+        .map(|bytes| serde_cbor::from_slice(&bytes).unwrap())
+}
+
+#[test]
+fn maker_rejects_expired_taproot_timelock() {
+    let makers_config_map = vec![(8802, Some(21301))];
+
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            makers_config_map,
+            Vec::new(),
+            vec![MakerBehavior::Normal],
+        );
+
+    let bitcoind = &test_framework.bitcoind;
+    fund_makers(
+        &makers,
+        bitcoind,
+        4,
+        Amount::from_btc(0.05).unwrap(),
+        AddressType::P2TR,
+    );
+
+    let maker_threads = makers
+        .iter()
+        .map(|maker| {
+            let maker = maker.clone();
+            thread::spawn(move || start_server(maker).unwrap())
+        })
+        .collect::<Vec<_>>();
+
+    wait_for_makers_setup(&makers, 120);
+    for maker in &makers {
+        maker.wallet.write().unwrap().sync_and_save().unwrap();
+    }
+    generate_blocks(bitcoind, 1);
+
+    let maker_port = makers[0].config.network_port;
+    let current_height = makers[0]
+        .wallet
+        .read()
+        .unwrap()
+        .blockchain
+        .get_block_count()
+        .unwrap() as u32;
+
+    // Sanity: a Taproot timelock sufficiently ahead of the tip must be accepted.
+    let mut stream = TcpStream::connect(("127.0.0.1", maker_port)).unwrap();
+    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
+    let valid = propose_swap_details(&mut stream, SwapDetails {
+        id: "valid-future-timelock".to_string(),
+        protocol_version: ProtocolVersion::Taproot,
+        amount: Amount::from_sat(500_000),
+        tx_count: 1,
+        timelock: current_height + 500,
+        refund_locktime_offset: 20,
+    });
+    assert!(
+        matches!(valid, Some(MakerToTakerMessage::AckSwapDetails(ref ack)) if ack.tweakable_point.is_some()),
+        "Maker must accept a Taproot timelock that is sufficiently far in the future"
+    );
+
+    // Attack: an absolute CLTV timelock that has already expired must be rejected.
+    let mut stream = TcpStream::connect(("127.0.0.1", maker_port)).unwrap();
+    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
+    let expired = propose_swap_details(&mut stream, SwapDetails {
+        id: "expired-timelock".to_string(),
+        protocol_version: ProtocolVersion::Taproot,
+        amount: Amount::from_sat(500_000),
+        tx_count: 1,
+        // Absolute height 1: long passed on any live chain, so the taker's
+        // refund path (height 1 + REFUND_LOCKTIME_STEP) is already spendable.
+        timelock: 1,
+        refund_locktime_offset: 20,
+    });
+    assert!(
+        !matches!(expired, Some(MakerToTakerMessage::AckSwapDetails(ref ack)) if ack.tweakable_point.is_some()),
+        "Maker accepted a Taproot swap with an already-expired absolute timelock"
+    );
+
+    makers
+        .iter()
+        .for_each(|maker| maker.shutdown.store(true, Relaxed));
+    maker_threads
+        .into_iter()
+        .for_each(|thread| thread.join().unwrap());
+
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+}

```
