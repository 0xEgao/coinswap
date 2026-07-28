# Reap abandoned pre-funding liquidity reservations

- **Finding ID:** 22
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:494-504
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** 78e31b33762fb9231da9f80d6aa3b2dd3d5bf886e6aaecf3cc3cb383d35b389f

## Description

`handle_swap_details` persists `AwaitingContractData` immediately after accepting the taker's proposed amount, before any incoming proof, outgoing swapcoin, or maker funding exists. `MakerServer::store_connection_state` treats every non-completed persisted amount as reserved liquidity, so later swaps are rejected when the sum would exceed the wallet balance. If the peer disconnects after receiving `AckSwapDetails`, this reservation is never released: `MakerServer::drain_idle_swaps` deliberately selects stale entries only when `outgoing_swapcoins` is non-empty, and pre-funding states created here have an empty vector. Consequently, an unauthenticated peer can reserve up to the maker's advertised maximum with the inexpensive hello/offer/details exchange and stop; the maker then remains unavailable for new swaps until restart, regardless of how long the entry is idle. A correct lifecycle must retain concurrency protection while separately expiring abandoned states that have no funds to recover. The PoC starts the real maker on regtest, completes the protocol through `SwapDetails`, drops the socket, invokes the public idle cleanup with a zero timeout, and confirms the reservation remains on HEAD. It compiled and failed as expected. Prior finding #3 was reviewed and is distinct: it overwrites a live state by reusing an ID, whereas this finding uses a fresh ID and the missing pre-funding cleanup. Searches for `liquidity reservation denial service SwapDetails` and `outgoing_swapcoins empty idle recovery` found no duplicate.

## Proof of Concept

```diff
diff --git a/tests/abandoned_reservation.rs b/tests/abandoned_reservation.rs
new file mode 100644
--- /dev/null
+++ b/tests/abandoned_reservation.rs
@@ -0,0 +1,107 @@
+#![cfg(feature = "integration-test")]
+
+#[macro_use]
+#[path = "integration/test_framework/mod.rs"]
+mod test_framework;
+
+use std::{
+    net::TcpStream,
+    sync::atomic::Ordering::Relaxed,
+    thread,
+    time::Duration,
+};
+
+use bitcoin::Amount;
+use coinswap::{
+    maker::start_server,
+    protocol::common_messages::{
+        GetOffer, MakerToTakerMessage, ProtocolVersion, SwapDetails, TakerHello,
+        TakerToMakerMessage,
+    },
+    utill::{read_message, send_message},
+    wallet::AddressType,
+};
+
+use test_framework::*;
+
+#[test]
+fn abandoned_swap_details_reservation_is_reaped() {
+    let (test_framework, takers, makers, block_generation_handle) =
+        TestFramework::init::<BitcoindBackend>(
+            vec![(8812, Some(21311))],
+            Vec::new(),
+            Vec::new(),
+        );
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
+    wait_for_makers_setup(&makers, 120);
+    for maker in &makers {
+        maker.wallet.write().unwrap().sync_and_save().unwrap();
+    }
+
+    let maker = &makers[0];
+    let mut stream = TcpStream::connect(("127.0.0.1", maker.config.network_port)).unwrap();
+    stream
+        .set_read_timeout(Some(Duration::from_secs(10)))
+        .unwrap();
+
+    send_message(&mut stream, &TakerToMakerMessage::TakerHello(TakerHello)).unwrap();
+    let hello: MakerToTakerMessage =
+        serde_cbor::from_slice(&read_message(&mut stream).unwrap()).unwrap();
+    assert!(matches!(hello, MakerToTakerMessage::MakerHello(_)));
+
+    send_message(&mut stream, &TakerToMakerMessage::GetOffer(GetOffer)).unwrap();
+    let offer: MakerToTakerMessage =
+        serde_cbor::from_slice(&read_message(&mut stream).unwrap()).unwrap();
+    assert!(matches!(offer, MakerToTakerMessage::Offer(_)));
+
+    send_message(
+        &mut stream,
+        &TakerToMakerMessage::SwapDetails(SwapDetails {
+            id: "abandoned-reservation".to_string(),
+            protocol_version: ProtocolVersion::Legacy,
+            amount: Amount::from_sat(500_000),
+            tx_count: 1,
+            timelock: 20,
+            refund_locktime_offset: 20,
+        }),
+    )
+    .unwrap();
+    let ack: MakerToTakerMessage =
+        serde_cbor::from_slice(&read_message(&mut stream).unwrap()).unwrap();
+    assert!(matches!(ack, MakerToTakerMessage::AckSwapDetails(_)));
+    drop(stream);
+
+    assert!(maker.has_ongoing_swaps());
+    maker.drain_idle_swaps(Duration::ZERO);
+    let reservation_reaped = !maker.has_ongoing_swaps();
+
+    makers
+        .iter()
+        .for_each(|maker| maker.shutdown.store(true, Relaxed));
+    maker_threads
+        .into_iter()
+        .for_each(|handle| handle.join().unwrap());
+    drop(takers);
+    test_framework.stop();
+    block_generation_handle.join().unwrap();
+
+    assert!(
+        reservation_reaped,
+        "idle cleanup retained an abandoned pre-funding liquidity reservation"
+    );
+}

```
