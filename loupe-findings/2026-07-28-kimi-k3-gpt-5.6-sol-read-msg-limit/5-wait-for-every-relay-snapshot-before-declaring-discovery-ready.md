# Wait for every relay snapshot before declaring discovery ready

- **Finding ID:** 5
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/nostr.rs:240-242
- **Job:** 2
- **CWE:** n/a
- **Fingerprint:** 9f98d0fdbe7876aae21431d055ab1318ef7e18b33042bbf47df9071f7c4369a0

## Description

All relay session threads share one `initial_sync_complete` boolean, and `read_event_loop` sets it after the first EOSE from any relay. That EOSE only certifies completion of the stored-event snapshot on its own WebSocket subscription; it says nothing about other configured relays. This matters because makers publish independently to each relay and publication is considered successful if any relay accepts it. A fast relay with an empty snapshot can therefore release `OfferSyncService::wait_for_discovery` while a slower relay is still delivering the only copy of a maker announcement. The immediately following manual sync snapshots the incomplete registry, so `prepare_coinswap` can fail for too few makers or select from a smaller route, reducing availability and route diversity until a later sync. The regression test starts two local relays, lets only the first send a correctly matched EOSE, and shows that HEAD marks global discovery complete while the second snapshot remains open. Readiness should be coordinated per configured relay (while preserving the existing bounded caller timeout for unavailable relays), and EOSE should be matched to the requested subscription. A prior-finding query for first-relay EOSE/global multi-relay readiness returned no matches.

## Proof of Concept

```diff
diff --git a/src/nostr.rs b/src/nostr.rs
index 4eb99a2..6cf8ef4 100644
--- a/src/nostr.rs
+++ b/src/nostr.rs
@@ -367,3 +367,78 @@ fn handle_relay_message(
 
     Ok(false)
 }
+
+#[cfg(all(test, feature = "integration-test"))]
+mod tests {
+    use super::*;
+    use std::{
+        net::TcpListener,
+        sync::mpsc,
+        time::{Duration, Instant},
+    };
+
+    use crate::wallet::{BackendConfig, CoreRpcConfig};
+
+    #[test]
+    fn first_relay_eose_does_not_complete_multi_relay_sync() {
+        let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let first_url = format!("ws://{}", first_listener.local_addr().unwrap());
+        let second_url = format!("ws://{}", second_listener.local_addr().unwrap());
+        let (first_ready_tx, first_ready_rx) = mpsc::channel();
+        let (second_ready_tx, second_ready_rx) = mpsc::channel();
+
+        let first_url_for_server = first_url.clone();
+        let first_server = std::thread::spawn(move || {
+            let (stream, _) = first_listener.accept().unwrap();
+            let mut socket = tungstenite::accept(stream).unwrap();
+            socket.read().unwrap();
+            let eose = RelayMessage::EndOfStoredEvents(Cow::Owned(SubscriptionId::new(format!(
+                "market-discovery-{first_url_for_server}"
+            ))));
+            socket
+                .send(Message::Text(eose.as_json().into()))
+                .unwrap();
+            first_ready_tx.send(()).unwrap();
+            std::thread::sleep(Duration::from_millis(250));
+        });
+        let second_server = std::thread::spawn(move || {
+            let (stream, _) = second_listener.accept().unwrap();
+            let mut socket = tungstenite::accept(stream).unwrap();
+            socket.read().unwrap();
+            // Keep this relay's stored-event snapshot incomplete.
+            second_ready_tx.send(()).unwrap();
+            std::thread::sleep(Duration::from_millis(250));
+        });
+
+        let temp_dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = FileRegistry::load(temp_dir.path().join("registry"));
+        let blockchain =
+            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();
+        let shutdown = Arc::new(AtomicBool::new(false));
+        let initial_sync_complete = Arc::new(AtomicBool::new(false));
+        run_discovery(
+            blockchain,
+            Network::Regtest,
+            registry,
+            shutdown.clone(),
+            initial_sync_complete.clone(),
+            &[first_url, second_url],
+            (0, String::new()),
+        )
+        .unwrap();
+
+        first_ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
+        second_ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
+        let deadline = Instant::now() + Duration::from_secs(2);
+        while !initial_sync_complete.load(Ordering::SeqCst) && Instant::now() < deadline {
+            std::thread::sleep(Duration::from_millis(10));
+        }
+        let completed_early = initial_sync_complete.load(Ordering::SeqCst);
+
+        shutdown.store(true, Ordering::SeqCst);
+        first_server.join().unwrap();
+        second_server.join().unwrap();
+        assert!(
+            !completed_early,
+            "one relay's EOSE must not release sync while another snapshot is incomplete"
+        );
+    }
+}

```
