# Bound Nostr history requests to the accepted freshness window

- **Finding ID:** 6
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/nostr.rs:143-148
- **Job:** 2
- **CWE:** CWE-400
- **Fingerprint:** e277dc5491b400937dc7c640da705fd24b30853565aa84ea25ce4316b6aa718d

## Description

`connect_and_run_once` adds a `since` filter only when a persisted cursor exists, and it uses an old cursor without clamping it. A new installation therefore requests the relay's entire history for the custom kind, even though `handle_relay_message` discards every event older than 24 hours. This history is naturally unbounded: each maker rebroadcast creates a fresh signing key every 30 minutes, so the addressable-event replacement key changes and relays may retain every announcement. Untrusted publishers can add further signed events. Downloading, parsing, and debug-logging the irrelevant backlog delays EOSE and initial offer synchronization; after reconnect it can be repeated when no fresh event advances the cursor. As history grows, swap preparation may time out with an empty or partial maker registry, and relay traffic/CPU usage becomes attacker-amplifiable. The regression test captures the initial REQ from a local relay and shows that HEAD omits `since` entirely. The filter should always start at the newer of the durable cursor and `now - EXPIRATION_SECS` (with a small boundary overlap if needed), matching the client's actual acceptance window. A prior-finding query for missing-`since` stale Nostr backlog exhaustion returned no matches.

## Proof of Concept

```diff
diff --git a/src/nostr.rs b/src/nostr.rs
index 4eb99a2..829b7a4 100644
--- a/src/nostr.rs
+++ b/src/nostr.rs
@@ -367,3 +367,60 @@ fn handle_relay_message(
 
     Ok(false)
 }
+
+#[cfg(all(test, feature = "integration-test"))]
+mod tests {
+    use super::*;
+    use std::{net::TcpListener, sync::mpsc};
+
+    use crate::wallet::{BackendConfig, CoreRpcConfig};
+
+    #[test]
+    fn initial_subscription_bounds_history_to_freshness_window() {
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let relay_url = format!("ws://{}", listener.local_addr().unwrap());
+        let (request_tx, request_rx) = mpsc::channel();
+        let server = std::thread::spawn(move || {
+            let (stream, _) = listener.accept().unwrap();
+            let mut socket = tungstenite::accept(stream).unwrap();
+            let request = match socket.read().unwrap() {
+                Message::Text(text) => text.to_string(),
+                other => panic!("expected text REQ, got {other:?}"),
+            };
+            request_tx.send(request).unwrap();
+            // Dropping before EOSE makes the client return after its request is captured.
+        });
+
+        let temp_dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = Arc::new(FileRegistry::load(temp_dir.path().join("registry")));
+        let blockchain = Arc::new(
+            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap(),
+        );
+        let shutdown = Arc::new(AtomicBool::new(false));
+        let initial_sync_complete = Arc::new(AtomicBool::new(false));
+        let before = Timestamp::now().as_secs();
+
+        let result = connect_and_run_once(
+            &relay_url,
+            Kind::Custom(coinswap_kind(Network::Regtest)),
+            registry,
+            shutdown,
+            blockchain,
+            &Arc::new(Mutex::new(SeenTxids::new())),
+            &initial_sync_complete,
+            (0, ""),
+        );
+        assert!(result.is_err());
+        server.join().unwrap();
+
+        let request = ClientMessage::from_json(request_rx.recv().unwrap()).unwrap();
+        let since = match request {
+            ClientMessage::Req { filters, .. } => filters
+                .first()
+                .and_then(|filter| filter.since)
+                .expect("freshness window must bound the initial relay query"),
+            other => panic!("expected REQ, got {other:?}"),
+        };
+        assert!(
+            since.as_secs() >= before.saturating_sub(EXPIRATION_SECS),
+            "initial query starts before the oldest event the client will accept"
+        );
+    }
+}

```
