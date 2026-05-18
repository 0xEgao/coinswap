# Correlate watchtower responses before consuming shared events

- **Finding ID:** 67
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/service.rs
- **Lines:** 74-76
- **CWE:** CWE-362
- **Fingerprint:** d9dab5644dcff8a0ad05c9518bc7d86104c7f4abf949fa2efae6fd4b694b3364

## Description

`WatchService` is clonable and all clones share a single `crossbeam_channel::Receiver<WatcherEvent>`. `request_maker_address()` sends a `MakerAddress` command and then blindly calls `self.rx.recv()`, accepting whichever event is next. Spend queries and recovery code use the same event stream for `UtxoSpent` responses containing watched spend transactions and hash preimages. A pending or concurrent spend event can therefore be consumed by an unrelated maker-address lookup, while the address lookup returns the wrong event. In the other direction, recovery callers can consume `MakerAddresses` and miss their queried spend response. This is exploitable as an event-stealing race against security-critical watchtower notifications: a peer that causes an on-chain contract spend at the same time as address discovery can prevent the intended recovery path from seeing the spend transaction/preimage in that polling iteration, potentially delaying or suppressing fund recovery depending on scheduling. I searched prior findings for `WatchService request_maker_address shared receiver UtxoSpent MakerAddresses` and `watch tower crossbeam receiver event confusion`; both returned no matches.

## Proof of Concept

```diff
diff --git a/src/watch_tower/service.rs b/src/watch_tower/service.rs
index 3975415..f711c71 100644
--- a/src/watch_tower/service.rs
+++ b/src/watch_tower/service.rs
@@ -120,3 +120,49 @@ pub fn start_maker_watch_service(
 
     Ok(WatchService::new(tx_requests, rx_responses))
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::watch_tower::watcher::{WatcherCommand, WatcherEvent};
+    use bitcoin::Txid;
+    use std::str::FromStr;
+
+    fn dummy_outpoint() -> OutPoint {
+        OutPoint {
+            txid: Txid::from_str(
+                "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7",
+            )
+            .unwrap(),
+            vout: 0,
+        }
+    }
+
+    #[test]
+    fn request_maker_address_does_not_consume_pending_spend_events() {
+        let (tx_requests, rx_requests) = std::sync::mpsc::channel();
+        let (tx_events, rx_events) = crossbeam_channel::unbounded();
+        let service = WatchService::new(tx_requests, rx_events);
+
+        tx_events
+            .send(WatcherEvent::UtxoSpent {
+                outpoint: dummy_outpoint(),
+                spending_tx: None,
+            })
+            .unwrap();
+
+        let tx_events_for_watcher = tx_events.clone();
+        let watcher = std::thread::spawn(move || match rx_requests.recv().unwrap() {
+            WatcherCommand::MakerAddress => tx_events_for_watcher
+                .send(WatcherEvent::MakerAddresses {
+                    maker_addresses: vec!["maker.example.onion".to_string()],
+                })
+                .unwrap(),
+            other => panic!("unexpected watcher command: {:?}", other),
+        });
+
+        let event = service.request_maker_address();
+        watcher.join().unwrap();
+
+        assert!(
+            matches!(event, Some(WatcherEvent::MakerAddresses { .. })),
+            "request_maker_address returned an unrelated event: {:?}",
+            event
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

