# Route watcher events before competing clients can consume them

- **Finding ID:** 70
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/watcher.rs
- **Lines:** 214-218
- **CWE:** CWE-362
- **Fingerprint:** 04955442949716a79c28e558e50497a38ecec16acfcb297e0ee496cd519d7436

## Description

Watcher sends every response and asynchronous spend notification into one uncorrelated `tx_events` queue. `WatchService` is clonable and its clones share the same crossbeam receiver, so the first client thread to call `poll_event`, `wait_for_event`, or `request_maker_address` consumes the next event regardless of which command or monitor it belongs to. In the taker, the breach detector runs on a cloned service while offer sync and other code also receive from clones. If an adversary broadcasts a contract transaction and the watcher records a `UtxoSpent`, an unrelated clone can consume that event before the breach detector receives it; the detector then misses the adversarial spend and continues the protocol without setting the breach flag. I checked prior finding searches for the shared watcher event stream and BreachDetector/WatchService event theft and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/watch_tower/service.rs b/src/watch_tower/service.rs
index 3669272..2d4e4c8 100644
--- a/src/watch_tower/service.rs
+++ b/src/watch_tower/service.rs
@@ -121,3 +121,27 @@ pub fn start_maker_watch_service(
 
     Ok(WatchService::new(tx_requests, rx_responses))
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn cloned_watch_services_do_not_steal_security_events() {
+        let (tx_requests, _rx_requests) = mpsc::channel();
+        let (tx_events, rx_events) = crossbeam_channel::unbounded();
+
+        let monitor = WatchService::new(tx_requests, rx_events);
+        let unrelated_client = monitor.clone();
+        let outpoint = OutPoint::null();
+
+        // The breach detector uses one cloned WatchService while offer sync and
+        // other clients use others. A security event must not disappear from
+        // the monitoring clone merely because another clone polls first.
+        monitor.watch_request(outpoint);
+        tx_events
+            .send(WatcherEvent::UtxoSpent {
+                outpoint,
+                spending_tx: None,
+            })
+            .unwrap();
+        let _ = unrelated_client.poll_event();
+
+        assert!(matches!(monitor.poll_event(), Some(WatcherEvent::UtxoSpent { outpoint: op, .. }) if op == outpoint));
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

