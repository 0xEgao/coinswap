# Correlate breach-detector watcher events to the queried outpoint

- **Finding ID:** 34
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/background_services.rs
- **Lines:** 416-419
- **CWE:** CWE-362
- **Fingerprint:** 9d6bc5bec33dd77671b020fd4e7b4ceec295aba4fe8dc49a676a7d3abbd82aac

## Description

`BreachDetector` sends `WatchRequest` for a sentinel outpoint and then trusts the next event returned by the shared `WatchService` receiver as that request's response. It does not verify that the `WatcherEvent::UtxoSpent` outpoint matches the sentinel being checked, and the same `WatchService` response channel is cloned for other taker background services such as offer sync. A stale or unrelated watcher response can therefore be consumed while the real sentinel-spend response remains queued. During that window `is_breached()` stays false, so legacy swap code that polls the detector while waiting for maker confirmations or retrying finalization can continue into key handover/finalization even though an adversarial contract broadcast has already been observed. A malicious peer that times a contract broadcast with unrelated watcher traffic can bypass the intended abort check until the detector's next heartbeat, which is security-critical in this protocol phase. I searched prior findings for `BreachDetector wait_for_event watch_request outpoint UtxoSpent` and `background_services breach detector watcher event correlation`; no duplicate was found.

## Proof of Concept

```diff
diff --git a/src/taker/background_services.rs b/src/taker/background_services.rs
index 0000000..0000000 100644
--- a/src/taker/background_services.rs
+++ b/src/taker/background_services.rs
@@ -491,3 +491,88 @@ impl Drop for BreachDetector {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::{Height, LockTime},
+        hashes::Hash,
+        transaction, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+    };
+    use std::{sync::mpsc, time::Duration};
+
+    use crate::watch_tower::watcher::WatcherCommand;
+
+    fn txid(byte: u8) -> Txid {
+        Txid::from_slice(&[byte; 32]).unwrap()
+    }
+
+    fn spending_tx(previous_output: OutPoint) -> Transaction {
+        Transaction {
+            version: transaction::Version(2),
+            lock_time: LockTime::Blocks(Height::from_consensus(0).unwrap()),
+            input: vec![TxIn {
+                previous_output,
+                script_sig: ScriptBuf::new(),
+                sequence: Sequence::MAX,
+                witness: Witness::new(),
+            }],
+            output: vec![TxOut {
+                value: Amount::ZERO,
+                script_pubkey: ScriptBuf::new(),
+            }],
+        }
+    }
+
+    #[test]
+    fn breach_detector_ignores_unrelated_watcher_events_before_matching_response() {
+        let (cmd_tx, cmd_rx) = mpsc::channel();
+        let (event_tx, event_rx) = crossbeam_channel::unbounded();
+        let watch_service = WatchService::new(cmd_tx, event_rx);
+        let detector = BreachDetector::start(watch_service.clone());
+
+        let sentinel = OutPoint {
+            txid: txid(1),
+            vout: 0,
+        };
+        let unrelated = OutPoint {
+            txid: txid(2),
+            vout: 0,
+        };
+        let contract_tx = spending_tx(sentinel);
+        let expected_contract_txid = contract_tx.compute_txid();
+
+        detector.add_sentinels(&watch_service, &[(sentinel, expected_contract_txid)]);
+
+        match cmd_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
+            WatcherCommand::RegisterWatchRequest { outpoint } => assert_eq!(outpoint, sentinel),
+            other => panic!("unexpected watcher command: {other:?}"),
+        }
+
+        match cmd_rx.recv_timeout(Duration::from_secs(6)).unwrap() {
+            WatcherCommand::WatchRequest { outpoint } => assert_eq!(outpoint, sentinel),
+            other => panic!("unexpected watcher command: {other:?}"),
+        }
+
+        event_tx
+            .send(WatcherEvent::UtxoSpent {
+                outpoint: unrelated,
+                spending_tx: Some(spending_tx(unrelated)),
+            })
+            .unwrap();
+        event_tx
+            .send(WatcherEvent::UtxoSpent {
+                outpoint: sentinel,
+                spending_tx: Some(contract_tx),
+            })
+            .unwrap();
+
+        std::thread::sleep(Duration::from_millis(200));
+
+        assert!(
+            detector.is_breached(),
+            "detector must keep reading until it observes the event for the queried sentinel"
+        );
+
+        detector.stop();
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

