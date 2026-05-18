# Validate ZMQ notification sequence frames before trusting payloads

- **Finding ID:** 72
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/zmq_backend.rs
- **Lines:** 49-56
- **CWE:** CWE-345
- **Fingerprint:** 28bdfa96c5089d6eb3bee50852ddce35c0d47fafe1400ca97422937a8323306b

## Description

`recv_event` accepts any multipart message with at least two frames and forwards frame 1 as a trusted `rawtx`/`rawblock` payload. Bitcoin Core ZMQ notifications include a sequence frame after the payload; this backend neither requires that frame nor validates it. A malicious or MITM publisher reachable at the configured ZMQ endpoint can therefore feed truncated or non-Bitcoin-Core-looking notifications into the watchtower. For `rawtx`, downstream code treats accepted payloads as mempool evidence when they deserialize; for `rawblock`, accepted payloads can drive checkpoint and fidelity processing. The missing sequence validation also prevents detecting dropped or replayed notifications, which is security-relevant for breach and preimage monitoring. I checked prior findings with `zmq_backend rawtx unauthenticated forged transaction` and `zmq_backend recv_multipart sequence frame rawblock`; both returned no matches. The assumption is that an adversary can control or intercept the configured ZMQ endpoint; the code currently provides no in-band verification to reject such malformed frames.

## Proof of Concept

```diff
diff --git a/src/watch_tower/zmq_backend.rs b/src/watch_tower/zmq_backend.rs
index 8a8e2d1..d5324b7 100644
--- a/src/watch_tower/zmq_backend.rs
+++ b/src/watch_tower/zmq_backend.rs
@@ -73,3 +73,40 @@ impl ZmqBackend {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::{thread, time::Duration};
+
+    #[test]
+    fn drops_rawtx_notifications_without_sequence_frame() {
+        let ctx = zmq::Context::new();
+        let endpoint = "inproc://drops-rawtx-without-sequence-frame";
+
+        let receiver = ctx.socket(zmq::PAIR).expect("receiver");
+        receiver.bind(endpoint).expect("bind receiver");
+
+        let sender = ctx.socket(zmq::PAIR).expect("sender");
+        sender.connect(endpoint).expect("connect sender");
+        thread::sleep(Duration::from_millis(20));
+
+        sender
+            .send_multipart([b"rawtx".as_ref(), b"forged raw transaction".as_ref()], 0)
+            .expect("send malformed notification");
+
+        let mut backend = ZmqBackend { socket: receiver };
+        let mut observed = None;
+        for _ in 0..20 {
+            observed = backend.poll();
+            if observed.is_some() {
+                break;
+            }
+            thread::sleep(Duration::from_millis(5));
+        }
+
+        assert!(
+            observed.is_none(),
+            "accepted a rawtx notification that omitted Bitcoin Core's sequence frame"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

