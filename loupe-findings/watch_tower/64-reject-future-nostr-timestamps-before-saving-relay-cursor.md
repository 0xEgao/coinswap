# Reject future Nostr timestamps before saving relay cursor

- **Finding ID:** 64
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/nostr_discovery.rs
- **Lines:** 267-283
- **CWE:** CWE-20
- **Fingerprint:** 8a1176fd011540610e071a3a8a64a8cf7b57ffaedf26fd51544cf721144fdf3c

## Description

`handle_relay_message` tries to discard stale announcements by subtracting `event.created_at` from `Timestamp::now()` with `saturating_sub`. If a relay supplies an event whose `created_at` is far in the future, the subtraction saturates to zero, so the event is treated as fresh as long as its expiration tag is also in the future. After only parsing the `txid:vout` content, the code immediately persists `event.created_at` as the per-relay Nostr cursor before confirming the transaction exists or contains a valid fidelity announcement. A malicious or compromised relay can therefore send one signed event for a nonexistent txid with a far-future timestamp; `get_raw_tx` then fails, but the future cursor remains on disk. On reconnect, `connect_and_run_once` uses that cursor as the subscription `since`, causing the watcher to skip legitimate announcements from that relay until wall-clock time catches up or the registry is manually repaired. I checked prior finding searches for `nostr_discovery cursor future created_at save_nostr_cursor` and `Nostr stale event future timestamp denial service`; neither matched an existing report.

## Proof of Concept

```diff
diff --git a/src/watch_tower/nostr_discovery.rs b/src/watch_tower/nostr_discovery.rs
--- a/src/watch_tower/nostr_discovery.rs
+++ b/src/watch_tower/nostr_discovery.rs
@@ -316,4 +316,68 @@ fn handle_relay_message(
     }
 
     Ok(())
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::str::FromStr;
+
+    use bitcoind::bitcoincore_rpc::Auth;
+    use nostr::{event::Tag, event::TagStandard, EventBuilder};
+
+    use crate::wallet::RPCConfig;
+
+    #[test]
+    fn future_invalid_nostr_event_does_not_advance_relay_cursor() {
+        let dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = Arc::new(FileRegistry::load(dir.path().join("registry.cbor")));
+        let relay_url = "ws://attacker.example";
+        let kind = Kind::Custom(37780);
+        let txid = bitcoin::Txid::from_str(
+            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7",
+        )
+        .unwrap();
+
+        let rpc = Arc::new(
+            BitcoinRest::new(RPCConfig {
+                url: "127.0.0.1:1".to_string(),
+                auth: Auth::None,
+                wallet_name: "unused".to_string(),
+            })
+            .unwrap(),
+        );
+        let seen_txid = Arc::new(Mutex::new(SeenTxids::new()));
+        let initial_sync_complete = Arc::new(AtomicBool::new(false));
+        let future_created_at = Timestamp::now().as_secs() + EXPIRATION_SECS * 30;
+        let future_expiration = future_created_at + EXPIRATION_SECS;
+
+        let keys = nostr::key::Keys::generate();
+        let event = EventBuilder::new(kind, format!("{txid}:0"))
+            .tag(Tag::from_standardized(TagStandard::Expiration(
+                Timestamp::from_secs(future_expiration),
+            )))
+            .custom_created_at(Timestamp::from_secs(future_created_at))
+            .build(keys.public_key)
+            .sign_with_keys(&keys)
+            .unwrap();
+
+        let msg = RelayMessage::Event {
+            subscription_id: Cow::Owned(SubscriptionId::new("sub")),
+            event: Cow::Owned(event),
+        };
+
+        handle_relay_message(
+            registry.clone(),
+            msg,
+            rpc,
+            relay_url,
+            kind,
+            &seen_txid,
+            &initial_sync_complete,
+        )
+        .unwrap();
+
+        assert_eq!(registry.load_nostr_cursor(relay_url), None);
+    }
 }

```

## Suggested Fix

```diff
No suggested fix emitted.
```

