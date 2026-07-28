# Commit Nostr cursors only after the snapshot completes

- **Finding ID:** 1
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/nostr.rs:312-357
- **Job:** 2
- **CWE:** n/a
- **Fingerprint:** 01e9b508f7c0c9c0253cc41c1a6b8c15d18e6f25990e808263bb8b5fcaf803c5

## Description

NIP-01 does not require stored events to arrive in timestamp order when no `limit` is used. Nevertheless, `handle_relay_message` persists the maximum `created_at` after every successfully fetched or already-seen event, before the relay sends EOSE. If a relay sends a newer event first and the WebSocket drops before older matching events are delivered, the reconnect filter uses `since=<newer timestamp>` and makes the omitted older announcements ineligible. This is reachable through ordinary relay ordering plus a transient disconnect; repeated maker announcements and the shared cross-relay seen cache make the duplicate path routine. The taker's registry and offerbook can therefore remain incomplete, causing swap preparation to report too few makers or use a reduced route until makers publish again. The regression test pre-marks a txid as a normal multi-relay duplicate, processes one event without EOSE, and shows that HEAD durably advances the cursor. Cursor progress should be committed only after the matching stored-event snapshot completes, retaining timestamp-boundary overlap as needed. A prior-finding query for the cursor/EOSE/disconnect mechanism returned no matches.

## Proof of Concept

```diff
diff --git a/src/nostr.rs b/src/nostr.rs
index 4eb99a2..c587af0 100644
--- a/src/nostr.rs
+++ b/src/nostr.rs
@@ -367,3 +367,61 @@ fn handle_relay_message(
 
     Ok(false)
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::str::FromStr;
+
+    use bitcoin::Txid;
+    use nostr::{
+        event::{EventBuilder, Tag, TagStandard},
+        key::{Keys, SecretKey},
+    };
+
+    use crate::wallet::{BackendConfig, CoreRpcConfig};
+
+    #[test]
+    fn cursor_is_not_committed_before_eose() {
+        let temp_dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = Arc::new(FileRegistry::load(temp_dir.path().join("registry")));
+        let relay_url = "wss://relay.example";
+        let kind = Kind::Custom(coinswap_kind(Network::Regtest));
+        let txid = Txid::from_str(
+            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7",
+        )
+        .unwrap();
+
+        // Skip the backend lookup: the cursor update is independent of transaction
+        // validation, and a duplicate is a normal outcome with multiple relays.
+        let seen_txid = Arc::new(Mutex::new(SeenTxids::new()));
+        seen_txid.lock().unwrap().insert(txid);
+        let blockchain = Arc::new(
+            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap(),
+        );
+
+        let created_at = Timestamp::now();
+        let keys = Keys::new(SecretKey::generate());
+        let event = EventBuilder::new(kind, format!("{txid}:0"))
+            .custom_created_at(created_at)
+            .tag(Tag::from_standardized(TagStandard::Expiration(
+                Timestamp::from_secs(created_at.as_secs() + EXPIRATION_SECS),
+            )))
+            .build(keys.public_key)
+            .sign_with_keys(&keys)
+            .unwrap();
+        let msg = RelayMessage::Event {
+            subscription_id: Cow::Owned(SubscriptionId::new("test")),
+            event: Cow::Owned(event),
+        };
+
+        assert!(!handle_relay_message(
+            registry.clone(),
+            msg,
+            blockchain,
+            relay_url,
+            kind,
+            &seen_txid,
+        )
+        .unwrap());
+        assert_eq!(
+            registry.load_nostr_cursor(relay_url),
+            None,
+            "a disconnect before EOSE must not make unseen, unordered backlog ineligible"
+        );
+    }
+}

```
