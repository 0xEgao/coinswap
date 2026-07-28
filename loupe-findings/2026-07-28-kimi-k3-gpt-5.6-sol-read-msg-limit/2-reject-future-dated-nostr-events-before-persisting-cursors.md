# Reject future-dated Nostr events before persisting cursors

- **Finding ID:** 2
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/nostr.rs:275-278
- **Job:** 2
- **CWE:** CWE-20
- **Fingerprint:** f6e084541ee7c6b6f409bc74240907d06811ed40e29e582ef5641e62780e481f

## Description

The freshness check computes `now.saturating_sub(event.created_at)` and only rejects values over 24 hours. Any future `created_at` therefore produces zero age and is accepted, while `event.is_expired()` merely requires an expiration tag later than the current time. After a known fidelity txid is fetched or encountered through the shared multi-relay cache, the attacker-controlled future timestamp is persisted as that relay's monotonic cursor. On the next reconnect, `Filter::since` uses this future value, so ordinary maker announcements do not match until wall-clock time catches up. Nostr permits arbitrary timestamps unless a relay opts into separate timestamp-limit policy, so the client cannot delegate this invariant to configured relays. This can durably freeze discovery of new or renewed makers on affected relays, reducing route diversity or making swap preparation unavailable as older registry entries expire. The regression test constructs a correctly signed, unexpired event dated 30 days ahead for an already-seen txid and demonstrates that HEAD stores its timestamp. Rejecting timestamps beyond a small clock-skew allowance before RPC work or cursor mutation fixes the issue. A prior-finding query for Nostr future-`created_at` cursor poisoning returned no matches.

## Proof of Concept

```diff
diff --git a/src/nostr.rs b/src/nostr.rs
index 4eb99a2..842a542 100644
--- a/src/nostr.rs
+++ b/src/nostr.rs
@@ -367,3 +367,60 @@ fn handle_relay_message(
 
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
+    fn future_event_does_not_poison_reconnect_cursor() {
+        let temp_dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = Arc::new(FileRegistry::load(temp_dir.path().join("registry")));
+        let relay_url = "wss://relay.example";
+        let kind = Kind::Custom(coinswap_kind(Network::Regtest));
+        let txid = Txid::from_str(
+            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7",
+        )
+        .unwrap();
+
+        // A duplicate fidelity txid is sufficient to exercise timestamp handling
+        // without contacting a backend, as happens across multiple relays.
+        let seen_txid = Arc::new(Mutex::new(SeenTxids::new()));
+        seen_txid.lock().unwrap().insert(txid);
+        let blockchain = Arc::new(
+            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap(),
+        );
+
+        let future = Timestamp::from_secs(Timestamp::now().as_secs() + 30 * EXPIRATION_SECS);
+        let keys = Keys::new(SecretKey::generate());
+        let event = EventBuilder::new(kind, format!("{txid}:0"))
+            .custom_created_at(future)
+            .tag(Tag::from_standardized(TagStandard::Expiration(
+                Timestamp::from_secs(future.as_secs() + EXPIRATION_SECS),
+            )))
+            .build(keys.public_key)
+            .sign_with_keys(&keys)
+            .unwrap();
+        let msg = RelayMessage::Event {
+            subscription_id: Cow::Owned(SubscriptionId::new("test")),
+            event: Cow::Owned(event),
+        };
+
+        handle_relay_message(
+            registry.clone(),
+            msg,
+            blockchain,
+            relay_url,
+            kind,
+            &seen_txid,
+        )
+        .unwrap();
+        assert_eq!(
+            registry.load_nostr_cursor(relay_url),
+            None,
+            "events dated far in the future must not become reconnect cursors"
+        );
+    }
+}

```
