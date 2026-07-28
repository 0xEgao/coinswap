# Reconnect after a relay closes the Nostr subscription

- **Finding ID:** 7
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/nostr.rs:358-365
- **Job:** 2
- **CWE:** n/a
- **Fingerprint:** d4743ccb4e7c1c950d66d8f656adbdc5c6e4a3fcc3c6d1885320065d03967915

## Description

NIP-01 `CLOSED` ends the named subscription while leaving the WebSocket itself usable. `handle_relay_message` ignores every relay message other than EVENT and EOSE, so a matching `RelayMessage::Closed` returns `Ok(false)` and `read_event_loop` continues waiting on a connection that no longer has a market-discovery subscription. A relay can legitimately send this for rate limiting, authentication policy, resource pressure, or a transient server error. Because the socket may remain open and continue normal WebSocket control traffic, neither the connection-closed branch nor the outer five-second reconnect loop is reached. Discovery on that relay then stops indefinitely, making new maker announcements unavailable and potentially shrinking route diversity as registry entries expire. The regression test passes a correctly matched CLOSED message to the handler and shows that HEAD treats it as a benign no-op. A matching CLOSED outcome should terminate the current session (or explicitly issue a fresh REQ), allowing `run_nostr_session_for_relay` to retry; unrelated subscription IDs should still be ignored. A prior-finding query for ignored Nostr CLOSED/reconnect behavior returned no matches.

## Proof of Concept

```diff
diff --git a/src/nostr.rs b/src/nostr.rs
index 4eb99a2..7dfef32 100644
--- a/src/nostr.rs
+++ b/src/nostr.rs
@@ -367,3 +367,38 @@ fn handle_relay_message(
 
     Ok(false)
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    use crate::wallet::{BackendConfig, CoreRpcConfig};
+
+    #[test]
+    fn closed_subscription_terminates_the_session() {
+        let temp_dir = bitcoind::tempfile::TempDir::new().unwrap();
+        let registry = Arc::new(FileRegistry::load(temp_dir.path().join("registry")));
+        let blockchain = Arc::new(
+            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap(),
+        );
+        let seen_txid = Arc::new(Mutex::new(SeenTxids::new()));
+        let relay_url = "wss://relay.example";
+        let msg = RelayMessage::Closed {
+            subscription_id: Cow::Owned(SubscriptionId::new(format!(
+                "market-discovery-{relay_url}"
+            ))),
+            message: Cow::Borrowed("rate-limited: retry later"),
+        };
+
+        let result = handle_relay_message(
+            registry,
+            msg,
+            blockchain,
+            relay_url,
+            Kind::Custom(coinswap_kind(Network::Regtest)),
+            &seen_txid,
+        );
+        assert!(
+            result.is_err(),
+            "a CLOSED subscription must exit so the outer session loop can resubscribe"
+        );
+    }
+}

```
