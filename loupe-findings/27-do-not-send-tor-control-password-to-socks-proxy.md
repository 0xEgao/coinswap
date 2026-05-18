# Do not send Tor control password to SOCKS proxy

- **Finding ID:** 27
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/nostr_coinswap.rs
- **Lines:** 76-80
- **CWE:** CWE-522
- **Fingerprint:** 63777ea0a0b5306a44f41b409d24c23a1903c01ce7e8c04bca8cbcdd94d9e527

## Description

`connect_nostr_websocket` receives `tor_auth_password`, which elsewhere represents the Tor control password, but when it is non-empty the function passes it to `Socks5Stream::connect_with_password`. That sends the secret as SOCKS5 username/password authentication to whatever process is listening on `127.0.0.1:<socks_port>`. A malicious local process that wins the SOCKS port race, a misconfigured SOCKS endpoint, or a compromised proxy can capture the Tor control password before the WebSocket/TLS connection is attempted. Possession of that control password lets the attacker authenticate to the Tor control port and interfere with the maker's onion service or routing. This is distinct from prior finding 2, which covers persisting the same secret in the maker config; this issue leaks it over the SOCKS protocol at runtime. The Nostr connection should use unauthenticated SOCKS for Tor, or separate SOCKS isolation credentials from the Tor control password.

## Proof of Concept

```diff
diff --git a/src/nostr_coinswap.rs b/src/nostr_coinswap.rs
--- a/src/nostr_coinswap.rs
+++ b/src/nostr_coinswap.rs
@@ -253,3 +253,76 @@ fn broadcast_to_relay(
     log::warn!("nostr relay {} did not confirm event", relay);
     Err(MakerError::General("nostr relay did not confirm event"))
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::{
+        io::{Read, Write},
+        net::TcpListener,
+        sync::mpsc,
+        thread,
+        time::Duration,
+    };
+
+    #[test]
+    fn tor_control_password_is_not_sent_as_socks_password() {
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let port = listener.local_addr().unwrap().port();
+        let (tx, rx) = mpsc::channel();
+
+        thread::spawn(move || {
+            let (mut stream, _) = listener.accept().unwrap();
+
+            let mut greeting_header = [0u8; 2];
+            stream.read_exact(&mut greeting_header).unwrap();
+            assert_eq!(greeting_header[0], 5);
+
+            let mut methods = vec![0u8; greeting_header[1] as usize];
+            stream.read_exact(&mut methods).unwrap();
+
+            if !methods.contains(&2) {
+                tx.send(None).unwrap();
+                return;
+            }
+
+            // Select SOCKS5 username/password auth. A correct Tor connection
+            // must never offer the Tor control password to this auth exchange.
+            stream.write_all(&[5, 2]).unwrap();
+
+            let mut auth_header = [0u8; 2];
+            if stream.read_exact(&mut auth_header).is_err() {
+                tx.send(None).unwrap();
+                return;
+            }
+            assert_eq!(auth_header[0], 1);
+
+            let mut username = vec![0u8; auth_header[1] as usize];
+            stream.read_exact(&mut username).unwrap();
+
+            let mut password_len = [0u8; 1];
+            stream.read_exact(&mut password_len).unwrap();
+
+            let mut password = vec![0u8; password_len[0] as usize];
+            stream.read_exact(&mut password).unwrap();
+
+            let captured = String::from_utf8(password).unwrap();
+            tx.send(Some(captured)).unwrap();
+
+            let _ = stream.write_all(&[1, 1]);
+        });
+
+        let secret = "top-secret-tor-control-password";
+        let _ = connect_nostr_websocket("wss://relay.example", port, secret);
+
+        let captured = rx
+            .recv_timeout(Duration::from_secs(2))
+            .expect("fake SOCKS server should observe the client's auth behavior");
+
+        assert_ne!(
+            captured,
+            Some(secret.to_string()),
+            "connect_nostr_websocket must not send the Tor control password as SOCKS5 proxy authentication"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

