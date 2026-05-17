# Missing RPC read timeout lets a peer hang maker-cli

- **Finding ID:** 1
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/maker-cli.rs
- **Lines:** 135-140
- **CWE:** CWE-400
- **Fingerprint:** 25acbcb79064f8cddcd944c6fe91aa0443cdc020b6fa8e8448e21ae3a4f15eb6

## Description

`send_rpc_req` configures only a write timeout before sending the request and then calls `read_message` with no read deadline. A malicious or compromised RPC endpoint can accept a maker-cli connection, read the request, and keep the TCP stream open without returning a response. Because the client is the management interface for wallet and server operations, the operator's CLI process remains blocked indefinitely until killed. This is most directly exploitable when an operator points `--rpc-port` at an attacker-controlled address, or when a local process binds the expected loopback RPC port before `makerd` is available. I checked prior findings for maker-cli RPC read-timeout/stalled-response and unbounded response-length keywords and found no duplicates.

## Proof of Concept

```diff
diff --git a/src/bin/maker-cli.rs b/src/bin/maker-cli.rs
index 7b6e4f5..c9b3d25 100644
--- a/src/bin/maker-cli.rs
+++ b/src/bin/maker-cli.rs
@@ -148,3 +148,37 @@ fn send_rpc_req(mut stream: TcpStream, req: RpcMsgReq) -> Result<(), MakerError>
 
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::{
+        io::Read,
+        net::TcpListener,
+        sync::mpsc,
+        thread,
+        time::Duration,
+    };
+
+    #[test]
+    fn rpc_request_returns_when_peer_stalls_after_request() {
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let addr = listener.local_addr().unwrap();
+
+        thread::spawn(move || {
+            let (mut socket, _) = listener.accept().unwrap();
+            let mut len = [0u8; 4];
+            socket.read_exact(&mut len).unwrap();
+            let request_len = u32::from_be_bytes(len) as usize;
+            let mut request = vec![0u8; request_len];
+            socket.read_exact(&mut request).unwrap();
+
+            // Keep the connection open but never send a response. A hardened
+            // client should have its own read deadline and return an error.
+            thread::sleep(Duration::from_secs(30));
+        });
+
+        let stream = TcpStream::connect(addr).unwrap();
+        let (tx, rx) = mpsc::channel();
+        thread::spawn(move || {
+            let _ = tx.send(send_rpc_req(stream, RpcMsgReq::Ping).is_err());
+        });
+
+        assert_eq!(rx.recv_timeout(Duration::from_secs(21)).unwrap(), true);
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

