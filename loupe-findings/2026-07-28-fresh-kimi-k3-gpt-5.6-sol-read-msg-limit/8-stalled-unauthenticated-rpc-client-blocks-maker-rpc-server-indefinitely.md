# Stalled unauthenticated RPC client blocks maker RPC server indefinitely

- **Finding ID:** 8
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/server.rs:77
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** 477ab470a6e3549d8eaa25d56a6369969484b6fcaadfb7932f09e4c5618186b0

## Description

handle_request() performs the pre-authentication read (`read_message(socket)?`, line 77) on the single-threaded accept loop in start_rpc_server(). The socket read timeout configured at lines 245-246 (20s) is intended to bound how long one connection can occupy the server, but it is defeated by the read loop in crate::utill::read_message (src/utill.rs:253-262): after the 4-byte length prefix is read, any read error with kind WouldBlock or Interrupted is swallowed with `continue`. On Unix, a blocking socket that hits its read timeout returns exactly ErrorKind::WouldBlock, so the loop retries forever; the timeout never fires. Result: any local process can connect to 127.0.0.1:rpc_port, send only a 4-byte length prefix (no valid cookie needed — this is pre-auth), then stall, occupying the only RPC handling thread indefinitely. Legitimate maker-cli requests (including Stop) are starved for as long as the attacker keeps the connection open, and re-connecting is trivial. Impact is availability only: the maker's coinswap protocol keeps running, funds are not directly at risk. The primary fix belongs in utill::read_message (treat WouldBlock-after-timeout as an error or bound total read time), which is outside the reviewed module; I flag that cross-file root cause rather than claim it verified in-module. The regression test reproduces handle_request's read pattern and fails on HEAD (read_message never returns), passing once the retry-on-WouldBlock behavior is fixed.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/server.rs b/src/maker/rpc/server.rs
--- a/src/maker/rpc/server.rs
+++ b/src/maker/rpc/server.rs
@@ -302,4 +302,38 @@ mod tests {
             assert_eq!(mode & 0o777, 0o600);
         }
     }
+
+    #[test]
+    fn stalled_unauthenticated_rpc_client_does_not_block_reader_forever() {
+        // Reproduces handle_request's pre-authentication read: the peer sends a
+        // valid length prefix and then stalls. read_message must honor the
+        // socket read timeout instead of retrying WouldBlock forever, otherwise
+        // one unauthenticated connection blocks the single-threaded RPC server
+        // indefinitely.
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let addr = listener.local_addr().unwrap();
+
+        let _client = std::thread::spawn(move || {
+            let mut client = TcpStream::connect(addr).unwrap();
+            client.write_all(&1024_u32.to_be_bytes()).unwrap();
+            // Keep the connection open without ever sending the payload.
+            std::thread::sleep(Duration::from_secs(60));
+        });
+
+        let (mut server, _) = listener.accept().unwrap();
+        server
+            .set_read_timeout(Some(Duration::from_millis(500)))
+            .unwrap();
+
+        let (done_tx, done_rx) = std::sync::mpsc::channel();
+        std::thread::spawn(move || {
+            let outcome = read_message(&mut server);
+            let _ = done_tx.send(outcome.is_err());
+        });
+
+        let finished = done_rx.recv_timeout(Duration::from_secs(10)).expect(
+            "read_message hung on a stalled client; one connection can block the RPC server forever",
+        );
+        assert!(finished, "read_message should error out on a stalled client");
+    }
 }

```
