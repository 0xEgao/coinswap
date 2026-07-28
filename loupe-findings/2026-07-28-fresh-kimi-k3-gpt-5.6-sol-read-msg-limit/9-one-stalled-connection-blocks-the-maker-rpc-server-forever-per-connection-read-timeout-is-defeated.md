# One stalled connection blocks the maker RPC server forever; per-connection read timeout is defeated

- **Finding ID:** 9
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/server.rs:241-256
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** 740f37a36449a1a5282aa509b44051702573fb19d92ed4ce51b6629983b61772

## Description

`start_rpc_server` runs a single-threaded accept loop and calls `handle_request` inline for each accepted connection (server.rs:242-256), so only one RPC client is serviced at a time. It sets a 20s read timeout on the stream (server.rs:245) intending to bound how long one client can occupy the loop, but that mitigation is ineffective: `handle_request` calls `read_message` (src/utill.rs:238), whose read loop explicitly retries on `ErrorKind::WouldBlock` (utill.rs:257-258). On Unix, an expired socket read timeout is reported to Rust as exactly `ErrorKind::WouldBlock`, so when a client connects and stalls (or trickles a partial 4-byte length prefix), every read blocks for the timeout, errors with WouldBlock, and is retried forever. Authentication happens only after a complete message is read (server.rs:77-88), so no cookie is needed.

Impact: any local process (the RPC listener binds 127.0.0.1, so any user/process on the host can connect; the cookie file's 0600 mode does not help) can hold one connection open and indefinitely deny all RPC access to the maker — including `maker-cli` Stop, SyncWallet, Balances, and SendToAddress — for as long as it pleases, requiring no privileges and trivial resources. The maker's coinswap protocol keeps running, so this is a control-plane availability bug.

Reproduction: run the added regression test; it performs the same pattern as server.rs (read timeout + `read_message`) with a client that sends 2 bytes then stalls. On HEAD the reader never returns and the test fails via the 10s `recv_timeout`; a fix that propagates timeout/WouldBlock errors (or a per-connection deadline) makes it pass.

Notes/uncertainties: (1) The root cause lives in the shared helper `src/utill.rs:253-262`; the finding is reported against server.rs because that is where the serialized-accept-loop design turns the helper's behavior into a total RPC outage. (2) `read_message` is also used by the taker-facing and offer-fetching paths (e.g. src/maker/server.rs, src/taker/api.rs, src/taker/offers.rs); those call sites set read timeouts too and are presumably affected per-connection, but they were not audited here. (3) On Windows a read timeout surfaces as `ErrorKind::TimedOut`, which the current code propagates, so the infinite-loop behavior is Unix-specific.

## Proof of Concept

```diff
--- a/src/utill.rs
+++ b/src/utill.rs
@@ -1063,6 +1063,51 @@ mod tests {
         assert!(matches!(error, NetError::MessageTooLarge));
         sender.join().unwrap();
     }
 
+    #[test]
+    fn test_read_message_honors_socket_read_timeout() {
+        use std::sync::mpsc;
+        use std::time::Instant;
+
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let address = listener.local_addr().unwrap();
+
+        // Mimic the maker RPC server: per-connection read timeout, blocking read.
+        let (tx, rx) = mpsc::channel();
+        thread::spawn(move || {
+            let (mut socket, _) = listener.accept().unwrap();
+            socket
+                .set_read_timeout(Some(Duration::from_millis(500)))
+                .unwrap();
+            let start = Instant::now();
+            let result = read_message(&mut socket);
+            let _ = tx.send((start.elapsed(), result.is_err()));
+        });
+
+        // Client sends only a partial length prefix and then stalls.
+        let mut stream = TcpStream::connect(address).unwrap();
+        stream.write_all(&[0_u8, 0]).unwrap();
+
+        match rx.recv_timeout(Duration::from_secs(10)) {
+            Ok((elapsed, is_err)) => {
+                assert!(
+                    is_err,
+                    "read_message should fail once the socket read timeout expires"
+                );
+                assert!(
+                    elapsed < Duration::from_secs(5),
+                    "read_message ignored the socket read timeout (took {elapsed:?})"
+                );
+            }
+            Err(_) => panic!(
+                "read_message never returned despite a 500ms read timeout; \
+                 socket read timeouts surface as WouldBlock and are retried forever, \
+                 so one stalled connection blocks the whole RPC accept loop"
+            ),
+        }
+
+        drop(stream);
+    }
+
     #[test]
     fn test_redeemscript_to_scriptpubkey_custom() {

```
