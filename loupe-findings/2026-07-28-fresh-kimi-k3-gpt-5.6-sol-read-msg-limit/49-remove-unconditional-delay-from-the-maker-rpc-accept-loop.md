# Remove unconditional delay from the maker RPC accept loop

- **Finding ID:** 49
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/server.rs:241-268
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** 6310c03a41510ca239c1c536ba5e452d52b41dbe8e42f166785c1fcf58351a73

## Description

`start_rpc_server` handles each accepted connection inline and then unconditionally sleeps for `HEART_BEAT_INTERVAL` (three seconds), even when the listener already has more completed connections queued. This caps the entire RPC service at one connection every three seconds. No authentication is needed to consume a slot: a local process can rapidly queue well-formed requests with an invalid cookie, and each is rejected quickly but still forces the delay. A modest queued backlog therefore delays authenticated administrative operations (including `Stop`, wallet sync, and balance/send operations) by three seconds per attacker connection; continuously replenishing it can keep the RPC control plane unavailable. The listener is loopback-only, so the impact is local availability rather than remote compromise or direct fund loss.

The regression test starts the real accept loop with a test `MakerRpc`, completes one invalid-cookie request, queues a second, and requires the second rejection within one second. HEAD fails because the second connection is not accepted until after the unconditional three-second sleep. A fix should sleep/back off only after `accept()` returns `WouldBlock`, not after successfully processing a connection.

Prior findings #8 and #9 were reviewed and are distinct: they concern a single partial message hanging in `read_message` because the socket timeout is retried forever. This finding uses fully transmitted requests that complete normally and is caused by the unconditional post-request sleep.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/server.rs b/src/maker/rpc/server.rs
--- a/src/maker/rpc/server.rs
+++ b/src/maker/rpc/server.rs
@@ -280,26 +280,126 @@ pub(crate) fn start_rpc_server<M: MakerRpc>(maker: Arc<M>) -> Result<(), MakerEr
 #[cfg(test)]
 mod tests {
     use super::*;
 
+    struct AuthenticationOnlyMaker {
+        config: MakerServerConfig,
+        data_dir: std::path::PathBuf,
+        shutdown: AtomicBool,
+    }
+
+    impl MakerRpc for AuthenticationOnlyMaker {
+        fn wallet(&self) -> &RwLock<Wallet> {
+            panic!("wallet is not used while rejecting an unauthenticated request")
+        }
+
+        fn data_dir(&self) -> &Path {
+            &self.data_dir
+        }
+
+        fn config(&self) -> &MakerServerConfig {
+            &self.config
+        }
+
+        fn shutdown(&self) -> &AtomicBool {
+            &self.shutdown
+        }
+
+        #[cfg(not(feature = "integration-test"))]
+        fn get_tor_hostname(&self) -> Result<String, TorError> {
+            panic!("Tor is not used while rejecting an unauthenticated request")
+        }
+    }
+
     #[test]
     fn rpc_cookie_is_random_and_authenticated() {
         let dir = bitcoind::tempfile::tempdir().unwrap();
 
         let first = write_rpc_cookie(dir.path()).unwrap();
         let second = write_rpc_cookie(dir.path()).unwrap();
         assert_eq!(second.len(), 64);
         assert_ne!(first, second);
         assert!(cookie_matches(&second, &second));
         assert!(!cookie_matches(&first, &second));
 
         #[cfg(unix)]
         {
             use std::os::unix::fs::PermissionsExt;
             let mode = fs::metadata(dir.path().join(RPC_COOKIE_FILE))
                 .unwrap()
                 .permissions()
                 .mode();
             assert_eq!(mode & 0o777, 0o600);
         }
     }
+
+    #[test]
+    fn completed_unauthenticated_request_does_not_throttle_next_client() {
+        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
+        let port = reserved.local_addr().unwrap().port();
+        drop(reserved);
+
+        let dir = bitcoind::tempfile::tempdir().unwrap();
+        let maker = Arc::new(AuthenticationOnlyMaker {
+            config: MakerServerConfig {
+                rpc_port: port,
+                ..MakerServerConfig::default()
+            },
+            data_dir: dir.path().to_path_buf(),
+            shutdown: AtomicBool::new(false),
+        });
+        let server_maker = Arc::clone(&maker);
+        let server = std::thread::spawn(move || start_rpc_server(server_maker).unwrap());
+
+        let connect = || {
+            let deadline = std::time::Instant::now() + Duration::from_secs(10);
+            loop {
+                match TcpStream::connect(("127.0.0.1", port)) {
+                    Ok(stream) => break stream,
+                    Err(_) if std::time::Instant::now() < deadline => {
+                        std::thread::sleep(Duration::from_millis(10));
+                    }
+                    Err(e) => panic!("RPC server did not start: {}", e),
+                }
+            }
+        };
+        let send_unauthenticated_ping = |stream: &mut TcpStream| {
+            send_message(
+                stream,
+                &AuthenticatedRpcRequest {
+                    token: "invalid".to_owned(),
+                    request: RpcMsgReq::Ping,
+                },
+            )
+            .unwrap();
+        };
+
+        // Complete one request so the server is known to have left handle_request.
+        let mut first = connect();
+        send_unauthenticated_ping(&mut first);
+        let response = read_message(&mut first).unwrap();
+        assert!(matches!(
+            serde_cbor::from_slice::<RpcMsgResp>(&response).unwrap(),
+            RpcMsgResp::ServerError(_)
+        ));
+
+        // A completed request must not impose the heartbeat sleep on the next
+        // already-ready client. Otherwise a small unauthenticated backlog can
+        // delay authenticated administration by three seconds per connection.
+        let mut second = connect();
+        send_unauthenticated_ping(&mut second);
+        let (done_tx, done_rx) = std::sync::mpsc::channel();
+        std::thread::spawn(move || {
+            let result = read_message(&mut second);
+            let _ = done_tx.send(result);
+        });
+        let second_result = done_rx.recv_timeout(Duration::from_secs(1));
+
+        maker.shutdown.store(true, Relaxed);
+        server.join().unwrap();
+
+        assert!(
+            second_result.is_ok(),
+            "a completed unauthenticated request throttled the next client"
+        );
+    }
 }

```
