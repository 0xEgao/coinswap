# Require authentication for maker wallet RPC commands

- **Finding ID:** 3
- **Severity:** medium
- **State:** pending
- **Scanner:** llm-code-review
- **File:** src/bin/maker-cli.rs
- **Lines:** 105-112
- **CWE:** CWE-306
- **Fingerprint:** 1f70ffa5b0053ce7e83af8d806a6e71f87072d6c3c12d86dbe6887b2472fec04

## Description

`maker-cli` sends privileged maker RPC requests such as `SendToAddress` directly over the TCP socket with no authentication token, cookie, challenge response, or other authorization material. The daemon-side RPC listener is intended for local administration, but any process that can reach the bound RPC socket can speak the same CBOR protocol and instruct the maker wallet to derive addresses, reveal wallet state, stop the daemon, or broadcast a payment to an attacker-controlled address. This is exploitable in common multi-user hosts, compromised sibling containers, port-forwarded deployments, or any setup that accidentally exposes the RPC port. The CLI is part of the vulnerable protocol surface because it has no way to provide credentials, and line 105 constructs a wallet-spending request that contains only destination, amount, and feerate. I searched prior findings for `maker cli rpc unauthenticated SendToAddress Stop`, `rpc authentication makerd wallet send_to_address`, `maker rpc stop no auth localhost`, and `maker-cli authentication rpc_port`; none matched. A fix should add an authenticated RPC envelope and make the CLI refuse privileged commands unless it can load or supply valid credentials.

## Proof of Concept

```diff
diff --git a/tests/integration/main.rs b/tests/integration/main.rs
--- a/tests/integration/main.rs
+++ b/tests/integration/main.rs
@@ -15,6 +15,7 @@ mod malice1;
 mod malice2;
 mod multi_taker;
 mod skip_funding_recovery;
+mod maker_cli_auth;
 mod standard_swap;
 mod taproot_hashlock_recovery;
 mod taproot_maker_abort1;
diff --git a/tests/integration/maker_cli_auth.rs b/tests/integration/maker_cli_auth.rs
new file mode 100644
--- /dev/null
+++ b/tests/integration/maker_cli_auth.rs
@@ -0,0 +1,52 @@
+use coinswap::{
+    maker::{RpcMsgReq, RpcMsgResp},
+    utill::{read_message, send_message},
+};
+use std::{
+    net::TcpListener,
+    process::Command,
+    sync::mpsc,
+    thread,
+    time::Duration,
+};
+
+#[test]
+fn maker_cli_refuses_to_send_wallet_rpc_without_authentication() {
+    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+    let rpc_addr = listener.local_addr().unwrap().to_string();
+    let (tx, rx) = mpsc::channel();
+
+    thread::spawn(move || {
+        let (mut socket, _) = listener.accept().unwrap();
+        let msg_bytes = read_message(&mut socket).unwrap();
+        let parsed = serde_cbor::from_slice::<RpcMsgReq>(&msg_bytes).ok();
+        tx.send(parsed).unwrap();
+        let _ = send_message(
+            &mut socket,
+            &RpcMsgResp::ServerError("test server rejected unauthenticated request".to_string()),
+        );
+    });
+
+    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
+        .args([
+            "--rpc-port",
+            &rpc_addr,
+            "send-to-address",
+            "--address",
+            "bcrt1q7sl4h7f4g6m64k27vy0aew22kw4ps5k4r5qs5d",
+            "--amount",
+            "1000",
+        ])
+        .output()
+        .expect("failed to run maker-cli");
+
+    let unauthenticated_request = rx
+        .recv_timeout(Duration::from_secs(2))
+        .expect("maker-cli should either refuse locally or send an authenticated message");
+
+    assert!(
+        !output.status.success() || unauthenticated_request.is_none(),
+        "maker-cli sent a wallet-spending RpcMsgReq without any authentication envelope: {:?}",
+        unauthenticated_request
+    );
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

