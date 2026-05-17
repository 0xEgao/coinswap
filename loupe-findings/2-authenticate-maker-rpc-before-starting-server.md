# Authenticate maker RPC before starting server

- **Finding ID:** 2
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/makerd.rs
- **Lines:** 127-128
- **CWE:** CWE-306
- **Fingerprint:** 9a9a555ba28d1903dc204d189eba85d46f597d5cf38711f9c415b6893f6ccddf

## Description

`makerd` initializes the maker and immediately starts `start_server` with a config containing a discoverable localhost RPC port, but it never creates, loads, or passes any authentication material for the maker RPC control plane. `start_server` later spawns the maker RPC listener, whose CBOR request protocol accepts privileged operations such as `Stop`, `NewAddress`, wallet/UTXO enumeration, and `SendToAddress` from any process that can connect to `127.0.0.1:<rpc_port>`. On a multi-user host, sibling container, or port-forwarded deployment, an attacker who can reach that port can operate or drain the maker wallet without knowing the wallet password or Bitcoin Core RPC credentials. I searched prior findings for `makerd unauthenticated rpc start_server SendToAddress Stop CWE-306` and exact title-style terms and found no MCP match. A fix should provision an unguessable credential or same-user protected IPC channel during daemon startup and require it on every privileged RPC request.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/messages.rs b/src/maker/rpc/messages.rs
--- a/src/maker/rpc/messages.rs
+++ b/src/maker/rpc/messages.rs
@@ -136,3 +136,21 @@ impl Display for RpcMsgResp {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::RpcMsgReq;
+
+    #[test]
+    fn privileged_rpc_stop_requires_authentication_material() {
+        // Stop is a privileged operation exposed by makerd's localhost RPC
+        // listener. The request type must carry some credential so another
+        // local user cannot shut down the maker with a raw TCP connection.
+        let request = RpcMsgReq::Stop;
+        let debug = format!("{request:?}");
+
+        assert!(
+            debug.contains("auth") || debug.contains("token") || debug.contains("credential"),
+            "privileged maker RPC requests must include authentication material"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

