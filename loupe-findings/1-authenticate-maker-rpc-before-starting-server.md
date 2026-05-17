# Authenticate maker RPC before starting server

- **Finding ID:** 1
- **Severity:** medium
- **State:** pending
- **Scanner:** llm-code-review
- **File:** src/bin/makerd.rs
- **Lines:** 127-128
- **CWE:** CWE-306
- **Fingerprint:** 9a9a555ba28d1903dc204d189eba85d46f597d5cf38711f9c415b6893f6ccddf

## Description

`makerd` initializes the maker and immediately starts the server using a config that includes a discoverable local RPC port, but no authentication material is generated, required, or passed for the maker RPC control plane. The RPC server spawned from `start_server` accepts CBOR `RpcMsgReq` messages from any process that can connect to `127.0.0.1:<rpc_port>`, including privileged actions such as `Stop`, `NewAddress`, wallet balance/UTXO enumeration, and `SendToAddress`. On a multi-user host, another local user can read or guess the RPC port from the maker config and issue those operations without knowing the wallet password or Bitcoin RPC credentials, causing fund theft or maker shutdown. I considered prior searches for unauthenticated maker-cli/RPC access and found no matching prior finding. A fix should provision an unguessable RPC credential or use a same-user protected IPC mechanism, and require credentials on every privileged RPC request.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/messages.rs b/src/maker/rpc/messages.rs
index 899ee23..a7c7164 100644
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

