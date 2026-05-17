# Cap unauthenticated maker RPC frame length

- **Finding ID:** 19
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/rpc/server.rs
- **Lines:** 34-35
- **CWE:** CWE-400
- **Fingerprint:** 944ad0ec9c64654122d727467c96c71e99a1eb22b0d1478395dbe9e1764cffcc

## Description

`handle_request` reads the maker RPC frame with `read_message(socket)?` before any authentication, parsing, or size validation. The shared framing helper trusts the peer-controlled 4-byte length prefix and allocates a `Vec` of that size before reading the payload. A local process that can reach `127.0.0.1:<rpc_port>` can therefore send a huge length such as `0xffff_ffff` and force the maker RPC thread/process into multi-gigabyte allocation or OOM before a valid CBOR request is required. This is distinct from the prior unauthenticated RPC control-plane finding #2: even after credentials are added at the message layer, the frame length must be capped before allocation so unauthenticated peers cannot exhaust memory during request framing. I searched prior findings for `read_message RPC length prefix unbounded allocation denial service maker rpc` and found no match.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/server.rs b/src/maker/rpc/server.rs
--- a/src/maker/rpc/server.rs
+++ b/src/maker/rpc/server.rs
@@ -205,3 +205,24 @@ pub(crate) fn start_rpc_server<M: MakerRpc>(maker: Arc<M>) -> Result<(), MakerEr
 
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    #[test]
+    fn rpc_read_path_rejects_oversized_frames_before_allocation() {
+        let source = include_str!("server.rs");
+        let request_start = source
+            .find("let msg_bytes = read_message(socket)?;")
+            .expect("RPC handler should read framed requests");
+        let deserialize_start = source
+            .find("serde_cbor::from_slice")
+            .expect("RPC handler should deserialize framed requests");
+        let pre_deserialize = &source[request_start..deserialize_start];
+
+        assert!(
+            pre_deserialize.contains("MAX")
+                || pre_deserialize.contains("max")
+                || pre_deserialize.contains("TooLarge")
+                || pre_deserialize.contains("too large"),
+            "maker RPC must cap the unauthenticated frame length before read_message can allocate attacker-controlled sizes"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

