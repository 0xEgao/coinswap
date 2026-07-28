# Redact private metadata from maker RPC debug output

- **Finding ID:** 48
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/messages.rs:24
- **Job:** 3
- **CWE:** CWE-532
- **Fingerprint:** 77894163d6b9eefc745200c279661418d5976521662efd62ca584258bfbed005

## Description

`RpcMsgReq` derives the default `Debug` implementation, which includes every field verbatim. This is not merely a latent formatter: `maker::rpc::server::handle_request` logs `rpc_request` with `{:?}` at info level for every authenticated request, and `makerd` configures info logging. A `SendToAddress` therefore writes the recipient address, amount, and requested fee rate to the maker log/console, while `VerifyDeniability` writes the internal swap identifier. Those durable records link wallet activity and swap metadata to the maker process and can be exposed through service-log access, diagnostics, backups, or support bundles, undermining the privacy properties users expect from a coinswap wallet. The bearer token itself is not part of this specific path because the server logs the inner enum rather than the envelope. A custom redacted `Debug` implementation, or a representation that only emits the operation name, would retain operational logging without recording private values. The regression test places a unique recipient marker in a request and proves that HEAD's debug representation exposes it. Prior searches for `RpcMsgReq Debug log recipient swap_id privacy` and `RPC request log sensitive data` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/messages.rs b/src/maker/rpc/messages.rs
--- a/src/maker/rpc/messages.rs
+++ b/src/maker/rpc/messages.rs
@@ -159,3 +159,23 @@ impl Display for RpcMsgResp {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn rpc_request_debug_redacts_private_payment_metadata() {
+        let recipient_marker = "private-recipient-marker";
+        let request = RpcMsgReq::SendToAddress {
+            address: recipient_marker.to_owned(),
+            amount: 42,
+            feerate: 2.0,
+        };
+
+        assert!(
+            !format!("{request:?}").contains(recipient_marker),
+            "the request's Debug output is written to the maker info log"
+        );
+    }
+}

```
