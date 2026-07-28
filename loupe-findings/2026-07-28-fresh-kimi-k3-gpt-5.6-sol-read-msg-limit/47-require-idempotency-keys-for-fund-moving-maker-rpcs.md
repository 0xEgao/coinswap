# Require idempotency keys for fund-moving maker RPCs

- **Finding ID:** 47
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/messages.rs:13-18
- **Job:** 3
- **CWE:** n/a
- **Fingerprint:** d401835d3356c833776d81bc25d9f0d74830a3771c08865461b625527eece10c

## Description

`AuthenticatedRpcRequest` contains only a bearer token and operation; neither the envelope nor `SendToAddress` carries a unique operation/idempotency identifier. Consequently, the server cannot distinguish a retry from a new payment. This is a practical fund-safety issue because `maker::rpc::server::handle_request` broadcasts the transaction (`send_tx`) and synchronizes/persists the wallet before it sends `RpcMsgResp::SendToAddressResp`. If the TCP connection closes or the response is otherwise lost after broadcast/sync, the client receives no success acknowledgement. Retrying the same authenticated request can then select different still-confirmed UTXOs and broadcast a second transaction paying the same recipient and amount. The cookie correctly authenticates both requests but does not provide replay or duplicate-operation protection. A fix should require a client-generated unique ID on fund-moving requests and persist/cache the resulting status or txid before acknowledging, returning that result for duplicates. The regression test encodes the current legacy request shape and requires deserialization to reject a fund-moving request that lacks such an identifier; it fails on HEAD because the request is accepted. Prior searches for `SendToAddress idempotency retry duplicate payment` and `maker RPC replay` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/messages.rs b/src/maker/rpc/messages.rs
--- a/src/maker/rpc/messages.rs
+++ b/src/maker/rpc/messages.rs
@@ -159,3 +159,41 @@ impl Display for RpcMsgResp {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[derive(serde::Serialize)]
+    struct LegacyAuthenticatedRpcRequest {
+        token: String,
+        request: LegacyRpcMsgReq,
+    }
+
+    #[derive(serde::Serialize)]
+    enum LegacyRpcMsgReq {
+        SendToAddress {
+            address: String,
+            amount: u64,
+            feerate: f64,
+        },
+    }
+
+    #[test]
+    fn send_to_address_requires_an_idempotency_key() {
+        let legacy_request = LegacyAuthenticatedRpcRequest {
+            token: "test-token".to_owned(),
+            request: LegacyRpcMsgReq::SendToAddress {
+                address: "not-used-by-deserialization".to_owned(),
+                amount: 1,
+                feerate: 2.0,
+            },
+        };
+        let encoded = serde_cbor::to_vec(&legacy_request).unwrap();
+
+        assert!(
+            serde_cbor::from_slice::<AuthenticatedRpcRequest>(&encoded).is_err(),
+            "fund-moving RPC requests without an idempotency key must be rejected"
+        );
+    }
+}

```
