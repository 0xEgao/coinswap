# Reject non-finite fee rates in maker RPC requests

- **Finding ID:** 45
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/messages.rs:47
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 3ab3105b2f81069153e95422b48e4867cb89c2d35ead8835167a284cba9900b3

## Description

`RpcMsgReq::SendToAddress` exposes its fee rate as an unconstrained `f64`, so Serde/CBOR accepts values such as NaN and infinities as authenticated RPC input. `maker::rpc::server::handle_request` forwards that value unchanged to `Wallet::coin_select` and `spend_from_wallet`. The in-tree coin-selection code converts it to `f32`, performs fee arithmetic with it, and places it in `rust_coinselect::CoinSelectionOpt`; a non-finite fee rate therefore violates the numeric invariant expected by fund-selection code before any validation occurs. This is reachable by any client holding the RPC cookie (including automation that constructs CBOR directly) and can make a send fail unpredictably or, if downstream arithmetic panics, terminate the maker process. The precise behavior of the pinned `rust-coinselect` dependency for NaN is an uncertainty because its source is outside the provided worktree; the bug does not depend on assuming that behavior, because the protocol boundary demonstrably accepts an invalid fee value and passes it into fee arithmetic. The regression test serializes a NaN request and proves that HEAD deserializes it successfully instead of rejecting it. Prior searches for `maker rpc SendToAddress feerate` and `non finite feerate` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/messages.rs b/src/maker/rpc/messages.rs
--- a/src/maker/rpc/messages.rs
+++ b/src/maker/rpc/messages.rs
@@ -159,3 +159,25 @@ impl Display for RpcMsgResp {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn send_to_address_rejects_non_finite_feerate() {
+        let request = AuthenticatedRpcRequest {
+            token: "test-token".to_owned(),
+            request: RpcMsgReq::SendToAddress {
+                address: "not-used-by-deserialization".to_owned(),
+                amount: 1,
+                feerate: f64::NAN,
+            },
+        };
+        let encoded = serde_cbor::to_vec(&request).unwrap();
+
+        assert!(
+            serde_cbor::from_slice::<AuthenticatedRpcRequest>(&encoded).is_err(),
+            "non-finite fee rates must be rejected at the RPC boundary"
+        );
+    }
+}

```
