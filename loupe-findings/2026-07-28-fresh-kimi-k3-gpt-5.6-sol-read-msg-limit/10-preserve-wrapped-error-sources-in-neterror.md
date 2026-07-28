# Preserve wrapped error sources in NetError

- **Finding ID:** 10
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/error.rs:40-43
- **Job:** 3
- **CWE:** CWE-755
- **Fingerprint:** ef3e1396c95fba950ee25257d0bcf367184fd2f78d421c4e4a979e97a9c4ade4

## Description

`NetError` stores concrete `std::io::Error` and `serde_cbor::Error` values, but its `std::error::Error::source` implementation unconditionally returns `None`. This violates the expected wrapper behavior and makes the underlying cause unavailable to standard error-chain consumers. The public `send_message` and `read_message` paths return `NetError`, and a peer can readily cause an I/O failure such as a connection reset. A caller that classifies failures by traversing/downcasting the standard error chain therefore cannot distinguish that peer-triggered transport failure from the marker variants and may apply the wrong retry or shutdown policy, creating an availability risk. The concrete operational impact depends on downstream callers' error-handling policy; no in-tree caller currently invokes `source()`, so this is rated low. The same implementation also hides CBOR sources. The fix is to return `Some(e)` for `NetError::IO(e)` and `NetError::Cbor(e)`, and `None` only for marker variants. Prior-finding searches for `NetError source` and `NetError Display Debug` returned no matches.

## Proof of Concept

```diff
diff --git a/src/error.rs b/src/error.rs
--- a/src/error.rs
+++ b/src/error.rs
@@ -83,3 +83,17 @@ impl From<minreq::Error> for FeeEstimatorError {
         FeeEstimatorError::HttpError(err)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::NetError;
+
+    #[test]
+    fn net_error_exposes_wrapped_io_source() {
+        let error = NetError::from(std::io::Error::new(
+            std::io::ErrorKind::ConnectionReset,
+            "peer reset",
+        ));
+
+        assert!(std::error::Error::source(&error).is_some());
+    }
+}

```
