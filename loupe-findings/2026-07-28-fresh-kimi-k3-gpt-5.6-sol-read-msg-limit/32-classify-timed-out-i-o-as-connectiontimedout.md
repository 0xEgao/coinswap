# Classify timed-out I/O as ConnectionTimedOut

- **Finding ID:** 32
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/error.rs:46-50
- **Job:** 3
- **CWE:** CWE-755
- **Fingerprint:** 5248e6470b59a38f15d7840182b0245c00558cd7004a663b3749aa192385db39

## Description

`NetError` defines a dedicated `ConnectionTimedOut` protocol/network condition, but the blanket `From<std::io::Error>` implementation wraps every error—including `ErrorKind::TimedOut`—as `NetError::IO`. The public `send_message` and `read_message` functions use `?`, so a socket operation that reports `TimedOut` reaches callers under the wrong variant. A caller following the enum contract cannot apply its timeout-specific retry, peer-rotation, or cleanup policy and may instead treat a transient peer stall as an opaque/fatal transport failure, reducing availability. Conversely, code matching `ConnectionTimedOut` never observes organically converted timeout errors anywhere in this worktree; the variant otherwise has no constructor use. The regression test converts an actual `TimedOut` `std::io::Error` and expects the documented marker, failing on HEAD. The fix is to special-case `ErrorKind::TimedOut` in the conversion and preserve all other I/O errors in `IO`. Some platforms can report socket timeouts as `WouldBlock` instead, so this finding is limited to paths that actually surface `TimedOut`; no in-tree caller currently matches the marker, and severity is therefore low. Prior searches for `NetError ConnectionTimedOut conversion TimedOut` and `TimedOut IO error classification` found no duplicate. Prior #10 (`source()` chaining) and #31 (`Display` disclosure) are distinct.

## Proof of Concept

```diff
diff --git a/src/error.rs b/src/error.rs
--- a/src/error.rs
+++ b/src/error.rs
@@ -83,3 +83,16 @@ impl From<minreq::Error> for FeeEstimatorError {
         FeeEstimatorError::HttpError(err)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::NetError;
+
+    #[test]
+    fn timed_out_io_is_classified_as_connection_timeout() {
+        let error = NetError::from(std::io::Error::from(std::io::ErrorKind::TimedOut));
+
+        assert!(matches!(
+            error,
+            NetError::ConnectionTimedOut
+        ));
+    }
+}

```
