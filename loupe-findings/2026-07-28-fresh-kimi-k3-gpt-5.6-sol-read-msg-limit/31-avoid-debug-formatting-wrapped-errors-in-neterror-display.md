# Avoid Debug-formatting wrapped errors in NetError Display

- **Finding ID:** 31
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/error.rs:34-37
- **Job:** 3
- **CWE:** CWE-209
- **Fingerprint:** 8957aafc4029caf105b6b8fad96a4bb9ade48e9fad372a7b11241a584c87b46b

## Description

`NetError` implements its user-facing `Display` representation by delegating to `Debug` for the entire enum. For `NetError::IO`, this recursively uses the debug representation of an arbitrary custom error stored inside `std::io::Error`. Rust callers commonly keep `Display` redacted while allowing `Debug` to contain diagnostic context, including credentials or other sensitive values. Because both `NetError` and its `From<std::io::Error>` conversion are public, an embedding application can pass such an error through this boundary and later expose the secret merely by rendering the resulting `dyn Error` for a user or log. The regression test constructs an inner error whose `Display` is redacted but whose `Debug` contains a password; `NetError::to_string()` leaks the password on HEAD. A fix should match each variant explicitly and format wrapped errors through their `Display` implementations. In-tree socket I/O normally produces OS errors rather than custom secret-bearing errors, so the direct repository impact is limited and severity is low. Prior finding #10 concerns the distinct `Error::source()` chain omission, not this formatting disclosure; searches for `NetError Display Debug`, `error Debug sensitive information exposure`, and `NetError formatting secret` found no duplicate.

## Proof of Concept

```diff
diff --git a/src/error.rs b/src/error.rs
--- a/src/error.rs
+++ b/src/error.rs
@@ -83,3 +83,37 @@ impl From<minreq::Error> for FeeEstimatorError {
         FeeEstimatorError::HttpError(err)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::NetError;
+    use std::{error::Error, fmt};
+
+    struct RedactedError;
+
+    impl fmt::Debug for RedactedError {
+        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+            f.write_str("wallet password: correct horse battery staple")
+        }
+    }
+
+    impl fmt::Display for RedactedError {
+        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+            f.write_str("redacted I/O failure")
+        }
+    }
+
+    impl Error for RedactedError {}
+
+    #[test]
+    fn net_error_display_does_not_expose_debug_only_details() {
+        let error = NetError::from(std::io::Error::new(
+            std::io::ErrorKind::Other,
+            RedactedError,
+        ));
+
+        let rendered = error.to_string();
+        assert!(
+            !rendered.contains("correct horse battery staple"),
+            "Display exposed debug-only secret: {rendered}"
+        );
+    }
+}

```
