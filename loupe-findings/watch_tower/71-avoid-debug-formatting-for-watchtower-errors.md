# Avoid Debug formatting for watchtower errors

- **Finding ID:** 71
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/watcher_error.rs
- **Lines:** 77-79
- **CWE:** CWE-532
- **Fingerprint:** 4ba894004a1ca31671ec86f07c75fed7d713bbf66ad00258b621e51589833cad

## Description

`WatcherError` implements `Display` by delegating directly to the enum's derived `Debug` output. That prints every payload in full, including `HttpStatus.body`, `General(String)`, and the debug representations of wrapped transport/RPC errors. Watchtower errors are logged and can be propagated through higher-level maker/taker errors, so a failure path can write sensitive material from upstream diagnostics or wrapped client errors to logs or client-visible error strings. This file does not control what downstream error types include in their debug output; if a transport/RPC error includes URLs, headers, cookies, or echoed authorization diagnostics, `WatcherError` will disclose them verbatim. The safer behavior is for `Display` to emit only the stable variant kind or explicitly redacted summaries, while preserving full internals only for deliberately protected diagnostics. Prior searches for `WatcherError Display Debug secret leak HttpStatus General watcher_error` and `Debug error secret leak` returned no matching findings.

## Proof of Concept

```diff
diff --git a/src/watch_tower/watcher_error.rs b/src/watch_tower/watcher_error.rs
index 4d42c6d..c7a8c58 100644
--- a/src/watch_tower/watcher_error.rs
+++ b/src/watch_tower/watcher_error.rs
@@ -141,3 +141,18 @@ impl WatcherError {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::WatcherError;
+
+    #[test]
+    fn display_does_not_expose_wrapped_http_body() {
+        let secret = "rpcuser:super-secret-cookie";
+        let err = WatcherError::HttpStatus {
+            status: 500,
+            body: format!("upstream diagnostic echoed Authorization for {secret}"),
+        };
+
+        let rendered = err.to_string();
+        assert!(!rendered.contains(secret), "WatcherError display leaked: {rendered}");
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

