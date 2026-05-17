# Use owned maker error messages to avoid remote-triggered leaks

- **Finding ID:** 11
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/error.rs
- **Lines:** 31-32
- **CWE:** CWE-401
- **Fingerprint:** 1aa4a027d68fd0725a3f60fdf83380070fa71230b506105b4ae4551d86ee9595

## Description

`MakerError::General` only accepts `&'static str`. Maker protocol handlers and verification helpers need to include per-message details when rejecting malformed swap messages, so they convert dynamically formatted `String`s into this variant with `String::leak()`. Several of those errors are reachable while processing peer-controlled legacy/taproot swap messages, for example invalid contract scripts, missing inputs/outputs, signature failures, or phase/swap-id mismatches. A remote peer can repeatedly send malformed messages that force the maker to allocate and intentionally leak a new error string each time; those allocations are never reclaimed for the lifetime of the daemon, producing an unauthenticated memory-exhaustion DoS against a long-running maker. The vulnerable contract is in this file: the error type forces callers to choose between discarding useful dynamic context or leaking it. I searched prior findings for `MakerError General static str String leak memory leak DoS` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/error.rs b/src/maker/error.rs
index 20d1df2..bb69dd4 100644
--- a/src/maker/error.rs
+++ b/src/maker/error.rs
@@ -130,3 +130,15 @@ impl From<WatcherError> for MakerError {
         Self::Watcher(value)
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::MakerError;
+
+    #[test]
+    fn general_error_accepts_owned_dynamic_messages_without_leaking() {
+        let attacker_influenced_detail = format!("invalid contract tx {} has no outputs", 7);
+        let err = MakerError::General(attacker_influenced_detail);
+
+        assert!(matches!(err, MakerError::General(_)));
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

