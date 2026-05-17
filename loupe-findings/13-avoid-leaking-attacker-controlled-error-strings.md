# Avoid leaking attacker-controlled error strings

- **Finding ID:** 13
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/handlers.rs
- **Lines:** 154-175
- **CWE:** CWE-401
- **Fingerprint:** 14f1a2a87f45983c9c60aedf5c43482c1cbaecf014ceb83fe2b18911dd463e70

## Description

ConnectionState::expect_phase and check_swap_id build detailed error messages with format!(...).leak() to satisfy MakerError::General(&'static str). Those paths are reachable from network message handling before any authentication: a peer can send messages in the wrong phase, or send a protocol message with a mismatched swap id. Because the formatted string includes attacker-controlled data such as msg_swap_id and is deliberately leaked, each rejected message can permanently allocate memory for the lifetime of the maker process. Repeating mismatched swap ids with large unique strings turns ordinary validation failures into unbounded memory growth and eventual process denial of service. This is distinct from a normal log allocation because the Box<str> is converted into a static reference and is never freed. I searched prior findings for `check_swap_id expect_phase leak MakerError General memory leak` and found no duplicate. A fix should avoid embedding peer-controlled data in leaked static errors, or change the error type to own String without leaking it.

## Proof of Concept

```diff
diff --git a/src/maker/handlers.rs b/src/maker/handlers.rs
--- a/src/maker/handlers.rs
+++ b/src/maker/handlers.rs
@@ -569,3 +569,23 @@ fn handle_taproot_dispatch<M: Maker>(
 
     super::taproot_handlers::handle_taproot_message(maker, state, taproot_msg)
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn swap_id_mismatch_error_does_not_retain_untrusted_input() {
+        let mut state = ConnectionState::default();
+        state.swap_id = Some("expected-swap".to_string());
+        let attacker_swap_id = "attacker-controlled-swap-id".repeat(1024);
+
+        let err = state.check_swap_id(&attacker_swap_id).unwrap_err();
+
+        match err {
+            MakerError::General(message) => assert!(
+                !message.contains(&attacker_swap_id),
+                "rejecting a bad swap id must not leak attacker-controlled input into static memory"
+            ),
+            other => panic!("unexpected error: {:?}", other),
+        }
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

