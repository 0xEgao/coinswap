# Preserve funded swaps during reboot recovery

- **Finding ID:** 20
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/maker/server.rs
- **Lines:** 96-101
- **CWE:** CWE-664
- **Fingerprint:** ab722ed5cce65b6cbf9a5845d5e3007878128ad538995f386608b27d4f205103

## Description

On startup, `start_server` recovers wallet swapcoins found by `find_unfinished_swapcoins`, but it invents a fresh `reboot-recovery-<timestamp>` swap id instead of restoring or creating a matching tracker record. `recover_from_swap` later looks up that id in the persistent swap tracker and defaults a missing record to `funding_broadcast = false`. That drives the cleanup branch which removes all incoming and outgoing swapcoins from the wallet and saves the result. If the daemon is restarted after a malicious taker has progressed far enough for the maker's contract funding to be broadcast but before normal completion/recovery, the maker can forget the still-live contract outputs and skip both hashlock and timelock recovery. The taker can then profit from the maker failing to recover its funds or the funds can remain stranded until manual intervention. I searched prior findings for `recover_from_swap reboot recovery funding_broadcast unfinished swapcoins discard remove_outgoing_swapcoin` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/maker/server.rs b/src/maker/server.rs
--- a/src/maker/server.rs
+++ b/src/maker/server.rs
@@ -1003,6 +1003,32 @@ fn send_message(stream: &TcpStream, message: &MakerToTakerMessage) -> Result<(),
 
     Ok(())
 }
+
+#[cfg(test)]
+mod recovery_security_tests {
+    #[test]
+    fn reboot_recovery_must_not_treat_missing_tracker_record_as_unfunded() {
+        let server_source = include_str!("server.rs");
+
+        assert!(
+            !server_source.contains("let swap_id = format!(\"reboot-recovery-{}\"")
+                && !server_source.contains(".map(|r| r.funding_broadcast)\n            .unwrap_or(false)"),
+            "startup recovery must preserve a durable swap id/record or otherwise avoid treating \
+             a missing tracker record as funding_broadcast=false; that path deletes unfinished \
+             swapcoins even when their funding transaction may already be on chain"
+        );
+    }
+
+    #[test]
+    fn cleanup_without_funding_record_is_not_a_safe_default() {
+        let server_source = include_str!("server.rs");
+
+        assert!(
+            !server_source.contains("get_record(&swap_id)\n            .map(|r| r.funding_broadcast)\n            .unwrap_or(false)"),
+            "recovery must not default missing tracker metadata to 'not broadcast' before removing swapcoins"
+        );
+    }
+}
 
 /// Retry with different ports if not availabe
 #[hotpath::measure]

```

## Suggested Fix

```diff
No suggested fix emitted.
```

