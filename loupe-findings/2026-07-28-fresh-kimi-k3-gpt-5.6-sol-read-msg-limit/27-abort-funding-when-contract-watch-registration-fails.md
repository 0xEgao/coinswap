# Abort funding when contract watch registration fails

- **Finding ID:** 27
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:1026-1033
- **Job:** 3
- **CWE:** CWE-252
- **Fingerprint:** 139dd5e0003d8dbf7b0393ca66ee402421f51a0b617ab6bfaa1bb38b7d263c30

## Description

`register_watch_outpoint` receives the `SendError` returned when the watcher thread is gone, logs it, and returns success (`()`). Both protocol handlers therefore continue after a failed safety prerequisite: Legacy can create/broadcast pending funding, and Taproot has already broadcast each outgoing contract before calling this method. The watcher thread can exit independently (for example `Watcher::run` propagates an initial backend `chain_name` error after the service has already returned its handle). If the taker then drops and spends the maker's outgoing contract through the hashlock path, recovery depends on the registered watch to obtain the revealed preimage and sweep the incoming contract. With no registration, `watch_request` also fails, the maker cannot take the incoming hashlock path, and the taker can later refund that incoming contract while the maker's outgoing value is already gone. The regression test makes the concrete trait method satisfy a fallible function signature. It fails to compile on HEAD because the error is discarded, and passes once the trait and implementation return `Result<(), MakerError>` so callers must propagate failure. Searches for `register_watch_outpoint watcher gone error ignored`, `watch registration failure fund recovery`, `register_watch_request MakerServer`, and `watcher gone outgoing preimage` found no prior report.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -1595,3 +1595,21 @@ impl MakerRpc for MakerServer {
         )
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::{MakerError, MakerServer, MakerTrait};
+    use bitcoin::{OutPoint, ScriptBuf};
+
+    #[test]
+    fn watch_registration_failure_is_reported_to_protocol_callers() {
+        // Registering a contract outpoint is a fund-safety prerequisite. The
+        // concrete implementation must expose the `WatchService` send failure
+        // so handlers cannot continue funding after the watcher has exited.
+        type FallibleRegistration =
+            fn(&MakerServer, OutPoint, ScriptBuf) -> Result<(), MakerError>;
+        let registration: FallibleRegistration =
+            <MakerServer as MakerTrait>::register_watch_outpoint;
+
+        let _ = registration;
+    }
+}

```
