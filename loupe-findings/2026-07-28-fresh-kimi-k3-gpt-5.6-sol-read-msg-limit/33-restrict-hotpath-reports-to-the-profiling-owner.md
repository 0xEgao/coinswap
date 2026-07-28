# Restrict hotpath reports to the profiling owner

- **Finding ID:** 33
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/hotpath_local.rs:95-104
- **Job:** 3
- **CWE:** CWE-732
- **Fingerprint:** 1ead175f0b162b1ac76a649ffb8d06aed56da22c59ac997d3d08419b7ffd4d55

## Description

`write_json_pretty` opens the formatter's replacement file without setting or tightening its permissions. On Unix, a newly created file therefore inherits the process umask (commonly producing mode 0644), and an existing temporary file retains whatever broader mode it already had. `pretty_format_json_file_in_place` then renames that file over the final report. These reports include the `Threads` section; in-tree thread names embed remote connection addresses, Nostr relay URLs, and recovery swap IDs (`connection-{addr}`, `nostr-session-{relay}`, and `swap-recovery-{swap_id}`). When the chosen data directory is searchable by other local accounts, those accounts can learn swap activity and peer/network metadata. Profiling is opt-in and this does not expose wallet keys, so the impact is rated low. Set the report/replacement file to owner-only access (0600 on Unix), including when reopening an existing file, before writing it. The regression test deterministically pre-creates a 0644 report and shows that the writer leaves it readable. Prior searches for hotpath report permissions found no match; findings #12 and #13 were reviewed and are distinct path-containment and symlink-overwrite issues.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -274,3 +274,32 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(all(test, unix))]
+mod permission_tests {
+    use super::*;
+    use std::os::unix::fs::{PermissionsExt, OpenOptionsExt};
+
+    #[test]
+    fn pretty_json_writer_makes_report_private() {
+        let nonce = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_nanos();
+        let dir = std::env::temp_dir().join(format!(
+            "coinswap_hotpath_permissions_{}_{nonce}",
+            std::process::id()
+        ));
+        fs::create_dir_all(&dir).unwrap();
+        let report = dir.join("report.json");
+        fs::OpenOptions::new()
+            .create_new(true)
+            .write(true)
+            .mode(0o644)
+            .open(&report)
+            .unwrap();
+
+        write_json_pretty(&report, &serde_json::json!({"threads": []})).unwrap();
+        let mode = fs::metadata(&report).unwrap().permissions().mode() & 0o777;
+        let _ = fs::remove_dir_all(dir);
+
+        assert_eq!(mode, 0o600, "profiling reports must not be group/world readable");
+    }
+}

```
