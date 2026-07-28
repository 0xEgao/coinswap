# Refuse symlinks at hotpath temporary files

- **Finding ID:** 13
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/hotpath_local.rs:95-118
- **Job:** 3
- **CWE:** CWE-59
- **Fingerprint:** 52148591d04998b8a9894dcc126645e7a822b837319aea6e5edcc72fa5dd8208

## Description

`pretty_format_json_file_in_place` derives a fixed temporary name (`.<report-name>.tmp`) and opens it with `create(true)`, `truncate(true)`, and no exclusive/no-follow protection. If another local principal can write the selected report directory, it can place a symlink at that predictable temporary path before profiling finishes. The formatter follows the link and replaces the link target's contents with the profiling JSON under the profiler process's authority; the later rename does not undo that target overwrite. This can clobber files writable by a privileged or service account. The default per-user data directory reduces exposure, but `HotpathRun` is public and the binaries accept custom data directories, so shared or pre-created directories are reachable deployments. The regression test confirms the target file changes on HEAD. Use a unique same-directory temporary file created atomically with exclusive/no-follow semantics, then flush and atomically persist it. A prior search for `hotpath_local symlink tmp` and a repo-wide `hotpath` search returned no matches.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -274,3 +274,33 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(all(test, unix))]
+mod tests {
+    use super::*;
+    use std::os::unix::fs::symlink;
+
+    #[test]
+    fn pretty_formatter_does_not_follow_existing_temp_symlink() {
+        let nonce = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_nanos();
+        let dir = std::env::temp_dir().join(format!(
+            "coinswap_hotpath_symlink_{}_{nonce}",
+            std::process::id()
+        ));
+        fs::create_dir_all(&dir).unwrap();
+        let report = dir.join("report.json");
+        let victim = dir.join("victim");
+        fs::write(&report, r#"{"ok":true}"#).unwrap();
+        fs::write(&victim, b"do not overwrite").unwrap();
+        symlink(&victim, dir.join(".report.json.tmp")).unwrap();
+
+        let _ = pretty_format_json_file_in_place(&report);
+        let victim_contents = fs::read(&victim).unwrap();
+        let _ = fs::remove_dir_all(dir);
+
+        assert_eq!(victim_contents, b"do not overwrite");
+    }
+}

```
