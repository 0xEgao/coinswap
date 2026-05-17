# Use an exclusive temp file for Hotpath report formatting

- **Finding ID:** 8
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/hotpath_local.rs
- **Lines:** 111-118
- **CWE:** CWE-59
- **Fingerprint:** 6a2a22390eb7f2fa5c268f906e39b6756e67b6813962e80c6c1f4f4f34e6e9d0

## Description

`pretty_format_json_file_in_place` rewrites a Hotpath JSON report through a predictable sibling path named `.<report-file>.tmp`, then opens that path with `create(true).write(true).truncate(true)` before renaming it over the original report. Because the temporary name is deterministic and the open follows symlinks, any local attacker who can write in the report directory can pre-create `.report.json.tmp` as a symlink to another file writable by the Hotpath process. When profiling finishes, the formatter truncates and writes pretty-printed JSON through the symlink, clobbering the target file before the symlink is renamed over the report. The default report directory is derived from operator-controlled `data_dir`, so the practical impact depends on whether that directory is shared or otherwise attacker-writable, but in that deployment the bug allows arbitrary file overwrite as the profiling process user. I searched prior findings for `hotpath_local pretty_format_json_file_in_place symlink tmp tempfile` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
index 9c75c8d..2d8a7f0 100644
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -276,3 +276,46 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[cfg(unix)]
+    #[test]
+    fn pretty_format_does_not_follow_predictable_tmp_symlink() {
+        use std::os::unix::fs::symlink;
+
+        let dir = std::env::temp_dir().join(format!(
+            "coinswap-hotpath-symlink-poc-{}-{}",
+            std::process::id(),
+            SystemTime::now()
+                .duration_since(UNIX_EPOCH)
+                .unwrap()
+                .as_nanos()
+        ));
+        fs::create_dir_all(&dir).unwrap();
+
+        let report_path = dir.join("report.json");
+        let victim_path = dir.join("victim.txt");
+        let tmp_path = dir.join(".report.json.tmp");
+
+        fs::write(
+            &report_path,
+            r#"{"functions_timing":{"time_elapsed":"1ms","data":[]}}"#,
+        )
+        .unwrap();
+        fs::write(&victim_path, "do not overwrite").unwrap();
+        symlink(&victim_path, &tmp_path).unwrap();
+
+        pretty_format_json_file_in_place(&report_path).unwrap();
+
+        assert_eq!(
+            fs::read_to_string(&victim_path).unwrap(),
+            "do not overwrite",
+            "pretty formatting must not follow attacker-controlled temp symlinks"
+        );
+
+        let _ = fs::remove_file(&report_path);
+        let _ = fs::remove_file(&victim_path);
+        let _ = fs::remove_dir_all(&dir);
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

