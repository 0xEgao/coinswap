# Keep report labels inside the hotpath directory

- **Finding ID:** 12
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/hotpath_local.rs:25-31
- **Job:** 3
- **CWE:** CWE-22
- **Fingerprint:** c54c96dcfc0a2581fbcf5341716080eba3144fab2ba0f86550645767045fe410

## Description

`default_report_path` interpolates `prefix` and `swap_id` directly into a path component. Path separators and `..` components therefore remain meaningful after `report_dir.join(...)`; for example, a swap ID containing `x/../../outside` produces a report outside `{data_dir}/hotpath`, contrary to the function's documented invariant. Passing that result to `HotpathRun::start` lets profiling create or replace a timestamped JSON file outside the intended report directory with the process's filesystem authority. The helper is public, so an embedding caller that forwards an untrusted protocol/request identifier can expose this even though the current in-tree CLI callers use constant prefixes and a locally generated hexadecimal swap ID. Sanitizing both labels to a single filename component (or rejecting separators via a fallible API) restores containment. A prior search for `default_report_path traversal` and a repo-wide `hotpath` search returned no matches.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -274,3 +274,17 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn default_report_path_keeps_labels_in_hotpath_dir() {
+        let data_dir = PathBuf::from("data");
+        let report_dir = data_dir.join("hotpath");
+        let report = default_report_path(&data_dir, "taker_swap", "x/../../outside");
+
+        assert_eq!(report.parent(), Some(report_dir.as_path()));
+    }
+}

```
