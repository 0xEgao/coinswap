# Propagate the final buffered report write failure

- **Finding ID:** 34
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/hotpath_local.rs:101-103
- **Job:** 3
- **CWE:** CWE-252
- **Fingerprint:** 76f19f15db927c2de22cb1ee36969de49082aacd9f36ede7a8d2cfac4d32e2c8

## Description

`write_json_pretty` passes an owned `BufWriter<File>` into `serde_json::to_writer_pretty` and returns its serialization result without explicitly flushing the buffer. A write failure that occurs only when the remaining buffer is dropped is therefore not returned by this function: `BufWriter` cannot report errors from `Drop`. `pretty_format_json_file_in_place` treats that false success as a complete temporary report and renames the incomplete file over the original valid report, losing profiling data during conditions such as a filesystem becoming full at the final write. The issue is limited to optional profiling output, so it is rated low. Keep the writer locally, serialize through `&mut writer`, and call `flush()` (and propagate its error) before renaming. The Linux-gated regression uses `/dev/full` with a small JSON value so the write remains buffered until finalization; it returns `Ok` on the vulnerable implementation. This conclusion assumes pinned `serde_json` 1.0 does not itself force a successful flush of the supplied `BufWriter`; its source is outside the worktree, and the regression test makes that dependency behavior explicit. Prior search for `write_json_pretty BufWriter flush error ignored` found no match; #13 concerns symlink following, not error propagation.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -274,3 +274,13 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(all(test, target_os = "linux"))]
+mod flush_tests {
+    use super::*;
+
+    #[test]
+    fn pretty_json_writer_reports_final_flush_failure() {
+        let result = write_json_pretty(Path::new("/dev/full"), &serde_json::json!({"ok": true}));
+        assert!(result.is_err(), "the final buffered write error must be returned");
+    }
+}

```
