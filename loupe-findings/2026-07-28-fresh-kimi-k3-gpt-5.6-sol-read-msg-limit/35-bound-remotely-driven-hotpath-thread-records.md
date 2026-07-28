# Bound remotely driven hotpath thread records

- **Finding ID:** 35
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/hotpath_local.rs:133-141
- **Job:** 3
- **CWE:** CWE-770
- **Fingerprint:** cb18a56f45495dde81215869290fd34a4e9075633afd7004810dfe1b1bb15d2f

## Description

`HotpathRun::build` enables the `Threads` section and configures `threads_limit(0)`, yielding an unbounded thread table. This is remotely driven in the profiled maker: profiling begins at process startup and remains active until a swap completes, while `maker/server.rs` accepts unauthenticated TCP connections and spawns a uniquely named `connection-{addr}` thread whose `handle_connection` entry point is measured. An unauthenticated peer can repeatedly connect and disconnect before a legitimate swap finishes, causing profiling state and the eventual JSON/finalization work to grow with attacker-created threads. With enough connections this can consume memory, disk, or prolonged finalization time and impair an online maker during a fund-bearing session. Exposure requires the operator to enable the optional `hotpath` feature/flag, so this is rated medium rather than high. Configure a finite thread limit (the existing `ROW_LIMIT` is a natural bound), and consider a collection-time bound if the dependency only applies the limit during serialization. The PoC creates 51 simultaneous named measured threads and asserts the report is capped at 50; it fails with the unlimited configuration. The precise retention behavior depends on pinned `hotpath` 0.15.0, whose source is outside this worktree; the test makes the report behavior explicit. Searches for `hotpath threads_limit unlimited connections` and `maker connection thread unbounded` found no prior match.

## Proof of Concept

```diff
diff --git a/src/hotpath_local.rs b/src/hotpath_local.rs
--- a/src/hotpath_local.rs
+++ b/src/hotpath_local.rs
@@ -274,3 +274,48 @@ fn print_hotpath_tables_from_path(report_path: &Path) {
     print_section(&v, "functions_timing");
     print_section(&v, "functions_alloc");
 }
+
+#[cfg(test)]
+mod thread_limit_tests {
+    use super::*;
+    use std::sync::{Arc, Barrier};
+
+    #[hotpath::measure]
+    fn measured_test_work() {
+        std::hint::black_box(());
+    }
+
+    #[test]
+    fn profiling_report_caps_thread_rows() {
+        let nonce = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_nanos();
+        let report_path = std::env::temp_dir().join(format!(
+            "coinswap_hotpath_thread_limit_{}_{nonce}.json",
+            std::process::id()
+        ));
+        let run = HotpathRun::start("hotpath_thread_limit_test", report_path.clone()).unwrap();
+
+        let worker_count = ROW_LIMIT + 1;
+        let barrier = Arc::new(Barrier::new(worker_count + 1));
+        let workers = (0..worker_count)
+            .map(|i| {
+                let barrier = Arc::clone(&barrier);
+                thread::Builder::new()
+                    .name(format!("untrusted-connection-{i}"))
+                    .spawn(move || {
+                        barrier.wait();
+                        measured_test_work();
+                        barrier.wait();
+                    })
+                    .unwrap()
+            })
+            .collect::<Vec<_>>();
+        barrier.wait();
+        barrier.wait();
+        for worker in workers {
+            worker.join().unwrap();
+        }
+        drop(run);
+
+        let report = read_json_with_retries(&report_path).unwrap();
+        let rows = report["threads"]["data"].as_array().unwrap();
+        let _ = fs::remove_file(report_path);
+        assert!(rows.len() <= ROW_LIMIT, "thread rows must be bounded");
+    }
+}

```
