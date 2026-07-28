# ThreadPool::join_all_threads deadlocks with concurrent add_thread during shutdown

- **Finding ID:** 5
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:338-360
- **Job:** 3
- **CWE:** CWE-833
- **Fingerprint:** 8ef06906c178404229f221e15d5d28e7df8b2164691c792c37ea23359ed74991

## Description

`ThreadPool::join_all_threads` (src/maker/api.rs:338-360) holds the `threads` mutex while calling `JoinHandle::join()` on each pooled thread. One of the pooled threads is the idle-swap checker (`check_for_idle_states`, src/maker/server.rs:458-516, registered at server.rs:182), which calls `maker.thread_pool.add_thread(handle)` (server.rs:509) every time it spawns a swap-recovery thread — and `add_thread` (api.rs:332-335) needs the same mutex. If the checker is in the middle of registering a recovery thread while the main thread runs shutdown (`join_all_threads` at server.rs:229), the joiner blocks waiting for the checker to exit while the checker blocks forever on the mutex held by the joiner: a single-mutex deadlock. The maker process hangs on shutdown exactly when a taker dropped mid-swap, so the designed timeout-recovery path is stalled and the operator must SIGKILL, potentially interrupting wallet save / swap recovery. Reachability is timing-dependent (an idle swap must be drained during the shutdown window), hence low severity; no data corruption results. The regression test reproduces the deadlock deterministically: a pooled thread released into `add_thread` after the joiner has taken the lock; on HEAD `join_all_threads` never returns and the test fails on a 5-second recv timeout (verified locally: test FAILS on HEAD with the deadlock). The fix is to drain the handle vector under the lock (e.g. `std::mem::take`) and release the mutex before joining. Prior findings checked and ruled out: #2 (Taproot timelock, unrelated), #3 (duplicate swap id, unrelated); keyword searches for thread-pool/join/deadlock found no matches.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
index 1111111..2222222 100644
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -1593,5 +1593,54 @@
             &self.config.tor_auth_password,
             tor_key_bytes,
         )
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::ThreadPool;
+    use std::sync::{mpsc, Arc};
+    use std::thread;
+    use std::time::Duration;
+
+    /// Regression test: `join_all_threads` must not deadlock when a pooled
+    /// thread concurrently calls `add_thread`. On HEAD, `join_all_threads`
+    /// holds the `threads` mutex across `JoinHandle::join`, while
+    /// `check_for_idle_states` (src/maker/server.rs) — itself a pooled
+    /// thread — calls `thread_pool.add_thread(handle)` when it spawns a
+    /// swap-recovery thread. If that happens during shutdown, the joiner
+    /// waits for the checker thread while the checker thread waits for the
+    /// mutex held by the joiner: the maker hangs on shutdown.
+    #[test]
+    fn join_all_threads_does_not_deadlock_with_concurrent_add_thread() {
+        let pool = Arc::new(ThreadPool::new(6102));
+        let (start_tx, start_rx) = mpsc::channel::<()>();
+
+        // Simulates the idle-checker thread: on signal, it spawns a recovery
+        // thread and registers it via `add_thread`.
+        let worker_pool = Arc::clone(&pool);
+        let worker = thread::spawn(move || {
+            start_rx.recv().unwrap();
+            worker_pool.add_thread(thread::spawn(|| {}));
+        });
+        pool.add_thread(worker);
+
+        let join_pool = Arc::clone(&pool);
+        let (done_tx, done_rx) = mpsc::channel::<()>();
+        thread::spawn(move || {
+            let _ = join_pool.join_all_threads();
+            let _ = done_tx.send(());
+        });
+
+        // Give the joiner time to acquire the mutex and block in `join`,
+        // then release the worker into `add_thread`.
+        thread::sleep(Duration::from_millis(200));
+        start_tx.send(()).unwrap();
+
+        assert!(
+            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
+            "join_all_threads deadlocked: it holds the threads mutex while \
+             joining a thread that is blocked in add_thread on the same mutex"
+        );
+    }
+}

```
