# Unauthenticated remote memory leak via String::leak in expect_phase/check_swap_id error paths

- **Finding ID:** 4
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:157-186
- **Job:** 3
- **CWE:** CWE-401
- **Fingerprint:** b89bfd3addf7cb28d3e2d2e4d5d0a5084d0efec871ff77665d42532a268fd3ba

## Description

`ConnectionState::expect_phase` (lines 157-169) and `ConnectionState::check_swap_id` (lines 173-186) build their error strings with `format!(...).leak()` because `MakerError::General` holds a `&'static str` (src/maker/error.rs:32). Every rejected message therefore permanently leaks a heap `String` (~170-190 bytes including the formatted phase/swap-id content) for the lifetime of the maker daemon process.

Both error paths are reachable by unauthenticated remote takers: `expect_phase` fires on any out-of-sequence protocol message (e.g. sending `GetOffer` twice, or any contract message before `SwapDetails`), and `check_swap_id` fires on any message carrying a mismatched swap id — the handlers in legacy_handlers.rs and taproot_handlers.rs call these on the pre-authentication message path. A remote peer that opens a connection (or many) and streams malformed/out-of-phase messages grows the long-running makerd process's RSS without bound; measured with a counting global allocator, 10,000 failing `expect_phase` calls leak ~1.9 MB and 10,000 failing `check_swap_id` calls leak ~1.7 MB, monotonically and never reclaimed. Over days/weeks of uptime this is a slow remote memory-exhaustion DoS against the maker service. Amplification is roughly 1:1 with attacker bandwidth, hence low severity.

The regression test installs a counting `#[global_allocator]` in its own test binary (tests/maker_expect_phase_leak.rs), drives both error paths in a loop, drops the returned errors, and asserts live heap bytes do not grow. It fails on HEAD (~1.7-1.9 MB growth per path) and passes once the errors stop leaking (e.g. `MakerError::General(String)` or static messages). No prior findings matched (searched: 'leak static str expect_phase memory', 'String leak DoS maker handler error').

## Proof of Concept

```diff
diff --git a/tests/maker_expect_phase_leak.rs b/tests/maker_expect_phase_leak.rs
new file mode 100644
index 0000000..b9249d5
--- /dev/null
+++ b/tests/maker_expect_phase_leak.rs
@@ -0,0 +1,79 @@
+//! Regression test: `ConnectionState::expect_phase` / `check_swap_id` build their
+//! error messages with `format!(...).leak()`, permanently leaking a heap `String`
+//! on every out-of-phase or wrong-swap-id message. These handlers are reachable
+//! by unauthenticated remote takers, so a peer can grow the maker daemon's memory
+//! without bound (remote memory-leak DoS).
+
+use std::alloc::{GlobalAlloc, Layout, System};
+use std::sync::atomic::{AtomicI64, Ordering};
+
+use coinswap::maker::handlers::{ConnectionState, SwapPhase};
+
+static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);
+
+struct CountingAllocator;
+
+unsafe impl GlobalAlloc for CountingAllocator {
+    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
+        LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::SeqCst);
+        System.alloc(layout)
+    }
+    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
+        LIVE_BYTES.fetch_sub(layout.size() as i64, Ordering::SeqCst);
+        System.dealloc(ptr, layout)
+    }
+}
+
+#[global_allocator]
+static ALLOC: CountingAllocator = CountingAllocator;
+
+#[test]
+fn expect_phase_error_path_does_not_leak_memory() {
+    // Fresh connection state: phase == AwaitingHello.
+    let state = ConnectionState::default();
+
+    // Warm up so one-time allocations settle before measuring.
+    for _ in 0..1_000 {
+        drop(state.expect_phase(&[SwapPhase::Completed]).unwrap_err());
+    }
+
+    let before = LIVE_BYTES.load(Ordering::SeqCst);
+    const ITERS: usize = 10_000;
+    for _ in 0..ITERS {
+        drop(state.expect_phase(&[SwapPhase::Completed]).unwrap_err());
+    }
+    let after = LIVE_BYTES.load(Ordering::SeqCst);
+
+    let growth = after - before;
+    assert!(
+        growth < 16_384,
+        "expect_phase leaked {} bytes across {} error paths (remote-triggerable memory leak)",
+        growth,
+        ITERS
+    );
+}
+
+#[test]
+fn check_swap_id_error_path_does_not_leak_memory() {
+    let mut state = ConnectionState::default();
+    state.swap_id = Some("expected-swap-id".to_string());
+
+    for _ in 0..1_000 {
+        drop(state.check_swap_id("attacker-swap-id").unwrap_err());
+    }
+
+    let before = LIVE_BYTES.load(Ordering::SeqCst);
+    const ITERS: usize = 10_000;
+    for _ in 0..ITERS {
+        drop(state.check_swap_id("attacker-swap-id").unwrap_err());
+    }
+    let after = LIVE_BYTES.load(Ordering::SeqCst);
+
+    let growth = after - before;
+    assert!(
+        growth < 16_384,
+        "check_swap_id leaked {} bytes across {} error paths (remote-triggerable memory leak)",
+        growth,
+        ITERS
+    );
+}

```
