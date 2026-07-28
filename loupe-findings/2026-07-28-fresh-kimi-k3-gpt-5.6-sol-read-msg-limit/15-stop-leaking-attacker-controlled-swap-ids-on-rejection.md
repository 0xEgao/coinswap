# Stop leaking attacker-controlled swap IDs on rejection

- **Finding ID:** 15
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/handlers.rs:157-182
- **Job:** 3
- **CWE:** CWE-401
- **Fingerprint:** b01cf34b8b6039f58d07937f39425d489da8bcea5b24ed77c0cdf9b0cdd5f908

## Description

`ConnectionState::check_swap_id` builds an error containing the peer-supplied ID and converts the `String` into `&'static str` with `String::leak`. Dropping the resulting `MakerError` can therefore never release the allocation. `expect_phase` uses the same pattern for every phase violation. The protocol accepts frames up to 10 MiB (`src/maker/server.rs`), and message IDs are deserialized as unbounded `String`s within that frame. After negotiating valid `SwapDetails`, a peer can send a protocol message carrying a large mismatching ID; the phase check succeeds, `check_swap_id` permanently retains a copy of the ID, and the server closes only that connection. Repeating the sequence grows the long-lived maker process until memory pressure terminates or stalls it. The PoC installs a counting allocator in a dedicated test binary, supplies a 1 MiB mismatching ID, drops the error, and observes that roughly the full allocation remains live; it fails on HEAD and passes when dynamic error text is owned and freed (or when rejection uses bounded static text). Prior finding #3 was reviewed: it covers duplicate-ID state overwrite, not this permanent allocation leak, though that separate bug can make repetition easier. Searches for `format leak MakerError General`, `expect_phase`, and `check_swap_id` found no matching prior report.

## Proof of Concept

```diff
diff --git a/tests/handlers_error_allocation.rs b/tests/handlers_error_allocation.rs
new file mode 100644
--- /dev/null
+++ b/tests/handlers_error_allocation.rs
@@ -0,0 +1,45 @@
+use std::{
+    alloc::{GlobalAlloc, Layout, System},
+    sync::atomic::{AtomicUsize, Ordering},
+};
+
+use coinswap::maker::ConnectionState;
+
+struct CountingAllocator;
+static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
+
+unsafe impl GlobalAlloc for CountingAllocator {
+    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
+        let ptr = System.alloc(layout);
+        if !ptr.is_null() {
+            LIVE_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
+        }
+        ptr
+    }
+
+    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
+        LIVE_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
+        System.dealloc(ptr, layout);
+    }
+}
+
+#[global_allocator]
+static ALLOCATOR: CountingAllocator = CountingAllocator;
+
+#[test]
+fn rejected_swap_id_does_not_retain_attacker_controlled_text() {
+    let mut state = ConnectionState::default();
+    state.swap_id = Some("expected".to_string());
+    let attacker_id = "x".repeat(1024 * 1024);
+    let before = LIVE_BYTES.load(Ordering::SeqCst);
+
+    let error = state.check_swap_id(&attacker_id).unwrap_err();
+    drop(error);
+
+    let retained = LIVE_BYTES.load(Ordering::SeqCst).saturating_sub(before);
+    assert!(
+        retained < 128 * 1024,
+        "rejecting one mismatched swap id permanently retained {} bytes",
+        retained
+    );
+}

```
