# Public fee requests can block fee estimation indefinitely

- **Finding ID:** 11
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/fee_estimation.rs:120-121
- **Job:** 3
- **CWE:** CWE-400
- **Fingerprint:** 3fd770761938bcab305bd3c95deb0f32140648c39291e28b63bc886e8f6c1056

## Description

`get_fee_rate()` calls `estimate_fees()`, which spawns both public HTTP fetches and then joins every scoped worker before considering any successful result. The mempool.space request at lines 120-121 and the equivalent Blockstream request at lines 167-168 have no explicit deadline. If either fixed third-party endpoint accepts a connection but delays or trickles its response indefinitely, its worker never finishes and the scope cannot return; successful Bitcoin Core or other HTTP estimates therefore provide no fallback. Repeated concurrent calls can additionally retain one OS thread per stalled request. This makes the public fee-estimation API remotely availability-dependent on every queried oracle.

The regression test checks that both request call sites set an explicit timeout; it fails on HEAD because neither does. A fix should place a finite request deadline on each worker (and ideally bound response size), allowing its error to be ignored by the existing fallback logic.

I reviewed prior finding #1 and ruled it out as a duplicate: #1 concerns unchecked fee values and fund safety, while this report concerns transport liveness. Uncertainty: `minreq` 2.12.0 is pinned but its source is outside the permitted worktree. If `send()` already guarantees a finite default total/body deadline, this should be dismissed or downgraded; no such guarantee is visible in the reviewed code.

## Proof of Concept

```diff
--- a/src/fee_estimation.rs
+++ b/src/fee_estimation.rs
@@ -221,3 +221,30 @@
     #[serde(flatten)]
     fees: HashMap<String, f64>,
 }
+
+#[cfg(test)]
+mod tests {
+    #[test]
+    fn remote_fee_requests_set_explicit_timeouts() {
+        let source = include_str!("fee_estimation.rs");
+
+        let mempool_start = source
+            .find("pub fn fetch_mempool_fees")
+            .expect("mempool fetch function");
+        let smart_fee_start = source
+            .find("fn estimate_smart_fee")
+            .expect("smart-fee function");
+        let mempool_fetch = &source[mempool_start..smart_fee_start];
+        assert!(
+            mempool_fetch.contains(".with_timeout("),
+            "mempool.space request has no explicit timeout"
+        );
+
+        let esplora_start = source
+            .find("pub fn fetch_esplora_fees")
+            .expect("esplora fetch function");
+        let response_types_start = source
+            .find("#[derive(Debug, Deserialize)]")
+            .expect("response types");
+        let esplora_fetch = &source[esplora_start..response_types_start];
+        assert!(
+            esplora_fetch.contains(".with_timeout("),
+            "blockstream request has no explicit timeout"
+        );
+    }
+}

```
