# Reject negative remote fee estimates

- **Finding ID:** 7
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/fee_estimation.rs
- **Lines:** 123-125
- **CWE:** CWE-20
- **Fingerprint:** b54dd4cdd4568edec9c5b4004061be9ed281a59cbd01ae5fcaada19a98407a84

## Description

`fetch_mempool_fees` and `fetch_esplora_fees` deserialize public fee-estimation responses directly into `f64` values and insert them into the returned fee map without checking that each rate is finite and non-negative. A compromised endpoint, DNS/TLS interception in the caller's environment, or any future test/mock caller of these public functions can supply a negative fee such as `-1.0`; `get_fee_rate` will then expose that value as a valid sat/vB estimate. This is security-relevant because the module is a public fee oracle for wallet spending code, and downstream fee arithmetic often casts or subtracts fee rates while assuming they are sane. In this worktree the estimator is not currently called by the binaries, so impact is limited to library users or future wiring, but the vulnerable API boundary is in this file. I searched prior findings for `fee_estimation negative f64 fee rate public fee API` and `MempoolFeeResponse EsploraFeeResponse finite nonnegative fee` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/fee_estimation.rs b/src/fee_estimation.rs
index d3a5a90..fca88c1 100644
--- a/src/fee_estimation.rs
+++ b/src/fee_estimation.rs
@@ -217,3 +217,30 @@ struct EsploraFeeResponse {
     #[serde(flatten)]
     fees: HashMap<String, f64>,
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn mempool_fee_response_rejects_negative_rates() {
+        let parsed = serde_json::from_str::<MempoolFeeResponse>(
+            r#"{"fastestFee":-1.0,"hourFee":2.0,"economyFee":3.0}"#,
+        );
+
+        assert!(
+            parsed.is_err(),
+            "negative fee rates from mempool.space must not be accepted"
+        );
+    }
+
+    #[test]
+    fn esplora_fee_response_rejects_negative_rates() {
+        let parsed = serde_json::from_str::<EsploraFeeResponse>(
+            r#"{"1":2.0,"6":-1.0,"24":3.0}"#,
+        );
+
+        assert!(
+            parsed.is_err(),
+            "negative fee rates from Esplora must not be accepted"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

