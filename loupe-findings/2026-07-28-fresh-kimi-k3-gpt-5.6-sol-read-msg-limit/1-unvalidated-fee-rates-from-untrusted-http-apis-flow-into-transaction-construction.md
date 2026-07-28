# Unvalidated fee rates from untrusted HTTP APIs flow into transaction construction

- **Finding ID:** 1
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/fee_estimation.rs:119-206
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** c0ab70e60e9eb94daea24521407887cc2c612b3529cfc69bb18d0c768e73a22c

## Description

fetch_mempool_fees() and fetch_esplora_fees() deserialize fee rates (f64) from two third-party HTTP APIs (mempool.space, blockstream.info) and insert them into the fee map with no sanity validation whatsoever; estimate_fees() then averages them and get_fee_rate()/get_high_priority_rate() etc. return the result to library consumers. Downstream wallet code converts the rate directly into a transaction fee, e.g. src/wallet/api.rs:979 `Amount::from_sat((vsize as f64 * fee_rate) as u64)`. A compromised, malfunctioning, or (via DNS/BGP-level attack despite TLS on a compromised CA/endpoint) malicious API can return: (a) negative rates, which the saturating float-to-int cast turns into a 0-sat fee — an unconfirmable transaction that can strand swap/recovery funds until timelock expiry; (b) absurdly inflated rates (e.g. 1e6 sat/vB), turning into catastrophic fee overpayment burned to miners whenever the input value covers it; (c) zero rates with the same stuck-transaction effect. JSON cannot carry NaN/Inf, but negative/zero/huge finite values parse fine. The regression test mirrors the exact deserialization + insert mapping of fetch_mempool_fees and asserts the resulting rate is finite and within sane bounds (0 < r <= 100_000 sat/vB); it fails on HEAD because -1000, 0, and 1e12 are all accepted unchecked. Fix: validate each fetched rate (finite, > 0, below a sane ceiling) before inserting/averaging, or reject at deserialization. Uncertainty note: I could not inspect minreq/bitcoincore-rpc sources (out of tree); the bug stands on this file alone since no bound check exists anywhere in the module. Prior-findings search (fee estimation negative fee rate validation; mempool esplora untrusted fee rate overpayment) returned no matches.

## Proof of Concept

```diff
--- a/src/fee_estimation.rs
+++ b/src/fee_estimation.rs
@@ -221,3 +221,38 @@
     #[serde(flatten)]
     fees: HashMap<String, f64>,
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    // Mirrors the mapping performed by `fetch_mempool_fees`.
+    fn mempool_map(response: MempoolFeeResponse) -> HashMap<BlockTarget, f64> {
+        let mut fees = HashMap::new();
+        fees.insert(BlockTarget::Fastest, response.fastest_fee);
+        fees.insert(BlockTarget::Standard, response.hour_fee);
+        fees.insert(BlockTarget::Economy, response.economy_fee);
+        fees
+    }
+
+    // Fee rates are supplied by untrusted third-party HTTP APIs and are fed
+    // straight into transaction construction
+    // (`Amount::from_sat((vsize as f64 * fee_rate) as u64)` in wallet code).
+    // Negative, zero, non-finite or absurd rates must never be accepted.
+    #[test]
+    fn rejects_out_of_range_remote_fee_rates() {
+        for bad in [-1000.0_f64, 0.0, 1e12] {
+            let json = format!(r#"{{"fastestFee":{bad},"hourFee":10.0,"economyFee":5.0}}"#);
+            let fees = match serde_json::from_str::<MempoolFeeResponse>(&json) {
+                // Rejection at deserialization time is an acceptable fix.
+                Err(_) => continue,
+                Ok(resp) => mempool_map(resp),
+            };
+            let fastest = fees[&BlockTarget::Fastest];
+            assert!(
+                fastest.is_finite() && fastest > 0.0 && fastest <= 100_000.0,
+                "out-of-range fee rate {fastest} sat/vB accepted from remote API response"
+            );
+        }
+    }
+}

```
