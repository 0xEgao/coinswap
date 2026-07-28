# Reject negative and non-finite maker fee percentages

- **Finding ID:** 41
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:219-226
- **Job:** 3
- **CWE:** CWE-20
- **Fingerprint:** 4eb7d1b3dbbfbdcf88430406f144dd052153f7672da74cd2862e8cfd93966bef

## Description

`MakerServerConfig::new` accepts any value that parses as `f64` for both fee percentages, without requiring the values to be finite and non-negative. `calculate_swap_fee` later sums those values in floating point and casts the rounded result to `u64`. With `base_fee = 0`, `amount_relative_fee_pct = -1`, and a zero time fee, every positive swap produces a negative total that the float-to-integer cast saturates to zero. Negative values can also partially cancel the base or time fee; non-finite values can collapse the calculation to zero or an unusable extreme. Thus a syntactically accepted first-party configuration can silently waive the maker's advertised compensation rather than failing startup, creating a direct fee/fund-accounting safety issue. The regression test writes a minimal config containing the negative percentage and confirms HEAD returns `Ok`; a fixed loader must reject it. This is conservatively rated low because modifying the maker's local configuration already requires operator/deployment access, but validation is still necessary to prevent silent financial misconfiguration. Prior #36 and #18 concern taker-controlled duration fields bypassing otherwise valid fee policy; they do not cover invalid local percentage values. A search for `calculate_swap_fee negative NaN percentage config` returned no prior finding.

## Proof of Concept

```diff
diff --git a/tests/maker_fee_config_validation.rs b/tests/maker_fee_config_validation.rs
new file mode 100644
--- /dev/null
+++ b/tests/maker_fee_config_validation.rs
@@ -0,0 +1,17 @@
+use coinswap::maker::MakerServerConfig;
+
+#[test]
+fn maker_rejects_negative_fee_percentages() {
+    let dir = bitcoind::tempfile::tempdir().unwrap();
+    let config_path = dir.path().join("config.toml");
+    std::fs::write(
+        &config_path,
+        "base_fee = 0\namount_relative_fee_pct = -1\ntime_relative_fee_pct = 0\n",
+    )
+    .unwrap();
+
+    assert!(
+        MakerServerConfig::new(Some(&config_path)).is_err(),
+        "negative percentages can make the configured service fee saturate to zero"
+    );
+}

```
