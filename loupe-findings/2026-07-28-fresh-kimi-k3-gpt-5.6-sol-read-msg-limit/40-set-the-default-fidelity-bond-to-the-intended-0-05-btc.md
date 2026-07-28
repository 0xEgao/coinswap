# Set the default fidelity bond to the intended 0.05 BTC

- **Finding ID:** 40
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:149
- **Job:** 3
- **CWE:** CWE-1188
- **Fingerprint:** 78d56e96d91e60f39fea45754cd7bb31137ad72e202a3d3319f630d50b7bf663

## Description

`MakerServerConfig::default` sets `fidelity_amount` to 10,000 satoshis while the same line documents a 0.05 BTC default, which is 5,000,000 satoshis. This is not just a stale comment: the in-tree fidelity integration test asserts a 5,000,000-satoshi bond and the integration maker configuration explicitly uses that value. `MakerServerConfig::new` writes this default into a newly created production config, and `setup_fidelity_bond` locks exactly `self.config.fidelity_amount`, so an operator accepting the generated configuration creates a bond 500 times smaller than the intended economic commitment. Fidelity bonds are the protocol's advertised Sybil-resistance signal; weakening the default by this factor makes default maker identities substantially cheaper to create and churn, even though the proof remains cryptographically valid. The regression test directly checks the generated default and fails on HEAD with left=10,000 and right=5,000,000. A fix should use the intended satoshi value (or otherwise make the documented/tested policy consistent) before auto-writing first-run configuration. Searches for `MakerServerConfig default fidelity_amount 10000 0.05 BTC` and `fidelity bond Sybil insecure default amount` returned no prior finding.

## Proof of Concept

```diff
diff --git a/tests/maker_default_fidelity.rs b/tests/maker_default_fidelity.rs
new file mode 100644
--- /dev/null
+++ b/tests/maker_default_fidelity.rs
@@ -0,0 +1,10 @@
+use coinswap::maker::MakerServerConfig;
+
+#[test]
+fn default_fidelity_bond_matches_the_documented_sybil_cost() {
+    assert_eq!(
+        MakerServerConfig::default().fidelity_amount,
+        5_000_000,
+        "the documented 0.05 BTC default is 5,000,000 satoshis"
+    );
+}

```
