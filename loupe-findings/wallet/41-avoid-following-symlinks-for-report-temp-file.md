# Avoid following symlinks for report temp file

- **Finding ID:** 41
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/report.rs
- **Lines:** 611-618
- **CWE:** CWE-61
- **Fingerprint:** cb0640a38c94ea5c1fb32b09f6996f42cb8573c8616920199c0633a5ca46883a

## Description

`write_to_file` writes reports through a predictable temporary path, `swap_reports.partial`, using `std::fs::File::create`. On Unix this follows an existing symlink. If an attacker can pre-create entries in the coinswap root used for reports, they can point `swap_reports.partial` at any file writable by the wallet process. The next report save truncates and writes JSON to that target before the symlink is renamed into place as `swap_reports.json`. In deployments where the wallet process runs with higher privileges than the directory writer, or where the report root is shared/mis-permissioned, this becomes an arbitrary file clobber via report generation. A safer implementation should create the temporary file with symlink-resistant semantics, use a randomized temp file created with `create_new`, or otherwise reject pre-existing links before writing. I searched prior findings for `report swap_reports symlink partial File create rename` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/report.rs b/src/wallet/report.rs
--- a/src/wallet/report.rs
+++ b/src/wallet/report.rs
@@ -620,3 +620,63 @@ where
     log::info!("Saved swap report to: {}", file_path.display());
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoind::tempfile::tempdir;
+    use std::fs;
+
+    fn minimal_taker_report() -> TakerReport {
+        TakerReport {
+            swap_id: "swap-id".to_string(),
+            status: SwapStatus::Success,
+            network: "regtest".to_string(),
+            swap_duration_seconds: 0.0,
+            start_timestamp: 0,
+            end_timestamp: 0,
+            error_message: None,
+            outgoing_amount: 0,
+            incoming_amount: 0,
+            fee_paid: 0,
+            mining_fee: 0,
+            fee_percentage: 0.0,
+            total_maker_fees: 0,
+            outgoing_contract_txid: None,
+            incoming_contract_txid: None,
+            funding_txids: Vec::new(),
+            makers_count: 0,
+            maker_addresses: Vec::new(),
+            maker_fee_info: Vec::new(),
+            input_utxos: Vec::new(),
+            output_change_amounts: Vec::new(),
+            output_swap_amounts: Vec::new(),
+            output_change_utxos: Vec::new(),
+            output_swap_utxos: Vec::new(),
+        }
+    }
+
+    #[cfg(unix)]
+    #[test]
+    fn save_does_not_follow_preexisting_partial_symlink() {
+        use std::os::unix::fs::symlink;
+
+        let temp = tempdir().unwrap();
+        let root = temp.path().join("coinswap-root");
+        let data_dir = root.join("taker");
+        fs::create_dir_all(&data_dir).unwrap();
+
+        let victim_path = temp.path().join("victim.txt");
+        let original = "contents that must not be replaced";
+        fs::write(&victim_path, original).unwrap();
+        symlink(&victim_path, root.join("swap_reports.partial")).unwrap();
+
+        let _ = minimal_taker_report().save(&data_dir);
+
+        let victim_after = fs::read_to_string(&victim_path).unwrap();
+        assert_eq!(
+            victim_after, original,
+            "report writes must not follow attacker-controlled partial-file symlinks"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

