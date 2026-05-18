# Create swap reports with private permissions

- **Finding ID:** 43
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/report.rs
- **Lines:** 614-618
- **CWE:** CWE-732
- **Fingerprint:** 72cf4f2fcdfb126bf489662a2795662e4c6ec1f1b417c4663be3a4805776933b

## Description

`write_to_file` creates `swap_reports.json` through `File::create` on a temporary path and then renames it into place. `File::create` uses the process umask and does not force private permissions. With a permissive or typical umask, the resulting report can be group/world-readable. The report contains wallet transaction metadata including swap amounts, fee data, UTXO amounts/addresses, maker route information, and contract/funding txids, so a local user who can traverse the report directory can learn private wallet activity. This is a local information disclosure rather than remote compromise, so I rate it low. The report writer should create the file with mode `0600` (and consider private directory permissions) independent of the ambient umask. I searched prior findings for `swap_reports permissions world readable report file privacy umask` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/report.rs b/src/wallet/report.rs
--- a/src/wallet/report.rs
+++ b/src/wallet/report.rs
@@ -620,3 +620,66 @@ where
     log::info!("Saved swap report to: {}", file_path.display());
     Ok(())
 }
+
+#[cfg(test)]
+#[cfg(unix)]
+mod permission_tests {
+    use super::*;
+    use bitcoind::tempfile::tempdir;
+    use std::os::unix::fs::PermissionsExt;
+
+    unsafe extern "C" {
+        fn umask(mask: u32) -> u32;
+    }
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
+            outgoing_amount: 42,
+            incoming_amount: 41,
+            fee_paid: 1,
+            mining_fee: 0,
+            fee_percentage: 0.0,
+            total_maker_fees: 0,
+            outgoing_contract_txid: Some("outgoing".to_string()),
+            incoming_contract_txid: Some("incoming".to_string()),
+            funding_txids: Vec::new(),
+            makers_count: 0,
+            maker_addresses: Vec::new(),
+            maker_fee_info: Vec::new(),
+            input_utxos: vec![42],
+            output_change_amounts: Vec::new(),
+            output_swap_amounts: Vec::new(),
+            output_change_utxos: Vec::new(),
+            output_swap_utxos: Vec::new(),
+        }
+    }
+
+    #[test]
+    fn report_file_is_not_created_group_or_world_readable() {
+        let temp = tempdir().unwrap();
+        let data_dir = temp.path().join("coinswap-root").join("taker");
+        std::fs::create_dir_all(&data_dir).unwrap();
+
+        let old_umask = unsafe { umask(0) };
+        let save_result = minimal_taker_report().save(&data_dir);
+        unsafe { umask(old_umask) };
+        save_result.unwrap();
+
+        let mode = std::fs::metadata(temp.path().join("coinswap-root/swap_reports.json"))
+            .unwrap()
+            .permissions()
+            .mode();
+        assert_eq!(
+            mode & 0o077,
+            0,
+            "swap reports contain wallet metadata and must not be group/world accessible"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

