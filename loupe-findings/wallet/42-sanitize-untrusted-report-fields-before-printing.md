# Sanitize untrusted report fields before printing

- **Finding ID:** 42
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/report.rs
- **Lines:** 219-220
- **CWE:** CWE-117
- **Fingerprint:** 60b0b71fed66d6be84eb9c092207f355d93d0578eb05ffbb743ae4a7d8a0c006

## Description

`TakerReport::print` writes maker addresses directly to the terminal. Those addresses are peer-derived data: the taker report builds them from selected makers, and the in-tree watcher/offer path accepts `.onion` strings without stripping terminal control bytes. A malicious maker can therefore cause report generation to emit raw ANSI/OSC sequences. In terminals that honor these sequences, this can spoof report contents, hide warnings, or trigger clipboard-setting escape sequences when an operator views the report after a swap. This is not a memory-safety issue and requires a terminal that interprets the sequence, so I rate it low, but wallet reports should neutralize control characters in all untrusted fields before `println!` while preserving the code's own trusted formatting escapes. I searched prior findings for `report terminal escape maker_address print ansi` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/wallet/report.rs b/src/wallet/report.rs
--- a/src/wallet/report.rs
+++ b/src/wallet/report.rs
@@ -620,3 +620,65 @@ where
     log::info!("Saved swap report to: {}", file_path.display());
     Ok(())
 }
+
+#[cfg(test)]
+mod terminal_escape_tests {
+    use super::*;
+    use std::process::Command;
+
+    const MALICIOUS_OSC: &str = "\x1b]52;c;YXR0YWNrZXI=\x07";
+
+    fn report_with_maker_address(addr: &str) -> TakerReport {
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
+            makers_count: 1,
+            maker_addresses: vec![addr.to_string()],
+            maker_fee_info: Vec::new(),
+            input_utxos: Vec::new(),
+            output_change_amounts: Vec::new(),
+            output_swap_amounts: Vec::new(),
+            output_change_utxos: Vec::new(),
+            output_swap_utxos: Vec::new(),
+        }
+    }
+
+    #[test]
+    fn print_report_child_emits_untrusted_fields() {
+        if std::env::var_os("COINSWAP_PRINT_MALICIOUS_REPORT").is_none() {
+            return;
+        }
+        report_with_maker_address(MALICIOUS_OSC).print();
+    }
+
+    #[test]
+    fn print_sanitizes_untrusted_maker_addresses() {
+        let output = Command::new(std::env::current_exe().unwrap())
+            .env("COINSWAP_PRINT_MALICIOUS_REPORT", "1")
+            .arg("print_report_child_emits_untrusted_fields")
+            .arg("--nocapture")
+            .output()
+            .unwrap();
+        assert!(output.status.success());
+
+        let stdout = String::from_utf8_lossy(&output.stdout);
+        assert!(
+            !stdout.contains(MALICIOUS_OSC),
+            "untrusted report fields must not emit raw terminal control sequences"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

