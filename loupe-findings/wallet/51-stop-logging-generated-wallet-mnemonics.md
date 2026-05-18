# Stop logging generated wallet mnemonics

- **Finding ID:** 51
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/wallet/api.rs
- **Lines:** 280-282
- **CWE:** CWE-532
- **Fingerprint:** ad9740e36f026979fdebc0b01c9f146da9c70d752138bbf013b30fe3e3be902b

## Description

Wallet::init generates a fresh BIP-39 mnemonic for the wallet master key and immediately emits the mnemonic words through log::info!. Anyone with access to application logs, process stdout, journald, Docker logs, or centralized log collection receives the full seed phrase and can reconstruct the wallet master key offline, bypassing any wallet-file encryption because the secret is leaked before storage. This is exploitable during normal wallet creation and affects both encrypted and unencrypted wallet files. I searched prior findings for the Wallet::init mnemonic logging issue and found no duplicate. The fix should remove the mnemonic value from logs entirely and use an out-of-band backup display/storage path that is not written to operational logs.

## Proof of Concept

```diff
diff --git a/src/wallet/api.rs b/src/wallet/api.rs
--- a/src/wallet/api.rs
+++ b/src/wallet/api.rs
@@ -2728,3 +2728,18 @@ pub fn wait_for_tx_confirmation(
         }
     }
 }
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn wallet_init_does_not_log_generated_mnemonic() {
+        let source = include_str!("api.rs");
+
+        assert!(
+            !source.contains("Backup the Wallet Mnemonics")
+                && !source.contains("mnemonic.words()")
+                && !source.contains("{words:?}"),
+            "wallet initialization must not emit seed mnemonics through logs"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

