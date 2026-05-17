# Remove wallet and RPC secrets from taker argv

- **Finding ID:** 5
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/taker.rs
- **Lines:** 52-64
- **CWE:** CWE-522
- **Fingerprint:** 7805599157a8dc9d7c8a70143eb3a206c3b9e3e338cd73ac8ada61761a129ed0

## Description

The taker binary accepts both Bitcoin Core RPC credentials (`--USER:PASSWORD` / `-a`) and the wallet encryption passphrase (`--PASSWORD` / `-p`) directly as command-line arguments. On normal multi-user systems, argv is exposed through process metadata such as `ps`, `/proc/<pid>/cmdline`, shell history, terminal scrollback, and job logs. A local unprivileged observer can therefore recover the RPC password or wallet passphrase while a victim runs long-lived operations such as `coinswap`, `fetch-offers`, `backup`, or `recover`. The impact is credential disclosure and, depending on local file/RPC permissions, possible wallet decryption or Bitcoin Core RPC abuse. I searched prior findings for `taker password auth command line argv process list secret leak` and `taker USER PASSWORD cli`; both returned no matches. A fix should remove secret-bearing CLI arguments and use a prompt, protected config file, cookie auth, or environment/fd-based secret input that does not place secrets in argv.

## Proof of Concept

```diff
diff --git a/tests/integration/taker_cli.rs b/tests/integration/taker_cli.rs
index 70c2037..b7d2c9a 100644
--- a/tests/integration/taker_cli.rs
+++ b/tests/integration/taker_cli.rs
@@ -97,6 +97,22 @@ impl TakerCli {
     }
 }
 
+#[test]
+fn test_taker_cli_does_not_accept_secrets_in_argv() {
+    let output = Command::new(env!("CARGO_BIN_EXE_taker"))
+        .arg("--help")
+        .output()
+        .expect("Failed to execute taker --help");
+
+    assert!(output.status.success());
+    let help = String::from_utf8(output.stdout).expect("help output should be utf8");
+
+    assert!(
+        !help.contains("USER:PASSWORD") && !help.contains("PASSWORD"),
+        "the taker CLI must not accept RPC credentials or wallet passphrases as argv arguments"
+    );
+}
+
 #[test]
 fn test_taker_cli() {
     info!("Running Test: Taker CLI functionality and wallet operations");

```

## Suggested Fix

```diff
No suggested fix emitted.
```

