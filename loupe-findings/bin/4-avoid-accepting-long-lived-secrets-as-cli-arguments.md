# Avoid accepting long-lived secrets as CLI arguments

- **Finding ID:** 4
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/makerd.rs
- **Lines:** 46-62
- **CWE:** CWE-214
- **Fingerprint:** 23a84e24c1abdc1b49b383be982e60adfc930d097427f323506b366265b45ba4

## Description

`makerd` defines the Bitcoin Core RPC credential (`--auth USER:PASSWORD`), Tor control password (`--tor-auth`), and wallet encryption password (`--password`) as normal command-line options. These values become part of the daemon's process arguments for the lifetime of the process. On typical multi-user hosts, sibling containers with process visibility, crash collectors, or diagnostic tooling can read argv and recover the credentials. The leaked Bitcoin RPC credential can be used to control the configured node RPC endpoint, the Tor control password can operate the maker's Tor controller, and the wallet password can decrypt the maker wallet wherever the data directory is accessible. This is distinct from persisting `tor_auth_password` to config: the exposure exists even when no config file is readable. I searched prior findings for makerd command-line password/auth secret leaks and `CWE-214` and found no MCP match. A fix should read these secrets from protected files, environment-specific secret stores, or interactive prompts instead of long-lived argv values.

## Proof of Concept

```diff
diff --git a/src/bin/makerd.rs b/src/bin/makerd.rs
--- a/src/bin/makerd.rs
+++ b/src/bin/makerd.rs
@@ -129,3 +129,23 @@ fn main() -> Result<(), MakerError> {
 
     Ok(())
 }
+
+#[cfg(test)]
+mod cli_security_tests {
+    use super::Cli;
+    use clap::CommandFactory;
+
+    #[test]
+    fn cli_does_not_accept_secrets_as_process_arguments() {
+        let command = Cli::command();
+        let secret_args: Vec<_> = command
+            .get_arguments()
+            .map(|arg| arg.get_id().as_str())
+            .filter(|id| matches!(*id, "auth" | "password" | "tor_auth"))
+            .collect();
+
+        assert!(
+            secret_args.is_empty(),
+            "makerd must not accept long-lived secrets via argv-visible CLI options: {secret_args:?}"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

