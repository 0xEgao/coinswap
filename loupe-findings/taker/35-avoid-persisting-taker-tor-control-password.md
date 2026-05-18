# Avoid persisting taker Tor control password

- **Finding ID:** 35
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/config.rs
- **Lines:** 85-90
- **CWE:** CWE-312
- **Fingerprint:** d7b59e20c1c73d12ea9fc78a8bd4054e7955ba2caba11233cbae586c0fc39882

## Description

`TakerConfig::write_to_file` serializes `tor_auth_password` directly into `config.toml` and opens the file with ordinary `File::create` semantics. `Taker::init_taker_config` copies any CLI-supplied Tor control password into this struct and calls this writer on startup, so a long-lived Tor control secret is left in cleartext under the taker data directory. On a multi-user host, permissive umask, backup collection, or accidental data-directory exposure lets another local process recover the password and authenticate to the Tor control port. Control-port access can alter Tor circuits or onion-service state used by the taker. I searched prior findings for `taker tor_auth_password write_to_file config plaintext secret leak` and found no duplicate; I also considered #4 and #27, which cover argv exposure and SOCKS misuse rather than this on-disk taker config persistence. Prior maker-side persistence is distinct because this vulnerable sink is the taker config writer in this file.

## Proof of Concept

```diff
diff --git a/src/taker/config.rs b/src/taker/config.rs
--- a/src/taker/config.rs
+++ b/src/taker/config.rs
@@ -136,3 +136,28 @@ mod tests {
+    #[test]
+    fn test_write_to_file_does_not_persist_tor_auth_secret() {
+        let config = TakerConfig {
+            tor_auth_password: "super-secret-tor-control-password".to_string(),
+            ..TakerConfig::default()
+        };
+
+        let dir = std::env::temp_dir().join(format!(
+            "coinswap-taker-config-secret-test-{}",
+            std::process::id()
+        ));
+        let path = dir.join("config.toml");
+
+        let _ = std::fs::remove_dir_all(&dir);
+        config.write_to_file(&path).unwrap();
+
+        let contents = std::fs::read_to_string(&path).unwrap();
+        let _ = std::fs::remove_dir_all(&dir);
+
+        assert!(
+            !contents.contains("super-secret-tor-control-password"),
+            "taker config must not persist the Tor control password in cleartext"
+        );
+    }
+
     #[test]
     fn test_missing_fields() {
         let contents = r#"

```

## Suggested Fix

```diff
No suggested fix emitted.
```

