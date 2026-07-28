# Restrict permissions on configs containing the Tor password

- **Finding ID:** 23
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/api.rs:308-310
- **Job:** 3
- **CWE:** CWE-732
- **Fingerprint:** a270469d0ea1227fce122bb89f30e8f67344cd1a3cc24b095565b9f466ca601e

## Description

`MakerServerConfig::write_to_file` persists `tor_auth_password` using `File::create` without setting restrictive permissions. `makerd` invokes this method after applying the CLI `--tor-auth` value and again whenever it selects ports. On a newly created file, the resulting mode is governed by the process umask (commonly 0644); on an existing file, `File::create` truncates while preserving whatever group/world-readable mode it already has. The parent directory is also created with ordinary defaults. A different local account able to traverse the data directory can therefore read the Tor control credential and interfere with the maker's onion-service control plane or privacy. The deterministic PoC pre-creates a config at mode 0644, rewrites it with a recognizable Tor secret, and asserts no group/other permission bits remain. HEAD preserves 0644 and fails. A fix should create new files with mode 0600 and explicitly tighten existing files before writing. Prior search `tor_auth_password config permissions` returned no findings.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -1593,5 +1593,46 @@
             &self.config.tor_auth_password,
             tor_key_bytes,
         )
     }
 }
+
+#[cfg(all(test, unix))]
+mod tests {
+    use super::MakerServerConfig;
+    use std::{
+        fs,
+        os::unix::fs::PermissionsExt,
+        time::{SystemTime, UNIX_EPOCH},
+    };
+
+    #[test]
+    fn config_file_permissions_protect_tor_password() {
+        let unique = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_nanos();
+        let dir = std::env::temp_dir().join(format!("maker-config-permissions-{unique}"));
+        let path = dir.join("config.toml");
+        fs::create_dir_all(&dir).unwrap();
+
+        // Model an existing config created with ordinary group/world-readable
+        // permissions. Secure rewriting must tighten it before storing a secret.
+        fs::File::create(&path).unwrap();
+        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
+
+        let mut config = MakerServerConfig::default();
+        config.tor_auth_password = "local-control-secret".to_string();
+        config.write_to_file(&path).unwrap();
+
+        let contents = fs::read_to_string(&path).unwrap();
+        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
+        fs::remove_dir_all(&dir).unwrap();
+
+        assert!(contents.contains("local-control-secret"));
+        assert_eq!(
+            mode & 0o077,
+            0,
+            "config containing the Tor control password is readable by group or other users"
+        );
+    }
+}

```
