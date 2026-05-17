# Avoid persisting Tor control password in maker config

- **Finding ID:** 3
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/makerd.rs
- **Lines:** 110-125
- **CWE:** CWE-312
- **Fingerprint:** 62ac49d0342ecd5e8e80388b8caded6b2ee899368131140af3606dedbe033633

## Description

When `--tor-auth` is supplied, `makerd` copies the Tor control password into `config.tor_auth_password`. The same startup path then rewrites `config.toml` while discovering and saving maker/RPC ports, and the config writer serializes `tor_auth_password` in cleartext. This leaves the Tor control credential on disk after startup with permissions determined by the process umask and data-directory exposure. Any local user, backup process, or log/diagnostic collector that can read the maker data directory can recover the Tor control password and use it to control the maker's Tor instance, including onion-service and circuit operations. I searched prior findings for `makerd tor_auth_password config write_to_file cleartext CWE-312` and exact title-style terms and found no MCP match. A fix should avoid storing CLI-supplied Tor passwords in the persistent config or write only a protected reference using restrictive file permissions.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -303,6 +303,34 @@ required_confirms = {}
         Ok(())
     }
 }
+
+#[cfg(test)]
+mod config_security_tests {
+    use super::MakerServerConfig;
+
+    #[test]
+    fn write_to_file_does_not_persist_tor_auth_secret() {
+        let mut config = MakerServerConfig::default();
+        config.tor_auth_password = "super-secret-control-password".to_string();
+
+        let dir = std::env::temp_dir().join(format!(
+            "coinswap-maker-config-secret-test-{}",
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
+            !contents.contains("super-secret-control-password"),
+            "maker config must not persist the Tor control password in cleartext"
+        );
+    }
+}
 
 /// Thread pool for managing background threads.
 pub struct ThreadPool {

```

## Suggested Fix

```diff
No suggested fix emitted.
```

