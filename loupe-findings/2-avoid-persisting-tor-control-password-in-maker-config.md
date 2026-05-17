# Avoid persisting Tor control password in maker config

- **Finding ID:** 2
- **Severity:** medium
- **State:** pending
- **Scanner:** llm-code-review
- **File:** src/bin/makerd.rs
- **Lines:** 110-125
- **CWE:** CWE-312
- **Fingerprint:** 62ac49d0342ecd5e8e80388b8caded6b2ee899368131140af3606dedbe033633

## Description

When `--tor-auth` is provided, `makerd` copies the Tor control password into `config.tor_auth_password` and then rewrites `config.toml` during port discovery. The config writer persists that field in cleartext using normal `File::create` semantics. On typical systems this produces a user-readable or world-readable config depending on umask, and the password remains on disk after startup. Any local user or backup/log collection process that can read the maker data directory can recover the Tor control password and connect to the Tor control port, allowing control over the maker's onion service and traffic routing. I searched prior findings for `tor_auth_password`, config secret leakage, and `write_to_file` and found no duplicate. A fix should avoid persisting CLI-supplied Tor passwords, or store only a protected reference in a file created with restrictive permissions.

## Proof of Concept

```diff
diff --git a/src/maker/api.rs b/src/maker/api.rs
index dc113ce..77cc399 100644
--- a/src/maker/api.rs
+++ b/src/maker/api.rs
@@ -300,11 +300,39 @@ required_confirms = {}
         std::fs::create_dir_all(path.parent().expect("Config path should not be root"))?;
         let mut file = std::fs::File::create(path)?;
         file.write_all(toml_data.as_bytes())?;
         file.flush()?;
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
     threads: Mutex<Vec<JoinHandle<()>>>,
     port: u16,

```

## Suggested Fix

```diff
No suggested fix emitted.
```

