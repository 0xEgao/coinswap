# Unescaped tor_auth_password serialization allows config-file injection

- **Finding ID:** 43
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/taker/config.rs:78-87
- **Job:** 5
- **CWE:** CWE-74
- **Fingerprint:** 346eddd45e4863e94eabfd0d44367a07abe162e7aad85f069b1d5fbd86e10908

## Description

TakerConfig::write_to_file serializes tor_auth_password into the config file with plain string interpolation (`tor_auth_password = {}`), without TOML quoting or escaping. The corresponding loader (parse_toml in src/utill.rs:360) is a naive line-based `key = value` splitter. A password containing a newline therefore injects arbitrary config directives into config.toml: e.g. password "secret\ncontrol_port = 1234" is written across two lines, and on the next TakerConfig::new load the injected `control_port = 1234` line is honored, silently redirecting the Tor control port (privacy/security-relevant: the taker would authenticate to an attacker-chosen control endpoint). The write path is reachable with caller-supplied passwords: init_taker_config in src/taker/api.rs:662-674 copies TakerInitConfig.tor_auth_password (public API / CLI input) into the config and calls write_to_file. Additionally, passwords with leading/trailing whitespace or surrounding double quotes are silently mangled on reload (round-trip data-corruption), which can break Tor control authentication. The PoC regression test fails on HEAD (password truncated at the newline; injected control_port parsed) and passes once the value is properly quoted/escaped (with matching unescaping in the parser). No prior findings matched this bug (queried: tor_auth_password/config injection/TOML serialization, write_to_file unquoted password, taker config parse_toml control_port).

## Proof of Concept

```diff
--- a/src/taker/config.rs
+++ b/src/taker/config.rs
@@ -190,5 +190,22 @@
         let config = TakerConfig::new(Some(&config_path)).unwrap();
         remove_temp_config(&config_path);
         assert_eq!(config, TakerConfig::default());
     }
+
+    #[test]
+    fn test_password_roundtrip_no_config_injection() {
+        // A tor_auth_password containing a newline must not be able to inject
+        // extra config directives into the serialized config file, and the
+        // password must round-trip unchanged through write_to_file + new().
+        let cfg = TakerConfig {
+            tor_auth_password: "secret\ncontrol_port = 1234".to_string(),
+            ..TakerConfig::default()
+        };
+        let config_path = PathBuf::from("injection_taker_config.toml");
+        cfg.write_to_file(&config_path).unwrap();
+        let loaded = TakerConfig::new(Some(&config_path)).unwrap();
+        remove_temp_config(&config_path);
+        assert_eq!(loaded.tor_auth_password, cfg.tor_auth_password);
+        assert_eq!(loaded.control_port, 9051);
+    }
 }

```
