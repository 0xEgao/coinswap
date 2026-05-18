# Reject userinfo in Bitcoin REST RPC URLs

- **Finding ID:** 66
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/rest_backend.rs
- **Lines:** 129-151
- **CWE:** CWE-522
- **Fingerprint:** 31f6caabd5ebe0b26e78148ea6bdba15e0012f9ce55f75a2702d9d5901a8466c

## Description

`BitcoinRest::new` normalizes `RPCConfig::url` with string slicing and accepts authorities that contain URL userinfo (`user@host`). For a value such as `127.0.0.1:18443@attacker.invalid/wallet/victim`, `normalize_rest_base_url` returns `http://127.0.0.1:18443@attacker.invalid`; subsequent calls build requests to the attacker-controlled authority while `build_auth_header` has already prepared the real Bitcoin RPC Basic credential from `RPCConfig::auth`. If an attacker can influence the RPC URL through configuration, CLI wrapping, or a higher-level caller, the next REST call exfiltrates the Bitcoin Core RPC username/password or cookie-derived credential to the attacker. I did not rely on out-of-tree URL parsing internals; the issue is that this code performs no local rejection of userinfo before attaching credentials. I searched prior findings for `rest_backend normalize_rest_base_url Authorization Basic RPCConfig url credentials leak` and found no duplicate. A fix should parse the URL with a structured URL parser and reject any username/password/userinfo component before constructing authenticated requests.

## Proof of Concept

```diff
diff --git a/src/watch_tower/rest_backend.rs b/src/watch_tower/rest_backend.rs
--- a/src/watch_tower/rest_backend.rs
+++ b/src/watch_tower/rest_backend.rs
@@ -165,3 +165,24 @@ fn build_auth_header(auth: &Auth) -> Result<Option<String>, WatcherError> {
         }
     }
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn rejects_rpc_urls_with_userinfo_before_building_auth_header() {
+        let config = RPCConfig {
+            url: "127.0.0.1:18443@attacker.invalid/wallet/victim".to_string(),
+            auth: Auth::UserPass("rpcuser".to_string(), "rpcpass".to_string()),
+            wallet_name: "victim".to_string(),
+        };
+
+        let backend = BitcoinRest::new(config);
+
+        assert!(
+            backend.is_err(),
+            "REST backend must reject URLs containing userinfo before it constructs an Authorization header"
+        );
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

