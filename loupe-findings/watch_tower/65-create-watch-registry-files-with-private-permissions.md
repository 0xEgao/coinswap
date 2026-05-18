# Create watch registry files with private permissions

- **Finding ID:** 65
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/registry_storage.rs
- **Lines:** 84-86
- **CWE:** CWE-732
- **Fingerprint:** d1ca7b96b97b48a6b3cde12a8f38567e33fed738e3bd68819f1ecb97d6716003

## Description

`FileRegistry::load` initializes a missing registry with `std::fs::write`, and `flush` later uses the same API. On Unix this creates files with the process umask rather than an explicit private mode; with the common `022` umask the registry is `0644`. The registry stores watched outpoints and full spending transactions, so another local user on the same host can read the maker/taker watch history and correlate coinswap activity. This does not require wallet credentials, only local account access to a default-readable data directory. The fix should create new registry files with owner-only permissions (for example `OpenOptionsExt::mode(0o600)`) and tighten permissions on existing files before writing. I searched prior findings for `registry_storage file permissions world readable watch outpoints privacy leak` and found no duplicate. I considered prior finding #64 for Nostr cursor poisoning, but that is a separate bug in `nostr_discovery.rs`.

## Proof of Concept

```diff
diff --git a/src/watch_tower/registry_storage.rs b/src/watch_tower/registry_storage.rs
--- a/src/watch_tower/registry_storage.rs
+++ b/src/watch_tower/registry_storage.rs
@@ -267,6 +267,20 @@ mod tests {
         assert!(!path.exists());
         let _reg = FileRegistry::load(&path);
         assert!(path.exists());
+    }
+
+    #[cfg(unix)]
+    #[test]
+    fn test_load_creates_private_registry_file() {
+        use std::os::unix::fs::PermissionsExt;
+
+        let dir = TempDir::new().unwrap();
+        let path = dir.path().join("registry.cbor");
+
+        let _reg = FileRegistry::load(&path);
+        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
+
+        assert_eq!(mode & 0o077, 0, "registry file must not be readable by other users");
     }
 
     #[test]

```

## Suggested Fix

```diff
No suggested fix emitted.
```

