# Refuse symlinks when creating the RPC cookie

- **Finding ID:** 50
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/rpc/server.rs:35-49
- **Job:** 3
- **CWE:** CWE-59
- **Fingerprint:** c51fffb2de76614e55075e8ba991b604ab62e2d65d2790b2f3a8e6411c7b72c5

## Description

`write_rpc_cookie` opens `data_dir/rpc_cookie` with `create(true).truncate(true)` and no no-follow protection. On Unix, `OpenOptions` therefore follows an existing symbolic link before truncating, chmodding, and writing the random token. A local principal that can create entries in the maker data directory can pre-position `rpc_cookie` as a symlink to any file writable by the makerd account; the next startup overwrites that target with a 64-byte token and changes its mode to 0600. This can corrupt configuration, wallet/backups, or unrelated same-account files and cause loss of availability or data. The regression test links `rpc_cookie` to an unrelated file and demonstrates that HEAD returns success and overwrites the target.

The prerequisite is important: the default data directory is normally not writable by other OS users, so this is low severity. It becomes exploitable when deployments use a group/shared writable data directory or another less-privileged local service can populate it. A fix should open with platform no-follow semantics and verify the opened object is a newly created regular file, or create a private temporary regular file and atomically install it without following an existing path. A prior search for `write_rpc_cookie symlink truncate OpenOptions` found no match.

## Proof of Concept

```diff
diff --git a/src/maker/rpc/server.rs b/src/maker/rpc/server.rs
--- a/src/maker/rpc/server.rs
+++ b/src/maker/rpc/server.rs
@@ -301,5 +301,22 @@ mod tests {
                 .mode();
             assert_eq!(mode & 0o777, 0o600);
         }
     }
+
+    #[cfg(unix)]
+    #[test]
+    fn rpc_cookie_creation_does_not_follow_symlinks() {
+        use std::os::unix::fs::symlink;
+
+        let dir = bitcoind::tempfile::tempdir().unwrap();
+        let target = dir.path().join("unrelated");
+        fs::write(&target, b"must remain unchanged").unwrap();
+        symlink(&target, dir.path().join(RPC_COOKIE_FILE)).unwrap();
+
+        assert!(
+            write_rpc_cookie(dir.path()).is_err(),
+            "cookie creation must reject an existing symlink"
+        );
+        assert_eq!(fs::read(&target).unwrap(), b"must remain unchanged");
+    }
 }

```
