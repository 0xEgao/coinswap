# Restrict swap tracker files to the maker owner

- **Finding ID:** 52
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/swap_tracker.rs:196-212
- **Job:** 3
- **CWE:** CWE-732
- **Fingerprint:** 39d9dffa533c7055cad11e8b2dc273fe135e3dfd3757cfe6c43a1a4c4e38aafd

## Description

`flush` creates `maker_swap_tracker.cbor.tmp` with `std::fs::write` and renames it over the tracker without setting restrictive permissions. On Unix this uses `0666 & umask`; under the common `022` umask the regression test observes `0644`. The CBOR file contains swap identifiers, amounts, protocol choices, and recovery transaction IDs, which can let another local account correlate the maker with on-chain activity whenever it can traverse the configured data directory. This is a privacy exposure rather than a private-key leak, so severity is low. The issue also persists if an operator manually fixes the final file: every flush creates a new permissive temporary inode and the rename replaces the corrected inode. The writer should create the temporary file with owner-only mode (and correct permissions on existing files before replacement), analogous to the repository's RPC cookie handling. The Unix-only regression saves one record and asserts that the resulting tracker mode is exactly `0600`; it fails on HEAD with decimal mode 420 (`0644`) rather than 384 (`0600`). Prior searches for `maker swap tracker file permissions transaction ids privacy` and `swap_tracker permissions` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/swap_tracker.rs b/src/maker/swap_tracker.rs
--- a/src/maker/swap_tracker.rs
+++ b/src/maker/swap_tracker.rs
@@ -397,6 +397,25 @@ mod tests {
         assert!(
             !tmp_path.exists(),
             "tmp file should be removed after rename"
         );
     }
+
+    #[cfg(unix)]
+    #[test]
+    fn test_tracker_file_is_owner_only() {
+        use std::os::unix::fs::PermissionsExt;
+
+        let dir = TempDir::new().unwrap();
+        let mut tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
+        tracker
+            .save_record(&make_test_record("private", MakerSwapPhase::Active))
+            .unwrap();
+
+        let mode = std::fs::metadata(dir.path().join("maker_swap_tracker.cbor"))
+            .unwrap()
+            .permissions()
+            .mode()
+            & 0o777;
+        assert_eq!(mode, 0o600, "swap metadata must only be readable by its owner");
+    }
 }

```
