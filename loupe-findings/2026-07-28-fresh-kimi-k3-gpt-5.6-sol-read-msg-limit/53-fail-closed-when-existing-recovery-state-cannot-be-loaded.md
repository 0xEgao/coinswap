# Fail closed when existing recovery state cannot be loaded

- **Finding ID:** 53
- **Severity:** Low
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/swap_tracker.rs:166-172
- **Job:** 3
- **CWE:** CWE-391
- **Fingerprint:** e8e08386ef524362e65b2a4331f2359fb3a88eb631986a0d02959a2b16389902

## Description

`load_or_create` converts both failures to read an existing tracker and failures to deserialize it into `MakerSwapTrackerData::default()`. A malformed, truncated, permission-blocked, or schema-incompatible recovery file therefore looks exactly like a legitimate fresh installation, and `MakerServer::init` continues without notifying the caller. This loses all per-swap recovery decisions from the running view. In particular, startup recovery can no longer recognize explicitly unbroadcast swaps, so their persisted swapcoins may remain tied up in conservative recovery; a later successful `save_record` also serializes the partial empty-derived map over the original path, making the record loss permanent. This is primarily a local availability and recovery-data-integrity issue rather than a remote exploit, so severity is low. Because the API already returns `Result`, an existing file that cannot be read or decoded should return an error (or be explicitly quarantined through an operator-visible recovery path), not silently initialize empty state. The regression writes invalid CBOR to the existing tracker path and asserts startup fails; it fails on HEAD because `unwrap_or_default` returns an empty successful tracker. Prior searches for `maker swap tracker corrupt cbor unwrap_or_default empty recovery records` and `load_or_create tracker deserialization default` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/swap_tracker.rs b/src/maker/swap_tracker.rs
--- a/src/maker/swap_tracker.rs
+++ b/src/maker/swap_tracker.rs
@@ -327,6 +327,18 @@ mod tests {
         let tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
         assert!(tracker.incomplete_swaps().is_empty());
     }
+
+    #[test]
+    fn test_corrupt_existing_tracker_is_not_silently_accepted_as_empty() {
+        let dir = TempDir::new().unwrap();
+        std::fs::write(dir.path().join("maker_swap_tracker.cbor"), [0xff]).unwrap();
+
+        let result = MakerSwapTracker::load_or_create(dir.path());
+        assert!(
+            result.is_err(),
+            "corrupt recovery state must stop startup instead of being replaced with an empty tracker"
+        );
+    }
 
     #[test]
     fn test_save_and_reload() {

```
