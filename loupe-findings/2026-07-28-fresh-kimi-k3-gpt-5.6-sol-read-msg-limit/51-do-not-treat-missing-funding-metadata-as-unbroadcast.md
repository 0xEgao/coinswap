# Do not treat missing funding metadata as unbroadcast

- **Finding ID:** 51
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/swap_tracker.rs:123-126
- **Job:** 3
- **CWE:** CWE-665
- **Fingerprint:** 4116fa475ef3a7b8797b299068c326a0f306125491747e7b4075e8fdf20f5980

## Description

`MakerSwapRecord::funding_broadcast` uses `#[serde(default)]` on a `bool`, so any tracker record written by an older schema without this field deserializes as the affirmative state `false`. That is not a conservative migration: maker startup groups unfinished wallet swapcoins and `recover_from_swap` interprets `Some(false)` as proof that funding was never broadcast. It then removes both incoming and outgoing swapcoins from persistent wallet storage and saves the wallet without first checking the chain. Thus a routine upgrade/restart during a funded, unfinished swap can misclassify an old record and destroy the maker's persisted recovery material, potentially preventing recovery of funds. Missing metadata must remain unknown/conservatively mean “possibly broadcast” (for example via a true-on-missing deserializer or an `Option`), or loading must fail; only an explicitly serialized false value may authorize the discard branch. The regression test serializes the previous record shape without `funding_broadcast`, loads it through the current tracker, and asserts it is not classified as unbroadcast. It fails on HEAD because the loaded value is false. Prior searches for `maker swap tracker funding_broadcast serde default reboot discard swapcoins` and `funding_broadcast swap_tracker` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/swap_tracker.rs b/src/maker/swap_tracker.rs
--- a/src/maker/swap_tracker.rs
+++ b/src/maker/swap_tracker.rs
@@ -346,6 +346,53 @@ mod tests {
         assert_eq!(incomplete[0].phase, MakerSwapPhase::Recovering);
     }
 
+    #[test]
+    fn test_legacy_record_without_funding_status_is_not_assumed_unbroadcast() {
+        #[derive(serde::Serialize)]
+        struct LegacyMakerSwapRecord {
+            swap_id: String,
+            protocol: ProtocolVersion,
+            phase: MakerSwapPhase,
+            swap_amount_sat: u64,
+            incoming_count: usize,
+            outgoing_count: usize,
+            recovery: MakerRecoveryState,
+            created_at: u64,
+            updated_at: u64,
+        }
+
+        #[derive(serde::Serialize)]
+        struct LegacyMakerSwapTrackerData {
+            swaps: HashMap<String, LegacyMakerSwapRecord>,
+        }
+
+        let dir = TempDir::new().unwrap();
+        let swap_id = "legacy-funded".to_string();
+        let mut swaps = HashMap::new();
+        swaps.insert(
+            swap_id.clone(),
+            LegacyMakerSwapRecord {
+                swap_id: swap_id.clone(),
+                protocol: ProtocolVersion::Legacy,
+                phase: MakerSwapPhase::Recovering,
+                swap_amount_sat: 100_000,
+                incoming_count: 1,
+                outgoing_count: 1,
+                recovery: MakerRecoveryState::default(),
+                created_at: now_secs(),
+                updated_at: now_secs(),
+            },
+        );
+        let bytes = serde_cbor::to_vec(&LegacyMakerSwapTrackerData { swaps }).unwrap();
+        std::fs::write(dir.path().join("maker_swap_tracker.cbor"), bytes).unwrap();
+
+        let tracker = MakerSwapTracker::load_or_create(dir.path()).unwrap();
+        assert!(
+            tracker.get_record(&swap_id).unwrap().funding_broadcast,
+            "missing legacy metadata must not be treated as proof that funding was never broadcast"
+        );
+    }
+
     #[test]
     fn test_recovered_with_cleanup_not_in_incomplete() {
         let dir = TempDir::new().unwrap();

```
