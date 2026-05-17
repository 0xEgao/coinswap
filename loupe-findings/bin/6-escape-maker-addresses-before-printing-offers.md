# Escape maker addresses before printing offers

- **Finding ID:** 6
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/bin/taker.rs
- **Lines:** 217-221
- **CWE:** CWE-150
- **Fingerprint:** bc319b835c56235954e1f30dbf1438837707e4db150e0c9fd01e4ffa4cb6afd1

## Description

`list-offers` and `fetch-offers` print `candidate.address` directly into the operator's terminal. Maker addresses are populated from remote fidelity announcements through the watcher/offerbook path, and the production normalization only requires a value without an interior dot before appending/accepting `.onion`; it does not reject ASCII control bytes. A malicious maker can therefore publish an address such as an OSC 52/control sequence ending in `.onion`, have it cached as an unresponsive maker, and wait for a taker operator to run `taker list-offers` or `taker fetch-offers`. The raw `println!` emits the control bytes, allowing terminal injection effects such as clipboard overwrite, misleading terminal output, or other terminal-emulator-specific actions. I searched prior findings for `taker list offers terminal escape maker address` and `OSC 52 maker address terminal injection`; both returned no matches. A fix should validate maker addresses to a strict hostname/onion character set and/or escape control characters before any terminal output.

## Proof of Concept

```diff
diff --git a/src/taker/offers.rs b/src/taker/offers.rs
index 069ae74..c577c74 100644
--- a/src/taker/offers.rs
+++ b/src/taker/offers.rs
@@ -980,6 +980,20 @@ mod tests {
         }
     }
 
+    #[test]
+    fn maker_address_rejects_terminal_control_sequences() {
+        #[cfg(feature = "integration-test")]
+        let injected = "\x1b]52;c;c2VjcmV0\x07:9050";
+
+        #[cfg(not(feature = "integration-test"))]
+        let injected = "\x1b]52;c;c2VjcmV0\x07.onion";
+
+        assert!(
+            MakerAddress::try_from(injected.to_string()).is_err(),
+            "maker addresses printed by the taker CLI must reject terminal control sequences"
+        );
+    }
+
     #[test]
     fn mark_failure_state_and_backoff_growth() {
         let now_ts = 170000;

```

## Suggested Fix

```diff
No suggested fix emitted.
```

