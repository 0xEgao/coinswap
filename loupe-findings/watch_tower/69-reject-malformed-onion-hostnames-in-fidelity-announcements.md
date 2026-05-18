# Reject malformed onion hostnames in fidelity announcements

- **Finding ID:** 69
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/utils.rs
- **Lines:** 54-61
- **CWE:** CWE-20
- **Fingerprint:** 0cbd9c7290eab85a6195ffbf126145d298f262cf3fd5f33eaf4fa7e4e85ebec5

## Description

`normalize_onion_address` only strips an optional `.onion` suffix and rejects empty names or names containing another dot. It accepts punctuation/control characters and other non-onion hostnames such as `bad:onion`, then normalizes them into persisted maker addresses like `bad:onion.onion`. Discovery stores these addresses from blockchain/Nostr announcements and the taker offer sync later treats any stored string ending in `.onion` as a production maker hostname. This does not bypass the later fidelity proof check for successful offers, but it lets untrusted announcements poison the discovery registry with syntactically invalid attacker-chosen hostnames and cause repeated outbound connection attempts/log entries for records that should never enter the maker address set. I searched prior findings for `normalize_onion_address onion validation invalid hostname watch_tower utils` and found no matches.

## Proof of Concept

```diff
diff --git a/src/watch_tower/utils.rs b/src/watch_tower/utils.rs
index c8ad88e..a846b98 100644
--- a/src/watch_tower/utils.rs
+++ b/src/watch_tower/utils.rs
@@ -288,6 +288,21 @@ mod tests {
         assert_eq!(ann.expires_at_height, 500);
     }
 
+    #[cfg(not(feature = "integration-test"))]
+    #[test]
+    fn test_process_fidelity_rejects_malformed_onion_hostname() {
+        let tx = tx(
+            500,
+            vec![OutPoint::null()],
+            vec![ScriptBuf::new(), op_return(b"bad:onion#500").into()],
+        );
+
+        assert!(
+            process_fidelity(&tx).is_none(),
+            "fidelity announcements must contain syntactically valid onion hostnames"
+        );
+    }
+
     #[test]
     fn test_process_fidelity_invalid() {
         let tx0 = tx(

```

## Suggested Fix

```diff
No suggested fix emitted.
```

