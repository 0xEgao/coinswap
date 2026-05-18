# Bind fidelity announcements to transaction locktime

- **Finding ID:** 68
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/watch_tower/utils.rs
- **Lines:** 111-124
- **CWE:** CWE-345
- **Fingerprint:** ea4ac805d11a51004e8291163605e8340da6aa2cff54a9eb79355638801bf1be

## Description

`process_fidelity` accepts any transaction whose `nLockTime` is nonzero, then stores the expiry height supplied by the OP_RETURN payload as `expires_at_height`. Those two values are not required to match, so an attacker can publish a transaction that is spendable at height 1 but advertises `attacker.onion#500000`. `process_block`/Nostr discovery then persists that onion address until the advertised height, even though the on-chain transaction does not lock funds for that period. Later offer verification may reject a maker that cannot prove a real bond, but the discovery registry has already been polluted and takers will keep scheduling network connections to attacker-chosen addresses based on an unbonded transaction. I searched prior findings for `process_fidelity locktime expiry OP_RETURN fidelity announcement watch_tower utils` and found no matches.

## Proof of Concept

```diff
diff --git a/src/watch_tower/utils.rs b/src/watch_tower/utils.rs
index c8ad88e..cf95637 100644
--- a/src/watch_tower/utils.rs
+++ b/src/watch_tower/utils.rs
@@ -288,6 +288,20 @@ mod tests {
         assert_eq!(ann.expires_at_height, 500);
     }
 
+    #[test]
+    fn test_process_fidelity_rejects_mismatched_locktime_and_expiry() {
+        let tx = tx(
+            1,
+            vec![OutPoint::null()],
+            vec![ScriptBuf::new(), op_return(TEST_ADDR).into()],
+        );
+
+        assert!(
+            process_fidelity(&tx).is_none(),
+            "announcement expiry must be bound to the transaction locktime"
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

