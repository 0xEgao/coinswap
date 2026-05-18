# Reject malformed last-hop Taproot hashlocks

- **Finding ID:** 47
- **Severity:** high
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/taker/taproot_swap.rs
- **Lines:** 329-353
- **CWE:** CWE-345
- **Fingerprint:** f63ad21ab0e0ae1bcacf11c6ddc051a6d5c7e84f1d9b6541cc368a1640085474

## Description

For the last Taproot maker, the taker is supposed to verify that the maker's hashlock script pays to the taker's freshly generated key. The code skips three instructions, then only performs the comparison when the next instruction is a pushed x-only public key. If that instruction is missing, malformed, or an opcode rather than a push, the branch falls through and accepts the contract. The generic verifier only counts five instructions and extracts the hash; it does not enforce the exact opcode/pubkey layout. A malicious last maker can therefore return a P2TR contract whose hashlock leaf contains the right hash but no spendable taker pubkey, while also choosing cooperative key data that will not let the taker key-spend. After finalization, the maker has received the taker's outgoing private key, but the taker's incoming contract cannot be spent via the intended hashlock path. I searched prior findings for `last maker Taproot hashlock pubkey missing push instruction accepted` and found no duplicate. A fix should treat every parse failure or non-push at the pubkey position as a hard verification error, and preferably validate the full hashlock opcode sequence before accepting the maker contract.

## Proof of Concept

```diff
diff --git a/src/taker/taproot_swap.rs b/src/taker/taproot_swap.rs
--- a/src/taker/taproot_swap.rs
+++ b/src/taker/taproot_swap.rs
@@ -576,5 +576,25 @@
 
         log::info!("Contract transactions broadcast and confirmed");
         Ok(())
+    }
+}
+
+#[cfg(test)]
+mod security_regression_tests {
+    #[test]
+    fn taproot_last_maker_hashlock_pubkey_parse_failure_is_fatal() {
+        let source = include_str!("taproot_swap.rs");
+        let marker = "Last maker: hashlock pubkey should be taker's own key";
+        let start = source.find(marker).expect("last-maker hashlock check should exist");
+        let end = source[start..]
+            .find("self.swap_state_mut()")
+            .map(|offset| start + offset)
+            .expect("last-maker hashlock check should finish before state update");
+        let body = &source[start..end];
+
+        assert!(
+            body.contains("return Err") && body.contains("invalid pubkey") && body.contains("else"),
+            "last-maker Taproot hashlock verification must reject missing or non-push pubkey instructions instead of silently accepting them"
+        );
     }
 }

```

## Suggested Fix

```diff
No suggested fix emitted.
```

