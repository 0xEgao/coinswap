# Reject duplicated MuSig2 partial signatures before aggregation

- **Finding ID:** 31
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/protocol/musig2.rs
- **Lines:** 60-60
- **CWE:** CWE-347
- **Fingerprint:** bb7e815e6c984ca591e95adcd57f66596eaa9a6f0dece12e9234de1e7eb17d8f

## Description

`aggregate_partial_signatures` wraps `Session::partial_sig_agg` and returns `Ok` for whatever aggregate value it produces, without first authenticating that there is exactly one valid partial signature for each public key in the MuSig2 key set. A malicious or faulty participant can provide a duplicate/replayed partial signature in place of another signer’s share; the helper still reports success, and downstream code that treats this as a completed Taproot key-path signature can persist or broadcast an invalid cooperative spend. In the coinswap flow this can force fallback recovery paths and temporarily lock funds instead of failing the adversarial partial at the protocol boundary. I considered prior-finding searches for `musig2 partial signature aggregate assume_valid verify`, `aggregate_partial_signatures duplicate partial signatures validation musig2`, and `partial_sig_agg duplicate assume_valid`; none matched. The fix should verify each partial against the corresponding public key/nonce, reject duplicates and count mismatches, and only return an aggregate after all signer shares pass.

## Proof of Concept

```diff
diff --git a/src/protocol/musig2.rs b/src/protocol/musig2.rs
--- a/src/protocol/musig2.rs
+++ b/src/protocol/musig2.rs
@@ -59,3 +59,40 @@ pub fn aggregate_partial_signatures(
     let session = Session::new(&musig_key_agg_cache, agg_nonce, message.as_ref());
     Ok(session.partial_sig_agg(partial_sigs))
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn aggregate_rejects_duplicate_partial_signature() {
+        let keypair1 = Keypair::new(&mut rand::rng());
+        let keypair2 = Keypair::new(&mut rand::rng());
+        let mut pubkeys = [keypair1.public_key(), keypair2.public_key()];
+        pubkeys.sort_by_key(|a| a.serialize());
+
+        let (sec_nonce1, pub_nonce1) = generate_new_nonce_pair(keypair1.public_key());
+        let (_sec_nonce2, pub_nonce2) = generate_new_nonce_pair(keypair2.public_key());
+        let agg_nonce = AggregatedNonce::new(&[&pub_nonce1, &pub_nonce2]);
+        let message = Message::from_digest([42u8; 32]);
+        let tap_tweak = Scalar::ZERO;
+
+        let sig1 = generate_partial_signature(
+            message,
+            &agg_nonce,
+            sec_nonce1,
+            keypair1,
+            tap_tweak,
+            &[&pubkeys[0], &pubkeys[1]],
+        )
+        .unwrap();
+
+        let duplicate = aggregate_partial_signatures(
+            message,
+            agg_nonce,
+            tap_tweak,
+            &[&sig1, &sig1],
+            &[&pubkeys[0], &pubkeys[1]],
+        );
+
+        assert!(duplicate.is_err());
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

