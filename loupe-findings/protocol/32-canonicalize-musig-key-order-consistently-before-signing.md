# Canonicalize MuSig key order consistently before signing

- **Finding ID:** 32
- **Severity:** low
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/protocol/musig_interface.rs
- **Lines:** 79-106
- **CWE:** n/a
- **Fingerprint:** df4fd2e0e02fc9fce88928e008a1a5c856caea63dfd4b12b86209e1e3df1e621

## Description

`get_aggregated_pubkey_compat` exposes an order-independent aggregate key because it delegates to `get_aggregated_pubkey`, which sorts the two public keys before building the MuSig key aggregation cache. The signing and aggregation wrappers, however, pass `pubkey1` and `pubkey2` through in caller-supplied order. If an untrusted protocol path or future caller uses the aggregate-key wrapper with one key order and then signs through these wrappers with the reverse order, the resulting aggregate signature is for a different MuSig key than the Taproot internal key used in the output. The transaction witness is still constructed, but the Schnorr signature fails verification, causing cooperative Taproot spends to fail and potentially leaving funds only recoverable through timeout/hashlock paths. Existing in-tree callers appear to pre-sort before calling these functions, but the public compatibility API itself does not preserve that invariant. Prior searches `musig_interface pubkey order aggregate signing sorted` and `MuSig key aggregation order partial signature` returned no duplicates.

## Proof of Concept

```diff
diff --git a/src/protocol/musig_interface.rs b/src/protocol/musig_interface.rs
--- a/src/protocol/musig_interface.rs
+++ b/src/protocol/musig_interface.rs
@@ -106,3 +106,77 @@ pub fn aggregate_partial_signatures_compat(
         &[&pubkey1, &pubkey2],
     )
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::secp256k1::{
+        schnorr::Signature, Keypair, Message, Scalar, Secp256k1, SecretKey,
+    };
+
+    #[test]
+    fn compat_signing_matches_order_independent_aggregate_key() {
+        let secp = Secp256k1::new();
+        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let kp1 = Keypair::from_secret_key(&secp, &sk1);
+        let kp2 = Keypair::from_secret_key(&secp, &sk2);
+
+        let mut sorted_pubkeys = [kp1.public_key(), kp2.public_key()];
+        sorted_pubkeys.sort_by_key(|pk| pk.serialize());
+        let (first_sk, second_sk) = if sorted_pubkeys[0] == kp1.public_key() {
+            (sk2, sk1)
+        } else {
+            (sk1, sk2)
+        };
+        let first_kp = Keypair::from_secret_key(&secp, &first_sk);
+        let second_kp = Keypair::from_secret_key(&secp, &second_sk);
+        let unsorted_pubkeys = [first_kp.public_key(), second_kp.public_key()];
+
+        let aggregate_key =
+            get_aggregated_pubkey_compat(unsorted_pubkeys[0], unsorted_pubkeys[1]).unwrap();
+
+        let (sec_nonce1, pub_nonce1) =
+            generate_new_nonce_pair_compat(unsorted_pubkeys[0]).unwrap();
+        let (sec_nonce2, pub_nonce2) =
+            generate_new_nonce_pair_compat(unsorted_pubkeys[1]).unwrap();
+        let aggregate_nonce = get_aggregated_nonce_compat(&[&pub_nonce1, &pub_nonce2]);
+
+        let message = Message::from_digest([3u8; 32]);
+        let tweak = Scalar::from_be_bytes([0u8; 32]).unwrap();
+        let sig1 = generate_partial_signature_compat(
+            message,
+            &aggregate_nonce,
+            sec_nonce1,
+            first_kp,
+            tweak,
+            unsorted_pubkeys[0],
+            unsorted_pubkeys[1],
+        )
+        .unwrap();
+        let sig2 = generate_partial_signature_compat(
+            message,
+            &aggregate_nonce,
+            sec_nonce2,
+            second_kp,
+            tweak,
+            unsorted_pubkeys[0],
+            unsorted_pubkeys[1],
+        )
+        .unwrap();
+
+        let aggregate_sig = aggregate_partial_signatures_compat(
+            message,
+            aggregate_nonce,
+            tweak,
+            vec![&sig1, &sig2],
+            unsorted_pubkeys[0],
+            unsorted_pubkeys[1],
+        )
+        .unwrap();
+        let schnorr_sig = Signature::from_slice(aggregate_sig.assume_valid().as_byte_array())
+            .unwrap();
+
+        secp.verify_schnorr(&schnorr_sig, &message, &aggregate_key)
+            .expect("signature must verify against the aggregate key returned by the compat API");
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

