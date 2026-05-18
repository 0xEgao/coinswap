# Validate full Taproot hashlock script template

- **Finding ID:** 30
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/protocol/contract2.rs
- **Lines:** 29-73
- **CWE:** CWE-20
- **Fingerprint:** de98c2356c3e1478a69f7646ea833f5138f8e4fbdb4448af17aaecc5a9a9d84a

## Description

The Taproot hashlock validators only inspect positional fields instead of enforcing the script template. `extract_hash_from_hashlock` accepts any script with at least five instructions and a 32-byte push at instruction 1, while `check_taproot_hashlock_has_pubkey` accepts any script with the expected x-only key at instruction 3. Maker-side contract processing calls these helpers before accepting taker-supplied `TaprootContractData`; it then verifies only the instruction count and stores the supplied script as the incoming swapcoin. A malicious taker can therefore send a five-instruction script that contains the expected hash and maker-derived pubkey but replaces the final `OP_CHECKSIG` with `OP_CHECKSIGVERIFY` or otherwise changes the opcodes. That script passes current verification, yet the maker's hashlock witness path is unspendable or has different spend semantics. The maker may forward its own outgoing contract and later be unable to claim the taker's incoming contract after the preimage is available, allowing the adversary to take the forwarded funds while the maker's incoming funds remain locked until fallback or permanently depending on the alternate script. Prior search `contract2 extract_hash_from_hashlock OP_CHECKSIG hashlock script format taproot` returned no matching findings.

## Proof of Concept

```diff
diff --git a/src/protocol/contract2.rs b/src/protocol/contract2.rs
index 8b2e9ab..c5b98e1 100644
--- a/src/protocol/contract2.rs
+++ b/src/protocol/contract2.rs
@@ -144,3 +144,35 @@ pub(crate) fn calculate_contract_sighash(
 
     Ok(bitcoin::secp256k1::Message::from(sighash))
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        opcodes::all::OP_CHECKSIGVERIFY,
+        secp256k1::{PublicKey as SecpPublicKey, SecretKey},
+    };
+
+    #[test]
+    fn rejects_hashlock_script_without_final_checksig() {
+        let tweakable_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let nonce = SecretKey::from_slice(&[2u8; 32]).unwrap();
+        let secp = Secp256k1::new();
+        let tweakable_point = PublicKey {
+            compressed: true,
+            inner: SecpPublicKey::from_secret_key(&secp, &tweakable_secret),
+        };
+        let expected = crate::protocol::contract::calculate_pubkey_from_nonce(
+            &tweakable_point,
+            &nonce,
+        )
+        .unwrap();
+        let (expected_xonly, _) = expected.inner.x_only_public_key();
+        let hash = [3u8; 32];
+
+        let malformed = script::Builder::new()
+            .push_opcode(OP_SHA256)
+            .push_slice(hash)
+            .push_opcode(OP_EQUALVERIFY)
+            .push_x_only_key(&expected_xonly)
+            .push_opcode(OP_CHECKSIGVERIFY)
+            .into_script();
+
+        assert!(extract_hash_from_hashlock(&malformed).is_err());
+        assert!(check_taproot_hashlock_has_pubkey(&malformed, &tweakable_point, &nonce).is_err());
+    }
+}

```

## Suggested Fix

```diff
No suggested fix emitted.
```

