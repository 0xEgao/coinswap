# Bind Taproot handover keys to the MuSig internal key

- **Finding ID:** 3
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/taproot_verification.rs:293-308
- **Job:** 2
- **CWE:** CWE-345
- **Fingerprint:** 238649e87d3d0b4763fd0c70b101d244fcdbcfb1b716ef363a101af90934251b

## Description

`verify_taproot_contract_data` treats the taker-supplied `internal_keys[i]` as authoritative and only checks that the output script and tweak are self-consistent with that key. Later, `verify_taproot_privkey_handover` derives a public key from the handed-over secret and compares it only with `incoming.other_pubkey`; it never recomputes the MuSig aggregate from `incoming.my_pubkey` and that counterparty key or compares the result with `incoming.internal_key`.

A malicious taker can therefore fund a confirmed P2TR output using an attacker-only internal key while advertising an unrelated handover public key. The contract-data checks pass because the scripts, tweak, and output all match the attacker-selected internal key. During handover, the attacker supplies the secret for the unrelated advertised key, this verifier accepts it, and `process_taproot_handover` returns the maker's outgoing private key. The attacker can retain/spend the incoming output while claiming the maker-funded outgoing output; the maker's later cooperative sweep cannot authorize the attacker-keyed incoming output.

The regression test builds that self-consistent state and requires handover rejection. Prior-finding searches for `taproot_verification` and `handover internal key` returned no matches.

## Proof of Concept

```diff
diff --git a/src/maker/taproot_verification.rs b/src/maker/taproot_verification.rs
--- a/src/maker/taproot_verification.rs
+++ b/src/maker/taproot_verification.rs
@@ -484,4 +484,53 @@ mod tests {
 
         assert!(verify_taproot_contract_data(&data, MAKER_TIMELOCK, 0).is_err());
     }
+
+    #[test]
+    fn rejects_handover_key_unrelated_to_internal_key() {
+        let mut data = valid_contract_data();
+        let secp = Secp256k1::new();
+        let maker_secret =
+            bitcoin::secp256k1::SecretKey::from_slice(&[5u8; 32]).unwrap();
+        let taker_secret =
+            bitcoin::secp256k1::SecretKey::from_slice(&[4u8; 32]).unwrap();
+        let maker_pubkey = bitcoin::PublicKey::new(
+            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &maker_secret),
+        );
+
+        // Keep the output and tweak self-consistent, but make the internal key
+        // an attacker-only key rather than maker+taker MuSig aggregation.
+        data.internal_keys[0] =
+            bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair(6)).0;
+        refresh_output_script(&mut data);
+        let mut ordered_pubkeys = [maker_pubkey, data.pubkeys[0]];
+        ordered_pubkeys.sort_by_key(|key| key.inner.serialize());
+        let honest_internal =
+            crate::protocol::musig_interface::get_aggregated_pubkey_compat(
+                ordered_pubkeys[0].inner,
+                ordered_pubkeys[1].inner,
+            )
+            .unwrap();
+        assert_ne!(data.internal_keys[0], honest_internal);
+
+        let mut incoming = crate::wallet::swapcoin::IncomingSwapCoin::new_taproot(
+            maker_secret,
+            data.hashlock_script.clone(),
+            data.timelock_scripts[0].clone(),
+            data.contract_txs[0].clone(),
+            data.amounts[0],
+        );
+        incoming.set_taproot_params(
+            maker_secret,
+            maker_pubkey,
+            data.pubkeys[0],
+            data.internal_keys[0],
+            data.tap_tweak_scalar(0).unwrap(),
+        );
+        let handover = SwapPrivkey {
+            identifier: bitcoin::ScriptBuf::new(),
+            key: taker_secret,
+        };
+
+        assert!(verify_taproot_privkey_handover(&[handover], &[incoming], 0).is_err());
+    }
 }

```
