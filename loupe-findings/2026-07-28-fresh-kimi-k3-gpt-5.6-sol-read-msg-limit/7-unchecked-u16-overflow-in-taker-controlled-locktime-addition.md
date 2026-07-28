# Unchecked u16 overflow in taker-controlled locktime addition

- **Finding ID:** 7
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/legacy_verification.rs:38
- **Job:** 3
- **CWE:** CWE-190
- **Fingerprint:** 4e6ab09b7285abf484f9654985f1a596fcf507698d29d87f04bbede7906b8736

## Description

verify_req_contract_sigs_for_sender computes `let taker_locktime = locktime + REFUND_LOCKTIME_STEP;` where `locktime: u16` comes unvalidated from the remote taker's ReqContractSigsForSender message (src/protocol/legacy_messages.rs:39; passed straight through at src/maker/legacy_handlers.rs:100 and src/maker/api.rs:1234 with no range check anywhere). REFUND_LOCKTIME_STEP is 20 (or 75 on some cfgs), so any locktime > 65515 overflows u16. In debug builds this panics ("attempt to add with overflow") — a remote, unauthenticated taker can crash the maker's message handler (availability). In release builds (no overflow-checks in Cargo.toml profiles) the addition silently wraps, so taker_locktime becomes a tiny value (e.g. locktime=65530 -> 14); is_contract_out_valid then validates the taker's sender contract output against that wrapped, near-zero timelock and the maker signs it (src/maker/api.rs:1256-1277). This breaks the protocol's timelock-staggering invariant (sender refund timelock must exceed the receiver's by REFUND_LOCKTIME_STEP so refund cascades resolve in order), letting a malicious taker obtain maker signatures on contracts whose refund path fires far earlier than intended — a fund-safety/race risk during stalled swaps. The taproot mirror (src/maker/taproot_verification.rs:104) widens to u64 before adding, confirming this addition is expected to be overflow-safe. Confirmed with a regression test: `cargo test --lib maker::legacy_verification` panics at src/maker/legacy_verification.rs:38:26 with "attempt to add with overflow". Fix: use checked_add and return MakerError on overflow. No prior findings matched this bug.

## Proof of Concept

```diff
diff --git a/src/maker/legacy_verification.rs b/src/maker/legacy_verification.rs
index 279eec9..1c8000b 100644
--- a/src/maker/legacy_verification.rs
+++ b/src/maker/legacy_verification.rs
@@ -231,3 +231,69 @@ pub(crate) fn verify_legacy_privkey_handover(
     );
     Ok(())
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
+        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
+    };
+
+    fn dummy_contract_tx_info() -> ContractTxInfoForSender {
+        let secp = bitcoin::secp256k1::Secp256k1::new();
+        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
+        let pubkey = PublicKey {
+            compressed: true,
+            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret),
+        };
+        ContractTxInfoForSender {
+            multisig_nonce: secret,
+            hashlock_nonce: secret,
+            timelock_pubkey: pubkey,
+            senders_contract_tx: Transaction {
+                version: Version::TWO,
+                lock_time: LockTime::ZERO,
+                input: vec![TxIn {
+                    previous_output: OutPoint {
+                        txid: Txid::all_zeros(),
+                        vout: 0,
+                    },
+                    script_sig: ScriptBuf::new(),
+                    sequence: Sequence::MAX,
+                    witness: Witness::new(),
+                }],
+                output: vec![TxOut {
+                    value: Amount::from_sat(50_000),
+                    script_pubkey: ScriptBuf::new(),
+                }],
+            },
+            multisig_redeemscript: ScriptBuf::new(),
+            funding_input_value: Amount::from_sat(50_000),
+        }
+    }
+
+    // Regression test: `locktime` comes from the taker's ReqContractSigsForSender
+    // message and is u16. `locktime + REFUND_LOCKTIME_STEP` overflows u16 for
+    // locktime > u16::MAX - REFUND_LOCKTIME_STEP, panicking in debug builds and
+    // silently wrapping in release builds (wrapped taker_locktime is then used
+    // to validate the contract output the maker signs). It must be rejected
+    // gracefully instead.
+    #[test]
+    fn sender_contract_verification_rejects_overflowing_locktime() {
+        let txinfo = dummy_contract_tx_info();
+        let tweakable_pubkey = txinfo.timelock_pubkey;
+        let hashvalue = Hash160::from_slice(&[0u8; 20]).unwrap();
+        let result = verify_req_contract_sigs_for_sender(
+            &[txinfo],
+            &tweakable_pubkey,
+            &hashvalue,
+            u16::MAX,
+            6102,
+        );
+        assert!(
+            result.is_err(),
+            "overflowing locktime must return Err, not panic or wrap"
+        );
+    }
+}

```
