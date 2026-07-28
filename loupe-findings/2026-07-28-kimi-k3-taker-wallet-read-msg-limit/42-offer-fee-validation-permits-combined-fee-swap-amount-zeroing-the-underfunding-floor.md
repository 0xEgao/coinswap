# Offer fee validation permits combined fee >= swap amount, zeroing the underfunding floor

- **Finding ID:** 42
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/taker/api.rs:1415-1478
- **Job:** 5
- **CWE:** CWE-1284
- **Fingerprint:** b1bf94a8071231aeabcd54af244926973d6325c0e4671f0ab6969e5f952fc116

## Description

Taker::validate_offer checks each fee component of a maker's Offer individually (amount_relative_fee_pct < 100, time_relative_fee_pct < 100, base_fee <= send_amount) but never bounds the COMBINED fee. The fee formula used everywhere else is base_fee + amount*pct/100 + amount*locktime*time_pct/100, so with time_relative_fee_pct up to 99.99 and a locktime multiplier (REFUND_LOCKTIME_BASE=20 blocks minimum) the total fee can exceed the hop amount many times over while passing validation.

Downstream, min_expected_amount_for_hop (src/taker/api.rs:377-400) computes the expected hop amount and clamps negative values to zero with `.max(0.0)`, returning Some(0). That value is the floor for the maker-underfunding checks in verify_maker_taproot_contract (src/taker/taproot_verification.rs:307-316, `total_amount < min_amount`) and verify_maker_sender_contracts (src/taker/legacy_verification.rs). With a floor of 0 the check is vacuous: a malicious maker can advertise an offer that passes validation, commit the taker's full funding, and then hand the taker nearly worthless (e.g. dust-valued) incoming contracts, which the taker accepts. The taker only discovers the loss after funds are on-chain and must rely on timelock/hashlock recovery. The correct behavior is to reject offers whose computed total fee meets/exceeds the hop amount (or to treat a non-positive expected hop amount as a hard error rather than clamping to zero).

PoC: the added unit tests build a syntactically valid Offer (fidelity proof included) with base_fee=1000, amount_relative_fee_pct=50, time_relative_fee_pct=90 on a 100_000-sat swap. Every individual bound passes, so validate_offer returns Ok on HEAD and the regression test fails; a sane-fee control test passes. Verified locally: `cargo test --lib taker::api::tests` -> validate_offer_rejects_total_fee_exceeding_amount FAILED on HEAD, validate_offer_accepts_reasonable_fee ok. No prior findings matched (searched for validate_offer/min_expected_amount_for_hop/fee validation).

## Proof of Concept

```diff
diff --git a/src/taker/api.rs b/src/taker/api.rs
--- a/src/taker/api.rs
+++ b/src/taker/api.rs
@@ -2572,3 +2572,97 @@ pub enum TakerBehavior {
     /// send ProofOfFunding directly (maker_rejects_proof_of_funding_with_missing_contract_cache).
     SkipSenderContractSigs,
 }
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use bitcoin::{
+        absolute::LockTime,
+        bip32::ChainCode,
+        secp256k1::Message,
+        secp256k1::Secp256k1,
+        OutPoint, Txid,
+    };
+
+    use crate::{protocol::common_messages::FidelityProof, wallet::FidelityBond};
+
+    fn test_offer() -> Offer {
+        let secp = Secp256k1::new();
+        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
+        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
+        let pubkey = bitcoin::PublicKey::new(secp_pubkey);
+
+        let bond = FidelityBond {
+            outpoint: OutPoint {
+                txid: Txid::from_slice(&[2; 32]).expect("valid txid"),
+                vout: 0,
+            },
+            amount: Amount::from_sat(1000),
+            lock_time: LockTime::from_height(1000).expect("valid height locktime"),
+            pubkey,
+            conf_height: Some(1000),
+            is_spent: false,
+            bond_index: 0,
+        };
+
+        let cert_hash = bond.generate_cert_hash("testmaker.onion", &pubkey);
+        let msg = Message::from_digest_slice(cert_hash.as_byte_array()).expect("32-byte digest");
+        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);
+
+        Offer {
+            base_fee: 0,
+            amount_relative_fee_pct: 0.0,
+            time_relative_fee_pct: 0.0,
+            required_confirms: 1,
+            minimum_locktime: 1,
+            max_size: 1,
+            min_size: 1,
+            tweakable_point: pubkey,
+            fidelity: FidelityProof {
+                bond,
+                cert_hash,
+                cert_sig,
+            },
+            tweak_chain_code: ChainCode::from([0u8; 32]),
+        }
+    }
+
+    /// Regression test: an offer whose *combined* fee (base + amount% +
+    /// time% * locktime) meets or exceeds the swap amount must be rejected.
+    /// On HEAD each component passes its individual bound, the offer is
+    /// accepted, and `min_expected_amount_for_hop` clamps the expected hop
+    /// amount to zero, which disables the maker underfunding checks.
+    #[test]
+    fn validate_offer_rejects_total_fee_exceeding_amount() {
+        let send_amount = Amount::from_sat(100_000);
+        let mut offer = test_offer();
+        offer.base_fee = 1_000;
+        offer.amount_relative_fee_pct = 50.0;
+        offer.time_relative_fee_pct = 90.0;
+        offer.min_size = 1;
+        offer.max_size = 1_000_000;
+
+        // With the smallest possible locktime (REFUND_LOCKTIME_BASE = 20),
+        // the time-relative component alone is
+        // 100_000 * 20 * 90 / 100 = 1_800_000 sats, i.e. 18x the swap amount.
+        assert!(
+            Taker::validate_offer(&offer, 0, send_amount).is_err(),
+            "offer whose combined fee exceeds the swap amount must be rejected"
+        );
+    }
+
+    /// A sane offer with modest fees must still be accepted, so a fix for the
+    /// above must not over-reject.
+    #[test]
+    fn validate_offer_accepts_reasonable_fee() {
+        let send_amount = Amount::from_sat(100_000);
+        let mut offer = test_offer();
+        offer.base_fee = 100;
+        offer.amount_relative_fee_pct = 0.5;
+        offer.time_relative_fee_pct = 0.1;
+        offer.min_size = 1;
+        offer.max_size = 1_000_000;
+
+        assert!(Taker::validate_offer(&offer, 0, send_amount).is_ok());
+    }
+}

```
