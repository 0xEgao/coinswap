# Retry completed incoming sweeps after transient failure

- **Finding ID:** 54
- **Severity:** Medium
- **State:** pending
- **Scanner:** llm-code-review
- **Location:** src/maker/server.rs:374-392
- **Job:** 3
- **CWE:** CWE-703
- **Fingerprint:** 88d7811667291c2145be760de9d761694c3b488e2652bf7b56728ee7b6d0ea84

## Description

When a protocol handler reaches `SwapPhase::Completed`, `handle_connection` removes the swap from `ongoing_swaps` before attempting `sweep_incoming_swapcoins`. Any transient wallet/backend failure is only logged; the connection then exits and there is no retained state that schedules another attempt. This becomes persistent across restart: startup calls `find_unfinished_swapcoins`, whose incoming-side predicate intentionally selects only coins with `other_privkey == None`. A completed incoming coin already has the counterparty private key, so a failed sweep remains in the wallet but is excluded from reboot recovery. The maker has all keys needed to claim the output, yet will not automatically retry until an unrelated future completion happens to invoke the wallet-wide sweep; if no later swap occurs, funds remain locked indefinitely. The regression test constructs the exact persisted state left after key handover plus a failed sweep and shows that the startup selection used at server.rs:80-84 returns no recovery candidate on HEAD. Completion state should not be dropped until the sweep succeeds, or startup/background maintenance should explicitly retry completed-but-unswept incoming coins. Prior #29 concerns partial Legacy funding broadcasts and #51 concerns missing tracker metadata; neither covers post-completion sweep failure.

## Proof of Concept

```diff
diff --git a/src/wallet/api.rs b/src/wallet/api.rs
--- a/src/wallet/api.rs
+++ b/src/wallet/api.rs
@@ -3317,7 +3317,44 @@ mod prevout_contract_tests {
         let (reloaded_store, _) = WalletStore::read_from_disk(&wallet_path, String::new()).unwrap();
         assert_eq!(
             reloaded_store.prevout_to_contract_map.get(&prevout),
             Some(&approved_contract)
         );
     }
+
+    #[test]
+    fn startup_does_not_drop_completed_but_unswept_incoming_swapcoins() {
+        let temp_dir = tempdir().unwrap();
+        let mut wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));
+        let secp = Secp256k1::new();
+        let my_key = SecretKey::from_slice(&[1; 32]).unwrap();
+        let other_key = SecretKey::from_slice(&[2; 32]).unwrap();
+        let other_pubkey = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
+            &secp,
+            &other_key,
+        ));
+        let contract_tx = Transaction {
+            version: bitcoin::transaction::Version::TWO,
+            lock_time: bitcoin::absolute::LockTime::ZERO,
+            input: Vec::new(),
+            output: Vec::new(),
+        };
+        let mut coin = crate::wallet::swapcoin::IncomingSwapCoin::new_legacy(
+            my_key,
+            other_pubkey,
+            contract_tx,
+            ScriptBuf::new(),
+            SecretKey::from_slice(&[3; 32]).unwrap(),
+            Amount::from_sat(100_000),
+        );
+        coin.swap_id = Some("completed-unswept".to_string());
+        coin.set_other_privkey(other_key);
+        wallet.add_incoming_swapcoin(&coin);
+
+        let (startup_incoming, _) = wallet.find_unfinished_swapcoins();
+        assert_eq!(
+            startup_incoming.len(),
+            1,
+            "a failed completion sweep must remain eligible for startup recovery"
+        );
+    }
 }

```
