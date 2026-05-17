# Bound length-prefixed RPC messages before allocation

- **Finding ID:** 18
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/utill.rs
- **Lines:** 214-217
- **CWE:** CWE-400
- **Fingerprint:** 8739ba9946d8bbae1345a3f45988f5554c14766f70140adeaeec8fde042e8310

## Description

`read_message` trusts the peer-controlled 32-bit length prefix and immediately allocates `vec![0; length as usize]` before reading any payload bytes or applying a maximum frame size. The maker RPC server calls this helper for each accepted control-plane connection, so any process that can reach the RPC socket can send a large length such as `0xffff_ffff` and force the daemon to reserve a very large buffer before authentication or request validation. On typical deployments this can abort the maker process or put it under memory pressure, interrupting swap service and wallet operations. I treated prior finding #2 (unauthenticated maker RPC control plane) as related but distinct: that report covers missing authorization for privileged commands, while this issue remains a separate resource-exhaustion bug in the message framing layer and should be fixed by enforcing a conservative maximum frame size before allocation.

## Proof of Concept

```diff
diff --git a/src/utill.rs b/src/utill.rs
--- a/src/utill.rs
+++ b/src/utill.rs
@@ -961,7 +961,7 @@ pub fn select_utxo_from_wallet(utxos: Vec<(ListUnspentResultEntry, UTXOSpendInfo)>) -> io::Result<
 
 #[cfg(test)]
 mod tests {
-    use std::{net::TcpListener, thread};
+    use std::{io::Write, net::TcpListener, thread};
 
     use bitcoin::{
         blockdata::{opcodes::all, script::Builder},
@@ -1005,6 +1005,30 @@ mod tests {
         send_message(&mut stream, &message).unwrap();
     }
 
+    #[test]
+    fn read_message_rejects_oversized_length_prefix_before_body() {
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let address = listener.local_addr().unwrap();
+
+        let handle = thread::spawn(move || {
+            let (mut socket, _) = listener.accept().unwrap();
+            let err = read_message(&mut socket)
+                .expect_err("oversized message length must be rejected before reading a body");
+            let msg = err.to_string().to_ascii_lowercase();
+
+            assert!(
+                msg.contains("large") || msg.contains("size") || msg.contains("length"),
+                "oversized length prefix should return a size-limit error, got: {err:?}"
+            );
+        });
+
+        let mut stream = TcpStream::connect(address).unwrap();
+        stream.write_all(&(64_u32 * 1024 * 1024).to_be_bytes()).unwrap();
+        drop(stream);
+
+        handle.join().unwrap();
+    }
+
     #[test]
     fn test_redeemscript_to_scriptpubkey_custom() {
         // Create a custom puzzle script

```

## Suggested Fix

```diff
No suggested fix emitted.
```

