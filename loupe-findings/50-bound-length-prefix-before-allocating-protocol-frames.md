# Bound length prefix before allocating protocol frames

- **Finding ID:** 50
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/utill.rs
- **Lines:** 217-217
- **CWE:** CWE-400
- **Fingerprint:** e01a974b57046754db30d11b590b69b642967ef2ebecc0c3efaa1c8de4ef2a9f

## Description

`read_message` trusts the 4-byte peer-controlled length prefix and immediately allocates `vec![0; length as usize]` before enforcing any maximum frame size. Any endpoint using this shared helper can be forced to reserve up to the advertised u32 length even if the peer never sends a payload. In this tree the helper is used by the maker RPC server and by taker-side connections to makers, so a malicious local RPC client or malicious remote maker can consume large memory and stall the process before CBOR deserialization or protocol validation runs. The main maker P2P server has a separate 10 MiB cap, but this shared utility does not. I searched prior findings for `read_message length allocation u32 denial service utill` and found no duplicate.

## Proof of Concept

```diff
diff --git a/src/utill.rs b/src/utill.rs
--- a/src/utill.rs
+++ b/src/utill.rs
@@ -961,7 +961,11 @@
 
 #[cfg(test)]
 mod tests {
-    use std::{net::TcpListener, thread};
+    use std::{
+        net::TcpListener,
+        thread,
+        time::{Duration, Instant},
+    };
 
     use bitcoin::{
         blockdata::{opcodes::all, script::Builder},
@@ -1003,6 +1007,40 @@
 
         let mut stream = TcpStream::connect(address).unwrap();
         send_message(&mut stream, &message).unwrap();
+    }
+
+    #[test]
+    fn test_read_message_rejects_oversized_length_before_reading_payload() {
+        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
+        let address = listener.local_addr().unwrap();
+
+        let server = thread::spawn(move || {
+            let (mut socket, _) = listener.accept().unwrap();
+            socket.write_all(&(64_u32 * 1024 * 1024).to_be_bytes()).unwrap();
+            thread::sleep(Duration::from_secs(1));
+        });
+
+        let mut stream = TcpStream::connect(address).unwrap();
+        stream
+            .set_read_timeout(Some(Duration::from_millis(200)))
+            .unwrap();
+
+        let started = Instant::now();
+        let err = read_message(&mut stream).expect_err("oversized frames must be rejected");
+        let elapsed = started.elapsed();
+
+        match err {
+            NetError::IO(ref io_err)
+                if matches!(
+                    io_err.kind(),
+                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::UnexpectedEof
+                ) => panic!(
+                "oversized frame was treated as a normal payload read and timed out: {io_err}"
+            ),
+            _ => {}
+        }
+        assert!(elapsed < Duration::from_millis(100));
+        server.join().unwrap();
     }
 
     #[test]

```

## Suggested Fix

```diff
No suggested fix emitted.
```

