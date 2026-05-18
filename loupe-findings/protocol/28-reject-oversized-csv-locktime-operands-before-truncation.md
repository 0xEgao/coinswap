# Reject oversized CSV locktime operands before truncation

- **Finding ID:** 28
- **Severity:** medium
- **State:** awaiting_approval
- **Scanner:** llm-code-review
- **File:** src/protocol/contract.rs
- **Lines:** 323-337
- **CWE:** CWE-681
- **Fingerprint:** b5191351520c3c197a714409f2fba69ddd36d83ca7930fd7d4fe86565db31db2

## Description

`read_contract_locktime` parses the CSV operand from a contract redeem script as `u16`, but accepts both 2- and 3-byte pushes and then splits only the first two bytes. A malicious maker can therefore build a contract script whose actual `OP_CHECKSEQUENCEVERIFY` argument is larger than 65535 while the low 16 bits equal the taker's requested refund locktime. The taker-side legacy verification path reads this helper's truncated value and compares it to the requested `refund_locktime`, so such a script can pass that check while enforcing a much longer on-chain timelock. In abort/recovery cases this delays the victim's timelock spend beyond the negotiated window and can leave funds unavailable while the counterparty's timing assumptions no longer hold. I checked prior findings with `read_contract_locktime three byte truncates u16 CSV locktime` and `contract locktime truncation read_contract_locktime`; neither matched.

## Proof of Concept

```diff
diff --git a/src/protocol/contract.rs b/src/protocol/contract.rs
index 8b6f0d2..f0a1b2c 100644
--- a/src/protocol/contract.rs
+++ b/src/protocol/contract.rs
@@ -616,6 +616,48 @@ mod test {
         assert_eq!(read_contract_locktime(&contract_script).unwrap(), locktime);
     }
 
+    #[test]
+    fn read_contract_locktime_rejects_three_byte_overflow() {
+        let hashvalue = Hash160::from_slice(&[1u8; 20]).unwrap();
+
+        let pub_hashlock = PublicKey::from_str(
+            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
+        )
+        .unwrap();
+
+        let pub_timelock = PublicKey::from_str(
+            "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef",
+        )
+        .unwrap();
+
+        let contract_script = Builder::new()
+            .push_opcode(opcodes::all::OP_SIZE)
+            .push_opcode(opcodes::all::OP_SWAP)
+            .push_opcode(opcodes::all::OP_HASH160)
+            .push_slice(hashvalue.to_byte_array())
+            .push_opcode(opcodes::all::OP_EQUAL)
+            .push_opcode(opcodes::all::OP_IF)
+            .push_key(&pub_hashlock)
+            .push_int(32)
+            .push_int(0)
+            .push_opcode(opcodes::all::OP_ELSE)
+            .push_key(&pub_timelock)
+            .push_int(0)
+            .push_slice([0x10u8, 0x00, 0x01])
+            .push_opcode(opcodes::all::OP_ENDIF)
+            .push_opcode(opcodes::all::OP_CSV)
+            .push_opcode(opcodes::all::OP_DROP)
+            .push_opcode(opcodes::all::OP_ROT)
+            .push_opcode(opcodes::all::OP_EQUALVERIFY)
+            .push_opcode(opcodes::all::OP_CHECKSIG)
+            .into_script();
+
+        assert!(
+            read_contract_locktime(&contract_script).is_err(),
+            "three-byte CSV locktime operands must not be truncated to u16"
+        );
+    }
+
     #[test]
     fn test_pubkey_extraction_from_2of2_multisig() {
         // Create pubkeys to contruct 2of2 multi

```

## Suggested Fix

```diff
No suggested fix emitted.
```

