# Synthetic State - CTF Writeup

**Category:** Reverse Engineering  
**Points:** 500  
**Flag:** `IDEH{vm_sch3m4t1cs}`

---

## Challenge Description

> We live in a world where everything virtual

A 64-bit ELF binary that implements a custom virtual machine with cryptographic operations. The challenge requires understanding the VM architecture, reversing its bytecode, and bypassing the license validation to extract the flag.

---

## Initial Analysis

```bash
$ file Synthetic
Synthetic: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
```

Running the binary prompts for a license key:
```bash
$ ./Synthetic
license> test
Error
```

---

## Binary Structure Overview

The binary contains several key components:

| Address | Description |
|---------|-------------|
| `0x2020` | VM bytecode (104 bytes) |
| `0x20c0` | Expected state (first 16 bytes) |
| `0x20d0` | Expected state (last 16 bytes) |
| `0x20e0` | Encrypted flag (24 bytes) |
| `0x20f8` | VM opcode jump table |

---

## Virtual Machine Architecture

### VM State Structure
```c
struct vm_state {
    uint32_t registers[16];  // r0-r15 at offset 0x00
    uint32_t pc;             // Program counter at 0x40
    uint32_t stack_ptr;      // Stack pointer at 0x44
    uint32_t cmp_flag;       // Comparison flag at 0x48
    uint32_t error_flag;     // Error flag at 0x4c
    uint32_t iteration;      // Iteration counter at 0x50
    uint8_t  stack[256];     // Stack at 0x54
};
```

### Opcode Table

| Opcode | Mnemonic | Description |
|--------|----------|-------------|
| `0x00` | EXIT | Terminate VM execution |
| `0x10` | LOAD_IMM | Load 32-bit immediate into register |
| `0x11` | ADD_IMM | Add immediate to register |
| `0x12` | XOR_IMM | XOR immediate with register |
| `0x13` | SUB | Subtract register from register |
| `0x14` | MUL | Multiply registers |
| `0x15` | ADD | Add registers |
| `0x20` | XOR | XOR registers |
| `0x21` | AND | AND registers |
| `0x22` | OR | OR registers |
| `0x23` | SHR | Shift right by immediate |
| `0x24` | SHL | Shift left by immediate |
| `0x25` | ROR | Rotate right by immediate |
| `0x26` | ROL | Rotate left by immediate |
| `0x27` | CMP | Compare registers (sets flag) |
| `0x28` | MOV | Move register to register |
| `0x30` | JMP | Unconditional jump |
| `0x31` | JZ | Jump if zero (cmp_flag == 1) |
| `0x32` | JNZ | Jump if not zero (cmp_flag == 0) |
| `0x40` | PUSH | Push register to stack |
| `0x41` | POP | Pop from stack to register |
| `0x50` | SBOX | Apply AES S-box transformation |
| `0x60` | QUARTERROUND | ChaCha20 quarter round operation |

### Key Cryptographic Operations

#### ChaCha20 Quarter Round (Opcode 0x60)
```c
void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROL(*d, 16);
    *c += *d; *b ^= *c; *b = ROL(*b, 12);
    *a += *b; *d ^= *a; *d = ROL(*d, 8);
    *c += *d; *b ^= *c; *b = ROL(*b, 7);
}
```

#### AES S-box (Opcode 0x50)
Applies the AES S-box substitution to each byte of a 32-bit register using the formula:
```c
byte transform(byte x) {
    byte y = (x << 3) ^ (x >> 2) ^ x;
    y = y * 0x3d ^ 0xa7;
    byte z = (y << 1) ^ (y >> 4) ^ y;
    return z;
}
```

---

## Execution Flow

### 1. Input Processing
The binary reads a license key from stdin and initializes the first 8 VM registers (r0-r7) with the input bytes.

### 2. VM Execution
The VM executes the bytecode which performs:
- ChaCha20 quarter rounds on the registers
- AES S-box transformations
- Various arithmetic/logical operations
- Loop iterations controlled by comparison and conditional jumps

### 3. Post-VM Processing
After VM execution, the result undergoes:

1. **SSE Byte Transpose** - Rearranges bytes using SIMD instructions
2. **Mixing Loop 1** - Interleaves bytes between halves
3. **Mixing Loop 2** - Additional byte permutation

### 4. State Validation
The final state is compared against expected values at `0x20c0`/`0x20d0`:
```
Expected state (32 bytes):
0x224a3a3b 0x8ac72cb4 0x0abbcaf2 0xd87f5e1d
0x4f0e4a1e 0xc232b0f0 0x8c8a3b1d 0x58521012
```

### 5. Key Derivation & Decryption
If validation passes, a 128-bit XTEA key is derived:
```c
key[0] = state[0] ^ state[5];
key[1] = state[6] + state[1];
key[2] = ROL(state[4], 7) + state[3];
key[3] = ROL(state[7], 13) ^ state[2];
```

The encrypted flag at `0x20e0` is then decrypted using XTEA:
```
Encrypted flag: 52c4f02574f8b69c86c67df7a9abd737fb0dda535f625133
```

---

## Solution Strategy

Since finding the correct input that produces the expected state would require brute-forcing through complex cryptographic transformations, the solution involves **binary patching** to bypass the validation and force the correct state for key derivation.

### Patch Details

Two modifications are needed:

1. **NOP the validation jump** at `0x1413`:
   - Original: `jne 0x15a2` (6 bytes)
   - Patched: `nop` × 6

2. **Load expected state directly** at `0x13ca-0x13e6`:
   - Original code loads computed state from stack
   - Patched code loads expected state from `0x20c0`/`0x20d0`:

```asm
; Original (loads from stack)
movdqa 0x20(%rsp),%xmm0
movdqa 0x30(%rsp),%xmm1
movaps %xmm0,(%rsp)
...

; Patched (loads from expected data)
movdqa 0xcee(%rip),%xmm0   ; loads from 0x20c0
movdqa 0xcf6(%rip),%xmm1   ; loads from 0x20d0
movaps %xmm0,(%rsp)
movaps %xmm1,0x10(%rsp)
nop; nop; nop; nop
```

### Patch Script

```python
#!/usr/bin/env python3
data = bytearray(open("Synthetic", "rb").read())

# NOP the jne at 0x1413
for i in range(6):
    data[0x1413 + i] = 0x90
print("Patched jne at 0x1413")

# Replace 0x13ca-0x13e6 with code that loads expected state
new_code = bytes([
    0x66, 0x0f, 0x6f, 0x05, 0xee, 0x0c, 0x00, 0x00,  # movdqa 0xcee(%rip),%xmm0
    0x66, 0x0f, 0x6f, 0x0d, 0xf6, 0x0c, 0x00, 0x00,  # movdqa 0xcf6(%rip),%xmm1
    0x0f, 0x29, 0x04, 0x24,                          # movaps %xmm0,(%rsp)
    0x0f, 0x29, 0x4c, 0x24, 0x10,                    # movaps %xmm1,0x10(%rsp)
    0x90, 0x90, 0x90, 0x90                           # nops
])

for i, b in enumerate(new_code):
    data[0x13ca + i] = b

open("Synthetic_fixed", "wb").write(data)
print("Created Synthetic_fixed")
```

---

## Getting the Flag

```bash
$ chmod +x Synthetic_fixed
$ ./Synthetic_fixed <<< "anything"
license> IDEH{vm_sch3m4t1cs}
```

---

## Key Takeaways

1. **Custom VM Analysis** - Understanding the VM opcode table and execution model was crucial
2. **Cryptographic Primitives** - The VM used ChaCha20 quarter rounds and AES S-box operations
3. **Binary Patching** - Instead of reversing the full transformation, patching the binary to use expected values was more efficient
4. **XTEA Decryption** - The flag was encrypted with XTEA using a key derived from the validated state

---


## Flag

```
IDEH{vm_sch3m4t1cs}
```
