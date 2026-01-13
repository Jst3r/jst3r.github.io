# Symbol of Hope - UofTCTF 2026 Writeup

**Category:** Reverse Engineering  
**Points:** 46  
**Solves:** 196  
**Author:** SteakEnthusiast

## Challenge Description

> Like a beacon in the dark, Go Go Squid! stands as a symbol of hope to those who seek to be healed.

## TL;DR

The binary is UPX packed and contains 4200+ transformation functions that operate on each input byte independently. Using an `LD_PRELOAD` hook to intercept `memcmp`, we can bruteforce each byte position to find the flag.

**Flag:** `uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}`

---

## Initial Analysis

### File Identification

```bash
$ file checker
checker: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), statically linked, no section header
```

The binary is statically linked with no section header - classic signs of packing.

### Identifying the Packer

```bash
$ strings checker | grep -i upx
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $
```

Confirmed: **UPX 3.96** packed binary.

### Unpacking

```bash
$ upx -d checker -o checker_unpacked
                       Ultimate Packer for eXecutables
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    576699 <-    117368   20.35%   linux/amd64   checker_unpacked

Unpacked 1 file.
```

Binary went from 117KB to 576KB after unpacking.

---

## Binary Analysis

### Main Function (Decompiled)

```c
undefined8 main(void) {
    char input[48];
    char buffer[56];
    
    if (fgets(buffer, 0x2e, stdin) == NULL) {
        puts("No");
    } else {
        size_t len = strcspn(buffer, "\r\n");
        if (len == 0x2a) {  // 42 characters
            for (int i = 0; i < 0x2a; i++) {
                input[i] = buffer[i];
            }
            f_0(input);  // Start transformation chain
        } else {
            puts("No");
        }
    }
    return 0;
}
```

Key observations:
- Input must be exactly **42 characters**
- Calls `f_0()` which starts a chain of transformation functions

### Transformation Chain

The binary contains **4200+ functions** (`f_0` through `f_4199`) that form a chain. Each function:
1. Applies a transformation to a specific byte position
2. Calls the next function in the chain

Example transformations found:
- `add` - Add constant to byte
- `sub` - Subtract constant from byte
- `xor` - XOR with constant
- `not` - Bitwise NOT
- `rol8/ror8` - Rotate left/right by N bits
- `mul` - Multiply by constant (mod 256)
- `neg` - Two's complement negation

### Final Comparison

The last function `f_4200` compares the transformed input with expected bytes:

```c
// At address 0x40e66
memcmp(transformed_input, expected, 42);
```

Expected bytes located at `0x41020`:
```
e5 b6 89 60 c2 33 04 fb cb 37 d1 bc 51 1c 89 7b
b2 6d 34 ae ae b4 8f 23 1f 33 0c 5c 12 ab 51 51
6d 08 c9 d0 6d e2 f0 fc 72 40
```

---

## Solution Approach

### Initial Attempts (Failed)

1. **Static Operation Extraction**: Tried to extract all 4200 operations from disassembly using regex patterns. Managed to extract ~4100 operations but was still missing some, leading to incorrect simulation results.

2. **Z3 Symbolic Execution**: Created Z3 constraints for all extracted operations, but got UNSAT due to missing/incorrect operations.

### Successful Approach: Dynamic Analysis with LD_PRELOAD

#### Step 1: Create memcmp Hook

Created a shared library to intercept `memcmp` and dump the arguments:

```c
// memcmp_hook.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int memcmp(const void *s1, const void *s2, size_t n) {
    static int (*real_memcmp)(const void*, const void*, size_t) = NULL;
    if (!real_memcmp) {
        real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    }
    
    if (n == 42) {
        fprintf(stderr, "TRANSFORMED: ");
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, "%02x", ((unsigned char*)s1)[i]);
        fprintf(stderr, "\n");
        
        fprintf(stderr, "EXPECTED: ");
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, "%02x", ((unsigned char*)s2)[i]);
        fprintf(stderr, "\n");
    }
    
    return real_memcmp(s1, s2, n);
}
```

Compile: `gcc -shared -fPIC -o memcmp_hook.so memcmp_hook.c -ldl`

#### Step 2: Differential Analysis

Tested whether input bytes affect each other:

```bash
$ echo 'uoftctf{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}' | \
  LD_PRELOAD=./memcmp_hook.so ./checker_unpacked 2>&1
TRANSFORMED: 65b68960c23304fb4913e792acef6793...
```

Changed single bytes and observed which output positions changed:
- **Result**: Each input byte independently affects only its corresponding output byte!

This means we can solve each byte position separately.

#### Step 3: Byte-by-Byte Bruteforce

```python
#!/usr/bin/env python3
import subprocess
import os
import string

def run_checker(flag_bytes):
    result = subprocess.run(
        ['./checker_unpacked'],
        input=flag_bytes + b'\n',
        env={**os.environ, 'LD_PRELOAD': './memcmp_hook.so'},
        capture_output=True
    )
    for line in result.stderr.decode().split('\n'):
        if line.startswith('TRANSFORMED:'):
            return bytes.fromhex(line.split(':')[1].strip())
    return None

expected = bytes.fromhex("e5b68960c23304fbcb37d1bc511c897b"
                         "b26d34aeaeb48f231f330c5c12ab5151"
                         "6d08c9d06de2f0fc7240")

flag = bytearray(42)
printable = string.ascii_letters + string.digits + "_{}"

for pos in range(42):
    for c in printable:
        test = bytearray(b"A" * 42)
        test[pos] = ord(c)
        output = run_checker(bytes(test))
        if output and output[pos] == expected[pos]:
            flag[pos] = ord(c)
            print(f"Position {pos}: '{c}'")
            break

print(f"FLAG: {bytes(flag).decode()}")
```

### Result

```
Position  0: 'u'
Position  1: 'o'
Position  2: 'f'
Position  3: 't'
Position  4: 'c'
Position  5: 't'
Position  6: 'f'
Position  7: '{'
Position  8: '5'
Position  9: 'y'
Position 10: 'm'
...
Position 41: '}'

FLAG: uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}
```

### Verification

```bash
$ echo 'uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}' | ./checker_unpacked
Yes
```

---

## Flag

```
uoftctf{5ymb0l1c_3x3cu710n_15_v3ry_u53ful}
```

**Decoded:** "symbolic_execution_is_very_useful" (leetspeak)

---

## Lessons Learned

1. **Don't overcomplicate it**: I spent significant time trying to extract all 4200 operations statically. The dynamic approach with `LD_PRELOAD` was much simpler.

2. **Differential analysis is powerful**: Testing how changes propagate through the binary revealed that bytes are independent, enabling a simple bruteforce.

3. **The irony**: The flag says "symbolic_execution_is_very_useful" but I solved it with bruteforce instead! Though symbolic execution (angr/Z3) would work if operations were extracted correctly.

---

## Tools Used

- `upx` - Unpacker
- `objdump` / Ghidra - Disassembly and decompilation
- `gcc` - Compiling LD_PRELOAD hook
- Python 3 - Solver script
- `ltrace` - Library call tracing
