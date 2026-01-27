# KrackM3 - KnightCTF 2026 Writeup

**Category:** Reverse Engineering  
**Challenge:** KrackM3  
**Flag:** `KCTF{_R3_iS_FuNR1gHT?_EnjOy_r3_}`

---

## Challenge Overview

We are given a binary file `KrackM3.ks` that prompts for a flag and validates it. The goal is to reverse engineer the validation algorithm and find the correct flag.

```
╔══════════════════════════════════════╗
║              KrackM3                 ║
║          KnightCTF 2026              ║
╚══════════════════════════════════════╝

Enter flag: 
```

---

## Initial Analysis

### File Information

```bash
$ file KrackM3.ks
KrackM3.ks: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```

The binary is a 64-bit ELF executable. Running `strings` reveals some interesting messages:

```
Success! Real flag accepted.
KnightCTF 2026 says: GG!
Success! ...but you won't get points for this flag :P
Failed!
```

This tells us there are two types of "success" - a real flag and a decoy flag.

### Flag Format

Testing the binary reveals:
- Flag must be exactly **32 characters**
- Format: `KCTF{` + 26 characters + `}`
- The validation distinguishes between a "real" flag (returns 1) and a "decoy" flag (returns 2)

---

## Decompilation Analysis

Using Ghidra, we decompiled the main validation logic:

### Main Function (`FUN_00401080`)

```c
undefined8 FUN_00401080(void) {
    // ...
    sVar3 = strcspn(local_408, "\r\n");
    local_408[sVar3] = '\0';
    
    // Anti-debug check
    if (((sVar3 >> 1 ^ sVar3) & 1) != 0) {
        FUN_004012c0();  // Dummy computation
    }
    
    // Validation
    if ((sVar3 == 0x20) && (iVar1 = FUN_00401890(local_408), iVar1 != 0)) {
        FUN_00401320(local_308, local_208);  // Generate S-boxes
        FUN_00401480(local_108);              // Generate XORSHIFT S-box
        iVar1 = FUN_00401590(local_408, local_308, local_208, local_108);
        
        if (iVar1 == 2) {
            puts("Success! ...but you won't get points for this flag :P");
        } else if (iVar1 == 1) {
            puts("Success! Real flag accepted.");
            puts("KnightCTF 2026 says: GG!");
        }
    }
    // ...
}
```

### Format Check (`FUN_00401890`)

```c
bool FUN_00401890(int *param_1) {
    // Check for "KCTF{" prefix and "}" suffix
    if ((*param_1 == 0x4654434b) && ((char)param_1[1] == '{')) {
        return *(char *)((long)param_1 + 0x1f) == '}';
    }
    return false;
}
```

This confirms the flag format: `KCTF{...}` with 32 total characters.

---

## S-Box Generation

### S-Box 1: Fisher-Yates Shuffle (`FUN_00401320`)

```c
void FUN_00401320(char *param_1, long param_2) {
    // Initialize identity permutation [0, 1, 2, ..., 255]
    // Then Fisher-Yates shuffle with XORSHIFT32 PRNG
    
    local_c = 0xf5a4ada5;  // Seed
    
    for (i = 255; i > 0; i--) {
        // XORSHIFT32
        local_c = local_c << 0xd ^ local_c;
        local_c = local_c ^ local_c >> 0x11;
        local_c = local_c ^ local_c << 5;
        
        j = local_c % (i + 1);
        swap(sbox[i], sbox[j]);
    }
    
    // Create inverse S-box
    for (i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = i;
    }
}
```

### S-Box 2: XORSHIFT64 (`FUN_00401480`)

```c
void FUN_00401480(undefined1 *param_1) {
    uVar1 = 0x99ed0ebacd107339;  // Seed
    
    for (i = 0; i < 256; i++) {
        uVar1 = uVar1 ^ uVar1 >> 0xc;
        uVar1 = uVar1 << 0x19 ^ uVar1;
        uVar1 = (uVar1 >> 0x1b ^ uVar1) * 0x2545f4914f6cdd1d;
        param_1[i] = (char)(uVar1 >> 0x38);  // Top byte
    }
}
```

---

## Core Validation Algorithm (`FUN_00401590`)

The validation function is the heart of the challenge. Key observations:

### State Variables

```c
uVar16 = 0x4d;                        // 'M'
cVar13 = 0x42;                        // 'B'  
uVar12 = 0x881db3e005d90dff;          // 64-bit state (r9)
uVar11 = 0xb1eb4606f35cf7f9;          // 64-bit state (r8)
bVar17 = 0;
cVar15 = 0x2f;                        // '/'
uVar8 = 0x0e;

// 16-byte state array initialized from DAT_004022c0
local_48 = {0x42, 0x19, 0xa7, 0x5c, 0xd3, 0x0e, 0x91, 0x2f,
            0x33, 0x77, 0xb1, 0x08, 0xe9, 0x4d, 0x12, 0x6a};
```

### Validation Loop

For each character position (0-31):

1. **Complex Mixing**: Combine input byte with state variables through XOR, rotations, and S-box lookups
2. **Expected Value Lookup**: Call `FUN_00401550` to get expected byte from static arrays
3. **Accumulate Result**: `local_61 |= (computed ^ expected)` 
4. **State Update**: Update all state variables for next iteration

### Expected Values

The expected values are stored in three static arrays:

| Position | Address | Data (hex) |
|----------|---------|------------|
| 0-11 | `DAT_004022a0` | `45 c0 01 fb 1e 3d fd 2e e5 7c cc b6` |
| 12-21 | `DAT_00402290` | `38 a6 14 f3 60 51 fb 1f d1 e3` |
| 22-31 | `DAT_00402280` | `03 f1 32 fe d6 3a 22 f3 ad 65` |

### Return Value Logic

```c
if ((local_63 == 0 || local_64 == 0) || (local_62 == 0)) {
    return 2;  // Decoy flag
} else {
    return (local_61 == 0);  // 1 = Real flag, 0 = Failed
}
```

For the **real flag**, `local_61` must be 0, meaning every computed value must match the expected value.

---

## Solving Strategy

The algorithm is **stateful** - each character affects the state for subsequent characters. This means we cannot solve positions independently.

### Approach: Character-by-Character Brute Force with GDB

Since the algorithm is complex with many state variables, we use GDB to:
1. Run the binary with a test flag
2. Break at the comparison point (`0x40177a`)
3. Check if `r13d` (the computed value) matches the expected value
4. Find the character that produces the correct value at each position

### Key GDB Breakpoint

At address `0x40177a`, register `r13d` contains the computed value that should match the expected byte from the static arrays.

### Solver Script

```python
#!/usr/bin/env python3
"""KrackM3 Batch Solver - Character-by-character brute force using GDB"""

import subprocess
import string

EXPECTED = [
    0x45, 0xc0, 0x01, 0xfb, 0x1e, 0x3d, 0xfd, 0x2e,  # pos 0-7
    0xe5, 0x7c, 0xcc, 0xb6, 0x38, 0xa6, 0x14, 0xf3,  # pos 8-15
    0x60, 0x51, 0xfb, 0x1f, 0xd1, 0xe3, 0x03, 0xf1,  # pos 16-23
    0x32, 0xfe, 0xd6, 0x3a, 0x22, 0xf3, 0xad, 0x65   # pos 24-31
]

def find_char_for_position(base_flag, pos, charset):
    """Find character that produces correct r13d at position."""
    expected = EXPECTED[pos]
    
    for char in charset:
        test_flag = base_flag[:pos] + char + base_flag[pos+1:]
        
        # Use GDB to check r13d value at this position
        gdb_cmds = ['break *0x40177a', 'run']
        for i in range(pos):
            gdb_cmds.append('c')
        gdb_cmds.append('printf "r13d=%02x\\n", $r13d & 0xff')
        
        result = subprocess.run(
            ['gdb', '-batch'] + [arg for c in gdb_cmds for arg in ['-ex', c]] + ['./KrackM3.ks'],
            input=test_flag + '\n', capture_output=True, text=True, timeout=5
        )
        
        for line in result.stdout.split('\n'):
            if line.startswith('r13d='):
                r13d = int(line.split('=')[1], 16)
                if r13d == expected:
                    return char
    return None

# Solve character by character
flag = list("KCTF{" + "_" * 26 + "}")
charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_"

for pos in range(5, 31):
    char = find_char_for_position("".join(flag), pos, charset)
    if char:
        flag[pos] = char
        print(f"[{pos:2d}] '{char}'")

print(f"Flag: {''.join(flag)}")
```

---

## Solution Progress

Running the solver character by character:

```
[*] KrackM3 Batch Solver

[ 5] '_'
[ 6] 'R'
[ 7] '3'
[ 8] '_'
[ 9] 'i'
[10] 'S'
[11] '_'
[12] 'F'
[13] 'u'
[14] 'N'
[15] 'R'
[16] '1'
[17] 'g'
[18] 'H'
[19] 'T'
[20] '?'
[21] '_'
[22] 'E'
[23] 'n'
[24] 'j'
[25] 'O'
[26] 'y'
[27] '_'
[28] 'r'
[29] '3'
[30] '_'

[*] Result: KCTF{_R3_iS_FuNR1gHT?_EnjOy_r3_}
[+] FLAG: KCTF{_R3_iS_FuNR1gHT?_EnjOy_r3_}
```

---

## Verification

```bash
$ echo "KCTF{_R3_iS_FuNR1gHT?_EnjOy_r3_}" | ./KrackM3.ks

╔══════════════════════════════════════╗
║              KrackM3                 ║
║          KnightCTF 2026              ║
╚══════════════════════════════════════╝

Enter flag: Success! Real flag accepted.
KnightCTF 2026 says: GG!
```

---

**Author:** jst3r  
**CTF:** KnightCTF 2026  
