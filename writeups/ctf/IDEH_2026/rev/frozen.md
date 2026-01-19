# Frozen Truth - Writeup

**Author:** Dreekos

## Challenge Description

A binary executable containing a hidden flag. The intern thought compiling code would protect it. They were wrong.

## Solution

### Step 1: Identify the Binary

```bash
$ file frozen_truth
frozen_truth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked...
```

### Step 2: Find Telltale Strings

```bash
$ strings frozen_truth | grep -i pyinstaller
Could not load PyInstaller's embedded PKG archive from the executable (%s)
```

The binary is a **PyInstaller-packed Python executable**.

### Step 3: Extract with pyinstxtractor

```bash
$ python3 pyinstxtractor.py frozen_truth
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Found 26 files in CArchive
[+] Possible entry point: challenge.pyc
```

### Step 4: Analyze the Bytecode

Decompilers failed due to Python version mismatch, so I analyzed the `.pyc` directly:

```bash
$ strings challenge.pyc
SHIFT
bytearray
append
decode
...
```

Key finding: A `SHIFT` constant (value = 3) used for a Caesar cipher.

### Step 5: Extract Encoded Data

Using `xxd` to examine the bytecode, I found:
- Const indices: `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 10, 12, ...]`
- Corresponding encoded byte values at offset `0x250+`

### Step 6: Decode

```python
SHIFT = 3
encoded = [76, 71, 72, 75, 126, 102, 114, 112, 115, 108, 111, 108, 
           113, 106, 98, 122, 108, 58, 107, 98, 115, 124, 108, 113, 
           118, 58, 100, 111, 111, 54, 117, 98, 108, 118, 98, 113, 
           114, 58, 98, 118, 54, 102, 120, 117, 54, 128]

decoded = bytes(b - SHIFT for b in encoded)
print(decoded)  # b'IDEH{compiling_wi7h_pyins7all3r_is_no7_s3cur3}'
```

## Flag

```
IDEH{compiling_wi7h_pyins7all3r_is_no7_s3cur3}
```
