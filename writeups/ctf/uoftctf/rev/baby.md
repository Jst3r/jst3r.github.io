# UofTCTF 2026 - baby (Rev) Writeup

## Overview
**Challenge**: `baby.py`  
**Goal**: Reverse engineer an obfuscated Python script to find the flag.

## Analysis

The provided `baby.py` script is heavily obfuscated using two main techniques:
1.  **XOR Encoding**: All strings, constants, and even control flow values are hidden behind nested function calls.
2.  **State Machine**: The control flow is flattened into `while True` loops with state transitions managed by XOR checks.

### Deobfuscation

A close inspection of the helper functions reveals they are all variations of XOR operations:

```python
def g0GOsquiD(a, b): return a ^ b
def G0g0sQu1D_116510(a, b): return a ^ b
# ... and so on
```


We can replace all these function calls with the `^` operator or a simple `xor()` function to make the code readable.

### Flag Verification Logic

The valid flag consists of 9 chunks. These chunks are stored in an encrypted matrix called `G0gosQu1D`. The verification process:
1.  Splits the user input into chunks of varying lengths (defined in `sQU1D`).
2.  Shuffles the input chunks using a custom PRNG-based shuffle (`Ggs` function).
3.  Compares the shuffled/processed input chunks against the stored encrypted chunks in `G0gosQu1D`.

### Comparison Vulnerability

The script compares the input against hardcoded XOR-encoded arrays. By extracting these arrays and the XOR key, we can recover the flag directly without fully reversing the state machine logic.

The comparison effectively checks:
```python
input_chunk ^ key == stored_chunk
```
Which means:
```python
input_chunk = stored_chunk ^ key
```

The XOR key was identified as `125` (from the final check constant).

## Solution

1.  **Extract Encrypted Chunks**: We extracted the 9 rows from the `G0gosQu1D` matrix in the source code.
2.  **Decrypt Chunks**: XORed each value in the matrix with `125`.
3.  **Determine Order**: The verification loop uses an indexing array `SqUId` to map the shuffled chunks to their original positions. The sequence found was `[1, 8, 0, 3, 6, 4, 7, 5, 2]`.

### Solver Script

```python
# Decoded chunks from G0gosQu1D (XOR 125)
chunks = [
    'p4TcH_',           # 0
    'uoftctf{d1d_',     # 1
    'XD???}',           # 2
    'd3BuG_',           # 3
    '0n3_sh07_',        # 4
    '4n_1LM_',          # 5
    'r3v_0r_',          # 6
    'th15_w17h_',       # 7
    'y0u_m0nk3Y_'       # 8
]

# Order used by the verification logic
order = [1, 8, 0, 3, 6, 4, 7, 5, 2]

# Reassemble
flag = ''.join(chunks[i] for i in order)
print(flag)
```

## Flag

`uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}`
