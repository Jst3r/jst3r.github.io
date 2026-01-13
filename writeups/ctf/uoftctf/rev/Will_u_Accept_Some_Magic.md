# Magic - UofTCTF 2026 Writeup

## Challenge Overview
**Category**: Reverse Engineering / Web
**Files**: `program.wasm`, `runner.mjs`

The challenge provides a WebAssembly binary (`program.wasm`) and a Node.js runner. The goal is to find the correct password. When run, the program prompts for a password and checks it, printing "CORRECT!" or "INCORRECT".

## Initial Analysis
We started by converting the WASM binary to a readable text format (`.wat`) using `wasm2wat`.
Inspection revealed that the binary was likely compiled from Kotlin (presence of Kotlin-specific type structures and string patterns).

The main entry point was identified as `_initialize` (func 248), which contained the primary loop structure for processing the password:
- It processes a 30-character input.
- It calculates a complex state evolution using a Linear Congruential Generator (LCG) and bitwise operations.
- The state updates involved rotated arithmetic and XOR operations unique to each of the 30 positions.

## The Rabbit Hole: LCG & XOR Logic
Initial reverse engineering focused on the complex math inside the loop. The code appeared to:
1. Initialize a seed `1699776000000000000`.
2. For each position, select a specific LCG function (Type 18) using a `br_table`.
3. Apply LCG transformations, rotations, and XORs to generate a "node" and a "character".
4. Verify the input against this generated character logic.

We spent significant time simulating this LCG logic in Python, handling 64-bit signed/unsigned arithmetic quirks and implementing a full WASM stack machine to handle rotations. However, the generated passwords (`C,,4;...`, `CJ4GI...`) were always rejected.

## The Breakthrough: "Where did my heap go?"
The challenge hint "Where did my heap go?" suggested observing how data is stored. In WasmGC (Garbage Collection), data is often stored in structs and globals rather than a linear memory heap.

We examined the `Global` variables mapped to each password position. Each position map (e.g., Position 1 -> Global 184) utilized a `struct` (Type 27) containing references to several functions.
- **Field 3**: The complex LCG function (Type 18).
- **Field 2**: A simple function (Type 9) that returned a constant integer.

Upon closer inspection of these "Type 9" functions:
- Position 0's function returned `1` (unclear, maybe SOH?).
- **Position 1's function returned `81`**. Constant `81` corresponds to the ASCII character **'Q'**.
- **Position 6's function returned `82`**. Constant `82` corresponds to **'R'**.

This was the smoking gun. The complex LCG math was likely an obfuscation or verification mechanism (checking if the loop ran exactly $N$ times), while the **Loop Count itself was the password character**.

## Solution Script
The following script extracts the hidden character codes directly from the WASM binary by parsing the Type 9 functions linked to each Global position.

```python
import re

def solve():
    with open('program.wat', 'r') as f:
        content = f.read()

    # 1. Parse all Type 9 functions (The "Count" functions)
    # These functions are defined as `(type 9) ... i32.const VALUE`
    count_funcs = {}
    t9_pattern = r'\(func \(;(\d+);\) \(type 9\).*?\n(.*?)(?=\n  \(func|\n\))'
    matches = re.findall(t9_pattern, content, re.DOTALL)
    
    for fid, body in matches:
        m = re.search(r'i32\.const\s+(\d+)', body)
        if m:
            count_funcs[int(fid)] = int(m.group(1))

    # 2. Map Globals to their "Count" function
    # Pattern: global ... ref.func ... ref.func (COUNT_FID) ...
    # Field 2 (3rd ref.func) is the Count function.
    global_map = {}
    g_pattern = r'\(global \(;(\d+);\) \(ref 27\).*?ref\.func \d+ ref\.func (\d+)'
    g_matches = re.findall(g_pattern, content)
    
    for g_id, count_fid in g_matches:
        global_map[int(g_id)] = int(count_fid)

    # 3. Position to Global Mapping (Extracted from func 248)
    # Pos 0 -> Global 134, Pos 1..29 -> 184..212
    pos_to_global = [134] + list(range(184, 213))

    password = []
    
    for pos in range(30):
        g_id = pos_to_global[pos]
        if g_id in global_map:
            count_fid = global_map[g_id]
            # The "Count" is actually the ASCII value of the password char
            char_code = count_funcs.get(count_fid, 0)
            password.append(chr(char_code))

    final_flag = "".join(password)
    print(f"Reconstructed Flag: uoftctf{{{final_flag}}}")

if __name__ == '__main__':
    solve()
```

### Output
```
Reconstructed Flag: uoftctf{0QGFCBREENDFDONZRC39BDS3DMEH3E}
```
