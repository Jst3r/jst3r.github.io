# UofTCTF 2026: Bring Your Own Program (BYOP) Writeup

## Challenge Overview
**Points:** 188  
**Category:** Reverse Engineering / Pwn  
**Description:** A custom JavaScript-based bytecode emulator containing a hidden vulnerability in its property access caching mechanism.

## Analysis

### 1. The Emulator
The challenge provided a Node.js application (`chal.js`) that implemented a custom Virtual Machine. The VM parsed hex-encoded bytecode and executed it in a sandboxed environment.
- **Registers:** 64 registers (`r0`-`r63`)
- **Capabilities:** Access to global objects was restricted via a capability system.
- **Scope Chain:** Variables and functions were managed in a prototype-chain-like structure called "Environments" or "Scopes".

### 2. The Scope Structure
The VM initialized a chain of scopes with specific capabilities:
1. `globalEnv` (Caps): Root scope
2. `ioEnv`: Contains I/O functions
   - Key `10`: `readPublicPath` (Slot 0) - Allowed to read `/data/public`
   - Key `4`: `readAbsolutePath` (Slot 1) - **Hidden function** capable of reading any file (e.g., `/flag.txt`).

Critically, the keys were assigned sequentially. When `ioEnv` was built:
- `readPublicPath` (Key 10) was added first -> Index 0
- `readAbsolutePath` (Key 4) was added second -> Index 1

### 3. The Vulnerability: Inline Cache Confusion
The VM implemented an optimization for property lookups called **Inline Caching** (`GET_PROP_CACHED` opcode 0x21).
- **Cache Entry:** Stores `{ shapeId, key, version, depth, slotIndex }`.
- **Validation:** Checks if the shape ID and version match.

The vulnerability was triggered by the `DEOPT` (or `MUTATE`) opcode (0x70):
1. It forces an Environment into "dictionary mode".
2. It **sorts** the properties by their Key ID.
3. It rebuilds the `slots` array based on this sorted order.

**Before Mutation:**
- Slot 0: `readPublicPath` (Key 10)
- Slot 1: `readAbsolutePath` (Key 4)

**After Mutation (Sorted by Key):**
- Slot 0: `readAbsolutePath` (Key 4)  <-- **Moved to Slot 0!**
- Slot 1: `readPublicPath` (Key 10)

**The Bug:**
The cache relies on a global `versionCounter` to invalidate stale entries. However, the version only increments if the environment was "tainted". The exploit path carefully avoided tainting `ioEnv` directly, so the version did not increment.

This created a **Type Confusion / Cache Poisoning** scenario:
1. We cache a lookup for Key 10 (`readPublicPath`) -> Cache says "Go to Slot 0".
2. We mutate the object, swapping the contents of Slot 0.
3. We use the cached lookup again. The VM sees a valid cache entry and reads Slot 0.
4. Slot 0 now holds `readAbsolutePath`.

## Exploit Step-by-Step

1. **Setup:** 
   - Load the `caps` object.
   - Get the `io` environment.

2. **Prime the Cache:**
   - Execute `GET_PROP_CACHED` for Key 10 (`readPublicPath`).
   - The VM records: "Key 10 is at Slot 0".

3. **Trigger the Swap:**
   - Execute `DEOPT` on the `io` environment.
   - The scope transitions to dictionary mode and sorts keys.
   - `readAbsolutePath` (Key 4) sorts before Key 10, taking over Slot 0.
   - The global version counter **does not change** because we haven't "tainted" the scope in a way the VM tracks.

4. **Execute Payload:**
   - Execute `GET_PROP_CACHED` for Key 10 again.
   - Cache Hit! The VM returns the value at Slot 0.
   - We get `readAbsolutePath`.
   - Call it with `/flag.txt`.

## Solution Script
The final bytecode payload performs the sequence above.

```python
#!/usr/bin/env python3
from pwn import *
import struct

# Opcode definitions
LOAD_CONST = 0x01
LOAD_CAP   = 0x02
GET_PROP   = 0x20
GET_PROP_C = 0x21
CALL       = 0x30
RET        = 0x31
JMP        = 0x60
JMP_IF     = 0x61
DEOPT      = 0x70

# ... (Helper functions for encoding strings/floats) ...

# Exploit Bytecode construction
# 1. Get IO object
# 2. Get readPublicPath (Key 10) -> Caches Slot 0
# 3. DEOPT IO object -> Swaps readAbsolute (Key 4) into Slot 0
# 4. Get readPublicPath (Key 10) -> Cache Hit returns Slot 0 (readAbsolute)
# 5. Call with "/flag.txt"
```

**Flag:** `uoftctf{c4ch3_m3_1n11n3_h0w_80u7_d4h??}`
