# Deception - Malware Analysis Challenge

**Category:** Misc
**Author:** Primo

## Description

> Our SOC team detected what is believed to be a malware, can you assist them?
> 
> ZIP password: infected
> 
> Note: Not harmful, but be cautious.

## Initial Analysis

We're given a password-protected ZIP file containing `Deception.exe`. After extracting with the password "infected", we have a PE32+ executable:

```bash
$ file Deception.exe
Deception.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections
```

The executable has an unusual 19 sections, which is suspicious for a typical program.

## Static Analysis

### Section Headers

Running `objdump` or manually inspecting the PE headers reveals oddly-named sections:

```
.text, .data, .rdata, .pdata, .xdata, .bss, .idata, .CRT, .tls, .reloc
/4, /19, /31, /45, /57, /70, /81, /97, /113
```

The sections named with `/XX` are unusual. These turn out to be **offsets into the String Table** that resolve to standard DWARF debug sections:
- `/4` → `.debug_aranges`
- `/19` → `.debug_info`
- `/31` → `.debug_abbrev`
- `/45` → `.debug_line`
- etc.

However, all these debug sections share the same characteristics byte: **0x42** (`MEM_DISCARDABLE | MEM_READ`).

### Suspicious Strings

Extracting ASCII strings reveals:
```
WerFault.exe
C:\Windows\System32\
-u -p 8882 -s 9224
advapi32.dll
SystemFunction032
```

This suggests:
1. The malware may inject into `WerFault.exe` (Windows Error Reporting)
2. It uses `SystemFunction032`, an **undocumented API that's actually RC4 encryption**

### Function Analysis

The executable contains a function `_Z13ProcessInjectv` (mangled C++ name for `ProcessInject()`). Examining its disassembly shows it:
1. Allocates a large stack buffer (~0x6A0 bytes)
2. Constructs command-line arguments for WerFault.exe
3. Sets up data for injection

## Payload Reverse Engineering

### Locating the Payload

The `ProcessInject` function references data at offset `0x2488` in the `.rdata` section. This is **position-independent shellcode**.

```bash
$ objdump -D -b binary -m i386:x86-64 payload.bin
```

### API Resolution

The shellcode uses **FNV-1a hashing** with uppercase normalization to dynamically resolve Windows APIs:

```c
// FNV-1a hash (uppercase)
hash = 0x811c9dc5;
for (char c : api_name) {
    c = toupper(c);
    hash = (hash ^ c) * 0x1000193;
}
```

Hashes found in the payload:
- `0xe96ce9ef` → `LoadLibraryA`
- `0x12d71805` → `GetProcAddress`
- `0x6d3d9a28` → (Used for further resolution)

The shellcode:
1. Loads `advapi32.dll` using `LoadLibraryA`
2. Resolves `SystemFunction032` using `GetProcAddress`
3. Uses this function to decrypt a buffer

## Decryption Process

### Extracting the Encrypted Data

The shellcode constructs a buffer on the stack using `movabs` instructions:

```asm
movabs $0xd04944ca51973913,%rax  ; Block 1 (offset 0)
mov    %rax,(%r15)

movabs $0x74278a61f010894b,%rax  ; Block 2 (offset 8)
mov    %rax,0x8(%r15)

movabs $0xb41e269c52b6f950,%rax  ; Block 3 (offset 16)
mov    %rax,0x10(%r15)

movl   $0xed29e2b4,0x17(%r15)    ; Block 4 (offset 23)
```

This creates a 27-byte data buffer:
```
13 39 97 51 ca 44 49 d0 4b 89 10 f0 61 8a 27 74 50 f9 b6 52 9c 26 1e b4 ed 29 e2 b4
```

### Extracting the Key

Another buffer holds the RC4 key (9 bytes):

```asm
movabs $0xff12231287718223,%rax
mov    %rax,(%r14)
movb   $0xee,0x8(%r14)
```

Key: `23 82 71 87 12 23 12 ff ee`

### RC4 Decryption

`SystemFunction032` is Microsoft's undocumented wrapper for RC4. Using standard RC4:

```python
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    res = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(res)

key = bytes([0x23, 0x82, 0x71, 0x87, 0x12, 0x23, 0x12, 0xff, 0xee])
data = bytes([0x13, 0x39, 0x97, 0x51, 0xca, 0x44, 0x49, 0xd0,
              0x4b, 0x89, 0x10, 0xf0, 0x61, 0x8a, 0x27, 0x74,
              0x50, 0xf9, 0xb6, 0x52, 0x9c, 0x26, 0x1e, 0xb4,
              0xb4, 0xe2, 0x29, 0xed])

decrypted = rc4(key, data)
print(decrypted.decode())
```

## Flag

```
IDEH{D3c3pt10n_h1d35_tru7h}
```

## Key Takeaways

1. **Obfuscation Techniques:**
   - Use of string table offsets instead of actual section names
   - Position-independent shellcode in data sections
   - Dynamic API resolution via hashing

2. **Anti-Analysis:**
   - The "B/19" pattern was a red herring (just section header artifacts)
   - Multiple layers of indirection before reaching the actual payload

3. **Encryption:**
   - Abuse of undocumented Windows API (`SystemFunction032`)
   - Simple RC4 with hardcoded key/data

4. **Tools Used:**
   - `objdump` for disassembly
   - `strings` for initial reconnaissance
   - Python for decryption
   - Manual PE parsing for understanding structure
