# E4sy P3asy - KnightCTF 2026 Writeup

**Category:** Reverse Engineering  
**Flag:** `KCTF{_L0TS_oF_bRuTE_foRCE_:P}`

---

## Challenge Overview

We're given a 64-bit ELF binary called `E4sy_P3asy.ks`. When executed, it prompts for a flag and validates it:

```
========================================
   E4sy P3asy - KnightCTF 2026
========================================
[*] Enter the flag to prove your worth!

flag> test
Try again!
```

---

## Initial Analysis

### File Information

```bash
$ file E4sy_P3asy.ks
E4sy_P3asy.ks: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

The binary is **stripped**, meaning symbol names are removed.

### String Analysis

```bash
$ strings E4sy_P3asy.ks | grep -i flag
flag> 
FLAG{
KCTF{
GoogleCTF{
```

Interesting findings:
- Multiple flag formats are checked (`FLAG{`, `KCTF{`, `GoogleCTF{`)
- There's a message about a "decoy flag from a different universe"

### Library Functions

Looking at the PLT (Procedure Linkage Table):

```
EVP_MD_CTX_new
EVP_md5
EVP_DigestInit_ex
EVP_DigestUpdate
EVP_DigestFinal_ex
EVP_MD_CTX_free
strcmp
strncmp
snprintf
```

The binary uses **OpenSSL's EVP interface for MD5 hashing**. This is a key observation!

---

## Reverse Engineering

### Identifying the Validation Logic

By disassembling the binary, I found two main validation paths:

1. **GoogleCTF/FLAG{} path** - A decoy that accepts 13 characters
2. **KCTF{} path** - The real flag that accepts 23 characters

### The Hashing Scheme

From the disassembly at address `0x13f7` and `0x150b`, I identified the format string used:

```
%s%zu%c
```

This means each character is validated using: `MD5(salt + index + character)`

Where:
- `salt` = A hardcoded salt string
- `index` = Position of the character (0-indexed)
- `character` = The actual character being validated

### Extracting the Salt

By analyzing the assembly instructions that build the salt string:

**For KCTF{} (at 0x1493-0x14bd):**
```asm
movl   $0x67696e4b,0x50(%rsp)    # "Knig"
movw   $0x7468,0x54(%rsp)         # "ht"
movabs $0x363230325f465443,%rax  # "CTF_2026"
mov    %rax,0x56(%rsp)
movb   $0x5f,0x5e(%rsp)           # "_"
movl   $0x746c4073,0x5f(%rsp)     # "s@lt"
```

Reconstructed salt: **`KnightCTF_2026_s@lt`**

### Extracting the Target Hashes

The `.rodata` section contains 23 MD5 hashes for the KCTF flag (and 13 for the decoy):

```
781011edfb2127ee5ff82b06bb1d2959
4cf891e0ddadbcaae8e8c2dc8bb15ea0
d06d0cbe140d0a1de7410b0b888f22b4
d44c9a9b9f9d1c28d0904d6a2ee3e109
e20ab37bee9d2a1f9ca3d914b0e98f09
... (23 total)
```

---

## Exploitation Strategy

Since each character is hashed independently with a known salt and index, we can **brute-force each character separately**!

The validation formula is:
```
MD5("KnightCTF_2026_s@lt" + str(index) + char) == target_hash
```

### Solver Script

```python
#!/usr/bin/env python3
import hashlib
import string

kctf_salt = "KnightCTF_2026_s@lt"

kctf_hashes = [
    "781011edfb2127ee5ff82b06bb1d2959",
    "4cf891e0ddadbcaae8e8c2dc8bb15ea0",
    "d06d0cbe140d0a1de7410b0b888f22b4",
    # ... all 23 hashes
]

charset = string.printable.strip()

def crack_char(salt, index, target_hash):
    for c in charset:
        data = f"{salt}{index}{c}"
        md5_hash = hashlib.md5(data.encode()).hexdigest()
        if md5_hash == target_hash:
            return c
    return "?"

flag = ""
for i, target_hash in enumerate(kctf_hashes):
    flag += crack_char(kctf_salt, i, target_hash)

print(f"KCTF{{{flag}}}")
```

### Output

```
[ 0] 781011edfb2127ee5ff82b06bb1d2959 -> '_'
[ 1] 4cf891e0ddadbcaae8e8c2dc8bb15ea0 -> 'L'
[ 2] d06d0cbe140d0a1de7410b0b888f22b4 -> '0'
[ 3] d44c9a9b9f9d1c28d0904d6a2ee3e109 -> 'T'
[ 4] e20ab37bee9d2a1f9ca3d914b0e98f09 -> 'S'
[ 5] d0beea4ce1c12190db64d10a82b96ef8 -> '_'
[ 6] ac87da74d381d253820bcf4e5f19fcea -> 'o'
[ 7] ce3f3a34a04ba5e5142f5db272b6cb1f -> 'F'
[ 8] 13843aca227ef709694bbfe4e5a32203 -> '_'
[ 9] ca19a4c4eb435cb44d74c1e589e51a10 -> 'b'
[10] 19edec8e46bdf97e3018569c0a60baa3 -> 'R'
[11] 972e078458ce3cb6e32f795ff4972718 -> 'u'
[12] 071824f6039981e9c57725453e005beb -> 'T'
[13] 66cd6098426b0e69e30e7fa360310728 -> 'E'
[14] f78d152df5d277d0ab7d25fb7d1841f3 -> '_'
[15] dba3a36431c4aaf593566f7421abaa22 -> 'f'
[16] 8820bbdad85ebee06632c379231cfb6b -> 'o'
[17] 722bc7cde7d548b81c5996519e1b0f0f -> 'R'
[18] c2862c390c830eb3c740ade576d64773 -> 'C'
[19] 94da978fe383b341f9588f9bab246774 -> 'E'
[20] bea3bb724dbd1704cf45aea8e73c01e1 -> '_'
[21] ade2289739760fa27fd4f7d4ffbc722d -> ':'
[22] 3cd0538114fe416b32cdd814e2ee57b3 -> 'P'

Flag: KCTF{_L0TS_oF_bRuTE_foRCE_:P}
```

---

## Verification

```bash
$ echo 'KCTF{_L0TS_oF_bRuTE_foRCE_:P}' | ./E4sy_P3asy.ks
========================================
   E4sy P3asy - KnightCTF 2026
========================================
[*] Enter the flag to prove your worth!

flag> Good job! You got it!
```
---
**Flag: `KCTF{_L0TS_oF_bRuTE_foRCE_:P}`**
