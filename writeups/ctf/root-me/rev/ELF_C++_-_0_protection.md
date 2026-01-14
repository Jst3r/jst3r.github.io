
---
# ELF C++ - 0 protection

## Challenge Description
We are given a 32-bit ELF executable named `ch25.bin`. The goal is to reverse engineer it and find the valid password.

## Static Analysis
Running `file` confirms it's a 32-bit ELF executable.
```bash
$ file ch25.bin
ch25.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, ...
```

Running `strings` reveals some interesting C++ related strings and potential output messages:
```
Bravo, tu peux valider en utilisant ce mot de passe...
Congratz. You can validate with this password...
Password incorrect.
```

## Disassembly
Disassembling `main` with `objdump` shows the program logic:
1.  It checks if an argument is provided (`argc > 1`).
2.  It initializes two `std::string` objects using data from `.rodata`.
3.  It calls a function likely named `plouf` (symbol `_Z5ploufSsSs`) taking these two strings.
4.  It compares the result of `plouf` with the first command-line argument (`argv[1]`).

### The `plouf` Function
The `plouf` function implements a custom XOR encryption:
-   It iterates over the bytes of the first string (which acts as the ciphertext).
-   It uses the second string as a key.
-   The decryption logic is effectively: `decoded[i] = ciphertext[i] ^ key[i % len(key)]`.

### Extracted Data
From the `.rodata` section, we extracted the raw bytes for the two strings:

**Key:** `\x18\xd6\x15\xca\xfa\x77`

**Ciphertext:** `\x50\xb3\x67\xaf\xa5\x0e\x77\xa3...` (rest of the bytes)

## Solution
I wrote a Python script to reproduce the logic and decrypt the flag.

```python
def solve():
    # Key extracted from binary
    key = b"\x18\xd6\x15\xca\xfa\x77"
    
    # Ciphertext extracted from binary
    ciphertext = [
        0x50, 0xb3, 0x67, 0xaf, 0xa5, 0x0e, 0x77, 0xa3,
        0x4a, 0xa2, 0x9b, 0x01, 0x7d, 0x89, 0x61, 0xa5,
        0xa5, 0x02, 0x76, 0xb2, 0x70, 0xb8, 0x89, 0x03,
        0x79, 0xb8, 0x71, 0x95, 0x9b, 0x28, 0x74, 0xbf,
        0x61, 0xbe, 0x96, 0x12, 0x47, 0x95, 0x3e, 0xe1,
        0xa5, 0x04, 0x6c, 0xa3, 0x73, 0xac, 0x89
    ]

    result = ""
    for i, byte in enumerate(ciphertext):
        k = key[i % len(key)]
        result += chr(byte ^ k)
    
    print(f"Flag: {result}")

if __name__ == "__main__":
    solve()
```

Running the script gives the flag:

**Flag:** `Here_you_have_to_understand_a_little_C++_stuffs`
