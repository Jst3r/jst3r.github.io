# Reversing ELF - TryHackMe

A beginner-friendly room focused on reverse engineering ELF binaries on Linux.

---

## Crackme1

```bash
$ ./crackme1
flag{not_that_kind_of_elf}
```

## Crackme2

```bash
$ strings crackme2 | grep password
Usage: %s password
super_secret_password
$ ./crackme2 super_secret_password
Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
```

## Crackme3

```bash
$ strings crackme3
...
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
...
$ echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d
f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
$ ./crackme3 f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
Correct password!
```

**Flag:** `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`

---

## Crackme4


**Method 1: Dynamic Analysis (Easy Way)**

Using `ltrace` allows us to see the library calls made by the program. Since it uses `strcmp` to compare the input with the real password, we can see the password in cleartext.

```bash
$ ltrace ./crackme4 test
__libc_start_main(0x400716, 2, 0x7ffd9e69c588, 0x400760 <unfinished ...>
strcmp("my_m0r3_secur3_pwd", "test")              = -7
printf("password "%s" not OK\n", "test"password "test" not OK
)          = 25
+++ exited (status 0) +++
```

**Method 2: Static Analysis (Hard Way)**

Disassembling with `objdump -M intel -d crackme4` revealed that `compare_pwd` constructs a string on the stack and calls `get_pwd`.
The `get_pwd` function XORs each byte of the string with `0x24`.

**Reconstruction:**
1. Extracted hardcoded bytes from `compare_pwd`.
2. XORed them with `0x24`.

```python
# Extracted bytes from movabs/stacks
bytes_list = [0x49, 0x5d, 0x7b, 0x49, 0x14, 0x56, 0x17, 0x7b, 0x57, 0x41, 0x47, 0x51, 0x56, 0x17, 0x7b, 0x54, 0x53, 0x40]
# XOR with 0x24
print("".join([chr(b ^ 0x24) for b in bytes_list]))
# Output: my_m0r3_secur3_pwd
```

```bash
$ ./crackme4 my_m0r3_secur3_pwd
password OK
```


**Password:** `my_m0r3_secur3_pwd`

---

## Crackme5

**Method 1: Dynamic Analysis (Easy Way)**

Just like Crackme4, we can use `ltrace` to peek at library calls. Even though there is a custom comparison function, it eventually calls `strncmp`.

```bash
$ echo "test" | ltrace ./crackme5 
...
strncmp("test", "OfdlDSA|3tXb32~X3tX@sX`4tXtz", 28) = 1
...
```
The string `OfdlDSA|3tXb32~X3tX@sX`4tXtz` is revealed directly!

**Method 2: Static Analysis (Hard Way)**

The binary asks for input and compares it against a hardcoded string.
Disassembly reveals a custom `strcmp_` function that XORs the input with a global `key` before comparing.
The `key` is 0 by default. A hidden `check` function sets `key` to 7, but it is never called in the normal execution flow.

**Input for "Good game":**
Since `key` is 0, the input must match the hardcoded string directly.

```bash
$ echo 'OfdlDSA|3tXb32~X3tX@sX`4tXtz' | ./crackme5
Enter your input:
Good game
```

**Hidden Flag:**
If we assume the `check` function was meant to run (setting `key=7`), or if we XOR the hardcoded string with 7 manually, we get a meaningful string which is likely the intended flag:


## Crackme6

`ltrace` isn't very helpful for finding the password here because the binary doesn't use standard library functions like `strcmp` for comparison. Instead, it uses a custom function `my_secure_test`.

**Analysis:**
Disassembling `my_secure_test` shows a series of byte-by-byte comparisons:
- `cmp al, 0x31` ('1')
- `cmp al, 0x33` ('3')
- `cmp al, 0x33` ('3')
- `cmp al, 0x37` ('7')
- `cmp al, 0x5f` ('_')
- `cmp al, 0x70` ('p')
- `cmp al, 0x77` ('w')
- `cmp al, 0x64` ('d')


## Crackme7

The binary presents a menu with 3 options.
Analyzing the `main` function with `objdump`, we see a comparison `cmp eax, 0x7a69` right after reading the input.
`0x7a69` in decimal is `31337`.
If the input matches `31337`, it calls the `giveFlag` function.

```bash
$ echo "31337" | ./crackme7
Menu:
...
[>] Wow such h4x0r!
flag{much_reversing_very_ida_wow}
```


## Crackme8

The binary takes an argument and converts it to an integer using `atoi`.
Disassembly of `main` shows a comparison: `cmp eax, 0xcafef00d`.
`0xcafef00d` interpreted as a 32-bit signed integer is `-889262067`.

```bash
$ ./crackme8 -889262067
Access granted.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```

**Flag:**`flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`





