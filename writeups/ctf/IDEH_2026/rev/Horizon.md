# Horizon

## Files

- `Horizon` - ELF 64-bit executable

## Analysis

### Initial Recon

```bash
$ file Horizon
Horizon: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
```

The binary contains several key functions:
- `vm_run` - A custom VM interpreter
- `digest256` - Custom hash function
- `xtea_dec` - XTEA decryption
- `g_vm0_code` / `g_vm1_code` - VM bytecode

### Program Flow

1. Takes input as command-line argument
2. Runs **VM0** on input, must return 1
3. Hashes VM0 output state and compares with expected hash at `0x3350` (**Checkpoint A**)
4. Runs **VM1** on transformed data, must return 1
5. Hashes VM1 output and compares with expected hash at `0x3380` (**Checkpoint B**)
6. **If Checkpoint B fails**: Decrypts decoy flag using hardcoded XTEA key
7. **If Checkpoint B passes**: Derives XTEA key from hash output and decrypts real flag

### The Trap

If you simply patch the binary to bypass the VM checks, you'll get the decoy flag:
```
IDEH{vm_patch_prints_this_fake}
```

This is the "patch it and you get a decoy" from the hint.

### Getting the Real Flag

The real flag path is taken when Checkpoint B hash **matches**. At that point:
1. A key is derived from the digest output bytes
2. Different encrypted data at `0x32f8` is decrypted

The key derivation at `0x1625`:
```
key[0] = digest[0x80] ^ digest[0x94]
key[1] = digest[0x98] + digest[0x84]
key[2] = rol(digest[0x90], 7) + digest[0x8c]
key[3] = rol(digest[0x9c], 13) ^ digest[0x88]
```

Since we know the expected hash values, we can derive the key directly!

### Hash to Key Mapping

From the comparison code:
- `0x80(%rsp)` = `expected_hash_b[16:32]`
- `0x90(%rsp)` = `expected_hash_b[0:16]`

Expected hash B at `0x3380`:
```
3ce6fc0914b72e8fcdf3a27c3e7c5f4ea009cc1ccc96f686deb573d495423a73
```

## Solution

```python
import struct

def xtea_decrypt_block(v0, v1, key):
    delta = 0x9E3779B9
    sum_val = 0xC6EF3720
    for _ in range(32):
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3])
        v1 &= 0xFFFFFFFF
        sum_val = (sum_val + 0x61C88647) & 0xFFFFFFFF
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3])
        v0 &= 0xFFFFFFFF
    return v0, v1

# Expected hash B
expected_hash_b = bytes.fromhex("3ce6fc0914b72e8fcdf3a27c3e7c5f4ea009cc1ccc96f686deb573d495423a73")

# Memory layout when hash matches
digest_at_80 = expected_hash_b[16:32]
digest_at_90 = expected_hash_b[0:16]

# Derive key
k0_a = struct.unpack('<I', digest_at_80[0:4])[0]
k0_b = struct.unpack('<I', digest_at_90[4:8])[0]
key_part0 = k0_a ^ k0_b

k1_a = struct.unpack('<I', digest_at_90[8:12])[0]
k1_b = struct.unpack('<I', digest_at_80[4:8])[0]
key_part1 = (k1_a + k1_b) & 0xFFFFFFFF

k2_a = struct.unpack('<I', digest_at_90[0:4])[0]
k2_b = struct.unpack('<I', digest_at_80[12:16])[0]
key_part2 = (((k2_a << 7) | (k2_a >> 25)) + k2_b) & 0xFFFFFFFF

k3_a = struct.unpack('<I', digest_at_90[12:16])[0]
k3_b = struct.unpack('<I', digest_at_80[8:12])[0]
key_part3 = ((k3_a << 13) | (k3_a >> 19)) ^ k3_b & 0xFFFFFFFF

derived_key = (key_part0, key_part1, key_part3, key_part2)

# Encrypted flag at 0x32f8
enc_flag = bytes.fromhex("f7537fee56feb53fc5d303bb2f256531a035bcdd5d74245c460e27448e0d4d62e605540d639c7155")

# Decrypt
decrypted = bytearray()
for i in range(0, 40, 8):
    v0, v1 = struct.unpack('<2I', enc_flag[i:i+8])
    d0, d1 = xtea_decrypt_block(v0, v1, derived_key)
    decrypted.extend(struct.pack('<2I', d0, d1))

print(decrypted.rstrip(b'\x00').decode())
```

## Flag

```
IDEH{H0pe_y0u_enj0y3d_s33_u_n3xt_year}
```

## Key Takeaways

- The hints were crucial: "Patch it and you get a decoy, reverse it to recover the flag"
- Instead of finding the correct input, we derived the XTEA key directly from the expected hash
- The challenge had two code paths - one for failed hash (decoy) and one for matched hash (real flag)
