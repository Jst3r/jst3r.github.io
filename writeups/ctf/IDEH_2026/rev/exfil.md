# Exfil - Writeup


## Challenge Description
Easy but hard & chaining is key, how good you are?

## Solution

### Step 1: Initial Analysis
The challenge provided `exfil.apk`. I unpacked it and decompiled the code using `apktool` and `jadx` (simulated).

### Step 2: Static Analysis
Analysis of `AndroidManifest.xml` revealed a `DocsActivity` that handles `ideh://docs` intents.
The `DocsActivity` sets up a WebView with a JavaScript Interface `i1.a` bound to the name `IDEH`.

The `assets/docs/index.html` file calls `IDEH.getDeviceInfo()`.

```javascript
document.getElementById("diag").innerText = IDEH.getDeviceInfo();
```

### Step 3: Decompilation of the Interface
Analyzing `smali/i1/a.smali` (the implementation of the interface), I found the `getDeviceInfo` method.
This method:
1.  Reads a raw resource `flag_blob` from `res/raw/flag_blob.bin`.
2.  Extracts the APK's **V2/V3 Signature** (X.509 Certificate).
3.  Calculates the SHA-256 hash of the signature.
4.  Derives an AES key from the first 16 bytes of the hash.
5.  Decrypts the `flag_blob` using **AES-GCM**.
    *   **IV**: First 12 bytes of the blob.
    *   **AAD**: The package name `com.cit.ideh.exfil`.
    *   **Ciphertext**: The rest of the blob.

### Step 4: Solving
Since the APK was not signed with the debug keystore (no `META-INF/CERT.RSA`), I had to parse the **APK Signing Block** manually from the binary to extract the certificate.
I wrote a Python script `solve_exfil.py` to:
1.  Parse the APK Signing Block.
2.  Extract the certificate.
3.  Derive the key.
4.  Decrypt the flag using `cryptography` library with the correct AAD tag.

```python

import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zipfile
import sys

# Constants for APK Signing Block
APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041
APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42
APK_SIG_BLOCK_MIN_SIZE = 32

def get_zip_eocd(f):
    f.seek(0, 2)
    fsize = f.tell()
    # Search for EOCD in last 64KB
    size = min(fsize, 65535)
    f.seek(fsize - size)
    data = f.read(size)
    # EOCD signature: 0x06054b50
    idx = data.rfind(b'\x50\x4b\x05\x06')
    if idx == -1:
        raise Exception("EOCD not found")
    
    eocd = data[idx:]
    # Offset of CD is at offset 16 in EOCD
    cd_offset = struct.unpack('<I', eocd[16:20])[0]
    return cd_offset

def parse_signing_block(f, cd_offset):
    # APK Signing Block is immediately before CD
    # Block format: [size (8)] [ID-value pairs] [size (8)] [magic (16)]
    # We check the footer first
    f.seek(cd_offset - 24)
    footer = f.read(24)
    size_of_block_footer = struct.unpack('<Q', footer[0:8])[0]
    magic_lo = struct.unpack('<Q', footer[8:16])[0]
    magic_hi = struct.unpack('<Q', footer[16:24])[0]
    
    if magic_lo != APK_SIG_BLOCK_MAGIC_LO or magic_hi != APK_SIG_BLOCK_MAGIC_HI:
        raise Exception("APK Signing Block Magic not found")
        
    start_offset = cd_offset - (size_of_block_footer + 8)
    f.seek(start_offset)
    
    # Read block size
    size_of_block = struct.unpack('<Q', f.read(8))[0]
    if size_of_block != size_of_block_footer:
        raise Exception("Block sizes do not match")

    # Read pairs
    pairs_data = f.read(size_of_block - 24) # Exclude footer
    
    # Parse pairs
    pos = 0
    while pos < len(pairs_data):
        len_pair = struct.unpack('<Q', pairs_data[pos:pos+8])[0]
        pos += 8
        id_pair = struct.unpack('<I', pairs_data[pos:pos+4])[0]
        value_pair = pairs_data[pos+4 : pos + int(len_pair)]
        pos += int(len_pair) - 4 # len_pair includes ID size (4)
        
        # ID 0x7109871a is v2 Signature Scheme
        # ID 0xf05368c0 is v3 Signature Scheme
        if id_pair == 0x7109871a or id_pair == 0xf05368c0:
            print(f"Found Signature Block ID: {hex(id_pair)}")
            parse_v2_scheme(value_pair)
            return

def parse_v2_scheme(data):
    # Format: [len] [signer] [len] [signer] ...
    # Signer: [len] [signed data] [len] [signatures] [len] [public key]
    # Signed Data: [len] [digests] [len] [certificates] [len] [attrs]
    # Certificates: [len] [cert] [len] [cert] ...
    
    # Correct structure of v2 block:
    # u32 lengths prefixed sequence of signers
    signers_len = struct.unpack('<I', data[0:4])[0]
    signers_data = data[4:4+signers_len]
    
    # iterate signers
    spos = 0
    while spos < len(signers_data):
        signer_len = struct.unpack('<I', signers_data[spos:spos+4])[0]
        signer = signers_data[spos+4 : spos+4+signer_len]
        spos += 4 + signer_len
        
        # Parse signer
        # [len] signed data
        signed_data_len = struct.unpack('<I', signer[0:4])[0]
        signed_data = signer[4:4+signed_data_len]
        
        # Parse signed data
        # [len] digests
        # [len] certificates
        dpos = 0
        digests_len = struct.unpack('<I', signed_data[dpos:dpos+4])[0]
        dpos += 4 + digests_len
        
        certs_len = struct.unpack('<I', signed_data[dpos:dpos+4])[0]
        certs_data = signed_data[dpos+4 : dpos+4+certs_len]
        
        # First cert
        cpos = 0
        cert_len = struct.unpack('<I', certs_data[cpos:cpos+4])[0]
        cert = certs_data[cpos+4 : cpos+4+cert_len]
        
        print(f"Found certificate of length: {cert_len}")
        decrypt_flag(cert)
        return

def decrypt_flag(cert_bytes):
    # Hash check
    h = hashlib.sha256(cert_bytes).digest()
    key = h[:16]
    print(f"Key: {key.hex()}")
    
    # Load flag blob
    try:
        with open('exfil_apktool/res/raw/flag_blob.bin', 'rb') as f:
            blob = f.read()
    except:
        print("Flag blob not found locally, please specify path")
        return
    
    iv = blob[:12]
    ciphertext = blob[12:]
    tag = ciphertext[-16:]
    ct = ciphertext[:-16]

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(b"com.cit.ideh.exfil")
        decrypted = decryptor.update(ct) + decryptor.finalize()
        print(f"Decrypted Flag: {decrypted.decode('utf-8')}")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == '__main__':
    with open('exfil.apk', 'rb') as f:
        cd_offset = get_zip_eocd(f)
        parse_signing_block(f, cd_offset)

```



## Result

```bash
$ python3 solve_exfil.py
Found Signature Block ID: 0x7109871a
Found certificate of length: 734
Key: c797e89761eadaba8c60dd66eabdfae3
Decrypted Flag: IDEH{m4ster_0f_4ndro1d}
```

## Flag
`IDEH{m4ster_0f_4ndro1d}`
