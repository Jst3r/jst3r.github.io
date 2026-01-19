# Under-Dev

**Category:** Reverse Engineering  
**Points:** 500  
**Flag:** `IDEH{e4sy_andro1d_interc3pt}`

---

## Challenge Description

> Intercept 500 0 0  
> Just a warmup.

We're provided with an Android APK file: `under-dev.apk`

---

## Solution

### Step 1: Initial Analysis

First, we verify the file type and examine the APK structure:

```bash
$ file under-dev.apk
under-dev.apk: Android package (APK), with APK Signing Block

$ unzip -l under-dev.apk | head -20
```

The APK contains the standard Android application structure with `classes.dex`, `classes2.dex`, and `classes3.dex` files.

### Step 2: Decompiling the APK

We use `apktool` and `baksmali` to decompile the APK and analyze the source code:

```bash
$ apktool d under-dev.apk -o under-dev-apktool
$ baksmali d classes3.dex -o under-dev-smali
```

### Step 3: Analyzing MainActivity

Looking at the `AndroidManifest.xml`, we identify the main activity:

```
com.example.ideh_android_easy.MainActivity
```

Examining the decompiled smali code in `MainActivity.smali`, we find the critical pieces:

#### Hardcoded URL (line 81):
```smali
const-string v0, "http://ideh.cloud/andro1d"
iput-object v0, ... flagUrl
```

#### Hardcoded API Key (line 86):
```smali
const-string v0, "IDEH-CTF-e4sy"
iput-object v0, ... apiKey
```

### Step 4: Understanding the HTTP Request

The `fetch()` method (lines 94-351) reveals how the app makes the request:

```smali
# Sets the HTTP method
const-string v1, "GET"
invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

# Sets the X-Api-Key header
const-string v1, "X-Api-Key"
iget-object v2, p0, ... apiKey
invoke-virtual {v0, v1, v2}, Ljava/net/HttpURLConnection;->setRequestProperty(...)V

# Sets the User-Agent header
const-string v1, "User-Agent"
const-string v2, "IDEH-2025/1.0"
invoke-virtual {v0, v1, v2}, Ljava/net/HttpURLConnection;->setRequestProperty(...)V
```

### Step 5: Crafting the Request

With all the extracted information, we craft the HTTP request:

| Parameter | Value |
|-----------|-------|
| **Method** | GET |
| **URL** | `http://ideh.cloud/andro1d` |
| **X-Api-Key** | `IDEH-CTF-e4sy` |
| **User-Agent** | `IDEH-2025/1.0` |

### Step 6: Getting the Flag

```bash
$ curl -H "X-Api-Key: IDEH-CTF-e4sy" -H "User-Agent: IDEH-2025/1.0" http://ideh.cloud/andro1d
IDEH{e4sy_andro1d_interc3pt}
```

---

## Flag

```
IDEH{e4sy_andro1d_interc3pt}
```

---

## Key Takeaways

1. **APK Decompilation**: Android APKs can be easily decompiled using tools like `apktool` and `baksmali` to reveal the underlying logic
2. **Hardcoded Secrets**: The app contained hardcoded API credentials that could be extracted through static analysis
3. **Request Interception**: The challenge hint "Intercept" pointed to the need to manually craft and send the HTTP request with the correct headers

## Tools Used

- `file` - File type identification
- `unzip` - APK extraction
- `apktool` - APK decompilation
- `baksmali` - DEX to smali disassembly
- `strings` - String extraction
- `curl` - HTTP request crafting
